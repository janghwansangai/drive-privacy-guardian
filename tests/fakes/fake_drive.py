"""In-memory fake of the Drive v3 API surface used by dpg (SPEC 8).

It mimics the google-api-python-client call style::

    svc = fake.service()
    svc.files().list(q="trashed = false", fields="nextPageToken, files(id,name)").execute()

Design goals:
- No network, no real account. Errors are real `googleapiclient.errors.HttpError`s.
- Conservative: unsupported query syntax / fields raise instead of silently returning data, and
  default `fields` return only the minimal resource, so code must request what it needs.
- Write detection: in read-only mode (the default) *building* any write request raises
  `WriteAttemptError`, which fails the test. Permanent deletion (`files.delete`,
  `files.emptyTrash`) raises `ForbiddenCallError` in every mode (SPEC 1.2 principle 4).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import itertools
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import httplib2
from googleapiclient.errors import HttpError

FOLDER_MIME = "application/vnd.google-apps.folder"
GOOGLE_APPS_PREFIX = "application/vnd.google-apps."
EXPORT_SIZE_LIMIT = 10 * 1024 * 1024  # V7: to be confirmed against official docs

ROLE_RANK = {
    "reader": 1,
    "commenter": 2,
    "writer": 3,
    "fileOrganizer": 4,
    "organizer": 5,
    "owner": 6,
}

READ_METHODS = frozenset(
    {
        "about.get",
        "drives.list",
        "drives.get",
        "files.list",
        "files.get",
        "files.get_media",
        "files.export",
        "files.export_media",
        "permissions.list",
        "permissions.get",
        "changes.getStartPageToken",
        "changes.list",
    }
)
FORBIDDEN_METHODS = frozenset({"files.delete", "files.emptyTrash", "drives.delete"})


class WriteAttemptError(AssertionError):
    """A write API was called while the fake is read-only."""


class ForbiddenCallError(AssertionError):
    """A permanently destructive API was called. Never allowed (SPEC 1.2 principle 4)."""


def http_error(status: int, reason: str, message: str | None = None) -> HttpError:
    msg = message or reason
    resp = httplib2.Response({"status": str(status)})
    resp.reason = msg
    body = {
        "error": {"code": status, "message": msg, "errors": [{"reason": reason, "message": msg}]}
    }
    return HttpError(
        resp, json.dumps(body).encode(), uri="https://www.googleapis.com/drive/v3/fake"
    )


# ---------------------------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------------------------


def _stable_id(prefix: str, key: str) -> str:
    return prefix + hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class FakePermission:
    type: str  # user | group | domain | anyone
    role: str
    email: str | None = None
    domain: str | None = None
    allow_discovery: bool = False

    @property
    def id(self) -> str:
        # Real Drive permission IDs are per-principal (stable across files).
        if self.type == "anyone":
            return "anyone" if self.allow_discovery else "anyoneWithLink"
        if self.type == "domain":
            return _stable_id("d", f"{self.domain}|{self.allow_discovery}")
        return _stable_id("", f"{self.type}|{(self.email or '').lower()}")

    def base_resource(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "kind": "drive#permission",
            "id": self.id,
            "type": self.type,
            "role": self.role,
        }
        if self.email:
            res["emailAddress"] = self.email
            res["displayName"] = self.email.split("@", 1)[0]
        if self.domain:
            res["domain"] = self.domain
        if self.type in ("anyone", "domain"):
            res["allowFileDiscovery"] = self.allow_discovery
        return res


@dataclass
class FakeItem:
    id: str
    name: str
    mime_type: str
    parent: str | None  # internal single parent (file id, drive id, or None)
    owner: str | None  # None for shared-drive items
    drive_id: str | None
    created_time: str
    modified_time: str
    content: bytes | None = None
    exports: dict[str, bytes] = field(default_factory=dict)
    permissions: list[FakePermission] = field(default_factory=list)
    trashed: bool = False
    writers_can_share: bool = True
    copy_requires_writer_permission: bool = False
    can_list_permissions: bool | None = None  # None = derive from caller's role
    is_root: bool = False
    # "Limited access" folder (V5): stops inheritance from ancestors above this item.
    inherited_permissions_disabled: bool = False
    download_restricted_for_readers: bool = False

    @property
    def is_folder(self) -> bool:
        return self.mime_type == FOLDER_MIME

    @property
    def is_google_type(self) -> bool:
        return self.mime_type.startswith(GOOGLE_APPS_PREFIX)


@dataclass
class FakeSharedDrive:
    id: str
    name: str
    members: dict[str, str]  # email -> role


@dataclass
class _Injection:
    method: str
    status: int
    reason: str
    remaining: int | None  # None = forever
    when: Callable[[dict[str, Any]], bool] | None


# ---------------------------------------------------------------------------------------------
# Query language (subset of https://developers.google.com/workspace/drive/api/guides/search-files)
# ---------------------------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"\s*(?:(?P<str>'(?:[^'\\]|\\.)*')|(?P<op>!=|<=|>=|=|<|>)|(?P<lp>\()|(?P<rp>\))"
    r"|(?P<word>[A-Za-z_][A-Za-z0-9_]*))"
)


class QuerySyntaxError(ValueError):
    pass


def _tokenize(q: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    q = q.rstrip()
    while pos < len(q):
        m = _TOKEN_RE.match(q, pos)
        if not m or m.end() == pos:
            raise QuerySyntaxError(f"bad token at {pos}")
        kind = m.lastgroup
        assert kind is not None
        value = m.group(kind)
        if kind == "str":
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
        tokens.append((kind, value))
        pos = m.end()
    return tokens


Predicate = Callable[["FakeItem"], bool]


class _QueryParser:
    def __init__(self, drive: FakeDrive, q: str) -> None:
        self.drive = drive
        self.tokens = _tokenize(q)
        self.i = 0

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise QuerySyntaxError("unexpected end of query")
        self.i += 1
        return tok

    def is_word(self, word: str) -> bool:
        tok = self.peek()
        return tok is not None and tok[0] == "word" and tok[1].lower() == word

    def parse(self) -> Predicate:
        pred = self.or_expr()
        if self.peek() is not None:
            raise QuerySyntaxError("trailing tokens")
        return pred

    def or_expr(self) -> Predicate:
        preds = [self.and_expr()]
        while self.is_word("or"):
            self.take()
            preds.append(self.and_expr())
        return preds[0] if len(preds) == 1 else (lambda it: any(p(it) for p in preds))

    def and_expr(self) -> Predicate:
        preds = [self.unary()]
        while self.is_word("and"):
            self.take()
            preds.append(self.unary())
        return preds[0] if len(preds) == 1 else (lambda it: all(p(it) for p in preds))

    def unary(self) -> Predicate:
        if self.is_word("not"):
            self.take()
            inner = self.unary()
            return lambda it: not inner(it)
        tok = self.peek()
        if tok is not None and tok[0] == "lp":
            self.take()
            pred = self.or_expr()
            if self.take()[0] != "rp":
                raise QuerySyntaxError("missing )")
            return pred
        return self.term()

    def term(self) -> Predicate:
        kind, value = self.take()
        d = self.drive
        if kind == "str":
            if not self.is_word("in"):
                raise QuerySyntaxError("expected 'in'")
            self.take()
            fk, fname = self.take()
            if fk != "word":
                raise QuerySyntaxError("expected field after 'in'")
            return d._membership_predicate(value, fname)
        if kind != "word":
            raise QuerySyntaxError(f"unexpected token {kind}")
        fname = value
        if fname == "sharedWithMe" and (self.peek() is None or self.peek()[0] != "op"):  # type: ignore[index]
            return d._shared_with_me
        if self.is_word("contains"):
            self.take()
            sk, needle = self.take()
            if sk != "str":
                raise QuerySyntaxError("contains needs a string")
            if fname != "name":
                raise NotImplementedError(f"fake_drive: '{fname} contains' unsupported")
            return lambda it: needle.lower() in it.name.lower()
        ok, op = self.take()
        if ok != "op":
            raise QuerySyntaxError("expected operator")
        vk, rhs = self.take()
        if vk == "word" and rhs.lower() in ("true", "false"):
            rhs_val: Any = rhs.lower() == "true"
        elif vk == "str":
            rhs_val = rhs
        else:
            raise QuerySyntaxError("bad value")
        return d._compare_predicate(fname, op, rhs_val)


# ---------------------------------------------------------------------------------------------
# fields= selection
# ---------------------------------------------------------------------------------------------

FieldTree = dict[str, "FieldTree | None"]


def parse_fields(expr: str) -> FieldTree:
    if "/" in expr:
        raise NotImplementedError("fake_drive: 'a/b' fields syntax unsupported; use a(b)")
    pos = 0

    def parse_list() -> FieldTree:
        nonlocal pos
        tree: FieldTree = {}
        while pos < len(expr):
            m = re.match(r"\s*([A-Za-z*][A-Za-z0-9_]*)\s*", expr[pos:])
            if not m:
                raise QuerySyntaxError(f"bad fields at {pos}")
            name = m.group(1)
            pos += m.end()
            sub: FieldTree | None = None
            if pos < len(expr) and expr[pos] == "(":
                pos += 1
                sub = parse_list()
                if pos >= len(expr) or expr[pos] != ")":
                    raise QuerySyntaxError("missing ) in fields")
                pos += 1
                while pos < len(expr) and expr[pos] == " ":
                    pos += 1
            tree[name] = sub
            if pos < len(expr) and expr[pos] == ",":
                pos += 1
                continue
            break
        return tree

    tree = parse_list()
    if pos != len(expr.rstrip()):
        raise QuerySyntaxError("trailing characters in fields")
    return tree


def select_fields(obj: Any, tree: FieldTree | None) -> Any:
    if tree is None or "*" in tree:
        return obj
    if isinstance(obj, list):
        return [select_fields(x, tree) for x in obj]
    if isinstance(obj, dict):
        return {k: select_fields(obj[k], sub) for k, sub in tree.items() if k in obj}
    return obj


def _defaults(spec: str) -> FieldTree:
    return parse_fields(spec)


DEFAULT_FIELDS = {
    "files.list": _defaults("kind,nextPageToken,incompleteSearch,files(kind,id,name,mimeType)"),
    "files.get": _defaults("kind,id,name,mimeType"),
    "permissions.list": _defaults("kind,nextPageToken,permissions(kind,id,type,role)"),
    "permissions.get": _defaults("kind,id,type,role"),
    "drives.list": _defaults("kind,nextPageToken,drives(kind,id,name)"),
    "drives.get": _defaults("kind,id,name"),
    "about.get": None,  # real API requires fields; we are lenient here
}


# ---------------------------------------------------------------------------------------------
# The fake drive
# ---------------------------------------------------------------------------------------------


class FakeDrive:
    def __init__(
        self,
        me: str = "teacher@school.example",
        *,
        read_only: bool = True,
        start_time: dt.datetime | None = None,
    ) -> None:
        self.me = me.lower()
        self.my_domain = self.me.split("@", 1)[1]
        self.read_only = read_only
        self.items: dict[str, FakeItem] = {}
        self.drives: dict[str, FakeSharedDrive] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.change_log: list[str] = []  # file ids, in order (changes API)
        self.min_change_token = 0  # tokens below this are "expired" (400)
        self.corrupt_uploads = False  # test switch: flip one byte of every uploaded file
        self.notifications: list[str] = []  # file IDs for which a sharing e-mail would be sent
        self._injections: list[_Injection] = []
        self._ids = itertools.count(1)
        self._clock = start_time or dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
        self.root_id = "0AFakeMyDriveRoot"
        now = self._tick()
        self.items[self.root_id] = FakeItem(
            id=self.root_id,
            name="My Drive",
            mime_type=FOLDER_MIME,
            parent=None,
            owner=self.me,
            drive_id=None,
            created_time=now,
            modified_time=now,
            is_root=True,
        )

    # -- setup helpers (not API calls; never counted as writes) --------------------------------

    def _tick(self) -> str:
        self._clock += dt.timedelta(seconds=1)
        return self._clock.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _new_id(self, prefix: str = "1Fake") -> str:
        return f"{prefix}{next(self._ids):08d}"

    def add_shared_drive(self, name: str, members: dict[str, str] | None = None) -> str:
        drive_id = self._new_id("0AFakeDrive")
        self.drives[drive_id] = FakeSharedDrive(
            id=drive_id,
            name=name,
            members={k.lower(): v for k, v in (members or {self.me: "organizer"}).items()},
        )
        return drive_id

    def add_item(
        self,
        name: str,
        mime_type: str,
        parent: str | None = None,
        *,
        owner: str | None = None,
        content: bytes | None = None,
        exports: dict[str, bytes] | None = None,
        modified_time: str | None = None,
        **flags: Any,
    ) -> str:
        drive_id: str | None = None
        if parent is None:
            owner = (owner or self.me).lower()
            parent = self.root_id if owner == self.me else None
        elif parent in self.drives:
            drive_id = parent
        else:
            drive_id = self.items[parent].drive_id
        owner = (owner or self.me).lower() if drive_id is None else None
        now = self._tick()
        item = FakeItem(
            id=self._new_id(),
            name=name,
            mime_type=mime_type,
            parent=parent,
            owner=owner,
            drive_id=drive_id,
            created_time=now,
            modified_time=modified_time or now,
            content=content,
            exports=dict(exports or {}),
            **flags,
        )
        self.items[item.id] = item
        self.touch(item.id)
        return item.id

    def add_folder(self, name: str, parent: str | None = None, **kw: Any) -> str:
        return self.add_item(name, FOLDER_MIME, parent, **kw)

    def add_file(
        self,
        name: str,
        parent: str | None = None,
        *,
        mime_type: str = "text/plain",
        content: bytes | None = b"",
        **kw: Any,
    ) -> str:
        return self.add_item(name, mime_type, parent, content=content, **kw)

    def share(
        self,
        item_id: str,
        type: str,
        role: str,
        *,
        email: str | None = None,
        domain: str | None = None,
        allow_discovery: bool = False,
    ) -> str:
        perm = FakePermission(
            type=type,
            role=role,
            email=email.lower() if email else None,
            domain=domain,
            allow_discovery=allow_discovery,
        )
        item = self.items[item_id]
        item.permissions = [p for p in item.permissions if p.id != perm.id] + [perm]
        self.touch(item_id)
        return perm.id

    def touch(self, file_id: str) -> None:
        """Record a change (call after mutating `items` directly in a test)."""
        self.change_log.append(file_id)

    def expire_change_tokens(self) -> None:
        self.min_change_token = len(self.change_log) + 1

    def inject_error(
        self,
        method: str,
        status: int,
        reason: str = "backendError",
        *,
        times: int | None = 1,
        when: Callable[[dict[str, Any]], bool] | None = None,
    ) -> None:
        """Make the next `times` matching calls of `method` raise HttpError(status)."""
        self._injections.append(_Injection(method, status, reason, times, when))

    @property
    def write_calls(self) -> list[tuple[str, dict[str, Any]]]:
        return [c for c in self.calls if c[0] not in READ_METHODS]

    def call_count(self, method: str) -> int:
        return sum(1 for name, _ in self.calls if name == method)

    def service(self) -> FakeService:
        return FakeService(self)

    # -- model queries -------------------------------------------------------------------------

    def ancestors(self, item: FakeItem) -> Iterator[FakeItem]:
        seen = {item.id}
        cur = item.parent
        while cur is not None and cur in self.items and cur not in seen:
            seen.add(cur)
            anc = self.items[cur]
            yield anc
            cur = anc.parent

    def effective_permissions(self, item: FakeItem) -> list[dict[str, Any]]:
        """Merged permission resources, including inherited ones (with details on shared drives).

        Limited-access folders (inheritedPermissionsDisabled, V5): principals whose only access
        comes from above such a folder keep an entry with role=reader, view=metadata,
        inheritedPermissionsDisabled=true (they can see the item but not open it).
        """
        # (perm, inheritedFrom, permissionType, cut_off)
        sources: list[tuple[FakePermission, str | None, str, bool]] = []
        chain_disabled = item.inherited_permissions_disabled or any(
            a.inherited_permissions_disabled for a in self.ancestors(item)
        )
        if item.drive_id is None:
            if item.owner:
                sources.append(
                    (FakePermission("user", "owner", email=item.owner), None, "file", False)
                )
        else:
            for email, role in self.drives[item.drive_id].members.items():
                cut = chain_disabled and role != "organizer"
                sources.append(
                    (FakePermission("user", role, email=email), item.drive_id, "member", cut)
                )
        cut = item.inherited_permissions_disabled
        for anc in self.ancestors(item):
            for p in anc.permissions:
                sources.append((p, anc.id, "file", cut))
            cut = cut or anc.inherited_permissions_disabled
        for p in item.permissions:
            sources.append((p, None, "file", False))

        grouped: dict[str, list[tuple[FakePermission, str | None, str, bool]]] = {}
        for src in sources:
            grouped.setdefault(src[0].id, []).append(src)
        merged: list[dict[str, Any]] = []
        for group in grouped.values():
            live = [g for g in group if not g[3]]
            res = group[0][0].base_resource()
            if live:
                res["role"] = max((g[0].role for g in live), key=lambda r: ROLE_RANK[r])
            else:
                res["role"] = "reader"
                res["view"] = "metadata"
                res["inheritedPermissionsDisabled"] = True
            if item.drive_id is not None:
                details = []
                for perm, inherited_from, ptype, _cut in group:
                    detail: dict[str, Any] = {
                        "permissionType": ptype,
                        "role": perm.role,
                        "inherited": inherited_from is not None,
                    }
                    if inherited_from is not None:
                        detail["inheritedFrom"] = inherited_from
                    details.append(detail)
                res["permissionDetails"] = details
            merged.append(res)
        return merged

    def my_role(self, item: FakeItem) -> str | None:
        best: str | None = None
        for res in self.effective_permissions(item):
            if res.get("view") == "metadata":
                continue  # can see, cannot open
            applies = (res["type"] == "user" and res.get("emailAddress") == self.me) or (
                res["type"] == "domain" and res.get("domain") == self.my_domain
            )
            if applies and (best is None or ROLE_RANK[res["role"]] > ROLE_RANK[best]):
                best = res["role"]
        return best

    def accessible(self, item: FakeItem) -> bool:
        if item.is_root:
            return True
        return any(
            res["type"] == "user" and res.get("emailAddress") == self.me
            for res in self.effective_permissions(item)
        )

    def can_share(self, item: FakeItem) -> bool:
        if item.can_list_permissions is not None:
            return item.can_list_permissions
        role = self.my_role(item)
        if role is None:
            return False
        if item.drive_id is None and item.owner != self.me and role == "writer":
            return item.writers_can_share
        return ROLE_RANK[role] >= ROLE_RANK["writer"]

    def visibility(self, item: FakeItem) -> str | None:
        """V4: only 'anyoneCanFind' | 'anyoneWithLink' | 'limited' exist. Domain-shared items
        match none of them (None)."""
        live = [r for r in self.effective_permissions(item) if r.get("view") != "metadata"]
        anyone = [r for r in live if r["type"] == "anyone"]
        if any(r.get("allowFileDiscovery") for r in anyone):
            return "anyoneCanFind"
        if anyone:
            return "anyoneWithLink"
        if any(r["type"] == "domain" for r in live):
            return None
        return "limited"

    def file_resource(self, item: FakeItem) -> dict[str, Any]:
        perms = self.effective_permissions(item)
        can_share = self.can_share(item)
        role = self.my_role(item)
        res: dict[str, Any] = {
            "kind": "drive#file",
            "id": item.id,
            "name": item.name,
            "mimeType": item.mime_type,
            "trashed": item.trashed,
            "createdTime": item.created_time,
            "modifiedTime": item.modified_time,
            "copyRequiresWriterPermission": item.copy_requires_writer_permission,
            "inheritedPermissionsDisabled": item.inherited_permissions_disabled,
            "downloadRestrictions": {
                "itemDownloadRestriction": {
                    "restrictedForReaders": item.download_restricted_for_readers,
                    "restrictedForWriters": False,
                },
                "effectiveDownloadRestrictionWithContext": {
                    "restrictedForReaders": item.download_restricted_for_readers,
                    "restrictedForWriters": False,
                },
            },
            "capabilities": {
                "canShare": can_share,
                "canEdit": role is not None and ROLE_RANK[role] >= ROLE_RANK["writer"],
                "canListChildren": item.is_folder,
                "canTrash": role in ("owner", "organizer", "fileOrganizer"),
            },
        }
        if item.parent is not None and not item.is_root:
            parent = self.items.get(item.parent)
            if item.parent in self.drives or (parent is not None and self.accessible(parent)):
                res["parents"] = [item.parent]
        if item.drive_id is None:
            assert item.owner is not None
            res["owners"] = [
                {
                    "kind": "drive#user",
                    "emailAddress": item.owner,
                    "displayName": item.owner.split("@", 1)[0],
                    "me": item.owner == self.me,
                }
            ]
            res["ownedByMe"] = item.owner == self.me
            # Not populated for shared-drive items (files resource reference).
            res["shared"] = any(p["role"] != "owner" for p in perms)
            res["writersCanShare"] = item.writers_can_share
            if can_share:
                res["permissions"] = [
                    {k: v for k, v in p.items() if k != "permissionDetails"} for p in perms
                ]
        else:
            res["driveId"] = item.drive_id
            res["hasAugmentedPermissions"] = bool(item.permissions)
        if can_share:
            res["permissionIds"] = [p["id"] for p in perms]
        if not item.is_folder and not item.is_google_type and item.content is not None:
            res["size"] = str(len(item.content))
            res["md5Checksum"] = hashlib.md5(item.content, usedforsecurity=False).hexdigest()
        return res

    # predicates used by the query parser
    def _membership_predicate(self, value: str, fname: str) -> Predicate:
        if fname == "parents":
            target = self.root_id if value == "root" else value
            return lambda it: it.parent == target
        email = self.me if value == "me" else value.lower()
        if fname == "owners":
            return lambda it: it.owner == email
        if fname in ("writers", "readers"):
            min_rank = ROLE_RANK["writer"] if fname == "writers" else ROLE_RANK["reader"]
            return lambda it: any(
                p.get("emailAddress") == email and ROLE_RANK[p["role"]] >= min_rank
                for p in self.effective_permissions(it)
            )
        raise NotImplementedError(f"fake_drive: \"'...' in {fname}\" unsupported")

    def _shared_with_me(self, it: FakeItem) -> bool:
        return it.drive_id is None and it.owner != self.me and self.accessible(it)

    def _compare_predicate(self, fname: str, op: str, rhs: Any) -> Predicate:
        getters: dict[str, Callable[[FakeItem], Any]] = {
            "trashed": lambda it: it.trashed,
            "mimeType": lambda it: it.mime_type,
            "name": lambda it: it.name,
            "visibility": self.visibility,
            "modifiedTime": lambda it: it.modified_time,
            "createdTime": lambda it: it.created_time,
            "sharedWithMe": self._shared_with_me,
        }
        if fname not in getters:
            raise NotImplementedError(f"fake_drive: field {fname!r} unsupported in queries")
        if fname == "visibility" and rhs not in ("anyoneCanFind", "anyoneWithLink", "limited"):
            raise QuerySyntaxError(f"invalid visibility value {rhs!r}")
        get = getters[fname]
        ops: dict[str, Callable[[Any, Any], bool]] = {
            "=": lambda a, b: a == b,
            "!=": lambda a, b: a != b,
            "<": lambda a, b: a < b,
            "<=": lambda a, b: a <= b,
            ">": lambda a, b: a > b,
            ">=": lambda a, b: a >= b,
        }
        cmp = ops[op]
        return lambda it: cmp(get(it), rhs)

    # -- request plumbing ----------------------------------------------------------------------

    def _check_injection(self, method: str, kwargs: dict[str, Any]) -> None:
        for inj in self._injections:
            if inj.method != method or (inj.remaining is not None and inj.remaining <= 0):
                continue
            if inj.when is not None and not inj.when(kwargs):
                continue
            if inj.remaining is not None:
                inj.remaining -= 1
            raise http_error(inj.status, inj.reason)

    def request(self, method: str, kwargs: dict[str, Any], fn: Callable[[], Any]) -> FakeRequest:
        self.calls.append((method, dict(kwargs)))
        if method in FORBIDDEN_METHODS:
            raise ForbiddenCallError(f"{method} is never allowed (permanent deletion)")
        if method not in READ_METHODS and self.read_only:
            raise WriteAttemptError(f"write API {method} called while fake_drive is read-only")
        return FakeRequest(self, method, kwargs, fn)

    def _get_visible(self, file_id: str, supports_all_drives: bool) -> FakeItem:
        fid = self.root_id if file_id == "root" else file_id
        item = self.items.get(fid)
        if item is None or not self.accessible(item):
            raise http_error(404, "notFound", f"File not found: {file_id}.")
        if item.drive_id is not None and not supports_all_drives:
            raise http_error(404, "notFound", f"File not found: {file_id}.")
        return item

    @staticmethod
    def _fields(method: str, fields: str | None) -> FieldTree | None:
        return DEFAULT_FIELDS[method] if fields is None else parse_fields(fields)

    @staticmethod
    def _paginate(
        seq: list[Any], page_size: int | None, token: str | None, default: int | None, maximum: int
    ) -> tuple[list[Any], str | None]:
        start = 0
        if token:
            if not token.startswith("p") or not token[1:].isdigit():
                raise http_error(400, "invalidParameter", "Invalid pageToken")
            start = int(token[1:])
        size = page_size if page_size is not None else default
        if size is None:
            return seq[start:], None
        size = max(1, min(size, maximum))
        page = seq[start : start + size]
        nxt = f"p{start + size}" if start + size < len(seq) else None
        return page, nxt


class FakeRequest:
    def __init__(
        self, drive: FakeDrive, method: str, kwargs: dict[str, Any], fn: Callable[[], Any]
    ) -> None:
        self._drive = drive
        self.method = method
        self._kwargs = kwargs
        self._fn = fn

    def execute(self, num_retries: int = 0) -> Any:
        self._drive._check_injection(self.method, self._kwargs)
        result = self._fn()
        if self.method not in READ_METHODS and "fileId" in self._kwargs:
            self._drive.touch(str(self._kwargs["fileId"]))
        return result


class _Resource:
    def __init__(self, drive: FakeDrive) -> None:
        self._d = drive


class _Files(_Resource):
    def list(
        self,
        *,
        q: str | None = None,
        pageSize: int | None = None,
        pageToken: str | None = None,
        fields: str | None = None,
        corpora: str = "user",
        driveId: str | None = None,
        includeItemsFromAllDrives: bool = False,
        supportsAllDrives: bool = False,
        spaces: str = "drive",
        orderBy: str | None = None,
    ) -> FakeRequest:
        kwargs = dict(
            q=q,
            pageSize=pageSize,
            pageToken=pageToken,
            fields=fields,
            corpora=corpora,
            driveId=driveId,
            includeItemsFromAllDrives=includeItemsFromAllDrives,
            supportsAllDrives=supportsAllDrives,
            spaces=spaces,
            orderBy=orderBy,
        )
        d = self._d

        def run() -> Any:
            if orderBy is not None:
                raise NotImplementedError("fake_drive: orderBy unsupported")
            if spaces != "drive":
                raise NotImplementedError("fake_drive: only spaces='drive'")
            if includeItemsFromAllDrives and not supportsAllDrives:
                raise http_error(
                    400, "invalidParameter", "includeItemsFromAllDrives requires supportsAllDrives"
                )
            if corpora == "drive":
                if not (driveId and includeItemsFromAllDrives and supportsAllDrives):
                    raise http_error(
                        400,
                        "invalidParameter",
                        "corpora=drive requires driveId and all-drives flags",
                    )
                if driveId not in d.drives:
                    raise http_error(404, "notFound", f"Shared drive not found: {driveId}")

                def scope(it: FakeItem) -> bool:
                    return it.drive_id == driveId

            elif corpora == "user":

                def scope(it: FakeItem) -> bool:
                    return it.drive_id is None or includeItemsFromAllDrives

            elif corpora == "allDrives":
                if not includeItemsFromAllDrives:
                    raise http_error(400, "invalidParameter", "allDrives requires all-drives flags")

                def scope(it: FakeItem) -> bool:
                    return True

            else:
                raise NotImplementedError(f"fake_drive: corpora={corpora!r}")
            try:
                pred: Predicate = _QueryParser(d, q).parse() if q else (lambda it: True)
            except QuerySyntaxError as exc:
                raise http_error(400, "invalid", f"Invalid Value: {exc}") from None
            matches = [
                it
                for it in d.items.values()
                if not it.is_root and scope(it) and d.accessible(it) and pred(it)
            ]
            page, nxt = d._paginate(matches, pageSize, pageToken, default=100, maximum=1000)
            body: dict[str, Any] = {
                "kind": "drive#fileList",
                "incompleteSearch": False,
                "files": [d.file_resource(it) for it in page],
            }
            if nxt:
                body["nextPageToken"] = nxt
            return select_fields(body, d._fields("files.list", fields))

        return d.request("files.list", kwargs, run)

    def get(
        self, *, fileId: str, fields: str | None = None, supportsAllDrives: bool = False
    ) -> FakeRequest:
        d = self._d

        def run() -> Any:
            item = d._get_visible(fileId, supportsAllDrives)
            return select_fields(d.file_resource(item), d._fields("files.get", fields))

        return d.request(
            "files.get",
            dict(fileId=fileId, fields=fields, supportsAllDrives=supportsAllDrives),
            run,
        )

    def get_media(
        self, *, fileId: str, supportsAllDrives: bool = False, acknowledgeAbuse: bool = False
    ) -> FakeRequest:
        d = self._d

        def run() -> bytes:
            item = d._get_visible(fileId, supportsAllDrives)
            if item.is_google_type or item.content is None:
                raise http_error(
                    403, "fileNotDownloadable", "Only files with binary content can be downloaded."
                )
            return item.content

        return d.request("files.get_media", dict(fileId=fileId), run)

    def export_media(self, *, fileId: str, mimeType: str) -> FakeRequest:
        d = self._d

        def run() -> bytes:
            item = d._get_visible(fileId, True)
            if not item.is_google_type:
                raise http_error(
                    403, "fileNotExportable", "Export only supports Docs Editors files."
                )
            data = item.exports.get(mimeType)
            if data is None:
                raise http_error(400, "badRequest", "Export format not supported.")
            if len(data) > EXPORT_SIZE_LIMIT:
                raise http_error(
                    403, "exportSizeLimitExceeded", "This file is too large to be exported."
                )
            return data

        return d.request("files.export_media", dict(fileId=fileId, mimeType=mimeType), run)

    export = export_media

    # --- writes -------------------------------------------------------------------------------

    def update(
        self,
        *,
        fileId: str,
        body: dict[str, Any] | None = None,
        addParents: str | None = None,
        removeParents: str | None = None,
        supportsAllDrives: bool = False,
        fields: str | None = None,
    ) -> FakeRequest:
        d = self._d
        kwargs = dict(
            fileId=fileId,
            body=body,
            addParents=addParents,
            removeParents=removeParents,
            supportsAllDrives=supportsAllDrives,
        )

        def run() -> Any:
            item = d._get_visible(fileId, supportsAllDrives)
            allowed = {
                "trashed",
                "copyRequiresWriterPermission",
                "writersCanShare",
                "name",
                "downloadRestrictions",
            }
            owner_only = {"writersCanShare", "downloadRestrictions", "copyRequiresWriterPermission"}
            if owner_only & set(body or {}) and d.my_role(item) not in ("owner", "organizer"):
                raise http_error(
                    403, "insufficientFilePermissions", "Only the owner can change this setting."
                )
            if "writersCanShare" in (body or {}) and item.drive_id is not None:
                raise http_error(403, "fieldNotWritable", "Not supported for shared drive items.")
            for key, value in (body or {}).items():
                if key == "downloadRestrictions":
                    restriction = value.get("itemDownloadRestriction", {})
                    item.download_restricted_for_readers = bool(
                        restriction.get("restrictedForReaders")
                        or restriction.get("restrictedForWriters")
                    )
                    continue
                if key not in allowed:
                    raise NotImplementedError(f"fake_drive: files.update body key {key!r}")
                attr = {
                    "trashed": "trashed",
                    "name": "name",
                    "copyRequiresWriterPermission": "copy_requires_writer_permission",
                    "writersCanShare": "writers_can_share",
                }[key]
                setattr(item, attr, value)
            if addParents or removeParents:
                if removeParents != item.parent or not addParents or "," in addParents:
                    raise http_error(400, "badRequest", "single-parent move only")
                item.parent = addParents
            item.modified_time = d._tick()
            return select_fields(d.file_resource(item), d._fields("files.get", fields))

        return d.request("files.update", kwargs, run)

    def create(
        self,
        *,
        body: dict[str, Any],
        media_body: Any = None,
        fields: str | None = None,
        supportsAllDrives: bool = False,
    ) -> FakeRequest:
        """Upload a new file (media_body: googleapiclient MediaInMemoryUpload or similar)."""
        d = self._d
        kwargs = dict(body=body, supportsAllDrives=supportsAllDrives)

        def run() -> Any:
            parents = body.get("parents") or ["root"]
            if len(parents) != 1:
                raise http_error(400, "badRequest", "exactly one parent")
            parent = d._get_visible(parents[0], supportsAllDrives)
            if parent.drive_id is None and d.my_role(parent) not in ("owner", "writer"):
                raise http_error(403, "insufficientFilePermissions", "cannot add to folder")
            if body.get("mimeType") == FOLDER_MIME:
                fid = d.add_item(body["name"], FOLDER_MIME, parent.id)
                return select_fields(d.file_resource(d.items[fid]), d._fields("files.get", fields))
            data = b"" if media_body is None else media_body.getbytes(0, media_body.size())
            if d.corrupt_uploads:
                data = data[:-1] + bytes([data[-1] ^ 1]) if data else b"x"
            fid = d.add_item(
                body["name"],
                media_body.mimetype() if media_body is not None else "text/plain",
                parent.id,
                content=data,
            )
            return select_fields(d.file_resource(d.items[fid]), d._fields("files.get", fields))

        return d.request("files.create", kwargs, run)

    def copy(self, **kwargs: Any) -> FakeRequest:
        def run() -> Any:
            raise NotImplementedError("fake_drive: files.copy unsupported")

        return self._d.request("files.copy", kwargs, run)

    def delete(self, **kwargs: Any) -> FakeRequest:
        return self._d.request("files.delete", kwargs, lambda: None)

    def emptyTrash(self, **kwargs: Any) -> FakeRequest:
        return self._d.request("files.emptyTrash", kwargs, lambda: None)


class _Permissions(_Resource):
    def _perm_item(self, file_id: str, supports_all_drives: bool) -> FakeItem:
        d = self._d
        item = d._get_visible(file_id, supports_all_drives)
        if not d.can_share(item):
            raise http_error(
                403,
                "insufficientFilePermissions",
                "The user does not have sufficient permissions for this file.",
            )
        return item

    def list(
        self,
        *,
        fileId: str,
        pageSize: int | None = None,
        pageToken: str | None = None,
        fields: str | None = None,
        supportsAllDrives: bool = False,
        useDomainAdminAccess: bool = False,
    ) -> FakeRequest:
        d = self._d
        if useDomainAdminAccess:
            raise NotImplementedError("fake_drive: domain admin access is out of scope")

        def run() -> Any:
            if fileId in d.drives:  # the shared drive itself: its members
                if not supportsAllDrives or d.me not in d.drives[fileId].members:
                    raise http_error(404, "notFound", f"File not found: {fileId}.")
                perms = [
                    dict(
                        FakePermission("user", role, email=email).base_resource(),
                        permissionDetails=[
                            {"permissionType": "member", "role": role, "inherited": False}
                        ],
                    )
                    for email, role in d.drives[fileId].members.items()
                ]
                page, nxt = d._paginate(perms, pageSize, pageToken, default=100, maximum=100)
            else:
                item = self._perm_item(fileId, supportsAllDrives)
                perms = d.effective_permissions(item)
                default = 100 if item.drive_id else None  # reference: 100 for shared drives
                page, nxt = d._paginate(perms, pageSize, pageToken, default=default, maximum=100)
            body: dict[str, Any] = {"kind": "drive#permissionList", "permissions": page}
            if nxt:
                body["nextPageToken"] = nxt
            return select_fields(body, d._fields("permissions.list", fields))

        return d.request(
            "permissions.list",
            dict(
                fileId=fileId,
                pageSize=pageSize,
                pageToken=pageToken,
                fields=fields,
                supportsAllDrives=supportsAllDrives,
            ),
            run,
        )

    def get(
        self,
        *,
        fileId: str,
        permissionId: str,
        fields: str | None = None,
        supportsAllDrives: bool = False,
    ) -> FakeRequest:
        d = self._d

        def run() -> Any:
            item = self._perm_item(fileId, supportsAllDrives)
            for p in d.effective_permissions(item):
                if p["id"] == permissionId:
                    return select_fields(p, d._fields("permissions.get", fields))
            raise http_error(404, "notFound", f"Permission not found: {permissionId}.")

        return d.request(
            "permissions.get", dict(fileId=fileId, permissionId=permissionId, fields=fields), run
        )

    def _own(self, item: FakeItem, permission_id: str) -> FakePermission:
        for p in item.permissions:
            if p.id == permission_id:
                return p
        # Exists only as inherited/owner/member permission -> cannot change on this item.
        raise http_error(
            403,
            "cannotModifyInheritedPermission",
            "Inherited or owner permissions cannot be changed on this item.",
        )

    def create(
        self,
        *,
        fileId: str,
        body: dict[str, Any],
        sendNotificationEmail: bool | None = None,
        supportsAllDrives: bool = False,
        fields: str | None = None,
    ) -> FakeRequest:
        d = self._d
        kwargs = dict(
            fileId=fileId,
            body=body,
            sendNotificationEmail=sendNotificationEmail,
            supportsAllDrives=supportsAllDrives,
        )

        def run() -> Any:
            item = self._perm_item(fileId, supportsAllDrives)
            if body.get("role") == "owner":
                raise http_error(403, "forbidden", "ownership transfer is out of scope")
            if body["type"] in ("user", "group") and sendNotificationEmail is not False:
                d.notifications.append(fileId)  # the real API e-mails the person by default
            pid = d.share(
                item.id,
                body["type"],
                body["role"],
                email=body.get("emailAddress"),
                domain=body.get("domain"),
                allow_discovery=bool(body.get("allowFileDiscovery", False)),
            )
            return self.get(
                fileId=fileId, permissionId=pid, fields=fields, supportsAllDrives=supportsAllDrives
            )._fn()

        return d.request("permissions.create", kwargs, run)

    def update(
        self,
        *,
        fileId: str,
        permissionId: str,
        body: dict[str, Any],
        supportsAllDrives: bool = False,
        fields: str | None = None,
    ) -> FakeRequest:
        d = self._d
        kwargs = dict(
            fileId=fileId, permissionId=permissionId, body=body, supportsAllDrives=supportsAllDrives
        )

        def run() -> Any:
            item = self._perm_item(fileId, supportsAllDrives)
            perm = self._own(item, permissionId)
            if set(body) - {"role"} or body.get("role") == "owner":
                raise NotImplementedError("fake_drive: permissions.update supports role only")
            perm.role = body["role"]
            return self.get(
                fileId=fileId,
                permissionId=permissionId,
                fields=fields,
                supportsAllDrives=supportsAllDrives,
            )._fn()

        return d.request("permissions.update", kwargs, run)

    def delete(
        self, *, fileId: str, permissionId: str, supportsAllDrives: bool = False
    ) -> FakeRequest:
        d = self._d
        kwargs = dict(fileId=fileId, permissionId=permissionId, supportsAllDrives=supportsAllDrives)

        def run() -> None:
            item = self._perm_item(fileId, supportsAllDrives)
            perm = self._own(item, permissionId)
            item.permissions.remove(perm)

        return d.request("permissions.delete", kwargs, run)


class _Drives(_Resource):
    def list(
        self,
        *,
        pageSize: int | None = None,
        pageToken: str | None = None,
        fields: str | None = None,
        q: str | None = None,
    ) -> FakeRequest:
        d = self._d
        if q is not None:
            raise NotImplementedError("fake_drive: drives.list q unsupported")

        def run() -> Any:
            mine = [sd for sd in d.drives.values() if d.me in sd.members]
            page, nxt = d._paginate(mine, pageSize, pageToken, default=10, maximum=100)
            body: dict[str, Any] = {
                "kind": "drive#driveList",
                "drives": [{"kind": "drive#drive", "id": sd.id, "name": sd.name} for sd in page],
            }
            if nxt:
                body["nextPageToken"] = nxt
            return select_fields(body, d._fields("drives.list", fields))

        return d.request(
            "drives.list", dict(pageSize=pageSize, pageToken=pageToken, fields=fields), run
        )


class _About(_Resource):
    def get(self, *, fields: str | None = None) -> FakeRequest:
        d = self._d

        def run() -> Any:
            body = {
                "kind": "drive#about",
                "user": {
                    "kind": "drive#user",
                    "emailAddress": d.me,
                    "displayName": d.me.split("@", 1)[0],
                    "me": True,
                },
            }
            return select_fields(body, parse_fields(fields) if fields else None)

        return d.request("about.get", dict(fields=fields), run)


class _Changes(_Resource):
    """changes.getStartPageToken / changes.list over `FakeDrive.change_log`.

    Like the real API it only reports the item that changed — a folder's new sharing is NOT
    reported for every file below it (the worst case the incremental audit must handle).
    """

    def getStartPageToken(
        self, *, supportsAllDrives: bool = False, driveId: str | None = None
    ) -> FakeRequest:
        d = self._d
        return d.request(
            "changes.getStartPageToken",
            dict(driveId=driveId),
            lambda: {"startPageToken": f"c{len(d.change_log)}"},
        )

    def list(
        self,
        *,
        pageToken: str,
        pageSize: int = 100,
        includeRemoved: bool = True,
        includeItemsFromAllDrives: bool = False,
        supportsAllDrives: bool = False,
        driveId: str | None = None,
        spaces: str = "drive",
        fields: str | None = None,
    ) -> FakeRequest:
        d = self._d

        def run() -> Any:
            if not pageToken.startswith("c") or not pageToken[1:].isdigit():
                raise http_error(400, "invalidParameter", "Invalid pageToken")
            start = int(pageToken[1:])
            if start < d.min_change_token or start > len(d.change_log):
                raise http_error(400, "invalidParameter", "Invalid pageToken")
            size = max(1, min(pageSize, 1000))
            end = min(start + size, len(d.change_log))
            seen: dict[str, None] = {}
            for fid in d.change_log[start:end]:
                seen.pop(fid, None)
                seen[fid] = None  # latest change per file wins, in order
            out = []
            for fid in seen:
                item = d.items.get(fid)
                in_shared_drive = item is not None and item.drive_id is not None
                if in_shared_drive and driveId is None and not includeItemsFromAllDrives:
                    continue
                if driveId is not None and (item is None or item.drive_id != driveId):
                    continue
                if item is None or item.is_root or not d.accessible(item):
                    if includeRemoved:
                        out.append({"kind": "drive#change", "fileId": fid, "removed": True})
                    continue
                out.append(
                    {
                        "kind": "drive#change",
                        "fileId": fid,
                        "removed": False,
                        "file": d.file_resource(item),
                    }
                )
            body: dict[str, Any] = {"kind": "drive#changeList", "changes": out}
            if end < len(d.change_log):
                body["nextPageToken"] = f"c{end}"
            else:
                body["newStartPageToken"] = f"c{len(d.change_log)}"
            return select_fields(body, parse_fields(fields) if fields else None)

        kwargs = dict(pageToken=pageToken, driveId=driveId)
        return d.request("changes.list", kwargs, run)


class FakeService:
    """Stand-in for `googleapiclient.discovery.build("drive", "v3", ...)`."""

    def __init__(self, drive: FakeDrive) -> None:
        self._d = drive

    def files(self) -> _Files:
        return _Files(self._d)

    def permissions(self) -> _Permissions:
        return _Permissions(self._d)

    def drives(self) -> _Drives:
        return _Drives(self._d)

    def about(self) -> _About:
        return _About(self._d)

    def changes(self) -> _Changes:
        return _Changes(self._d)
