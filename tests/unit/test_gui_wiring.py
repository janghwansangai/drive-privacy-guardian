"""Buttons and menu items must not hand their `checked` flag to a method's first parameter.

Qt's clicked(bool) / triggered(bool) are passed to a slot that accepts a positional argument:
`btn.clicked.connect(self.change_selected)` with `def change_selected(self, items=None)` turned
every click into change_selected(False) (v0.2.5: "choose files first" although files were chosen).
"""

from __future__ import annotations

import ast
from pathlib import Path

GUI = Path(__file__).resolve().parents[2] / "src" / "dpg" / "gui"
BOOL_SIGNALS = {"clicked", "triggered"}


def test_click_slots_take_no_positional_arguments() -> None:
    problems: list[str] = []
    for path in sorted(GUI.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            methods = {f.name: f for f in cls.body if isinstance(f, ast.FunctionDef)}
            for node in ast.walk(cls):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "connect"
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr in BOOL_SIGNALS
                    and node.args
                ):
                    continue
                slot = node.args[0]
                if (
                    isinstance(slot, ast.Attribute)
                    and isinstance(slot.value, ast.Name)
                    and slot.value.id == "self"
                    and slot.attr in methods
                    and len(methods[slot.attr].args.args) > 1
                ):
                    problems.append(f"{path.name}:{node.lineno} {cls.name}.{slot.attr}")
    assert problems == [], "make these parameters keyword-only (`*, name=...`): " + ", ".join(
        problems
    )
