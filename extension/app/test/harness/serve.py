"""Dev-only static server for the viewer harness: serves the repository root on 127.0.0.1
with caching disabled (so edited modules are always reloaded). Not shipped."""

import functools
import http.server
import sys
from pathlib import Path


class NoCache(http.server.SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


root = Path(__file__).resolve().parents[4]
port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
handler = functools.partial(NoCache, directory=str(root))
http.server.ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()
