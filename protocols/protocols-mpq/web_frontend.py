#!/usr/bin/env python3
"""Static browser UI server for the Modbus 6.4 demo."""

from __future__ import annotations

import argparse
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "web"


class WebHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html", "/modbus_64_frontend.html", "/pq64"}:
            self.path = "/index.html"
        elif self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        super().do_GET()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Modbus 6.4 browser UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    index_page = STATIC_DIR / "index.html"
    if not index_page.exists():
        print(f"missing static page: {index_page}", file=sys.stderr)
        return 1

    server = ThreadingHTTPServer((args.host, args.port), WebHandler)
    print(f"web UI listening on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
