#!/usr/bin/env python3
"""Unified launcher and tabbed UI for the three Modbus security demos."""

from __future__ import annotations

import argparse
import atexit
import json
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class ProjectSpec:
    key: str
    title: str
    description: str
    directory: Path
    command: list[str]
    default_port: int


@dataclass
class ManagedProject:
    spec: ProjectSpec
    host: str
    port: int
    process: subprocess.Popen[str] | None = None
    logs: list[str] = field(default_factory=list)
    started_at: float | None = None

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def browser_url(self) -> str:
        return f"http://{{host}}:{self.port}/"

    def status(self) -> dict[str, Any]:
        return {
            "key": self.spec.key,
            "title": self.spec.title,
            "description": self.spec.description,
            "port": self.port,
            "pid": self.process.pid if self.running and self.process else None,
            "running": self.running,
            "exit_code": None if self.process is None or self.running else self.process.poll(),
            "url_template": self.browser_url(),
            "logs": self.logs[-24:],
        }


class ProjectManager:
    def __init__(self, projects: list[ManagedProject]) -> None:
        self.projects = projects
        self.lock = threading.Lock()
        self._stopping = False

    def start_all(self) -> None:
        for project in self.projects:
            self.start(project)

    def start(self, project: ManagedProject) -> None:
        with self.lock:
            if project.running:
                return
            cmd = [sys.executable, *project.spec.command, "--host", project.host, "--port", str(project.port)]
            process = subprocess.Popen(
                cmd,
                cwd=project.spec.directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            project.process = process
            project.started_at = time.time()
            project.logs.clear()
            threading.Thread(target=self._collect_logs, args=(project, process), daemon=True).start()

    def _collect_logs(self, project: ManagedProject, process: subprocess.Popen[str]) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            with self.lock:
                project.logs.append(line.rstrip())
                del project.logs[:-100]

    def stop_all(self) -> None:
        with self.lock:
            self._stopping = True
            processes = [project.process for project in self.projects if project.running and project.process]
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def status(self) -> list[dict[str, Any]]:
        with self.lock:
            return [project.status() for project in self.projects]


def find_available_port(preferred: int, host: str, reserved: set[int]) -> int:
    if preferred not in reserved and _can_bind(host, preferred):
        reserved.add(preferred)
        return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host_for_bind(host), 0))
        port = int(sock.getsockname()[1])
    reserved.add(port)
    return port


def _can_bind(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host_for_bind(host), port))
        except OSError:
            return False
    return True


def host_for_bind(host: str) -> str:
    return "0.0.0.0" if host in {"", "localhost"} else host


def make_projects(host: str, ports: dict[str, int]) -> list[ManagedProject]:
    specs = [
        ProjectSpec(
            key="ecc",
            title="ECC PKI",
            description="基于 ECC PKI 公钥证书的 Modbus 串行链路安全扩展协议",
            directory=BASE_DIR / "protocols-ECC",
            command=["-m", "secure_modbus.ui_server"],
            default_port=18080,
        ),
        ProjectSpec(
            key="psw",
            title="口令/预共享密钥",
            description="基于口令或预共享密钥的 Modbus 串行链路安全协议",
            directory=BASE_DIR / "protocols-psw",
            command=["web_frontend.py"],
            default_port=18081,
        ),
        ProjectSpec(
            key="mpq",
            title="后量子混合签名 PKI",
            description="基于后量子混合签名 PKI 公钥证书的 Modbus 串行链路安全协议",
            directory=BASE_DIR / "protocols-mpq",
            command=["web_frontend.py"],
            default_port=18082,
        ),
    ]
    return [
        ManagedProject(spec=spec, host=host_for_bind(host), port=ports.get(spec.key, spec.default_port))
        for spec in specs
    ]


UI_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Modbus 串行链路内生安全原生扩展协议</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #eef2f6;
      --surface: #ffffff;
      --surface-soft: #f8fafc;
      --text: #142033;
      --muted: #5d6b7c;
      --line: #c8d2df;
      --active: #135e5a;
      --active-strong: #0d4744;
      --red: #a8322a;
      --shadow: 0 16px 34px rgba(20, 32, 51, 0.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-width: 320px;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
    }
    header {
      border-bottom: 1px solid #122033;
      background: #172236;
      color: #fff;
    }
    .wrap {
      width: min(1440px, calc(100vw - 28px));
      margin: 0 auto;
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 16px;
      min-height: 104px;
      padding: 18px 0;
      position: relative;
      text-align: center;
    }
    .title-block {
      width: 100%;
      padding: 0 210px;
    }
    h1 {
      margin: 0;
      font-size: 48px;
      line-height: 1.2;
      letter-spacing: 0;
    }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-height: 34px;
      border: 1px solid #40516a;
      border-radius: 6px;
      padding: 7px 10px;
      color: #dbeafe;
      white-space: nowrap;
      font-size: 13px;
      font-weight: 700;
      position: absolute;
      right: 0;
      top: 50%;
      transform: translateY(-50%);
    }
    .dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: var(--red);
    }
    .dot.ok { background: #22c55e; }
    main.wrap { padding: 16px 0 24px; }
    .tabs {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }
    .tab {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      color: var(--text);
      min-height: 70px;
      padding: 12px;
      text-align: left;
      cursor: pointer;
      box-shadow: 0 2px 8px rgba(20, 32, 51, 0.06);
    }
    .tab.active {
      border-color: var(--active);
      background: #e4f0ed;
      box-shadow: inset 0 0 0 1px var(--active);
    }
    .tab-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      font-size: 15px;
      line-height: 1.25;
      font-weight: 800;
    }
    .tab-desc {
      margin-top: 7px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.35;
    }
    .badge {
      flex: 0 0 auto;
      border-radius: 999px;
      background: #e8edf3;
      color: var(--muted);
      padding: 3px 8px;
      font-size: 12px;
      font-weight: 800;
    }
    .badge.ok {
      background: #dceee8;
      color: var(--active-strong);
    }
    .viewer {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .viewer-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      min-height: 44px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-soft);
      padding: 8px 12px;
      color: var(--muted);
      font-size: 13px;
    }
    .viewer-bar a {
      color: var(--active);
      font-weight: 800;
      text-decoration: none;
    }
    iframe {
      display: block;
      width: 100%;
      height: calc(100vh - 224px);
      min-height: 640px;
      border: 0;
      background: #fff;
    }
    .log-panel {
      margin-top: 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      padding: 12px;
    }
    .log-title {
      margin: 0 0 8px;
      font-size: 14px;
      line-height: 1.3;
    }
    pre {
      margin: 0;
      max-height: 140px;
      overflow: auto;
      border-radius: 6px;
      background: #111827;
      color: #dbeafe;
      padding: 10px;
      white-space: pre-wrap;
      font-size: 12px;
      line-height: 1.45;
    }
    @media (max-width: 900px) {
      .topbar { flex-direction: column; min-height: 126px; }
      .title-block { padding: 0; }
      h1 { font-size: 36px; }
      .status { position: static; transform: none; }
      .tabs { grid-template-columns: 1fr; }
      iframe { height: calc(100vh - 410px); min-height: 560px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <div class="title-block">
        <h1>Modbus 串行链路内生安全原生扩展协议</h1>
      </div>
    </div>
  </header>
  <main class="wrap">
    <div id="tabs" class="tabs"></div>
    <section class="viewer">
      <div class="viewer-bar">
        <span id="viewerTitle">正在加载</span>
        <a id="openLink" href="#" target="_blank" rel="noreferrer">新窗口打开</a>
      </div>
      <iframe id="frame" title="Modbus secure protocol project"></iframe>
    </section>
    <section class="log-panel">
      <h2 class="log-title">当前项目启动日志</h2>
      <pre id="logs">暂无日志</pre>
    </section>
  </main>
  <script>
    let projects = [];
    let activeKey = localStorage.getItem("activeProject") || "ecc";

    function browserUrl(project) {
      const host = window.location.hostname || "172.22.116.146";
      return project.url_template.replace("{host}", host);
    }

    function setActive(key) {
      activeKey = key;
      localStorage.setItem("activeProject", key);
      render();
    }

    function render() {
      if (!projects.length) return;
      if (!projects.some(project => project.key === activeKey)) activeKey = projects[0].key;
      const tabs = document.getElementById("tabs");
      tabs.innerHTML = projects.map(project => `
        <button class="tab ${project.key === activeKey ? "active" : ""}" type="button" data-key="${project.key}">
          <span class="tab-title">${project.title}<span class="badge ${project.running ? "ok" : ""}">${project.running ? "运行中" : "未运行"}</span></span>
          <span class="tab-desc">${project.description}</span>
        </button>
      `).join("");
      tabs.querySelectorAll("button").forEach(button => {
        button.addEventListener("click", () => setActive(button.dataset.key));
      });

      const active = projects.find(project => project.key === activeKey);
      const url = browserUrl(active);
      const frame = document.getElementById("frame");
      if (frame.src !== url) frame.src = url;
      document.getElementById("viewerTitle").textContent = `${active.title} - ${url}`;
      document.getElementById("openLink").href = url;
      document.getElementById("logs").textContent = active.logs.length ? active.logs.join("\\n") : "暂无日志";

    }

    async function refresh() {
      const response = await fetch("/api/status", {cache: "no-store"});
      projects = await response.json();
      render();
    }

    refresh().catch(error => {
      console.error(error);
    });
    setInterval(() => refresh().catch(() => {}), 2500);
  </script>
</body>
</html>
"""


def make_handler(manager: ProjectManager) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_html(UI_HTML)
                return
            if parsed.path == "/api/status":
                self._send_json(manager.status())
                return
            if parsed.path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            self.send_error(404)

        def do_HEAD(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                body = UI_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return
            if parsed.path == "/api/status":
                body = json.dumps(manager.status(), ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return
            if parsed.path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            self.send_error(404)

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run all Modbus security demo UIs behind one tabbed UI.")
    parser.add_argument("--host", default="172.22.116.146", help="Unified UI and child UI bind address.")
    parser.add_argument("--port", type=int, default=18000, help="Unified UI port.")
    parser.add_argument("--ecc-port", type=int, default=18080, help="ECC PKI UI port.")
    parser.add_argument("--psw-port", type=int, default=18081, help="Password/PSK UI port.")
    parser.add_argument("--mpq-port", type=int, default=18082, help="Post-quantum hybrid PKI UI port.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    host = host_for_bind(args.host)
    requested_ports = {"ecc": args.ecc_port, "psw": args.psw_port, "mpq": args.mpq_port}
    reserved = {args.port}
    ports = {key: find_available_port(port, host, reserved) for key, port in requested_ports.items()}
    projects = make_projects(host, ports)
    manager = ProjectManager(projects)
    manager.start_all()
    atexit.register(manager.stop_all)

    def shutdown(_signum: int, _frame: Any) -> None:
        manager.stop_all()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server = ThreadingHTTPServer((host, args.port), make_handler(manager))
    print(f"unified UI listening on http://{args.host}:{args.port}", flush=True)
    for project in projects:
        print(f"{project.spec.key} UI listening on http://{args.host}:{project.port}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        manager.stop_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
