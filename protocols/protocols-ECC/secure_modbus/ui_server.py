from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .master_server import MasterClient
from .pki import init_demo_pki


LOG = logging.getLogger("secure-modbus-ui")


def bool_running(process: subprocess.Popen[str] | None) -> bool:
    return process is not None and process.poll() is None


class UiController:
    def __init__(self, cwd: Path) -> None:
        self.cwd = cwd
        self.lock = threading.Lock()
        self.slave_process: subprocess.Popen[str] | None = None
        self.slave_logs: list[str] = []
        self.master: MasterClient | None = None
        self.slave_config: dict[str, object] | None = None
        self.master_config: dict[str, object] | None = None
        self.pki_path: Path = Path("demo_pki")
        self.state_path: Path = Path(".secure_modbus_state")
        self.last_result: dict[str, object] | None = None
        self.events: list[dict[str, object]] = []

    def add_event(self, action: str, detail: dict[str, object], ok: bool = True) -> None:
        self.events.insert(
            0,
            {
                "time": time.strftime("%H:%M:%S"),
                "action": action,
                "ok": ok,
                "detail": detail,
            },
        )
        del self.events[40:]

    def append_slave_log(self, line: str) -> None:
        with self.lock:
            self.slave_logs.append(line.rstrip())
            del self.slave_logs[:-80]

    def read_slave_output(self, process: subprocess.Popen[str]) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            self.append_slave_log(line)

    def init_pki(self, pki: Path) -> dict[str, object]:
        with self.lock:
            self.pki_path = pki
            init_demo_pki(pki)
            result = {"pki": str(pki), "client_id": "0102030405060708", "server_id": "1112131415161718"}
            self.add_event("生成演示 PKI", result)
            return result

    def start_slave(self, config: dict[str, object]) -> dict[str, object]:
        with self.lock:
            if bool_running(self.slave_process):
                return {"running": True, "pid": self.slave_process.pid, "config": self.slave_config}
            pki = Path(str(config["pki"]))
            state = Path(str(config["state"]))
            self.pki_path = pki
            self.state_path = state
            cmd = [
                sys.executable,
                "-m",
                "secure_modbus.slave_server",
                "--host",
                str(config["host"]),
                "--port",
                str(int(config["port"])),
                "--address",
                str(int(config["address"])),
                "--pki",
                str(pki),
                "--state",
                str(state),
                "--log-level",
                "INFO",
            ]
            process = subprocess.Popen(
                cmd,
                cwd=self.cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            self.slave_process = process
            self.slave_config = dict(config)
            self.slave_logs.clear()
            threading.Thread(target=self.read_slave_output, args=(process,), daemon=True).start()
            self.add_event("启动从站", {"pid": process.pid, **dict(config)})
            return {"running": True, "pid": process.pid, "config": self.slave_config}

    def stop_slave(self) -> dict[str, object]:
        with self.lock:
            process = self.slave_process
            if not bool_running(process):
                self.slave_process = None
                return {"running": False}
            assert process is not None
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        with self.lock:
            self.add_event("停止从站", {"pid": process.pid})
            self.slave_process = None
            return {"running": False}

    def start_master(self, config: dict[str, object]) -> dict[str, object]:
        with self.lock:
            if self.master is not None:
                return {"running": True, "config": self.master_config}
            self.master = MasterClient(
                str(config["slave_host"]),
                int(config["slave_port"]),
                int(config["slave_address"]),
                Path(str(config["pki"])),
                Path(str(config["state"])),
            )
            self.pki_path = Path(str(config["pki"]))
            self.state_path = Path(str(config["state"]))
            self.master_config = dict(config)
            self.add_event("启动主站", dict(config))
            return {"running": True, "config": self.master_config}

    def stop_master(self) -> dict[str, object]:
        with self.lock:
            master = self.master
            if master is not None:
                master.close()
            self.master = None
            self.master_config = None
            self.add_event("停止主站", {})
            return {"running": False}

    def read_registers(self, start: int, quantity: int) -> dict[str, object]:
        master = self.master
        if master is None:
            raise RuntimeError("主站尚未启动")
        values = master.read_holding_registers(start, quantity)
        result = {"operation": "read", "start": start, "quantity": quantity, "values": values}
        with self.lock:
            self.last_result = result
            self.add_event("读取寄存器", result)
        return result

    def write_register(self, register: int, value: int) -> dict[str, object]:
        master = self.master
        if master is None:
            raise RuntimeError("主站尚未启动")
        result = {"operation": "write", **master.write_single_register(register, value)}
        with self.lock:
            self.last_result = result
            self.add_event("写入寄存器", result)
        return result

    def status(self) -> dict[str, object]:
        with self.lock:
            slave_running = bool_running(self.slave_process)
            slave_pid = self.slave_process.pid if slave_running and self.slave_process else None
            master = self.master
            master_status = master.status() if master is not None else None
            return {
                "pki_exists": (self.pki_path / "root_cert.json").exists(),
                "slave": {
                    "running": slave_running,
                    "pid": slave_pid,
                    "config": self.slave_config,
                    "logs": list(self.slave_logs),
                },
                "master": {
                    "running": master is not None,
                    "config": self.master_config,
                    "status": master_status,
                },
                "last_result": self.last_result,
                "events": list(self.events),
            }


UI_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>安全 Modbus 主从站启动控制台</title>
  <style>
    :root {
      --bg: #f5f6f8;
      --panel: #ffffff;
      --line: #d8dee8;
      --text: #172033;
      --muted: #667085;
      --green: #15803d;
      --red: #b42318;
      --blue: #1d4ed8;
      --amber: #b45309;
      --ink: #111827;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--text);
      background: var(--bg);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      background: #101828;
      color: white;
      border-bottom: 1px solid #0b1220;
    }
    .wrap { max-width: 1240px; margin: 0 auto; padding: 18px 20px; }
    .topbar { display: flex; justify-content: center; align-items: center; gap: 16px; text-align: center; position: relative; }
    h1 { margin: 0; font-size: 27px; line-height: 1.2; letter-spacing: 0; color: #facc15; }
    h2 { margin: 0 0 12px; font-size: 16px; line-height: 1.25; letter-spacing: 0; }
    .subtitle { color: #cbd5e1; font-size: 13px; margin-top: 6px; }
    .pill {
      min-height: 34px;
      border: 1px solid #344054;
      border-radius: 6px;
      padding: 7px 11px;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      white-space: nowrap;
      position: absolute;
      right: 0;
    }
    .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--red); }
    .dot.ok { background: #22c55e; }
    main.wrap { padding-top: 18px; padding-bottom: 32px; }
    .grid { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(360px, 0.9fr); gap: 16px; align-items: start; }
    .stack { display: grid; gap: 16px; }
    section { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
    .form-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; align-items: end; }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 12px; }
    input {
      width: 100%;
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 9px;
      font-size: 14px;
      color: var(--ink);
      background: white;
    }
    button {
      min-height: 36px;
      border: 1px solid #1d4ed8;
      border-radius: 6px;
      padding: 8px 10px;
      background: var(--blue);
      color: white;
      font-weight: 650;
      cursor: pointer;
    }
    button.secondary { background: white; color: var(--ink); border-color: var(--line); }
    button.danger { background: #b42318; border-color: #991b1b; }
    button:disabled { opacity: 0.55; cursor: wait; }
    .metrics { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
    .metric {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fbfcfe;
      padding: 10px;
      min-height: 68px;
    }
    .metric span { display: block; color: var(--muted); font-size: 12px; margin-bottom: 7px; }
    .metric strong {
      display: block;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 13px;
      overflow-wrap: anywhere;
      letter-spacing: 0;
    }
    .flow { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-top: 12px; }
    .step {
      border: 1px solid var(--line);
      border-left: 4px solid var(--red);
      border-radius: 6px;
      min-height: 72px;
      padding: 10px;
      background: white;
    }
    .step.ok { border-left-color: var(--green); }
    .step b { display: block; font-size: 13px; line-height: 1.35; }
    .step span { color: var(--muted); display: block; font-size: 12px; margin-top: 6px; }
    .registers { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin-top: 12px; }
    .reg { border: 1px solid var(--line); border-radius: 6px; min-height: 58px; padding: 8px; background: #fbfcfe; }
    .reg small { display: block; color: var(--muted); font-size: 11px; }
    .reg b { display: block; margin-top: 5px; font-size: 18px; line-height: 1.1; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); padding: 8px 6px; }
    th { color: var(--muted); font-size: 12px; font-weight: 650; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
    pre {
      margin: 0;
      min-height: 160px;
      max-height: 260px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #0f172a;
      color: #dbeafe;
      padding: 10px;
      white-space: pre-wrap;
    }
    .error { min-height: 20px; color: var(--red); font-size: 13px; margin-top: 10px; }
    .hint { color: var(--muted); font-size: 12px; line-height: 1.45; margin-top: 10px; }
    @media (max-width: 940px) {
      .grid { grid-template-columns: 1fr; }
      .form-grid, .metrics, .flow, .registers { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 560px) {
      .wrap { padding-left: 12px; padding-right: 12px; }
      .topbar { align-items: center; flex-direction: column; }
      .pill { position: static; }
      .form-grid, .metrics, .flow, .registers { grid-template-columns: 1fr; }
      h1 { font-size: 24px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <div>
        <h1>Modbus串行链路通信协议安全扩展</h1>
        <div class="subtitle">基于ECC公钥证书的安全协议</div>
      </div>
      <div class="pill"><span id="globalDot" class="dot"></span><span id="globalText">未启动</span></div>
    </div>
  </header>
  <main class="wrap">
    <div class="grid">
      <div class="stack">
        <section>
          <h2>准备工作</h2>
          <div class="form-grid">
            <label>PKI 目录<input id="pki" value="demo_pki"></label>
            <label>状态目录<input id="state" value=".secure_modbus_state"></label>
            <button id="pkiBtn">生成演示 PKI</button>
            <button class="secondary" id="refreshBtn">刷新状态</button>
          </div>
          <div class="hint">首次运行先生成 PKI；已有证书时可直接启动从站和主站。</div>
        </section>
        <section>
          <h2>启动从站</h2>
          <div class="form-grid">
            <label>监听地址<input id="slaveHost" value="127.0.0.1"></label>
            <label>监听端口<input id="slavePort" type="number" value="15020"></label>
            <label>从站地址<input id="slaveAddress" type="number" value="1"></label>
            <button id="slaveStartBtn">启动从站</button>
            <button class="danger" id="slaveStopBtn">停止从站</button>
          </div>
        </section>
        <section>
          <h2>启动主站</h2>
          <div class="form-grid">
            <label>从站地址<input id="masterSlaveHost" value="127.0.0.1"></label>
            <label>从站端口<input id="masterSlavePort" type="number" value="15020"></label>
            <label>目标从站号<input id="masterSlaveAddress" type="number" value="1"></label>
            <button id="masterStartBtn">启动主站</button>
            <button class="danger" id="masterStopBtn">停止主站</button>
          </div>
        </section>
        <section>
          <h2>寄存器操作</h2>
          <div class="form-grid">
            <label>读起始地址<input id="readStart" type="number" min="0" value="0"></label>
            <label>读取数量<input id="readQty" type="number" min="1" max="16" value="4"></label>
            <button id="readBtn">读取</button>
            <span></span>
            <label>写入地址<input id="writeReg" type="number" min="0" value="2"></label>
            <label>写入值<input id="writeValue" type="number" min="0" max="65535" value="4321"></label>
            <button id="writeBtn">写入</button>
          </div>
          <div class="error" id="error"></div>
          <div class="registers" id="registers"></div>
        </section>
        <section>
          <h2>安全链路参数</h2>
          <div class="metrics" id="identity"></div>
          <div class="flow" id="flow"></div>
        </section>
      </div>
      <div class="stack">
        <section>
          <h2>运行状态</h2>
          <div class="metrics" id="runtime"></div>
        </section>
        <section>
          <h2>密钥与计数器输出</h2>
          <div class="metrics" id="keys"></div>
          <div class="metrics" id="counters" style="margin-top:10px"></div>
        </section>
        <section>
          <h2>最近结果</h2>
          <pre id="result">暂无结果</pre>
        </section>
        <section>
          <h2>从站日志</h2>
          <pre id="slaveLogs">暂无日志</pre>
        </section>
        <section>
          <h2>操作事件</h2>
          <table>
            <thead><tr><th>时间</th><th>动作</th><th>详情</th></tr></thead>
            <tbody id="events"></tbody>
          </table>
        </section>
      </div>
    </div>
  </main>
  <script>
    const $ = id => document.getElementById(id);
    const buttons = ["pkiBtn","refreshBtn","slaveStartBtn","slaveStopBtn","masterStartBtn","masterStopBtn","readBtn","writeBtn"];

    function metric(label, value) {
      return `<div class="metric"><span>${label}</span><strong>${value ?? "未生成"}</strong></div>`;
    }

    function setBusy(busy) {
      buttons.forEach(id => $(id).disabled = busy);
    }

    async function api(path, options = {}) {
      const res = await fetch(path, options);
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || res.statusText);
      return data;
    }

    function qs(obj) {
      return new URLSearchParams(obj).toString();
    }

    function commonConfig() {
      return { pki: $("pki").value, state: $("state").value };
    }

    function renderRegisters(start, values) {
      $("registers").innerHTML = values.map((value, index) =>
        `<div class="reg"><small>HR ${start + index}</small><b>${value}</b></div>`
      ).join("");
    }

    function renderStatus(data) {
      const masterStatus = data.master.status;
      const secure = Boolean(data.slave.running && data.master.running && masterStatus && masterStatus.transport.connected);
      $("globalDot").className = secure ? "dot ok" : "dot";
      $("globalText").textContent = secure ? "主从站安全链路已建立" : "等待启动或握手";
      $("runtime").innerHTML = [
        metric("PKI", data.pki_exists ? "已生成" : "未生成"),
        metric("从站进程", data.slave.running ? `运行 PID ${data.slave.pid}` : "未运行"),
        metric("主站对象", data.master.running ? "已启动" : "未启动"),
        metric("从站配置", data.slave.config ? `${data.slave.config.host}:${data.slave.config.port} / ${data.slave.config.address}` : "未配置"),
        metric("主站目标", data.master.config ? `${data.master.config.slave_host}:${data.master.config.slave_port} / ${data.master.config.slave_address}` : "未配置"),
        metric("安全会话", masterStatus && masterStatus.transport.connected ? "已建立" : "未建立")
      ].join("");
      if (masterStatus) {
        $("identity").innerHTML = [
          metric("CLIENT_ID", masterStatus.identity.client_id),
          metric("SERVER_ID", masterStatus.identity.server_id),
          metric("功能码", masterStatus.transport.function_code),
          metric("认证上下文", masterStatus.identity.context_cached ? "已缓存" : "未缓存"),
          metric("从站 TCP", `${masterStatus.transport.slave_host}:${masterStatus.transport.slave_port}`),
          metric("最后错误", masterStatus.last_error || "无")
        ].join("");
        $("flow").innerHTML = masterStatus.stages.map((s, i) =>
          `<div class="step ${s.ok ? "ok" : ""}"><b>${i + 1}. ${s.name}</b><span>${s.ok ? "完成" : "待执行"}</span></div>`
        ).join("");
        $("keys").innerHTML = Object.entries(masterStatus.keys).map(([k, v]) => metric(k, v)).join("");
        $("counters").innerHTML = [
          metric("SAC 发送", masterStatus.counters.sac_send),
          metric("SAC 接收", masterStatus.counters.sac_recv),
          metric("内容发送", masterStatus.counters.content_tx)
        ].join("");
      } else {
        $("identity").innerHTML = [metric("CLIENT_ID", "主站启动后显示"), metric("SERVER_ID", "握手后显示"), metric("功能码", "0x00")].join("");
        $("flow").innerHTML = "";
        $("keys").innerHTML = [metric("AKH", null), metric("DHSK", null), metric("CK/CIV", null)].join("");
        $("counters").innerHTML = [metric("SAC 发送", null), metric("SAC 接收", null), metric("内容发送", null)].join("");
      }
      $("result").textContent = data.last_result ? JSON.stringify(data.last_result, null, 2) : "暂无结果";
      $("slaveLogs").textContent = data.slave.logs.length ? data.slave.logs.join("\\n") : "暂无日志";
      $("events").innerHTML = data.events.map(row =>
        `<tr><td>${row.time}</td><td>${row.action}</td><td><code>${JSON.stringify(row.detail)}</code></td></tr>`
      ).join("") || `<tr><td colspan="3">暂无事件</td></tr>`;
    }

    async function refresh() {
      renderStatus(await api("/api/status"));
    }

    async function run(fn) {
      setBusy(true);
      $("error").textContent = "";
      try {
        await fn();
        await refresh();
      } catch (err) {
        $("error").textContent = err.message;
      } finally {
        setBusy(false);
      }
    }

    $("pkiBtn").addEventListener("click", () => run(() => api(`/api/pki/init?${qs({pki: $("pki").value})}`, {method: "POST"})));
    $("slaveStartBtn").addEventListener("click", () => run(() => api(`/api/slave/start?${qs({
      ...commonConfig(), host: $("slaveHost").value, port: $("slavePort").value, address: $("slaveAddress").value
    })}`, {method: "POST"})));
    $("slaveStopBtn").addEventListener("click", () => run(() => api("/api/slave/stop", {method: "POST"})));
    $("masterStartBtn").addEventListener("click", () => run(() => api(`/api/master/start?${qs({
      ...commonConfig(), slave_host: $("masterSlaveHost").value, slave_port: $("masterSlavePort").value, slave_address: $("masterSlaveAddress").value
    })}`, {method: "POST"})));
    $("masterStopBtn").addEventListener("click", () => run(() => api("/api/master/stop", {method: "POST"})));
    $("readBtn").addEventListener("click", () => run(async () => {
      const start = Number($("readStart").value);
      const qty = Number($("readQty").value);
      const data = await api(`/api/read?${qs({start, qty})}`);
      renderRegisters(data.start, data.values);
    }));
    $("writeBtn").addEventListener("click", () => run(async () => {
      const register = Number($("writeReg").value);
      const value = Number($("writeValue").value);
      await api(`/api/write?${qs({register, value})}`, {method: "POST"});
      const start = Math.max(0, register - 1);
      const data = await api(`/api/read?${qs({start, qty: 4})}`);
      renderRegisters(data.start, data.values);
    }));
    $("refreshBtn").addEventListener("click", () => run(refresh));
    refresh().catch(err => $("error").textContent = err.message);
    setInterval(() => refresh().catch(() => {}), 3000);
  </script>
</body>
</html>
"""


def query_value(params: dict[str, list[str]], name: str, default: str) -> str:
    return params.get(name, [default])[0]


def make_handler(controller: UiController) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            LOG.info("%s - %s", self.address_string(), fmt % args)

        def send_json(self, code: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_html(self, code: int, payload: str) -> None:
            body = payload.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            try:
                if parsed.path == "/":
                    self.send_html(200, UI_HTML)
                    return
                if parsed.path == "/api/status":
                    self.send_json(200, controller.status())
                    return
                if parsed.path == "/api/read":
                    start = int(query_value(params, "start", "0"))
                    quantity = int(query_value(params, "qty", "1"))
                    self.send_json(200, controller.read_registers(start, quantity))
                    return
                self.send_json(404, {"error": "not found"})
            except Exception as exc:
                controller.add_event("请求失败", {"path": parsed.path, "error": str(exc)}, ok=False)
                self.send_json(500, {"error": str(exc)})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            try:
                if parsed.path == "/api/pki/init":
                    self.send_json(200, controller.init_pki(Path(query_value(params, "pki", "demo_pki"))))
                    return
                if parsed.path == "/api/slave/start":
                    config = {
                        "host": query_value(params, "host", "127.0.0.1"),
                        "port": int(query_value(params, "port", "15020")),
                        "address": int(query_value(params, "address", "1")),
                        "pki": query_value(params, "pki", "demo_pki"),
                        "state": query_value(params, "state", ".secure_modbus_state"),
                    }
                    self.send_json(200, controller.start_slave(config))
                    return
                if parsed.path == "/api/slave/stop":
                    self.send_json(200, controller.stop_slave())
                    return
                if parsed.path == "/api/master/start":
                    config = {
                        "slave_host": query_value(params, "slave_host", "127.0.0.1"),
                        "slave_port": int(query_value(params, "slave_port", "15020")),
                        "slave_address": int(query_value(params, "slave_address", "1")),
                        "pki": query_value(params, "pki", "demo_pki"),
                        "state": query_value(params, "state", ".secure_modbus_state"),
                    }
                    self.send_json(200, controller.start_master(config))
                    return
                if parsed.path == "/api/master/stop":
                    self.send_json(200, controller.stop_master())
                    return
                if parsed.path == "/api/write":
                    register = int(query_value(params, "register", "0"))
                    value = int(query_value(params, "value", "0"))
                    self.send_json(200, controller.write_register(register, value))
                    return
                self.send_json(404, {"error": "not found"})
            except Exception as exc:
                controller.add_event("请求失败", {"path": parsed.path, "error": str(exc)}, ok=False)
                self.send_json(500, {"error": str(exc)})

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="One-command UI launcher for secure Modbus master/slave demo.")
    parser.add_argument("--host", default="127.0.0.1", help="UI server bind IP address, for example 127.0.0.1 or 0.0.0.0")
    parser.add_argument("--port", default=18080, type=int, help="UI server bind TCP port")
    parser.add_argument("--log-level", default="INFO", help="logging level, for example INFO or DEBUG")
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(message)s")
    controller = UiController(Path.cwd())
    server = ThreadingHTTPServer((args.host, args.port), make_handler(controller))
    LOG.info("UI launcher listening on http://%s:%s", args.host, args.port)
    try:
        server.serve_forever()
    finally:
        controller.stop_master()
        controller.stop_slave()


if __name__ == "__main__":
    main()
