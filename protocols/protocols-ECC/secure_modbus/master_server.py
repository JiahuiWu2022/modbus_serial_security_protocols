from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .crypto import load_identity
from .frame import ProtocolError
from .session import SecureSession, client_handshake


LOG = logging.getLogger("secure-modbus-master")


class MasterClient:
    def __init__(self, host: str, port: int, address: int, pki: Path, state: Path) -> None:
        self.host = host
        self.port = port
        self.address = address
        self.pki = pki
        self.state = state
        self.lock = threading.Lock()
        self.sock: socket.socket | None = None
        self.session: SecureSession | None = None
        self.identity = load_identity(self.pki, "client")
        self.last_error: str | None = None
        self.operation_log: list[dict[str, object]] = []

    def add_log(self, action: str, detail: dict[str, object], ok: bool = True) -> None:
        self.operation_log.insert(
            0,
            {
                "time": time.strftime("%H:%M:%S"),
                "action": action,
                "ok": ok,
                "detail": detail,
            },
        )
        del self.operation_log[30:]

    def connect(self) -> None:
        if self.sock is not None:
            return
        sock = socket.create_connection((self.host, self.port), timeout=10)
        session = SecureSession(sock, self.address, self.identity)
        client_handshake(session, self.state / f"client_context_{self.address}.json")
        self.sock = sock
        self.session = session
        self.last_error = None
        self.add_log("安全握手", {"server_id": (session.peer_id or b"").hex(), "mode": "AES-GCM"})
        LOG.info("secure session ready: server_id=%s", (session.peer_id or b"").hex())

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
                self.session = None

    def transact(self, pdu: bytes) -> bytes:
        with self.lock:
            try:
                self.connect()
                assert self.session is not None
                self.session.send_encrypted_pdu(pdu)
                return self.session.recv_encrypted_pdu()
            except Exception:
                self.last_error = "connection reset after transaction failure"
                self.close()
                raise

    def read_holding_registers(self, start: int, quantity: int) -> list[int]:
        response = self.transact(bytes([0x03]) + struct.pack(">HH", start, quantity))
        if response[0] & 0x80:
            raise ProtocolError(f"Modbus exception {response[1]}")
        if response[0] != 0x03 or response[1] != quantity * 2:
            raise ProtocolError("invalid read holding registers response")
        values = []
        for offset in range(quantity):
            values.append(int.from_bytes(response[2 + offset * 2 : 4 + offset * 2], "big"))
        self.add_log("读保持寄存器", {"start": start, "quantity": quantity, "values": values})
        return values

    def write_single_register(self, register: int, value: int) -> dict[str, int]:
        response = self.transact(bytes([0x06]) + struct.pack(">HH", register, value))
        if response[0] & 0x80:
            raise ProtocolError(f"Modbus exception {response[1]}")
        if response != bytes([0x06]) + struct.pack(">HH", register, value):
            raise ProtocolError("invalid write single register response")
        self.add_log("写单寄存器", {"register": register, "value": value})
        return {"register": register, "value": value}

    def status(self) -> dict[str, object]:
        session = self.session
        context_path = self.state / f"client_context_{self.address}.json"
        connected = session is not None and self.sock is not None

        def short_hex(value: bytes | None, keep: int = 12) -> str | None:
            if not value:
                return None
            text = value.hex()
            if len(text) <= keep * 2:
                return text
            return f"{text[:keep]}...{text[-keep:]}"

        return {
            "transport": {
                "slave_host": self.host,
                "slave_port": self.port,
                "slave_address": self.address,
                "function_code": "0x00",
                "connected": connected,
            },
            "identity": {
                "client_id": self.identity.device_id_hex,
                "server_id": (session.peer_id.hex() if session and session.peer_id else None),
                "context_cached": context_path.exists(),
            },
            "stages": [
                {"name": "证书认证 / 重新认证", "ok": bool(session and session.auth_key)},
                {"name": "SAC 通道建立", "ok": bool(session and session.sac)},
                {"name": "内容密钥更新", "ok": bool(session and session.ck and session.civ)},
                {"name": "加密 Modbus PDU", "ok": connected},
            ],
            "keys": {
                "AKH": short_hex(session.auth_key if session else None),
                "DHSK": short_hex(session.dhsk if session else None),
                "SAK": short_hex(session.sac.sak if session and session.sac else None),
                "SEK": short_hex(session.sac.sek if session and session.sac else None),
                "CK": short_hex(session.ck if session else None),
                "CIV": short_hex(session.civ if session else None),
                "BCK": short_hex(session.bck if session else None),
                "BCIV": short_hex(session.bciv if session else None),
            },
            "counters": {
                "sac_send": session.sac.send_counter if session and session.sac else None,
                "sac_recv": session.sac.recv_counter if session and session.sac else None,
                "content_tx": session.tx_content_counter if session else None,
            },
            "last_error": self.last_error,
            "log": self.operation_log,
        }


INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>安全 Modbus 主站控制台</title>
  <style>
    :root {
      --bg: #f6f7f9;
      --panel: #ffffff;
      --line: #d9dee7;
      --text: #1d2430;
      --muted: #667085;
      --ok: #188a52;
      --warn: #b45309;
      --bad: #b42318;
      --blue: #2563eb;
      --ink: #111827;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    header {
      background: #111827;
      color: white;
      border-bottom: 1px solid #0b1220;
    }
    .wrap { max-width: 1180px; margin: 0 auto; padding: 18px 20px; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
    h1 { margin: 0; font-size: 22px; line-height: 1.2; font-weight: 700; letter-spacing: 0; }
    .subtitle { color: #cbd5e1; font-size: 13px; margin-top: 6px; }
    .status-pill {
      min-width: 112px;
      height: 34px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      border: 1px solid #334155;
      border-radius: 6px;
      font-size: 13px;
      white-space: nowrap;
    }
    .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--bad); }
    .dot.ok { background: #22c55e; }
    main.wrap { padding-top: 20px; padding-bottom: 34px; }
    .grid {
      display: grid;
      grid-template-columns: minmax(0, 1.25fr) minmax(320px, 0.75fr);
      gap: 16px;
      align-items: start;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }
    h2 { margin: 0 0 12px; font-size: 16px; line-height: 1.3; letter-spacing: 0; }
    .kv {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }
    .metric {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      min-height: 72px;
      background: #fbfcfe;
    }
    .metric span { display: block; color: var(--muted); font-size: 12px; margin-bottom: 7px; }
    .metric strong {
      display: block;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 13px;
      overflow-wrap: anywhere;
      letter-spacing: 0;
    }
    .flow {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin-top: 14px;
    }
    .step {
      border: 1px solid var(--line);
      border-left: 4px solid var(--bad);
      border-radius: 6px;
      padding: 10px;
      min-height: 76px;
      background: #fff;
    }
    .step.ok { border-left-color: var(--ok); }
    .step b { display: block; font-size: 13px; line-height: 1.35; }
    .step span { color: var(--muted); font-size: 12px; display: block; margin-top: 6px; }
    .controls {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      align-items: end;
    }
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
      background: var(--blue);
      color: white;
      font-weight: 650;
      cursor: pointer;
    }
    button.secondary {
      background: white;
      color: var(--ink);
      border-color: var(--line);
    }
    button:disabled { opacity: 0.55; cursor: wait; }
    .registers {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
      margin-top: 14px;
    }
    .reg {
      border: 1px solid var(--line);
      border-radius: 6px;
      min-height: 58px;
      padding: 8px;
      background: #fbfcfe;
    }
    .reg small { display: block; color: var(--muted); font-size: 11px; }
    .reg b { display: block; margin-top: 5px; font-size: 18px; line-height: 1.1; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 9px 6px; vertical-align: top; }
    th { color: var(--muted); font-size: 12px; font-weight: 600; }
    td code { font-size: 12px; white-space: pre-wrap; overflow-wrap: anywhere; }
    .stack { display: grid; gap: 16px; }
    .hint { color: var(--muted); font-size: 12px; line-height: 1.45; margin-top: 10px; }
    .error { color: var(--bad); font-size: 13px; min-height: 20px; margin-top: 10px; }
    @media (max-width: 860px) {
      .grid { grid-template-columns: 1fr; }
      .kv, .flow, .controls, .registers { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .topbar { align-items: flex-start; flex-direction: column; }
    }
    @media (max-width: 520px) {
      .wrap { padding-left: 12px; padding-right: 12px; }
      .kv, .flow, .controls, .registers { grid-template-columns: 1fr; }
      h1 { font-size: 19px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <div>
        <h1>安全 Modbus 主站控制台</h1>
        <div class="subtitle">6.2 ECC PKI 认证、SAC 通道、内容密钥与加密 PDU 操作视图</div>
      </div>
      <div class="status-pill"><span id="connDot" class="dot"></span><span id="connText">未连接</span></div>
    </div>
  </header>
  <main class="wrap">
    <div class="grid">
      <div class="stack">
        <section>
          <h2>链路与身份</h2>
          <div class="kv" id="identity"></div>
          <div class="flow" id="flow"></div>
        </section>
        <section>
          <h2>寄存器操作</h2>
          <div class="controls">
            <label>起始地址<input id="readStart" type="number" min="0" value="0"></label>
            <label>数量<input id="readQty" type="number" min="1" max="16" value="4"></label>
            <button id="readBtn" title="读取保持寄存器">读取</button>
            <button class="secondary" id="refreshBtn" title="刷新状态">刷新</button>
            <label>写入地址<input id="writeReg" type="number" min="0" value="1"></label>
            <label>写入值<input id="writeValue" type="number" min="0" max="65535" value="1234"></label>
            <button id="writeBtn" title="写单个保持寄存器">写入</button>
          </div>
          <div class="error" id="error"></div>
          <div class="registers" id="registers"></div>
        </section>
      </div>
      <div class="stack">
        <section>
          <h2>密钥摘要</h2>
          <div class="kv" id="keys"></div>
          <div class="hint">界面只展示截断摘要，完整密钥仍保留在主站进程内存和认证上下文文件中。</div>
        </section>
        <section>
          <h2>计数器</h2>
          <div class="kv" id="counters"></div>
        </section>
        <section>
          <h2>操作日志</h2>
          <table>
            <thead><tr><th>时间</th><th>动作</th><th>详情</th></tr></thead>
            <tbody id="log"></tbody>
          </table>
        </section>
      </div>
    </div>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const state = { busy: false };

    function metric(label, value) {
      return `<div class="metric"><span>${label}</span><strong>${value ?? "未生成"}</strong></div>`;
    }

    function setBusy(busy) {
      state.busy = busy;
      ["readBtn", "writeBtn", "refreshBtn"].forEach(id => $(id).disabled = busy);
    }

    async function api(path, options) {
      const res = await fetch(path, options);
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || res.statusText);
      return data;
    }

    function renderStatus(data) {
      $("connDot").className = data.transport.connected ? "dot ok" : "dot";
      $("connText").textContent = data.transport.connected ? "已建立安全会话" : "等待首次操作";
      $("identity").innerHTML = [
        metric("主站 CLIENT_ID", data.identity.client_id),
        metric("从站 SERVER_ID", data.identity.server_id),
        metric("从站地址 / 功能码", `${data.transport.slave_address} / ${data.transport.function_code}`),
        metric("从站 TCP", `${data.transport.slave_host}:${data.transport.slave_port}`),
        metric("认证上下文", data.identity.context_cached ? "已缓存" : "未缓存"),
        metric("错误状态", data.last_error || "无")
      ].join("");
      $("flow").innerHTML = data.stages.map((s, i) => `
        <div class="step ${s.ok ? "ok" : ""}">
          <b>${i + 1}. ${s.name}</b>
          <span>${s.ok ? "完成" : "待执行"}</span>
        </div>
      `).join("");
      $("keys").innerHTML = Object.entries(data.keys).map(([k, v]) => metric(k, v)).join("");
      $("counters").innerHTML = [
        metric("SAC 发送计数", data.counters.sac_send),
        metric("SAC 接收计数", data.counters.sac_recv),
        metric("内容发送计数", data.counters.content_tx)
      ].join("");
      $("log").innerHTML = data.log.map(row => `
        <tr><td>${row.time}</td><td>${row.action}</td><td><code>${JSON.stringify(row.detail)}</code></td></tr>
      `).join("") || `<tr><td colspan="3">暂无操作</td></tr>`;
    }

    function renderRegisters(start, values) {
      $("registers").innerHTML = values.map((value, index) => `
        <div class="reg"><small>HR ${start + index}</small><b>${value}</b></div>
      `).join("");
    }

    async function refresh() {
      const data = await api("/status");
      renderStatus(data);
    }

    async function readRegs() {
      setBusy(true);
      $("error").textContent = "";
      try {
        const start = Number($("readStart").value);
        const qty = Number($("readQty").value);
        const data = await api(`/read?start=${start}&qty=${qty}`);
        renderRegisters(data.start, data.values);
        await refresh();
      } catch (err) {
        $("error").textContent = err.message;
      } finally {
        setBusy(false);
      }
    }

    async function writeReg() {
      setBusy(true);
      $("error").textContent = "";
      try {
        const register = Number($("writeReg").value);
        const value = Number($("writeValue").value);
        await api(`/write?register=${register}&value=${value}`, { method: "POST" });
        $("readStart").value = Math.max(0, register - 1);
        $("readQty").value = 4;
        await readRegs();
      } catch (err) {
        $("error").textContent = err.message;
      } finally {
        setBusy(false);
      }
    }

    $("readBtn").addEventListener("click", readRegs);
    $("writeBtn").addEventListener("click", writeReg);
    $("refreshBtn").addEventListener("click", refresh);
    refresh().catch(err => $("error").textContent = err.message);
    setInterval(() => refresh().catch(() => {}), 3000);
  </script>
</body>
</html>
"""


def make_handler(master: MasterClient) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            LOG.info("%s - %s", self.address_string(), fmt % args)

        def send_json(self, code: int, payload: dict) -> None:
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
                    self.send_html(200, INDEX_HTML)
                    return
                if parsed.path == "/health":
                    self.send_json(200, {"ok": True})
                    return
                if parsed.path == "/status":
                    self.send_json(200, master.status())
                    return
                if parsed.path == "/read":
                    start = int(params.get("start", ["0"])[0])
                    quantity = int(params.get("qty", ["1"])[0])
                    values = master.read_holding_registers(start, quantity)
                    self.send_json(200, {"start": start, "quantity": quantity, "values": values})
                    return
                self.send_json(404, {"error": "not found"})
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            try:
                if parsed.path == "/write":
                    register = int(params.get("register", params.get("reg", ["0"]))[0])
                    value = int(params.get("value", ["0"])[0])
                    self.send_json(200, master.write_single_register(register, value))
                    return
                self.send_json(404, {"error": "not found"})
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure Modbus master control server based on section 6.2.")
    parser.add_argument("--slave-host", default="127.0.0.1")
    parser.add_argument("--slave-port", default=15020, type=int)
    parser.add_argument("--slave-address", default=1, type=int)
    parser.add_argument("--http-host", default="127.0.0.1")
    parser.add_argument("--http-port", default=18080, type=int)
    parser.add_argument("--pki", default=Path("demo_pki"), type=Path)
    parser.add_argument("--state", default=Path(".secure_modbus_state"), type=Path)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(message)s")
    master = MasterClient(args.slave_host, args.slave_port, args.slave_address, args.pki, args.state)
    server = ThreadingHTTPServer((args.http_host, args.http_port), make_handler(master))
    LOG.info("HTTP control server listening on http://%s:%s", args.http_host, args.http_port)
    LOG.info("read example: curl 'http://%s:%s/read?start=0&qty=4'", args.http_host, args.http_port)
    server.serve_forever()
    #If a real UART interface is used in frame.py, 
    #the socket initialized here is only formal and not actually used. 
    # Every frame read and sent is completed on UART.

if __name__ == "__main__":
    main()
