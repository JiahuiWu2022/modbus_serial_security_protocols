#!/usr/bin/env python3
"""Browser UI and JSON API for the secure Modbus master/slave demo."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Sequence

from modbus_security_psk import (
    ProtocolError,
    build_encrypted_data_send,
    parse_encrypted_data_send,
    parse_hex_or_int,
    parse_register_response,
    read_holding_registers_pdu,
    recv_record,
    run_master_handshake,
    run_slave_handshake,
    send_record,
    handle_modbus_pdu,
)


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "web"


class InputError(ValueError):
    """Raised when browser-provided parameters are invalid."""


def _int_field(data: Dict[str, Any], name: str, default: int | None = None) -> int:
    value = data.get(name, default)
    if value is None or value == "":
        raise InputError(f"{name} is required")
    try:
        return parse_hex_or_int(str(value).strip())
    except ValueError as exc:
        raise InputError(f"{name} must be an integer or hex value") from exc


def _str_field(data: Dict[str, Any], name: str, default: str = "") -> str:
    value = data.get(name, default)
    if value is None:
        value = default
    return str(value).strip()


def _parse_registers(value: Any) -> List[int]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        raw_items = value
    else:
        raw_items = str(value or "").replace("\n", ",").split(",")

    registers: List[int] = []
    for raw_item in raw_items:
        item = str(raw_item).strip()
        if not item:
            continue
        try:
            register = parse_hex_or_int(item)
        except ValueError as exc:
            raise InputError("register values must be integers or hex values") from exc
        if not 0 <= register <= 0xFFFF:
            raise InputError("register values must be in 0..65535")
        registers.append(register)

    if not registers:
        raise InputError("at least one slave register is required")
    return registers


def _validate_read_params(slave_id: int, start: int, quantity: int, registers: Sequence[int]) -> None:
    if not 1 <= slave_id <= 247:
        raise InputError("slave_id must be in 1..247")
    if not 0 <= start <= 0xFFFF:
        raise InputError("start must be in 0..65535")
    if not 1 <= quantity <= 125:
        raise InputError("quantity must be in 1..125")
    if start + quantity > len(registers):
        raise InputError("requested register range exceeds the configured slave registers")


def read_with_embedded_slave(params: Dict[str, Any]) -> Dict[str, Any]:
    slave_host = _str_field(params, "slave_host", "192.168.0.106")
    slave_port = _int_field(params, "slave_port", 0)
    master_host = _str_field(params, "master_host", slave_host)
    slave_id = _int_field(params, "slave_id", 1)
    password = _str_field(params, "password", "modbus-psk-demo").encode()
    server_id = _int_field(params, "server_id", 0x1001000100000001)
    client_id = _int_field(params, "client_id", 0x2001000100000001)
    start = _int_field(params, "start", 0)
    quantity = _int_field(params, "quantity", 4)
    registers = _parse_registers(params.get("registers", "10,20,30,40,50,60,70,80"))

    if not 0 <= slave_port <= 0xFFFF:
        raise InputError("slave_port must be in 0..65535")
    _validate_read_params(slave_id, start, quantity, registers)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((slave_host, slave_port))
    listener.listen(1)
    actual_host, actual_port = listener.getsockname()[:2]

    slave_result: Dict[str, Any] = {}
    slave_ready = threading.Event()

    def slave_once() -> None:
        slave_ready.set()
        try:
            conn, address = listener.accept()
            with conn:
                context = run_slave_handshake(conn, slave_id, password, server_id)
                frame = recv_record(conn)
                request_pdu = parse_encrypted_data_send(frame, context, expected_slave_id=slave_id)
                response_pdu = handle_modbus_pdu(request_pdu, registers)
                send_record(conn, build_encrypted_data_send(slave_id, context, response_pdu))
                slave_result.update(
                    {
                        "client_id": f"0x{context.client_id:016x}",
                        "mode": context.mode_name,
                        "peer": f"{address[0]}:{address[1]}",
                    }
                )
        except Exception as exc:  # Passed back to the request handler below.
            slave_result["error"] = str(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=slave_once, daemon=True)
    thread.start()
    slave_ready.wait(timeout=1)

    connect_host = master_host
    if master_host in {"0.0.0.0", "::"}:
        connect_host = "127.0.0.1"

    try:
        with socket.create_connection((connect_host, actual_port), timeout=10) as sock:
            context = run_master_handshake(sock, slave_id, password, client_id)
            request_pdu = read_holding_registers_pdu(start, quantity)
            send_record(sock, build_encrypted_data_send(slave_id, context, request_pdu))
            response_pdu = parse_encrypted_data_send(recv_record(sock), context, expected_slave_id=slave_id)
            read_registers = parse_register_response(response_pdu)
    finally:
        thread.join(timeout=10)
        listener.close()

    if thread.is_alive():
        raise TimeoutError("embedded slave did not finish the request")
    if "error" in slave_result:
        raise ProtocolError(f"embedded slave error: {slave_result['error']}")

    rows = [
        {
            "address": start + index,
            "value": value,
            "hex": f"0x{value:04x}",
        }
        for index, value in enumerate(read_registers)
    ]
    return {
        "endpoint": f"{actual_host}:{actual_port}",
        "slave_id": slave_id,
        "start": start,
        "quantity": quantity,
        "registers": rows,
        "master": {
            "client_id": f"0x{context.client_id:016x}",
            "server_id": f"0x{context.server_id:016x}",
            "mode": context.mode_name,
            "ck": context.keys.ck.hex(),
            "civ": context.keys.civ.hex(),
        },
        "slave": slave_result,
    }


class WebHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_POST(self) -> None:
        if self.path != "/api/read":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(length)
            params = json.loads(payload or b"{}")
            result = read_with_embedded_slave(params)
            self._send_json(HTTPStatus.OK, {"ok": True, "result": result})
        except (InputError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
        except (OSError, ProtocolError, TimeoutError, ValueError) as exc:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})

    def _send_json(self, status: HTTPStatus, body: Dict[str, Any]) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Modbus secure-extension browser UI.")
    parser.add_argument("--host", default="192.168.0.106")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    if not STATIC_DIR.exists():
        print(f"missing static directory: {STATIC_DIR}", file=sys.stderr)
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
