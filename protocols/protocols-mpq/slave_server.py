#!/usr/bin/env python3
"""Slave station server for the Modbus serial-link 6.4 PQ PKI extension."""

from __future__ import annotations

import socket
import sys
from typing import List

from modbus_security_pq import (
    ProtocolError,
    build_encrypted_data_send,
    endpoint_args,
    handle_modbus_pdu,
    parse_encrypted_data_send,
    recv_record,
    run_slave_handshake,
    send_record,
)


def serve_connection(
    conn: socket.socket,
    slave_id: int,
    server_id: int,
    registers: List[int],
) -> None:
    context = run_slave_handshake(conn, slave_id, server_id)
    print(
        "handshake ok "
        f"client_id=0x{context.client_id:016x} mode={context.mode_name} "
        f"ck={context.keys.ck.hex()} civ={context.keys.civ.hex()} "
        f"bck={context.keys.bck.hex()} bciv={context.keys.bciv.hex()}",
        flush=True,
    )

    while True:
        try:
            frame = recv_record(conn)
        except EOFError:
            print("master disconnected", flush=True)
            return
        request_pdu = parse_encrypted_data_send(frame, context, expected_slave_id=slave_id)
        response_pdu = handle_modbus_pdu(request_pdu, registers)
        send_record(conn, build_encrypted_data_send(slave_id, context, response_pdu))


def serve(
    host: str,
    port: int,
    slave_id: int,
    server_id: int,
    registers: List[int],
    once: bool,
) -> None:
    # the socket initialized here is only formal and not actually used if use hardware UART in modbus_security_pq.py.
    conn = -1
    while True:
        try:
            serve_connection(conn, slave_id, server_id, registers)
        except (EOFError, ProtocolError, ValueError) as exc:
            print(f"connection error: {exc}", file=sys.stderr, flush=True)        
"""    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        print(f"slave listening on {host}:{port} slave_id={slave_id} server_id=0x{server_id:016x}", flush=True)

        while True:
            conn, address = listener.accept()
            with conn:
                print(f"accepted master from {address[0]}:{address[1]}", flush=True)
                try:
                    serve_connection(conn, slave_id, server_id, registers)
                except (EOFError, ProtocolError, ValueError) as exc:
                    print(f"connection error: {exc}", file=sys.stderr, flush=True)
            if once:
                return
"""    

def main() -> int:
    parser = endpoint_args("Run a Modbus 6.4 PQ PKI secure-extension slave station server.")
    parser.add_argument("--server-id", type=lambda v: int(v, 0), default=0x1001000100000001)
    parser.add_argument("--registers", type=int, default=64, help="number of demo holding registers")
    parser.add_argument("--once", action="store_true", help="serve one master connection and exit")
    args = parser.parse_args()

    if not (1 <= args.slave_id <= 247):
        parser.error("--slave-id must be in 1..247")
    registers = [(i + 1) * 10 for i in range(args.registers)]
    # If a real UART interface is used in modbus_security_pq.by, 
    # the socket initialized here is only formal and not actually used. 
    # Every frame read and sent is completed on UART.  
    try:
        serve(
            host=args.host,
            port=args.port,
            slave_id=args.slave_id,
            server_id=args.server_id,
            registers=registers,
            once=args.once,
        )
    except (OSError, ProtocolError, ValueError) as exc:
        print(f"slave error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
