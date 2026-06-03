#!/usr/bin/env python3
"""Master station endpoint for the Modbus serial-link 6.4 PQ PKI extension."""

from __future__ import annotations

import socket
import sys

from modbus_security_pq import (
    ProtocolError,
    build_encrypted_data_send,
    endpoint_args,
    parse_encrypted_data_send,
    parse_register_response,
    read_holding_registers_pdu,
    recv_record,
    run_master_handshake,
    send_record,
)


def run_master(
    host: str,
    port: int,
    slave_id: int,
    client_id: int,
    start: int,
    quantity: int,
) -> None:
    # the socket initialized here is only formal and not actually used if use hardware UART in modbus_security_pq.py.
    sock = -1
    context = run_master_handshake(sock, slave_id, client_id)
    print(
        "handshake ok "
        f"server_id=0x{context.server_id:016x} mode={context.mode_name} "
        f"ck={context.keys.ck.hex()} civ={context.keys.civ.hex()} "
        f"bck={context.keys.bck.hex()} bciv={context.keys.bciv.hex()}",
        flush=True,
    )

    request_pdu = read_holding_registers_pdu(start, quantity)
    send_record(sock, build_encrypted_data_send(slave_id, context, request_pdu))
    response_pdu = parse_encrypted_data_send(recv_record(sock), context, expected_slave_id=slave_id)
    registers = parse_register_response(response_pdu)
    print(f"read holding registers start={start} quantity={quantity}: {registers}", flush=True)    
"""   
    #simualation using Socket 
    with socket.create_connection((host, port), timeout=10) as sock:
        context = run_master_handshake(sock, slave_id, client_id)
        print(
            "handshake ok "
            f"server_id=0x{context.server_id:016x} mode={context.mode_name} "
            f"ck={context.keys.ck.hex()} civ={context.keys.civ.hex()} "
            f"bck={context.keys.bck.hex()} bciv={context.keys.bciv.hex()}",
            flush=True,
        )

        request_pdu = read_holding_registers_pdu(start, quantity)
        send_record(sock, build_encrypted_data_send(slave_id, context, request_pdu))
        response_pdu = parse_encrypted_data_send(recv_record(sock), context, expected_slave_id=slave_id)
        registers = parse_register_response(response_pdu)
        print(f"read holding registers start={start} quantity={quantity}: {registers}", flush=True)
"""

def main() -> int:
    parser = endpoint_args("Run a Modbus 6.4 PQ PKI secure-extension master station endpoint.")
    parser.add_argument("--client-id", type=lambda v: int(v, 0), default=0x2001000100000001)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--quantity", type=int, default=4)
    args = parser.parse_args()

    if not (1 <= args.slave_id <= 247):
        parser.error("--slave-id must be in 1..247")
    try:
    # If a real UART interface is used in modbus_security_pq.py, 
    # the socket initialized here is only formal and not actually used. 
    # Every frame read and sent is completed on UART.        
        run_master(
            host=args.host,
            port=args.port,
            slave_id=args.slave_id,
            client_id=args.client_id,
            start=args.start,
            quantity=args.quantity,
        )
    except (OSError, ProtocolError, ValueError) as exc:
        print(f"master error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
