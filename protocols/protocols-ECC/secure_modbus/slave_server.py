from __future__ import annotations

import argparse
import logging
import socket
import struct
from pathlib import Path

from .crypto import load_identity
from .frame import ProtocolError
from .session import SecureSession, server_handshake


LOG = logging.getLogger("secure-modbus-slave")


class RegisterBank:
    def __init__(self, size: int = 128) -> None:
        self.registers = [index for index in range(size)]

    def handle_pdu(self, pdu: bytes) -> bytes:
        if not pdu:
            raise ProtocolError("empty Modbus PDU")
        function = pdu[0]
        data = pdu[1:]
        if function == 0x03:
            if len(data) != 4:
                raise ProtocolError("read holding registers request must be 4 bytes")
            start, quantity = struct.unpack(">HH", data)
            if quantity < 1 or quantity > 125 or start + quantity > len(self.registers):
                return bytes([function | 0x80, 0x02])
            body = bytearray([function, quantity * 2])
            for value in self.registers[start : start + quantity]:
                body.extend((value & 0xFFFF).to_bytes(2, "big"))
            return bytes(body)
        if function == 0x06:
            if len(data) != 4:
                raise ProtocolError("write single register request must be 4 bytes")
            register, value = struct.unpack(">HH", data)
            if register >= len(self.registers):
                return bytes([function | 0x80, 0x02])
            self.registers[register] = value
            return bytes([function]) + data
        return bytes([function | 0x80, 0x01])


def handle_client(conn: socket.socket, peer: tuple[str, int], args: argparse.Namespace, bank: RegisterBank) -> None:
    identity = load_identity(args.pki, "server")
    session = SecureSession(conn, args.address, identity)
    context_path = args.state / f"server_context_{args.address}.json"
    LOG.info("client connected from %s:%s", *peer)
    server_handshake(session, context_path)
    LOG.info("secure session ready: client_id=%s", (session.peer_id or b"").hex())
    while True:
        request = session.recv_encrypted_pdu()
        LOG.info("received encrypted PDU: %s", request.hex())
        response = bank.handle_pdu(request)
        session.send_encrypted_pdu(response)


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure Modbus slave server based on section 6.2.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=15020, type=int)
    parser.add_argument("--address", default=1, type=int)
    parser.add_argument("--pki", default=Path("demo_pki"), type=Path)
    parser.add_argument("--state", default=Path(".secure_modbus_state"), type=Path)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(message)s")
    bank = RegisterBank()
    with socket.create_server((args.host, args.port), reuse_port=False) as server:
        LOG.info("listening on %s:%s as Modbus address %s", args.host, args.port, args.address)
        while True:
            conn, peer = server.accept()
            with conn:
                try:
                    handle_client(conn, peer, args, bank)
                except (ProtocolError, OSError) as exc:
                    LOG.warning("connection closed: %s", exc)


if __name__ == "__main__":
    main()
