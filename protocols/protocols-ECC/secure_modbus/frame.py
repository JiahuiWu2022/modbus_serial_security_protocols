from __future__ import annotations

import socket
import struct

from .constants import SECURE_FUNCTION_CODE


class ProtocolError(RuntimeError):
    pass


def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def build_rtu_frame(address: int, function_code: int, payload: bytes) -> bytes:
    if not 0 <= address <= 247:
        raise ValueError("Modbus address must be in 0..247")
    body = bytes([address, function_code]) + payload
    return body + struct.pack("<H", crc16_modbus(body))


def parse_rtu_frame(frame: bytes) -> tuple[int, int, bytes]:
    if len(frame) < 4:
        raise ProtocolError("RTU frame is too short")
    body, got_crc = frame[:-2], struct.unpack("<H", frame[-2:])[0]
    want_crc = crc16_modbus(body)
    if got_crc != want_crc:
        raise ProtocolError(f"CRC mismatch: got 0x{got_crc:04x}, want 0x{want_crc:04x}")
    return body[0], body[1], body[2:]


def build_apdu(tag: int, payload: bytes = b"") -> bytes:
    if len(payload) > 0xFFFF:
        raise ValueError("APDU payload exceeds 65535 bytes")
    return bytes([tag]) + len(payload).to_bytes(2, "big") + payload


def parse_apdu(data: bytes) -> tuple[int, bytes]:
    if len(data) < 3:
        raise ProtocolError("APDU is too short")
    tag = data[0]
    length = int.from_bytes(data[1:3], "big")
    payload = data[3:]
    if len(payload) != length:
        raise ProtocolError(f"APDU length mismatch: got {len(payload)}, want {length}")
    return tag, payload


def send_packet(sock: socket.socket, frame: bytes) -> None:
    if len(frame) > 0xFFFF:
        raise ValueError("transport frame exceeds 65535 bytes")
    sock.sendall(len(frame).to_bytes(2, "big") + frame)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        #simualation using Socket
        #chunk = sock.recv(remaining)
        #read the hardware UART.
        chunk = readUART(remaining)
        if not chunk:
            raise ProtocolError("connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_packet(sock: socket.socket) -> bytes:
    length = int.from_bytes(recv_exact(sock, 2), "big")
    return recv_exact(sock, length)


def send_secure_apdu(sock: socket.socket, address: int, tag: int, payload: bytes = b"") -> None:
    #simualation using Socket
    #send_packet(sock, build_rtu_frame(address, SECURE_FUNCTION_CODE, build_apdu(tag, payload)))
    #write the hardware UART.
    writeUART(build_rtu_frame(address, SECURE_FUNCTION_CODE, build_apdu(tag, payload)))


def recv_secure_apdu(sock: socket.socket, expected_address: int | None = None) -> tuple[int, int, bytes]:
    address, function_code, payload = parse_rtu_frame(recv_packet(sock))
    if expected_address is not None and address != expected_address:
        raise ProtocolError(f"unexpected Modbus address {address}, want {expected_address}")
    if function_code != SECURE_FUNCTION_CODE:
        raise ProtocolError(f"unexpected function code {function_code}, want secure extension code 0")
    tag, body = parse_apdu(payload)
    return address, tag, body
