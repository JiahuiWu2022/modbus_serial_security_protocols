#!/usr/bin/env python3
"""PSK/password based Modbus serial-link security extension.

This module implements the 6.3 flow from the supplied draft:

* ss_sk_open_req / ss_sk_open_cnf
* ss_sk_data_req / ss_sk_data_cnf for ECC point, mode, authenticator exchange
* Modbus RTU function-code 0 encapsulation
* encrypted Modbus function-code+data transport through ss_data_send

The serial timing layer is intentionally represented as RTU frames carried over a
TCP socket so the example can run without RS-485 hardware.
"""

from __future__ import annotations

import argparse
import dataclasses
import hmac
import os
import socket
from typing import Dict, List, Optional, Sequence, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - exercised only on minimal environments
    AESGCM = None


SYSTEM_ID_VERSION_1 = 0x01

FUNCTION_SECURITY = 0x00

TAG_SS_DATA_SEND = bytes.fromhex("9f9011")
TAG_SS_SK_OPEN_REQ = bytes.fromhex("9f9012")
TAG_SS_SK_OPEN_CNF = bytes.fromhex("9f9013")
TAG_SS_SK_DATA_REQ = bytes.fromhex("9f9014")
TAG_SS_SK_DATA_CNF = bytes.fromhex("9f9015")

TYPE_CLIENT_ID = 1
TYPE_SERVER_ID = 2
TYPE_RH_RM = 22
TYPE_R_B = 23
TYPE_MODE = 24
TYPE_S_M_S_H = 25

MODE_AES_GCM = 0x01
MODE_NAMES = {
    MODE_AES_GCM: "aes_gcm",
}

STATUS_OK = 0x00

SM2_P = int("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16)
SM2_A = int("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16)
SM2_B = int("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16)
SM2_N = int("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16)
SM2_GX = int("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16)
SM2_GY = int("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16)
SM2_G = (SM2_GX, SM2_GY)


class ProtocolError(Exception):
    """Raised when a frame or APDU violates the implemented protocol."""


def int_to_bytes(value: int, size: int) -> bytes:
    return value.to_bytes(size, "big")


def sm3(data: bytes) -> bytes:
    """Return the SM3 digest for *data*.

    Pure Python implementation following GB/T 32905. It is small enough for a
    reference server and keeps the examples independent of non-standard SM3
    packages.
    """

    iv = [
        0x7380166F,
        0x4914B2B9,
        0x172442D7,
        0xDA8A0600,
        0xA96F30BC,
        0x163138AA,
        0xE38DEE4D,
        0xB0FB0E4E,
    ]

    def rotl(x: int, n: int) -> int:
        n %= 32
        return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

    def p0(x: int) -> int:
        return x ^ rotl(x, 9) ^ rotl(x, 17)

    def p1(x: int) -> int:
        return x ^ rotl(x, 15) ^ rotl(x, 23)

    def ff(j: int, x: int, y: int, z: int) -> int:
        if j <= 15:
            return x ^ y ^ z
        return (x & y) | (x & z) | (y & z)

    def gg(j: int, x: int, y: int, z: int) -> int:
        if j <= 15:
            return x ^ y ^ z
        return (x & y) | (~x & z)

    length = len(data) * 8
    padded = data + b"\x80"
    padded += b"\x00" * ((56 - len(padded) % 64) % 64)
    padded += length.to_bytes(8, "big")

    state = iv[:]
    for offset in range(0, len(padded), 64):
        block = padded[offset : offset + 64]
        w = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 64, 4)]
        for j in range(16, 68):
            item = p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) ^ rotl(w[j - 13], 7) ^ w[j - 6]
            w.append(item & 0xFFFFFFFF)
        w1 = [(w[j] ^ w[j + 4]) & 0xFFFFFFFF for j in range(64)]

        a, b, c, d, e, f, g, h = state
        for j in range(64):
            tj = 0x79CC4519 if j <= 15 else 0x7A879D8A
            ss1 = rotl((rotl(a, 12) + e + rotl(tj, j)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ rotl(a, 12)
            tt1 = (ff(j, a, b, c) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (gg(j, e, f, g) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = rotl(f, 19)
            f = e
            e = p0(tt2)

        compressed = [a, b, c, d, e, f, g, h]
        state = [(x ^ y) & 0xFFFFFFFF for x, y in zip(state, compressed)]

    return b"".join(x.to_bytes(4, "big") for x in state)


def sm2_inverse(value: int) -> int:
    return pow(value, SM2_P - 2, SM2_P)


def sm2_add(p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % SM2_P == 0:
        return None
    if p1 == p2:
        slope = ((3 * x1 * x1 + SM2_A) * sm2_inverse(2 * y1 % SM2_P)) % SM2_P
    else:
        slope = ((y2 - y1) * sm2_inverse((x2 - x1) % SM2_P)) % SM2_P
    x3 = (slope * slope - x1 - x2) % SM2_P
    y3 = (slope * (x1 - x3) - y1) % SM2_P
    return x3, y3


def sm2_mul(k: int, point: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    if point is None or k % SM2_N == 0:
        return None
    k %= SM2_N
    result = None
    addend = point
    while k:
        if k & 1:
            result = sm2_add(result, addend)
        addend = sm2_add(addend, addend)
        k >>= 1
    return result


def encode_point(point: Tuple[int, int]) -> bytes:
    x, y = point
    return int_to_bytes(x, 32) + int_to_bytes(y, 32)


def decode_point(data: bytes) -> Tuple[int, int]:
    if len(data) != 64:
        raise ProtocolError(f"ECC point must be 64 bytes, got {len(data)}")
    point = (int.from_bytes(data[:32], "big"), int.from_bytes(data[32:], "big"))
    x, y = point
    if not (0 <= x < SM2_P and 0 <= y < SM2_P):
        raise ProtocolError("ECC point coordinate is out of field range")
    if (y * y - (x * x * x + SM2_A * x + SM2_B)) % SM2_P != 0:
        raise ProtocolError("ECC point is not on the SM2 curve")
    if point == SM2_G or sm2_mul(SM2_N, point) is not None:
        raise ProtocolError("ECC point failed subgroup checks")
    return point


def private_from_password(password: bytes, random_r: Optional[bytes] = None) -> Tuple[int, bytes]:
    random_r = random_r or os.urandom(32)
    if len(random_r) != 32:
        raise ValueError("random_r must be 32 bytes")
    private = int.from_bytes(sm3(password + random_r), "big") % SM2_N
    if private == 0:
        private = 1
    return private, random_r


def derive_content_keys(dhsk: bytes, server_id: int, client_id: int, r_b: bytes) -> "ContentKeys":
    server_id_b = int_to_bytes(server_id, 8)
    client_id_b = int_to_bytes(client_id, 8)
    material = sm3(dhsk + server_id_b)
    broadcast = sm3(dhsk + r_b + client_id_b)
    return ContentKeys(
        ck=material[:16],
        civ=material[16:],
        bck=broadcast[:16],
        bciv=broadcast[16:],
    )


def compute_server_auth(rh: bytes, rm: bytes, dhsk: bytes, server_id: int) -> bytes:
    return sm3(rh + rm + dhsk + int_to_bytes(server_id, 8))


def compute_master_auth(rh: bytes, rm: bytes, dhsk: bytes, client_id: int) -> bytes:
    return sm3(rm + rh + dhsk + int_to_bytes(client_id, 8))


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


def encode_ber_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("length cannot be negative")
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return b"\x81" + bytes([length])
    if length <= 0xFFFF:
        return b"\x82" + length.to_bytes(2, "big")
    raise ValueError("APDU is too large")


def decode_ber_length(data: bytes, offset: int = 0) -> Tuple[int, int]:
    if offset >= len(data):
        raise ProtocolError("missing BER length")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 2:
        raise ProtocolError("unsupported BER length form")
    end = offset + 1 + count
    if end > len(data):
        raise ProtocolError("truncated BER length")
    return int.from_bytes(data[offset + 1 : end], "big"), end


@dataclasses.dataclass(frozen=True)
class APDU:
    tag: bytes
    payload: bytes = b""

    def encode(self) -> bytes:
        if len(self.tag) != 3:
            raise ValueError("APDU tag must be exactly 3 bytes")
        return self.tag + encode_ber_length(len(self.payload)) + self.payload

    @classmethod
    def decode(cls, data: bytes) -> "APDU":
        if len(data) < 4:
            raise ProtocolError("APDU is too short")
        tag = data[:3]
        length, offset = decode_ber_length(data, 3)
        end = offset + length
        if end != len(data):
            raise ProtocolError("APDU length does not match frame payload")
        return cls(tag=tag, payload=data[offset:end])


@dataclasses.dataclass(frozen=True)
class DataPayload:
    system_mask: int
    send: Dict[int, bytes]
    request: Tuple[int, ...] = ()

    def encode_req(self) -> bytes:
        body = bytes([self.system_mask, len(self.send)])
        for data_type, value in self.send.items():
            body += bytes([data_type]) + len(value).to_bytes(2, "big") + value
        body += bytes([len(self.request)])
        body += bytes(self.request)
        return body

    def encode_cnf(self) -> bytes:
        body = bytes([self.system_mask, len(self.send)])
        for data_type, value in self.send.items():
            body += bytes([data_type]) + len(value).to_bytes(2, "big") + value
        return body

    @classmethod
    def decode_req(cls, data: bytes) -> "DataPayload":
        if len(data) < 3:
            raise ProtocolError("data request payload is too short")
        system_mask = data[0]
        count = data[1]
        offset = 2
        sent: Dict[int, bytes] = {}
        for _ in range(count):
            if offset + 3 > len(data):
                raise ProtocolError("truncated data item header")
            data_type = data[offset]
            length = int.from_bytes(data[offset + 1 : offset + 3], "big")
            offset += 3
            if offset + length > len(data):
                raise ProtocolError("truncated data item value")
            sent[data_type] = data[offset : offset + length]
            offset += length
        if offset >= len(data):
            raise ProtocolError("missing request datatype count")
        request_count = data[offset]
        offset += 1
        end = offset + request_count
        if end != len(data):
            raise ProtocolError("request datatype list length mismatch")
        return cls(system_mask=system_mask, send=sent, request=tuple(data[offset:end]))

    @classmethod
    def decode_cnf(cls, data: bytes) -> "DataPayload":
        if len(data) < 2:
            raise ProtocolError("data confirmation payload is too short")
        system_mask = data[0]
        count = data[1]
        offset = 2
        sent: Dict[int, bytes] = {}
        for _ in range(count):
            if offset + 3 > len(data):
                raise ProtocolError("truncated data item header")
            data_type = data[offset]
            length = int.from_bytes(data[offset + 1 : offset + 3], "big")
            offset += 3
            if offset + length > len(data):
                raise ProtocolError("truncated data item value")
            sent[data_type] = data[offset : offset + length]
            offset += length
        if offset != len(data):
            raise ProtocolError("trailing bytes in data confirmation payload")
        return cls(system_mask=system_mask, send=sent)


@dataclasses.dataclass(frozen=True)
class RtuFrame:
    slave_id: int
    function: int
    payload: bytes

    def encode(self) -> bytes:
        body = bytes([self.slave_id, self.function]) + self.payload
        crc = crc16_modbus(body)
        return body + crc.to_bytes(2, "little")

    @classmethod
    def decode(cls, data: bytes) -> "RtuFrame":
        if len(data) < 4:
            raise ProtocolError("RTU frame is too short")
        body = data[:-2]
        expected = int.from_bytes(data[-2:], "little")
        actual = crc16_modbus(body)
        if actual != expected:
            raise ProtocolError(f"bad RTU CRC: expected 0x{expected:04x}, computed 0x{actual:04x}")
        return cls(slave_id=body[0], function=body[1], payload=body[2:])


@dataclasses.dataclass
class ContentKeys:
    ck: bytes
    civ: bytes
    bck: bytes
    bciv: bytes


@dataclasses.dataclass
class SessionContext:
    role: str
    server_id: int
    client_id: int
    mode: int
    dhsk: bytes
    keys: ContentKeys
    local_point: bytes
    peer_point: bytes
    send_counter: int = 1
    recv_counter: int = 1

    @property
    def mode_name(self) -> str:
        return MODE_NAMES.get(self.mode, f"unknown({self.mode})")


def build_apdu_frame(slave_id: int, tag: bytes, payload: bytes = b"") -> bytes:
    return RtuFrame(slave_id, FUNCTION_SECURITY, APDU(tag, payload).encode()).encode()


def parse_apdu_frame(frame_data: bytes, expected_slave_id: Optional[int] = None) -> APDU:
    frame = RtuFrame.decode(frame_data)
    if expected_slave_id is not None and frame.slave_id != expected_slave_id:
        raise ProtocolError(f"unexpected slave id {frame.slave_id}, expected {expected_slave_id}")
    if frame.function != FUNCTION_SECURITY:
        raise ProtocolError(f"expected function code 0 security frame, got 0x{frame.function:02x}")
    return APDU.decode(frame.payload)


def _read_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_record(sock: socket.socket, frame: bytes) -> None:
    if len(frame) > 0xFFFF:
        raise ValueError("record too large")
    sock.sendall(len(frame).to_bytes(2, "big") + frame)


def recv_record(sock: socket.socket) -> bytes:
    header = _read_exact(sock, 2)
    size = int.from_bytes(header, "big")
    return _read_exact(sock, size)


def aes_gcm_encrypt(keys: ContentKeys, counter: int, pdu: bytes, broadcast: bool = False) -> Tuple[bytes, bytes]:
    if AESGCM is None:
        raise RuntimeError("cryptography is required for AES-GCM content encryption")
    key = keys.bck if broadcast else keys.ck
    civ = keys.bciv if broadcast else keys.civ
    nonce = civ[:8] + counter.to_bytes(4, "big")
    associated_data = sm3(b"Modbus")[:16]
    encrypted = AESGCM(key).encrypt(nonce, pdu, associated_data)
    return encrypted[-16:], encrypted[:-16]


def aes_gcm_decrypt(keys: ContentKeys, counter: int, mac: bytes, ciphertext: bytes, broadcast: bool = False) -> bytes:
    if AESGCM is None:
        raise RuntimeError("cryptography is required for AES-GCM content decryption")
    key = keys.bck if broadcast else keys.ck
    civ = keys.bciv if broadcast else keys.civ
    nonce = civ[:8] + counter.to_bytes(4, "big")
    associated_data = sm3(b"Modbus")[:16]
    return AESGCM(key).decrypt(nonce, ciphertext + mac, associated_data)


def build_encrypted_data_send(slave_id: int, context: SessionContext, modbus_pdu: bytes) -> bytes:
    if context.mode != MODE_AES_GCM:
        raise ProtocolError(f"unsupported content mode {context.mode}")
    mac, ciphertext = aes_gcm_encrypt(context.keys, context.send_counter, modbus_pdu)
    context.send_counter += 1
    return build_apdu_frame(slave_id, TAG_SS_DATA_SEND, mac + ciphertext)


def parse_encrypted_data_send(frame_data: bytes, context: SessionContext, expected_slave_id: int) -> bytes:
    apdu = parse_apdu_frame(frame_data, expected_slave_id=expected_slave_id)
    if apdu.tag != TAG_SS_DATA_SEND:
        raise ProtocolError(f"expected ss_data_send, got {apdu.tag.hex()}")
    if len(apdu.payload) < 16:
        raise ProtocolError("ss_data_send payload is missing MAC")
    mac = apdu.payload[:16]
    ciphertext = apdu.payload[16:]
    if context.mode != MODE_AES_GCM:
        raise ProtocolError(f"unsupported content mode {context.mode}")
    pdu = aes_gcm_decrypt(context.keys, context.recv_counter, mac, ciphertext)
    context.recv_counter += 1
    return pdu


def run_master_handshake(sock: socket.socket, slave_id: int, password: bytes, client_id: int) -> SessionContext:
    send_record(sock, build_apdu_frame(slave_id, TAG_SS_SK_OPEN_REQ))

    open_cnf = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if open_cnf.tag != TAG_SS_SK_OPEN_CNF:
        raise ProtocolError(f"expected ss_sk_open_cnf, got {open_cnf.tag.hex()}")
    if len(open_cnf.payload) != 1 or not (open_cnf.payload[0] & SYSTEM_ID_VERSION_1):
        raise ProtocolError("peer does not support security system version 1")

    private, _ = private_from_password(password)
    local_point = sm2_mul(private, SM2_G)
    if local_point is None:
        raise ProtocolError("failed to derive master ECC point")
    rh = encode_point(local_point)
    request = DataPayload(
        system_mask=SYSTEM_ID_VERSION_1,
        send={TYPE_RH_RM: rh, TYPE_MODE: bytes([MODE_AES_GCM])},
        request=(TYPE_RH_RM, TYPE_S_M_S_H),
    )
    send_record(sock, build_apdu_frame(slave_id, TAG_SS_SK_DATA_REQ, request.encode_req()))

    first_cnf = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if first_cnf.tag != TAG_SS_SK_DATA_CNF:
        raise ProtocolError(f"expected ss_sk_data_cnf, got {first_cnf.tag.hex()}")
    response = DataPayload.decode_cnf(first_cnf.payload)
    rm = response.send.get(TYPE_RH_RM)
    s_m = response.send.get(TYPE_S_M_S_H)
    server_id_b = response.send.get(TYPE_SERVER_ID)
    if rm is None or s_m is None or server_id_b is None:
        raise ProtocolError("slave response is missing R_M, S_M, or SERVER_ID")
    server_id = int.from_bytes(server_id_b, "big")

    peer_point = decode_point(rm)
    shared = sm2_mul(private, peer_point)
    if shared is None:
        raise ProtocolError("failed to derive shared point")
    dhsk = encode_point(shared)
    expected_s_m = compute_server_auth(rh, rm, dhsk, server_id)
    if not hmac.compare_digest(s_m, expected_s_m):
        raise ProtocolError("S_M verification failed")

    s_h = compute_master_auth(rh, rm, dhsk, client_id)
    r_b = os.urandom(32)
    final_req = DataPayload(
        system_mask=SYSTEM_ID_VERSION_1,
        send={
            TYPE_S_M_S_H: s_h,
            TYPE_R_B: r_b,
            TYPE_CLIENT_ID: int_to_bytes(client_id, 8),
        },
    )
    send_record(sock, build_apdu_frame(slave_id, TAG_SS_SK_DATA_REQ, final_req.encode_req()))

    final_cnf = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if final_cnf.tag != TAG_SS_SK_DATA_CNF:
        raise ProtocolError(f"expected final ss_sk_data_cnf, got {final_cnf.tag.hex()}")
    status_payload = DataPayload.decode_cnf(final_cnf.payload)
    status = status_payload.send.get(20, bytes([STATUS_OK]))
    if status != bytes([STATUS_OK]):
        raise ProtocolError(f"slave returned status 0x{status.hex()}")

    return SessionContext(
        role="master",
        server_id=server_id,
        client_id=client_id,
        mode=MODE_AES_GCM,
        dhsk=dhsk,
        keys=derive_content_keys(dhsk, server_id, client_id, r_b),
        local_point=rh,
        peer_point=rm,
    )


def run_slave_handshake(sock: socket.socket, slave_id: int, password: bytes, server_id: int) -> SessionContext:
    open_req = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if open_req.tag != TAG_SS_SK_OPEN_REQ:
        raise ProtocolError(f"expected ss_sk_open_req, got {open_req.tag.hex()}")
    if open_req.payload:
        raise ProtocolError("ss_sk_open_req payload must be empty")

    send_record(sock, build_apdu_frame(slave_id, TAG_SS_SK_OPEN_CNF, bytes([SYSTEM_ID_VERSION_1])))

    first_req = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if first_req.tag != TAG_SS_SK_DATA_REQ:
        raise ProtocolError(f"expected ss_sk_data_req, got {first_req.tag.hex()}")
    request = DataPayload.decode_req(first_req.payload)
    rh = request.send.get(TYPE_RH_RM)
    mode = request.send.get(TYPE_MODE)
    if rh is None or mode is None:
        raise ProtocolError("master request is missing R_H or mode")
    if mode[0] != MODE_AES_GCM:
        raise ProtocolError(f"unsupported requested mode 0x{mode[0]:02x}")
    peer_point = decode_point(rh)

    private, _ = private_from_password(password)
    local_point = sm2_mul(private, SM2_G)
    if local_point is None:
        raise ProtocolError("failed to derive slave ECC point")
    shared = sm2_mul(private, peer_point)
    if shared is None:
        raise ProtocolError("failed to derive shared point")
    rm = encode_point(local_point)
    dhsk = encode_point(shared)
    s_m = compute_server_auth(rh, rm, dhsk, server_id)
    response = DataPayload(
        system_mask=SYSTEM_ID_VERSION_1,
        send={
            TYPE_RH_RM: rm,
            TYPE_S_M_S_H: s_m,
            TYPE_SERVER_ID: int_to_bytes(server_id, 8),
        },
    )
    send_record(sock, build_apdu_frame(slave_id, TAG_SS_SK_DATA_CNF, response.encode_cnf()))

    final_req = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if final_req.tag != TAG_SS_SK_DATA_REQ:
        raise ProtocolError(f"expected final ss_sk_data_req, got {final_req.tag.hex()}")
    final_payload = DataPayload.decode_req(final_req.payload)
    s_h = final_payload.send.get(TYPE_S_M_S_H)
    r_b = final_payload.send.get(TYPE_R_B)
    client_id_b = final_payload.send.get(TYPE_CLIENT_ID)
    if s_h is None or r_b is None or client_id_b is None:
        raise ProtocolError("final master request is missing S_H, r_B, or CLIENT_ID")
    client_id = int.from_bytes(client_id_b, "big")
    expected_s_h = compute_master_auth(rh, rm, dhsk, client_id)
    if not hmac.compare_digest(s_h, expected_s_h):
        raise ProtocolError("S_H verification failed")
    if len(r_b) != 32:
        raise ProtocolError("r_B must be 32 bytes")

    status = DataPayload(system_mask=SYSTEM_ID_VERSION_1, send={20: bytes([STATUS_OK])})
    send_record(sock, build_apdu_frame(slave_id, TAG_SS_SK_DATA_CNF, status.encode_cnf()))

    return SessionContext(
        role="slave",
        server_id=server_id,
        client_id=client_id,
        mode=mode[0],
        dhsk=dhsk,
        keys=derive_content_keys(dhsk, server_id, client_id, r_b),
        local_point=rm,
        peer_point=rh,
    )


def read_holding_registers_pdu(start_address: int, quantity: int) -> bytes:
    if not (0 <= start_address <= 0xFFFF and 1 <= quantity <= 125):
        raise ValueError("invalid holding-register read range")
    return b"\x03" + start_address.to_bytes(2, "big") + quantity.to_bytes(2, "big")


def handle_modbus_pdu(pdu: bytes, registers: Sequence[int]) -> bytes:
    if not pdu:
        raise ProtocolError("empty Modbus PDU")
    function = pdu[0]
    if function != 0x03:
        return bytes([function | 0x80, 0x01])
    if len(pdu) != 5:
        return b"\x83\x03"
    start = int.from_bytes(pdu[1:3], "big")
    quantity = int.from_bytes(pdu[3:5], "big")
    if quantity < 1 or quantity > 125:
        return b"\x83\x03"
    if start + quantity > len(registers):
        return b"\x83\x02"
    data = b"".join((registers[start + i] & 0xFFFF).to_bytes(2, "big") for i in range(quantity))
    return bytes([0x03, len(data)]) + data


def parse_register_response(pdu: bytes) -> List[int]:
    if len(pdu) >= 2 and pdu[0] & 0x80:
        raise ProtocolError(f"Modbus exception function=0x{pdu[0]:02x} code=0x{pdu[1]:02x}")
    if len(pdu) < 2 or pdu[0] != 0x03:
        raise ProtocolError("unexpected Modbus response")
    byte_count = pdu[1]
    if byte_count % 2 or len(pdu) != 2 + byte_count:
        raise ProtocolError("invalid register response length")
    return [int.from_bytes(pdu[i : i + 2], "big") for i in range(2, len(pdu), 2)]


def parse_hex_or_int(value: str) -> int:
    return int(value, 0)


def endpoint_args(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=15020)
    parser.add_argument("--slave-id", type=parse_hex_or_int, default=1)
    parser.add_argument("--password", default="modbus-psk-demo")
    return parser
