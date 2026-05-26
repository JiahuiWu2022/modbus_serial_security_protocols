#!/usr/bin/env python3
"""6.4 post-quantum hybrid PKI Modbus serial-link security extension.

The protocol flow follows section 6.4 of the supplied technical requirement:

* ss_open_req / ss_open_cnf
* slave-initiated certificate-chain exchange
* KEM_C / KEM_BC / mode exchange
* AKH/AKM verification
* CK/CIV and BCK/BCIV derivation
* encrypted Modbus function-code+data transport through ss_data_send

This is a runnable reference endpoint. Python's standard cryptography stack
does not currently provide ML-KEM-768 and ML-DSA-44 primitives, so this module
uses a small deterministic demo KEM and Ed25519-backed demo certificates while
preserving the APDU fields, ciphertext length, key sizes, and derivation
formulas from the document. Replace DemoMlKem768 and the demo certificate
builder/verifier with certified ML-KEM/ML-DSA/X.509 code before production use.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hmac
import json
import os
import socket
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class ProtocolError(Exception):
    """Raised when a frame or APDU violates the implemented protocol."""


def int_to_bytes(value: int, size: int) -> bytes:
    return value.to_bytes(size, "big")


def sm3(data: bytes) -> bytes:
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
        return x ^ y ^ z if j <= 15 else (x & y) | (x & z) | (y & z)

    def gg(j: int, x: int, y: int, z: int) -> int:
        return x ^ y ^ z if j <= 15 else (x & y) | (~x & z)

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

        state = [(x ^ y) & 0xFFFFFFFF for x, y in zip(state, [a, b, c, d, e, f, g, h])]

    return b"".join(x.to_bytes(4, "big") for x in state)


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
    key = keys.bck if broadcast else keys.ck
    civ = keys.bciv if broadcast else keys.civ
    nonce = civ[:8] + counter.to_bytes(4, "big")
    associated_data = sm3(b"Modbus")[:16]
    encrypted = AESGCM(key).encrypt(nonce, pdu, associated_data)
    return encrypted[-16:], encrypted[:-16]


def aes_gcm_decrypt(keys: ContentKeys, counter: int, mac: bytes, ciphertext: bytes, broadcast: bool = False) -> bytes:
    key = keys.bck if broadcast else keys.ck
    civ = keys.bciv if broadcast else keys.civ
    nonce = civ[:8] + counter.to_bytes(4, "big")
    associated_data = sm3(b"Modbus")[:16]
    return AESGCM(key).decrypt(nonce, ciphertext + mac, associated_data)


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


SYSTEM_ID_VERSION_1 = 0x01
FUNCTION_SECURITY = 0x00

TAG_SS_OPEN_REQ = bytes.fromhex("9f9001")
TAG_SS_OPEN_CNF = bytes.fromhex("9f9002")
TAG_SS_DATA_REQ = bytes.fromhex("9f9003")
TAG_SS_DATA_CNF = bytes.fromhex("9f9004")
TAG_SS_DATA_SEND = bytes.fromhex("9f9011")

TYPE_CLIENT_ID = 1
TYPE_SERVER_ID = 2
TYPE_CLIENT_BRAND_CERT = 3
TYPE_SERVER_BRAND_CERT = 4
TYPE_CLIENT_DEV_CERT = 10
TYPE_SERVER_DEV_CERT = 11
TYPE_AKH = 17
TYPE_STATUS = 20
TYPE_MODE = 24
TYPE_KEM_C = 26
TYPE_KEM_BC = 27

STATUS_OK = 0x00
MODE_AES_GCM = 0x01
MODE_NAMES = {
    MODE_AES_GCM: "aes_gcm",
}

ML_KEM_768_CIPHERTEXT_BYTES = 1088
ML_KEM_SHARED_SECRET_BYTES = 32

_ROOT_SIGNING_SEED = bytes.fromhex("01" * 32)
_BRAND_SIGNING_SEED = bytes.fromhex("02" * 32)
_BROADCAST_KEM_SECRET = sm3(b"modbus-6.4-demo-broadcast-ml-kem-private")


@dataclasses.dataclass
class PQSessionContext:
    role: str
    server_id: int
    client_id: int
    mode: int
    kemsk: bytes
    kemsk_b: bytes
    auth_key: bytes
    keys: ContentKeys
    send_counter: int = 1
    recv_counter: int = 1

    @property
    def mode_name(self) -> str:
        return MODE_NAMES.get(self.mode, f"unknown({self.mode})")


@dataclasses.dataclass(frozen=True)
class DeviceMaterial:
    role: str
    device_id: int
    kem_secret: bytes
    kem_public: bytes
    brand_cert: bytes
    device_cert: bytes


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def _canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _signing_key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _signed_json(fields: Dict[str, Any], key: Ed25519PrivateKey) -> bytes:
    body = dict(fields)
    body["signature"] = _b64(key.sign(_canonical_json(body)))
    return _canonical_json(body)


def _verify_signed_json(data: bytes, public_key: Ed25519PublicKey, expected_kind: str) -> Dict[str, Any]:
    try:
        cert = json.loads(data.decode())
        signature = _unb64(cert.pop("signature"))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid certificate encoding") from exc
    if cert.get("kind") != expected_kind:
        raise ProtocolError(f"unexpected certificate kind {cert.get('kind')!r}")
    try:
        public_key.verify(signature, _canonical_json(cert))
    except Exception as exc:
        raise ProtocolError("certificate signature verification failed") from exc
    return cert


def _derive_kem_public(kem_secret: bytes) -> bytes:
    if len(kem_secret) != 32:
        raise ValueError("demo ML-KEM secret must be 32 bytes")
    return sm3(b"demo-ml-kem-public" + kem_secret)


class DemoMlKem768:
    """Tiny ML-KEM-shaped adapter for local interoperability tests.

    It intentionally exposes ML-KEM-like encaps/decaps operations and produces
    1088-byte ciphertexts with 32-byte shared secrets, matching ML-KEM-768 wire
    sizes used by section 6.4. It is not cryptographically equivalent to
    ML-KEM-768.
    """

    @staticmethod
    def encaps(public_key: bytes, label: bytes, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        if len(public_key) != 32:
            raise ProtocolError("demo ML-KEM public key must be 32 bytes")
        seed = seed or os.urandom(32)
        if len(seed) != 32:
            raise ValueError("demo ML-KEM seed must be 32 bytes")
        shared_secret = sm3(b"demo-ml-kem-768-ss" + label + public_key + seed)
        authenticator = sm3(b"demo-ml-kem-768-auth" + public_key + shared_secret + seed + label)
        stream = bytearray(seed + authenticator)
        block = sm3(seed + public_key + label)
        while len(stream) < ML_KEM_768_CIPHERTEXT_BYTES:
            block = sm3(block + seed + public_key + label)
            stream.extend(block)
        return bytes(stream[:ML_KEM_768_CIPHERTEXT_BYTES]), shared_secret

    @staticmethod
    def decaps(secret_key: bytes, ciphertext: bytes, label: bytes) -> bytes:
        if len(ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
            raise ProtocolError(f"KEM ciphertext must be {ML_KEM_768_CIPHERTEXT_BYTES} bytes")
        public_key = _derive_kem_public(secret_key)
        seed = ciphertext[:32]
        shared_secret = sm3(b"demo-ml-kem-768-ss" + label + public_key + seed)
        authenticator = sm3(b"demo-ml-kem-768-auth" + public_key + shared_secret + seed + label)
        if not hmac.compare_digest(ciphertext[32:64], authenticator):
            raise ProtocolError("KEM ciphertext authentication failed")
        return shared_secret


def make_device_material(role: str, device_id: int) -> DeviceMaterial:
    if role not in {"client", "server"}:
        raise ValueError("role must be client or server")
    if not 0 <= device_id <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("device_id must fit in 64 bits")

    root_key = _signing_key(_ROOT_SIGNING_SEED)
    brand_key = _signing_key(_BRAND_SIGNING_SEED)
    brand_public = _public_key_bytes(brand_key.public_key())

    brand_cert = _signed_json(
        {
            "kind": "brand",
            "subject": "Demo Modbus 6.4 Brand",
            "issuer": "Demo ROT",
            "algorithm": "SM2-with-SM3+ML-DSA-demo",
            "brand_sign_public_key": _b64(brand_public),
        },
        root_key,
    )

    kem_secret = sm3(f"modbus-6.4-demo-{role}-{device_id:016x}-ml-kem-private".encode())
    kem_public = _derive_kem_public(kem_secret)
    device_fields: Dict[str, Any] = {
        "kind": "device",
        "role": role,
        "issuer": "Demo Modbus 6.4 Brand",
        "device_id": f"0x{device_id:016x}",
        "algorithm": "SM2-with-SM3+ML-DSA-demo",
        "ml_kem_public_key": _b64(kem_public),
        "encryption_capability": ["aes_gcm"],
    }
    if role == "server":
        device_fields["broadcast_ml_kem_public_key"] = _b64(_derive_kem_public(_BROADCAST_KEM_SECRET))
    device_cert = _signed_json(device_fields, brand_key)
    return DeviceMaterial(role, device_id, kem_secret, kem_public, brand_cert, device_cert)


def verify_device_certificate(
    device_cert: bytes,
    brand_cert: bytes,
    expected_role: str,
) -> Tuple[int, bytes, Dict[str, Any]]:
    root_public = _signing_key(_ROOT_SIGNING_SEED).public_key()
    brand = _verify_signed_json(brand_cert, root_public, "brand")
    brand_public = Ed25519PublicKey.from_public_bytes(_unb64(brand["brand_sign_public_key"]))
    device = _verify_signed_json(device_cert, brand_public, "device")
    if device.get("role") != expected_role:
        raise ProtocolError(f"certificate role mismatch: expected {expected_role}")
    try:
        device_id = int(str(device["device_id"]), 0)
        kem_public = _unb64(device["ml_kem_public_key"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolError("device certificate is missing required 6.4 fields") from exc
    if MODE_NAMES[MODE_AES_GCM] not in device.get("encryption_capability", []):
        raise ProtocolError("peer certificate does not advertise aes_gcm")
    if len(kem_public) != 32:
        raise ProtocolError("device certificate has an invalid ML-KEM public key")
    return device_id, kem_public, device


def derive_pq_content_keys(kemsk: bytes, kemsk_b: bytes, server_id: int, client_id: int) -> ContentKeys:
    if len(kemsk) != ML_KEM_SHARED_SECRET_BYTES or len(kemsk_b) != ML_KEM_SHARED_SECRET_BYTES:
        raise ProtocolError("KEM shared secrets must be 32 bytes")
    content = sm3(kemsk + int_to_bytes(server_id, 8))
    broadcast = sm3(kemsk_b + int_to_bytes(client_id, 8))
    return ContentKeys(
        ck=content[:16],
        civ=content[16:],
        bck=broadcast[:16],
        bciv=broadcast[16:],
    )


def compute_auth_key(server_id: int, client_id: int, kemsk: bytes) -> bytes:
    return sm3(int_to_bytes(server_id, 8) + int_to_bytes(client_id, 8) + kemsk)


def build_apdu_frame(slave_id: int, tag: bytes, payload: bytes = b"") -> bytes:
    return RtuFrame(slave_id, FUNCTION_SECURITY, APDU(tag, payload).encode()).encode()


def parse_apdu_frame(frame_data: bytes, expected_slave_id: Optional[int] = None) -> APDU:
    frame = RtuFrame.decode(frame_data)
    if expected_slave_id is not None and frame.slave_id != expected_slave_id:
        raise ProtocolError(f"unexpected slave id {frame.slave_id}, expected {expected_slave_id}")
    if frame.function != FUNCTION_SECURITY:
        raise ProtocolError(f"expected function code 0 security frame, got 0x{frame.function:02x}")
    return APDU.decode(frame.payload)


def build_encrypted_data_send(
    slave_id: int,
    context: PQSessionContext,
    modbus_pdu: bytes,
    broadcast: bool = False,
) -> bytes:
    if context.mode != MODE_AES_GCM:
        raise ProtocolError(f"unsupported content mode {context.mode}")
    mac, ciphertext = aes_gcm_encrypt(context.keys, context.send_counter, modbus_pdu, broadcast=broadcast)
    context.send_counter += 1
    return build_apdu_frame(slave_id, TAG_SS_DATA_SEND, mac + ciphertext)


def parse_encrypted_data_send(
    frame_data: bytes,
    context: PQSessionContext,
    expected_slave_id: int,
    broadcast: bool = False,
) -> bytes:
    apdu = parse_apdu_frame(frame_data, expected_slave_id=expected_slave_id)
    if apdu.tag != TAG_SS_DATA_SEND:
        raise ProtocolError(f"expected ss_data_send, got {apdu.tag.hex()}")
    if len(apdu.payload) < 16:
        raise ProtocolError("ss_data_send payload is missing MAC")
    mac = apdu.payload[:16]
    ciphertext = apdu.payload[16:]
    if context.mode != MODE_AES_GCM:
        raise ProtocolError(f"unsupported content mode {context.mode}")
    pdu = aes_gcm_decrypt(context.keys, context.recv_counter, mac, ciphertext, broadcast=broadcast)
    context.recv_counter += 1
    return pdu


def run_master_handshake(sock: socket.socket, slave_id: int, client_id: int) -> PQSessionContext:
    open_req = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if open_req.tag != TAG_SS_OPEN_REQ:
        raise ProtocolError(f"expected ss_open_req, got {open_req.tag.hex()}")
    if open_req.payload:
        raise ProtocolError("ss_open_req payload must be empty")
    send_record(sock, build_apdu_frame(slave_id, TAG_SS_OPEN_CNF, bytes([SYSTEM_ID_VERSION_1])))

    first_req = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if first_req.tag != TAG_SS_DATA_REQ:
        raise ProtocolError(f"expected ss_data_req, got {first_req.tag.hex()}")
    request = DataPayload.decode_req(first_req.payload)
    server_dev_cert = request.send.get(TYPE_SERVER_DEV_CERT)
    server_brand_cert = request.send.get(TYPE_SERVER_BRAND_CERT)
    if server_dev_cert is None or server_brand_cert is None:
        raise ProtocolError("slave did not send its server certificate chain")

    server_id, server_kem_public, server_cert = verify_device_certificate(
        server_dev_cert,
        server_brand_cert,
        expected_role="server",
    )
    try:
        broadcast_public = _unb64(server_cert["broadcast_ml_kem_public_key"])
    except (KeyError, ValueError) as exc:
        raise ProtocolError("server certificate is missing broadcast ML-KEM public key") from exc

    kem_c, kemsk = DemoMlKem768.encaps(server_kem_public, b"KEM_C")
    kem_bc, kemsk_b = DemoMlKem768.encaps(broadcast_public, b"KEM_BC")
    client_material = make_device_material("client", client_id)
    response = DataPayload(
        system_mask=SYSTEM_ID_VERSION_1,
        send={
            TYPE_KEM_C: kem_c,
            TYPE_KEM_BC: kem_bc,
            TYPE_MODE: bytes([MODE_AES_GCM]),
            TYPE_CLIENT_DEV_CERT: client_material.device_cert,
            TYPE_CLIENT_BRAND_CERT: client_material.brand_cert,
        },
    )
    send_record(sock, build_apdu_frame(slave_id, TAG_SS_DATA_CNF, response.encode_cnf()))

    auth_key = compute_auth_key(server_id, client_id, kemsk)
    akh_req = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if akh_req.tag != TAG_SS_DATA_REQ:
        raise ProtocolError(f"expected AKH ss_data_req, got {akh_req.tag.hex()}")
    akh_payload = DataPayload.decode_req(akh_req.payload)
    if TYPE_AKH not in akh_payload.request:
        raise ProtocolError("slave did not request AKH")
    send_record(
        sock,
        build_apdu_frame(
            slave_id,
            TAG_SS_DATA_CNF,
            DataPayload(SYSTEM_ID_VERSION_1, {TYPE_AKH: auth_key}).encode_cnf(),
        ),
    )

    return PQSessionContext(
        role="master",
        server_id=server_id,
        client_id=client_id,
        mode=MODE_AES_GCM,
        kemsk=kemsk,
        kemsk_b=kemsk_b,
        auth_key=auth_key,
        keys=derive_pq_content_keys(kemsk, kemsk_b, server_id, client_id),
    )


def run_slave_handshake(sock: socket.socket, slave_id: int, server_id: int) -> PQSessionContext:
    server_material = make_device_material("server", server_id)
    send_record(sock, build_apdu_frame(slave_id, TAG_SS_OPEN_REQ))

    open_cnf = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if open_cnf.tag != TAG_SS_OPEN_CNF:
        raise ProtocolError(f"expected ss_open_cnf, got {open_cnf.tag.hex()}")
    if len(open_cnf.payload) != 1 or not (open_cnf.payload[0] & SYSTEM_ID_VERSION_1):
        raise ProtocolError("peer does not support security system version 1")

    request = DataPayload(
        system_mask=SYSTEM_ID_VERSION_1,
        send={
            TYPE_SERVER_DEV_CERT: server_material.device_cert,
            TYPE_SERVER_BRAND_CERT: server_material.brand_cert,
        },
        request=(TYPE_KEM_C, TYPE_KEM_BC, TYPE_MODE, TYPE_CLIENT_DEV_CERT, TYPE_CLIENT_BRAND_CERT),
    )
    send_record(sock, build_apdu_frame(slave_id, TAG_SS_DATA_REQ, request.encode_req()))

    first_cnf = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if first_cnf.tag != TAG_SS_DATA_CNF:
        raise ProtocolError(f"expected ss_data_cnf, got {first_cnf.tag.hex()}")
    response = DataPayload.decode_cnf(first_cnf.payload)
    kem_c = response.send.get(TYPE_KEM_C)
    kem_bc = response.send.get(TYPE_KEM_BC)
    mode = response.send.get(TYPE_MODE)
    client_dev_cert = response.send.get(TYPE_CLIENT_DEV_CERT)
    client_brand_cert = response.send.get(TYPE_CLIENT_BRAND_CERT)
    if None in (kem_c, kem_bc, mode, client_dev_cert, client_brand_cert):
        raise ProtocolError("master response is missing KEM, mode, or certificate data")
    if len(mode) != 1 or mode[0] != MODE_AES_GCM:
        raise ProtocolError(f"unsupported content mode {mode.hex()}")

    client_id, _, _ = verify_device_certificate(
        client_dev_cert or b"",
        client_brand_cert or b"",
        expected_role="client",
    )
    kemsk = DemoMlKem768.decaps(server_material.kem_secret, kem_c or b"", b"KEM_C")
    kemsk_b = DemoMlKem768.decaps(_BROADCAST_KEM_SECRET, kem_bc or b"", b"KEM_BC")
    auth_key = compute_auth_key(server_id, client_id, kemsk)

    akh_request = DataPayload(system_mask=SYSTEM_ID_VERSION_1, send={}, request=(TYPE_AKH,))
    send_record(sock, build_apdu_frame(slave_id, TAG_SS_DATA_REQ, akh_request.encode_req()))

    final_cnf = parse_apdu_frame(recv_record(sock), expected_slave_id=slave_id)
    if final_cnf.tag != TAG_SS_DATA_CNF:
        raise ProtocolError(f"expected AKH ss_data_cnf, got {final_cnf.tag.hex()}")
    final_payload = DataPayload.decode_cnf(final_cnf.payload)
    akh = final_payload.send.get(TYPE_AKH)
    if akh is None or akh == bytes(ML_KEM_SHARED_SECRET_BYTES):
        raise ProtocolError("master returned an invalid AKH")
    if not hmac.compare_digest(akh, auth_key):
        raise ProtocolError("AKH verification failed")

    return PQSessionContext(
        role="slave",
        server_id=server_id,
        client_id=client_id,
        mode=mode[0],
        kemsk=kemsk,
        kemsk_b=kemsk_b,
        auth_key=auth_key,
        keys=derive_pq_content_keys(kemsk, kemsk_b, server_id, client_id),
    )


def endpoint_args(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=15020)
    parser.add_argument("--slave-id", type=parse_hex_or_int, default=1)
    return parser


__all__ = [
    "MODE_AES_GCM",
    "PQSessionContext",
    "ProtocolError",
    "build_encrypted_data_send",
    "compute_auth_key",
    "derive_pq_content_keys",
    "endpoint_args",
    "handle_modbus_pdu",
    "make_device_material",
    "parse_encrypted_data_send",
    "parse_register_response",
    "read_holding_registers_pdu",
    "recv_record",
    "run_master_handshake",
    "run_slave_handshake",
    "send_record",
    "verify_device_certificate",
]
