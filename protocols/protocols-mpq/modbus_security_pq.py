#!/usr/bin/env python3
"""6.4 post-quantum hybrid PKI Modbus serial-link security extension.

The protocol flow follows section 6.4 of the supplied technical requirement:

* ss_open_req / ss_open_cnf
* slave-initiated certificate-chain exchange
* KEM_C / KEM_BC / mode exchange
* AKH/AKM verification
* CK/CIV and BCK/BCIV derivation
* encrypted Modbus function-code+data transport through ss_data_send

This is a runnable reference endpoint. It uses pqcrypto's ML-KEM-768 and
ML-DSA-44 primitives for key encapsulation and certificate-chain signatures
while keeping the compact JSON certificate container used by this reference
implementation. Replace the built-in test trust anchor with real X.509/HSM or
device-secure-storage integration before production use.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hmac
import json
import socket
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_44


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
        #simualation using Socket
        #chunk = sock.recv(remaining)
        #read the hardware UART.
        chunk = readUART(remaining)        
        if not chunk:
            raise EOFError("socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_record(sock: socket.socket, frame: bytes) -> None:
    if len(frame) > 0xFFFF:
        raise ValueError("record too large")
    #simualation using Socket
    #sock.sendall(len(frame).to_bytes(2, "big") + frame)
    #write the hardware UART.
    writeUART(len(frame).to_bytes(2, "big") + frame)


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

ML_KEM_768_CIPHERTEXT_BYTES = ml_kem_768.CIPHERTEXT_SIZE
ML_KEM_SHARED_SECRET_BYTES = ml_kem_768.PLAINTEXT_SIZE
ML_KEM_768_PUBLIC_KEY_BYTES = ml_kem_768.PUBLIC_KEY_SIZE
ML_KEM_768_SECRET_KEY_BYTES = ml_kem_768.SECRET_KEY_SIZE
ML_DSA_44_PUBLIC_KEY_BYTES = ml_dsa_44.PUBLIC_KEY_SIZE
ML_DSA_44_SECRET_KEY_BYTES = ml_dsa_44.SECRET_KEY_SIZE


def _decode_b64_blob(data: str) -> bytes:
    return base64.b64decode("".join(data.split()).encode("ascii"), validate=True)


_ROOT_ML_DSA_44_PUBLIC = _decode_b64_blob("""
vY22AexTM7an2voI/fPPIr39erni/mqTp4FzAiZXig1pUSeAeV8RtssoTt2YckVFE+306NX3YGuk3HRE/9lF41BD
EiRyndZ+o6vdE3jvKp10A3bOSEISzzHcq45N06GrHBWZ24WxFq7/eGswl/8QF51oa5hhyUFDdKUqe2z/k5A5o3yW
kCEmeqUYaapNgxQaUxHLxUXSyHLikHvBkNexaFCOnH2h6Z6BYyGjgb3lnJrHxvRUiEkI2qpbIFmBah+q+uFycu7X
/DsSIwQhd59YlgQDv4XNLyqhLGQNG0lStmSgOrXWJpWvtFO5tHAD7lrPoJcTXNOtR2xHGmYImV5jpz3bbfyNhYC/
KSsVw9EExg2Vg3opGo1vLrTKvyBS/cr9Xbply1XZHEznqzxD6nnT1Fe1PRDp3Vezgqq6X6/l4oS24HwPULDiKguC
kTiRHYGYLIu/Km9HTLfRaAnKLX1csyZIPXVcJNWjRKeOr6Tk9cap9LQBBcK3stL31JzzPyQ6ipMZTFV8vAYBR2vS
6hP6OjvFnWhxoEdqWq+D/dkGGY1JUhz+lz567Ls71041FyZMt+Xgegf0pr19toNFe9QFCDUZzTJi4FAHwtwIKmMX
LkFXntE+xE989AkjVpFCEC+LhT/DF3FOqq9oetwtEhN3fpYTEhtb19cibV4zHzlJol+XfOKF0p8qQv/z4nBL5iKw
Mj6SH2De8AqWWge84pTHKMETwcacT9sgjlGQ7X81+mmh2rDSZyUdlHor6hZ2V1UnH1PAE/1adbviOUToBHmCU+Ln
5EGT8coeB3wH7sVcH/fhAUypOvq1vTuBaBX32USrvnDglf6b1bzX8dGAcPOSV0Md7T/HjjrVVE1RlGsonnfu9he+
dhsHmgmLkVeuXCmM1pMwpbuly/A47UTgu4nV5UkomA3RkD95nW1H2N0FnxN9A9YzG2djpOjukx13t1JR1TybN/SX
55baiaZyx3Y4oWQ/0oqukm3oqkhL7TdQ0WZa+z4nncT/ipl/6uQY6EFGiFlyKx7MOPhp22EjxMIyUIVaGpIKJ6BR
K3LvioT187wEkUg7wUPo197kGj2EC6uCnnly12Tsho1Izjaiiuk1GhSUbuSVv5VtWDfocbYUIsPOLbjeU1fdm8yZ
8tW6XyWno7x4GrIhELareEHcGWTloFvUjKPdVERz6VM1eOQH/8NiQVuLUdJyg0+XVxzoC3gr5bo0Z43nkjYeSP7W
tliDOSV/dRO5pIgkxa0HZB8prNbUBPOFFcw3HDumG38EQtgmS7jEqLxNG0F5ZM944sLtBUXrARGHI/760ElRQkCt
GekDByswdkBrd1z3A2hOwqTliRQizNlKIF26xnFLZSKfsjmRUdrifWtOUt/4NvIqZEw+F6WsglTKif01qoVgDw22
SzH5wFpaWEUM1MVmGSmBgD3jRh2un4VZf2+btMmhONsjr+kM6xv9kswwE2AW7WKkVxpNa2AivshcFVWSMp0nTOut
DQMNfkEA+28ctQWzQ1wcQj0W9X2MYZuh2+lxU/9WdrStq88H/zrqltXV+tw3OaCsrsnxuT2nodaOO9MaOabTJZOp
KTvpjhTA7/ddU63by+MxaxkzS8N4j47fBmap/qGDn2G1qiCTjKOvCLFBAjBJX3KYtuOt5kD/Mv4w9d1RGvhWIaLK
1a9L1p3L1cwYDa/qAFifLrr4vtjKvzVhbRsrqmvnFlowCPmfb6b05G7ekjTX+Qtupp7/ti82oU1v/Q==
""")
_ROOT_ML_DSA_44_SECRET = _decode_b64_blob("""
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
""")
_BRAND_ML_DSA_44_PUBLIC = _decode_b64_blob("""
bHI35oDTFEiAX92YQV4p2MGG3nRADmODOr5gcSQQsrSFbjXxeERVNuRB/m7RCM1ky807wOnkwPAXxkiaDj+RKquY
rnNwwd2eILexnjMoeIG+QlMYKSE2q1kQo0cthZ5eCyhssh3jL2ni7sBidRVHCS7vSetGRWGIleF0cneXzalcnxBR
1Du9R0CVyfd7T+MpsxBBA1M3p3GhYifWsTUwVnpQzSBKysA18d/x1uZ4DPtrJxKxxXPMqM609ZC2+U6SP0a4i19P
SCMQ2TdxcWpAf+ninmrzUsz7SkVs5aCgr9OfzM6+Ysujfbmi2u2uxzQQQhOC1D1x0UNCnWLdOU0kvrBHX1hZUC+3
hA1AwT2TWmmBleWn//LUXW/mbenMinqWwUQH40dJfPyVl+c6MRkmxeb6b9u9Qb60isVXzIHVzlfrZIXxD5xSqy4o
pY18DX2eb7/KYiCGW8J89OfcoCKxchE7qQlg6R09qiufkh07ljsEk5fs33j8IXptwA9NHbQGX4o5yrQLCyhGbqvg
f9Bny4vGg+qCX5A1UtdMtmL1k8U4bZSHx3czQfnqIC3Egdlcs0tMafSUziefRNPdj+VAWv7cExXE30TPgtC/tlNc
TJnA0LTb9t9mns1BTRj43ur2Mg++Rmk56w/NohwzcXbTG2swIgPEQ0FhyjCqnH10lfkMJ/SxXrrseAo7cgtQsxcL
+6ap1Z34l88dmDE9D5AJztuTtAWeQcIfRdzpb/GUMSIujyAO1wRxSzb2yyeNqCkbMVwdsON1A8LKCxYk/wkI76sz
xOrD8zNDMZdqmQE5wxu1QHCvjo6fNwlXqxcyz+FjchFtFyszGikBod02olO77Kda0OgDS5wVZTbapDqPQ8jqJg0J
0t59Lk32XOOnjdKZSUjBXyA4cWeDtEBUmSqg1AcUS8BpMkEPiH+T0dVdojzpbLhzGBAVNd7IPbb5+efWkyNrqkUu
2NDc2ENwVF8XT6vzwRS0cmh4o27LNNZN1vQclyo/ZGFH6Nk4Il7JSYNz8fgFTZ6s0zLTZ5KkEJfrriitg2Vn1XTt
Uehp6PphDHJUJf1kgvqR4MZTEQSEmNzLjX6CHcO5iYyWOzsO8J1I4dP3+xsRLLodH4c6GXaGWQRgNqqVSFMhVDli
bc83oe9aXAgNljR7hqX2OyI27+IDbbZ+4u+7QRU4YqzfOARFQdmuP1P6EfQYm2LRvaiRcqj7ll4SFQUvprezSwr7
XVmG9871Uw54riSd9ECAicLyzRLk1ztJc0sCIGixyenb1Ges+tRyKIbumFKiij0bTfDtS33i/MP9gly3K92du2lt
ulnyAU/Nig6dZ+DvJKABK03yadbHcg/TcsPjsn0DpCtK7LEIPhUG8ARPeVsofyEnESu8hQFKY73LkDe+F6P+rufr
nuzc7+R5S5ws0Li7UcNANAb7F6jUyoXcihL85I9TzeCIlW5ry7WbVh4dHO4IjqsRZ4feN3GO5dB561YKvKTSSYUt
vZ5Ag1l3neENDONr0AYWQ/H79JNSexpnZlMCi/yezI924cGBlJybmr394d9fSeGS9S4lUw8R61u9C/4pzP2bxJQY
dwb79AnKOPaZ9hrn/jT1x1WcbniyQZ7Lu6x+wsNOSUZTSOj89jN4HPQ40+woH+7YaO4BbcAHYdgAyF2GKw/bT4BN
lQ9ubzob6HtFZXsot6I60kQ2pQSd0/acqAEWi761Fmx3a18+IjQ53ydRmYtvToUstOgqyugCGd+N/Q==
""")
_BRAND_ML_DSA_44_SECRET = _decode_b64_blob("""
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
""")


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
    broadcast_kem_secret: bytes = b""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def _canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _validate_ml_dsa_secret_key(secret_key: bytes) -> None:
    if len(secret_key) != ML_DSA_44_SECRET_KEY_BYTES:
        raise ValueError("ML-DSA-44 secret key has an invalid length")


def _signed_json(fields: Dict[str, Any], secret_key: bytes) -> bytes:
    _validate_ml_dsa_secret_key(secret_key)
    body = dict(fields)
    body["signature"] = _b64(ml_dsa_44.sign(secret_key, _canonical_json(body)))
    return _canonical_json(body)


def _verify_signed_json(data: bytes, public_key: bytes, expected_kind: str) -> Dict[str, Any]:
    if len(public_key) != ML_DSA_44_PUBLIC_KEY_BYTES:
        raise ProtocolError("ML-DSA-44 public key has an invalid length")
    try:
        cert = json.loads(data.decode())
        signature = _unb64(cert.pop("signature"))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid certificate encoding") from exc
    if cert.get("kind") != expected_kind:
        raise ProtocolError(f"unexpected certificate kind {cert.get('kind')!r}")
    try:
        verified = ml_dsa_44.verify(public_key, _canonical_json(cert), signature)
    except Exception as exc:
        raise ProtocolError("certificate signature verification failed") from exc
    if not verified:
        raise ProtocolError("certificate signature verification failed")
    return cert


class MlKem768:
    """Small adapter around pqcrypto's ML-KEM-768 API."""

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        public_key, secret_key = ml_kem_768.generate_keypair()
        return public_key, secret_key

    @staticmethod
    def encaps(public_key: bytes, _label: bytes) -> Tuple[bytes, bytes]:
        if len(public_key) != ML_KEM_768_PUBLIC_KEY_BYTES:
            raise ProtocolError("ML-KEM-768 public key has an invalid length")
        return ml_kem_768.encrypt(public_key)

    @staticmethod
    def decaps(secret_key: bytes, ciphertext: bytes, _label: bytes) -> bytes:
        if len(secret_key) != ML_KEM_768_SECRET_KEY_BYTES:
            raise ProtocolError("ML-KEM-768 secret key has an invalid length")
        if len(ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
            raise ProtocolError(f"KEM ciphertext must be {ML_KEM_768_CIPHERTEXT_BYTES} bytes")
        try:
            return ml_kem_768.decrypt(secret_key, ciphertext)
        except Exception as exc:
            raise ProtocolError("ML-KEM-768 decapsulation failed") from exc


def make_device_material(role: str, device_id: int) -> DeviceMaterial:
    if role not in {"client", "server"}:
        raise ValueError("role must be client or server")
    if not 0 <= device_id <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("device_id must fit in 64 bits")

    root_key = _ROOT_ML_DSA_44_SECRET
    brand_key = _BRAND_ML_DSA_44_SECRET
    brand_public = _BRAND_ML_DSA_44_PUBLIC

    brand_cert = _signed_json(
        {
            "kind": "brand",
            "subject": "Demo Modbus 6.4 Brand",
            "issuer": "Demo ROT",
            "algorithm": "ML-DSA-44",
            "brand_sign_public_key": _b64(brand_public),
        },
        root_key,
    )

    kem_public, kem_secret = MlKem768.generate_keypair()
    broadcast_kem_secret = b""
    device_fields: Dict[str, Any] = {
        "kind": "device",
        "role": role,
        "issuer": "Demo Modbus 6.4 Brand",
        "device_id": f"0x{device_id:016x}",
        "algorithm": "ML-DSA-44",
        "ml_kem_public_key": _b64(kem_public),
        "encryption_capability": ["aes_gcm"],
    }
    if role == "server":
        broadcast_kem_public, broadcast_kem_secret = MlKem768.generate_keypair()
        device_fields["broadcast_ml_kem_public_key"] = _b64(broadcast_kem_public)
    device_cert = _signed_json(device_fields, brand_key)
    return DeviceMaterial(role, device_id, kem_secret, kem_public, brand_cert, device_cert, broadcast_kem_secret)


def verify_device_certificate(
    device_cert: bytes,
    brand_cert: bytes,
    expected_role: str,
) -> Tuple[int, bytes, Dict[str, Any]]:
    root_public = _ROOT_ML_DSA_44_PUBLIC
    brand = _verify_signed_json(brand_cert, root_public, "brand")
    brand_public = _unb64(brand["brand_sign_public_key"])
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
    if len(kem_public) != ML_KEM_768_PUBLIC_KEY_BYTES:
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

    kem_c, kemsk = MlKem768.encaps(server_kem_public, b"KEM_C")
    kem_bc, kemsk_b = MlKem768.encaps(broadcast_public, b"KEM_BC")
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
    kemsk = MlKem768.decaps(server_material.kem_secret, kem_c or b"", b"KEM_C")
    kemsk_b = MlKem768.decaps(server_material.broadcast_kem_secret, kem_bc or b"", b"KEM_BC")
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
