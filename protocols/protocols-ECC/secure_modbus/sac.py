from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from .crypto import aes_cbc_decrypt, aes_cbc_encrypt, hmac16
from .frame import ProtocolError


@dataclass
class SacChannel:
    sak: bytes
    sek: bytes
    send_counter: int = 1
    recv_counter: int = 1

    def pack(self, payload: bytes, encrypt: bool = True) -> bytes:
        counter = self.send_counter
        self.send_counter += 1
        payload_flag = 1 if encrypt else 0
        header = bytes(
            [
                *counter.to_bytes(4, "big"),
                payload_flag,
                0,
                *len(payload).to_bytes(2, "big"),
            ]
        )
        auth = hmac16(self.sak, bytes([len(header)]), counter.to_bytes(4, "big"), header, payload)
        if encrypt:
            body = aes_cbc_encrypt(self.sek, payload + auth)
        else:
            body = payload + auth
        return header + body

    def unpack(self, message: bytes) -> bytes:
        if len(message) < 8 + 16:
            raise ProtocolError("SAC message is too short")
        header = message[:8]
        counter = int.from_bytes(header[:4], "big")
        if counter != self.recv_counter:
            raise ProtocolError(f"SAC message counter mismatch: got {counter}, want {self.recv_counter}")
        self.recv_counter += 1
        payload_flag = header[4]
        length = int.from_bytes(header[6:8], "big")
        body = message[8:]
        if payload_flag == 1:
            payload_auth = aes_cbc_decrypt(self.sek, body)
        elif payload_flag == 0:
            payload_auth = body
        else:
            raise ProtocolError("unsupported SAC payload encryption flag")
        if len(payload_auth) != length + 16:
            raise ProtocolError("SAC payload length mismatch")
        payload, auth = payload_auth[:length], payload_auth[length:]
        expected = hmac16(self.sak, bytes([len(header)]), counter.to_bytes(4, "big"), header, payload)
        if auth != expected:
            raise InvalidSignature("SAC authentication failed")
        return payload
