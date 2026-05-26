from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import ASSOCIATED_DATA, SAC_SIV
from .frame import ProtocolError


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def digest(*parts: bytes, size: int = 32) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    for part in parts:
        h.update(part)
    value = h.finalize()
    if size <= len(value):
        return value[:size]
    return hkdf(value, b"", b"digest-expand", size)


def hkdf(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt or None, info=info).derive(secret)


def public_key_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def load_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def private_key_to_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def private_key_from_pem(data: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("expected EC private key")
    return key


def canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_json(key: ec.EllipticCurvePrivateKey, data: dict[str, Any]) -> str:
    return b64e(key.sign(canonical_json(data), ec.ECDSA(hashes.SHA256())))


def verify_json(public_key: ec.EllipticCurvePublicKey, data: dict[str, Any], signature_b64: str) -> None:
    public_key.verify(b64d(signature_b64), canonical_json(data), ec.ECDSA(hashes.SHA256()))


def make_certificate(
    subject_id: str,
    subject_public_key: ec.EllipticCurvePublicKey,
    issuer_id: str,
    issuer_key: ec.EllipticCurvePrivateKey,
    cert_type: str,
) -> dict[str, Any]:
    body = {
        "version": 1,
        "type": cert_type,
        "subject_id": subject_id,
        "issuer_id": issuer_id,
        "curve": "secp256r1",
        "public_key": b64e(public_key_bytes(subject_public_key)),
    }
    return {"body": body, "signature": sign_json(issuer_key, body)}


def cert_to_bytes(cert: dict[str, Any]) -> bytes:
    return canonical_json(cert)


def cert_from_bytes(data: bytes) -> dict[str, Any]:
    return json.loads(data.decode("utf-8"))


def cert_public_key(cert: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    return load_public_key(b64d(cert["body"]["public_key"]))


@dataclass
class DeviceIdentity:
    role: str
    device_id: bytes
    device_key: ec.EllipticCurvePrivateKey
    device_cert: dict[str, Any]
    brand_cert: dict[str, Any]
    root_cert: dict[str, Any]

    @property
    def device_id_hex(self) -> str:
        return self.device_id.hex()

    def device_cert_bytes(self) -> bytes:
        return cert_to_bytes(self.device_cert)

    def brand_cert_bytes(self) -> bytes:
        return cert_to_bytes(self.brand_cert)

    def verify_peer_chain(self, brand_data: bytes, device_data: bytes, expected_type: str) -> bytes:
        brand = cert_from_bytes(brand_data)
        device = cert_from_bytes(device_data)
        root_public = cert_public_key(self.root_cert)
        try:
            verify_json(root_public, brand["body"], brand["signature"])
            verify_json(cert_public_key(brand), device["body"], device["signature"])
        except InvalidSignature as exc:
            raise ProtocolError("certificate chain signature verification failed") from exc
        if brand["body"]["issuer_id"] != self.root_cert["body"]["subject_id"]:
            raise ProtocolError("brand certificate issuer does not match root")
        if device["body"]["issuer_id"] != brand["body"]["subject_id"]:
            raise ProtocolError("device certificate issuer does not match brand")
        if device["body"]["type"] != expected_type:
            raise ProtocolError(f"unexpected peer certificate type {device['body']['type']}")
        subject = device["body"]["subject_id"]
        peer_id = bytes.fromhex(subject)
        if len(peer_id) != 8:
            raise ProtocolError("peer device id must be 64 bits")
        return peer_id


def load_identity(pki_dir: Path, role: str) -> DeviceIdentity:
    role_dir = pki_dir / role
    with (role_dir / "private_key.pem").open("rb") as f:
        key = private_key_from_pem(f.read())
    with (role_dir / "device_cert.json").open("rb") as f:
        device_cert = json.load(f)
    with (role_dir / "brand_cert.json").open("rb") as f:
        brand_cert = json.load(f)
    with (pki_dir / "root_cert.json").open("rb") as f:
        root_cert = json.load(f)
    device_id = bytes.fromhex(device_cert["body"]["subject_id"])
    return DeviceIdentity(role, device_id, key, device_cert, brand_cert, root_cert)


def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(SAC_SIV)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(SAC_SIV)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def hmac16(key: bytes, *parts: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    for part in parts:
        h.update(part)
    return h.finalize()[:16]


def derive_dhsk(shared_secret: bytes, client_id: bytes, server_id: bytes) -> bytes:
    return hkdf(shared_secret, client_id + server_id, b"modbus-6.2-dhsk", 64)


def derive_auth_key(dhsk: bytes, client_id: bytes, server_id: bytes) -> bytes:
    return digest(server_id, client_id, dhsk, size=32)


def derive_sac_keys(dhsk: bytes, auth_key: bytes, ns_h: bytes, ns_m: bytes) -> tuple[bytes, bytes]:
    seed = digest(dhsk, auth_key, ns_h, ns_m, size=32)
    return seed[:16], seed[16:]


def derive_content_keys(kp: bytes, server_id: bytes, kp_client: bytes, client_id: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    unicast = digest(kp, server_id, size=32)
    broadcast = digest(kp_client, client_id, size=32)
    return unicast[:16], unicast[16:], broadcast[:16], broadcast[16:]


def encrypt_content(ck: bytes, civ: bytes, pdu: bytes, counter: int, direction: int) -> bytes:
    nonce = bytearray(civ[:12])
    nonce[0] ^= (direction & 0x01) << 7
    counter_bytes = counter.to_bytes(4, "big")
    for index, byte in enumerate(counter_bytes):
        nonce[8 + index] ^= byte
    encrypted = AESGCM(ck).encrypt(bytes(nonce), pdu, digest(ASSOCIATED_DATA, size=16))
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    return tag + counter_bytes + ciphertext


def decrypt_content(ck: bytes, civ: bytes, data: bytes, direction: int) -> tuple[bytes, int]:
    if len(data) < 20:
        raise ProtocolError("encrypted content payload is too short")
    tag, counter_bytes, ciphertext = data[:16], data[16:20], data[20:]
    nonce = bytearray(civ[:12])
    nonce[0] ^= (direction & 0x01) << 7
    for index, byte in enumerate(counter_bytes):
        nonce[8 + index] ^= byte
    pdu = AESGCM(ck).decrypt(bytes(nonce), ciphertext + tag, digest(ASSOCIATED_DATA, size=16))
    return pdu, int.from_bytes(counter_bytes, "big")


def random_bytes(length: int) -> bytes:
    return os.urandom(length)
