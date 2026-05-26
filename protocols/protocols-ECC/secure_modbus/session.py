from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from .constants import (
    APDU_DATA_CNF,
    APDU_DATA_REQ,
    APDU_DATA_SEND,
    APDU_OPEN_CNF,
    APDU_OPEN_REQ,
    APDU_SAC_DATA_CNF,
    APDU_SAC_DATA_REQ,
    APDU_SAC_SYNC_CNF,
    APDU_SAC_SYNC_REQ,
    APDU_SYNC_CNF,
    APDU_SYNC_REQ,
    DT_AKH,
    DT_CLIENT_BRAND_CERT,
    DT_CLIENT_DEV_CERT,
    DT_CLIENT_ID,
    DT_DHPM,
    DT_DHPH,
    DT_KP,
    DT_MODE,
    DT_NS_H,
    DT_NS_M,
    DT_RH,
    DT_RM,
    DT_SERVER_BRAND_CERT,
    DT_SERVER_DEV_CERT,
    DT_SERVER_ID,
    DT_STATUS,
    MODE_AES_GCM,
    STATUS_OK,
    SYSTEM_ID_V1,
)
from .crypto import (
    DeviceIdentity,
    decrypt_content,
    derive_auth_key,
    derive_content_keys,
    derive_dhsk,
    derive_sac_keys,
    digest,
    encrypt_content,
    load_public_key,
    public_key_bytes,
    random_bytes,
)
from .frame import ProtocolError, recv_secure_apdu, send_secure_apdu
from .sac import SacChannel
from .tlv import decode_data_message, encode_data_message


@dataclass
class SecureSession:
    sock: socket.socket
    address: int
    identity: DeviceIdentity
    peer_id: bytes | None = None
    dhsk: bytes | None = None
    auth_key: bytes | None = None
    sac: SacChannel | None = None
    ck: bytes | None = None
    civ: bytes | None = None
    bck: bytes | None = None
    bciv: bytes | None = None
    tx_content_counter: int = 1

    def send(self, tag: int, payload: bytes = b"") -> None:
        send_secure_apdu(self.sock, self.address, tag, payload)

    def recv(self, expected_tag: int) -> bytes:
        _, tag, payload = recv_secure_apdu(self.sock, self.address)
        if tag != expected_tag:
            raise ProtocolError(f"unexpected APDU tag 0x{tag:02x}, want 0x{expected_tag:02x}")
        return payload

    def send_sac(self, tag: int, payload: bytes) -> None:
        if self.sac is None:
            raise ProtocolError("SAC channel is not initialized")
        self.send(tag, self.sac.pack(payload, encrypt=True))

    def recv_sac(self, expected_tag: int) -> bytes:
        if self.sac is None:
            raise ProtocolError("SAC channel is not initialized")
        return self.sac.unpack(self.recv(expected_tag))

    def send_encrypted_pdu(self, pdu: bytes) -> None:
        if self.ck is None or self.civ is None:
            raise ProtocolError("content key is not initialized")
        direction = 0 if self.identity.role == "client" else 1
        payload = encrypt_content(self.ck, self.civ, pdu, self.tx_content_counter, direction)
        self.tx_content_counter += 1
        self.send(APDU_DATA_SEND, payload)

    def recv_encrypted_pdu(self) -> bytes:
        if self.ck is None or self.civ is None:
            raise ProtocolError("content key is not initialized")
        payload = self.recv(APDU_DATA_SEND)
        peer_direction = 1 if self.identity.role == "client" else 0
        pdu, _counter = decrypt_content(self.ck, self.civ, payload, peer_direction)
        return pdu

    def save_context(self, path: Path) -> None:
        if self.peer_id is None or self.dhsk is None or self.auth_key is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "peer_id": self.peer_id.hex(),
                    "dhsk": self.dhsk.hex(),
                    "auth_key": self.auth_key.hex(),
                    "mode": MODE_AES_GCM,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def load_context(self, path: Path) -> bool:
        if not path.exists():
            return False
        data = json.loads(path.read_text(encoding="utf-8"))
        self.peer_id = bytes.fromhex(data["peer_id"])
        self.dhsk = bytes.fromhex(data["dhsk"])
        self.auth_key = bytes.fromhex(data["auth_key"])
        return True


def client_authenticate(session: SecureSession, context_path: Path) -> None:
    session.recv(APDU_OPEN_REQ)
    session.send(APDU_OPEN_CNF, bytes([SYSTEM_ID_V1]))

    body = session.recv(APDU_DATA_REQ)
    request = decode_data_message(body)
    if DT_AKH in request.requests and DT_SERVER_ID in request.values and session.load_context(context_path):
        if request.values[DT_SERVER_ID] == session.peer_id:
            session.send(APDU_DATA_CNF, encode_data_message({DT_AKH: session.auth_key or bytes(32)}))
            return
        session.send(APDU_DATA_CNF, encode_data_message({DT_AKH: bytes(32)}))

    if DT_SERVER_DEV_CERT not in request.values or DT_SERVER_BRAND_CERT not in request.values:
        raise ProtocolError("server did not provide certificate chain")
    server_id = session.identity.verify_peer_chain(
        request.values[DT_SERVER_BRAND_CERT],
        request.values[DT_SERVER_DEV_CERT],
        expected_type="server",
    )
    session.peer_id = server_id

    ephemeral = ec.generate_private_key(ec.SECP256R1())
    dhph = public_key_bytes(ephemeral.public_key())
    session.send(
        APDU_DATA_CNF,
        encode_data_message(
            {
                DT_DHPH: dhph,
                DT_CLIENT_DEV_CERT: session.identity.device_cert_bytes(),
                DT_CLIENT_BRAND_CERT: session.identity.brand_cert_bytes(),
            }
        ),
    )

    response = decode_data_message(session.recv(APDU_DATA_REQ))
    dhpm = response.values[DT_DHPM]
    rm = response.values[DT_RM]
    shared = ephemeral.exchange(ec.ECDH(), load_public_key(dhpm))
    session.dhsk = derive_dhsk(shared, session.identity.device_id, server_id)
    expected_rm = digest(dhph, dhpm, session.dhsk, server_id)
    if rm != expected_rm:
        raise ProtocolError("RM verification failed")
    rh = digest(dhpm, dhph, session.dhsk, session.identity.device_id)
    session.auth_key = derive_auth_key(session.dhsk, session.identity.device_id, server_id)
    session.send(APDU_DATA_CNF, encode_data_message({DT_RH: rh}))

    request_akh = decode_data_message(session.recv(APDU_DATA_REQ))
    if DT_AKH not in request_akh.requests:
        raise ProtocolError("server did not request AKH")
    session.send(APDU_DATA_CNF, encode_data_message({DT_AKH: session.auth_key}))
    session.save_context(context_path)


def server_authenticate(session: SecureSession, context_path: Path) -> None:
    session.send(APDU_OPEN_REQ)
    open_cnf = session.recv(APDU_OPEN_CNF)
    if not open_cnf or not (open_cnf[0] & SYSTEM_ID_V1):
        raise ProtocolError("client does not support security system id version 1")

    if session.load_context(context_path):
        session.send(
            APDU_DATA_REQ,
            encode_data_message(
                {DT_SERVER_ID: session.identity.device_id},
                requests=[DT_AKH],
            ),
        )
        response = decode_data_message(session.recv(APDU_DATA_CNF))
        if response.values.get(DT_AKH) == session.auth_key:
            return

    session.send(
        APDU_DATA_REQ,
        encode_data_message(
            {
                DT_SERVER_DEV_CERT: session.identity.device_cert_bytes(),
                DT_SERVER_BRAND_CERT: session.identity.brand_cert_bytes(),
            },
            requests=[DT_DHPH, DT_CLIENT_DEV_CERT, DT_CLIENT_BRAND_CERT],
        ),
    )
    client_msg = decode_data_message(session.recv(APDU_DATA_CNF))
    client_id = session.identity.verify_peer_chain(
        client_msg.values[DT_CLIENT_BRAND_CERT],
        client_msg.values[DT_CLIENT_DEV_CERT],
        expected_type="client",
    )
    session.peer_id = client_id
    dhph = client_msg.values[DT_DHPH]

    ephemeral = ec.generate_private_key(ec.SECP256R1())
    dhpm = public_key_bytes(ephemeral.public_key())
    shared = ephemeral.exchange(ec.ECDH(), load_public_key(dhph))
    session.dhsk = derive_dhsk(shared, client_id, session.identity.device_id)
    rm = digest(dhph, dhpm, session.dhsk, session.identity.device_id)
    session.send(APDU_DATA_REQ, encode_data_message({DT_DHPM: dhpm, DT_RM: rm}, requests=[DT_STATUS]))

    client_rh = decode_data_message(session.recv(APDU_DATA_CNF))
    rh = client_rh.values[DT_RH]
    expected_rh = digest(dhpm, dhph, session.dhsk, client_id)
    if rh != expected_rh:
        raise ProtocolError("RH verification failed")
    session.auth_key = derive_auth_key(session.dhsk, client_id, session.identity.device_id)

    session.send(APDU_DATA_REQ, encode_data_message({}, requests=[DT_AKH]))
    akh_msg = decode_data_message(session.recv(APDU_DATA_CNF))
    if akh_msg.values.get(DT_AKH) != session.auth_key:
        raise ProtocolError("AKH verification failed")
    session.save_context(context_path)


def client_init_sac(session: SecureSession) -> None:
    msg = decode_data_message(session.recv(APDU_DATA_REQ))
    if msg.values.get(DT_SERVER_ID) != session.peer_id:
        raise ProtocolError("SAC init SERVER_ID mismatch")
    ns_m = msg.values[DT_NS_M]
    ns_h = random_bytes(8)
    session.send(APDU_DATA_CNF, encode_data_message({DT_CLIENT_ID: session.identity.device_id, DT_NS_H: ns_h}))
    sak, sek = derive_sac_keys(session.dhsk or b"", session.auth_key or b"", ns_h, ns_m)
    session.sac = SacChannel(sak=sak, sek=sek)
    session.recv(APDU_SYNC_REQ)
    session.send(APDU_SYNC_CNF, bytes([STATUS_OK]))


def server_init_sac(session: SecureSession) -> None:
    ns_m = random_bytes(8)
    session.send(
        APDU_DATA_REQ,
        encode_data_message(
            {DT_SERVER_ID: session.identity.device_id, DT_NS_M: ns_m},
            requests=[DT_CLIENT_ID, DT_NS_H],
        ),
    )
    msg = decode_data_message(session.recv(APDU_DATA_CNF))
    if msg.values.get(DT_CLIENT_ID) != session.peer_id:
        raise ProtocolError("SAC init CLIENT_ID mismatch")
    ns_h = msg.values[DT_NS_H]
    sak, sek = derive_sac_keys(session.dhsk or b"", session.auth_key or b"", ns_h, ns_m)
    session.sac = SacChannel(sak=sak, sek=sek)
    session.send(APDU_SYNC_REQ)
    status = session.recv(APDU_SYNC_CNF)
    if status != bytes([STATUS_OK]):
        raise ProtocolError("client rejected SAC sync")


def client_update_content_key(session: SecureSession) -> None:
    msg = decode_data_message(session.recv_sac(APDU_SAC_DATA_REQ))
    if msg.values.get(DT_SERVER_ID) != session.peer_id:
        raise ProtocolError("CK update SERVER_ID mismatch")
    kp = msg.values[DT_KP]
    nonce = random_bytes(32)
    kp_client = digest(nonce)
    session.ck, session.civ, session.bck, session.bciv = derive_content_keys(
        kp, session.peer_id or b"", kp_client, session.identity.device_id
    )
    session.send_sac(
        APDU_SAC_DATA_CNF,
        encode_data_message({DT_CLIENT_ID: session.identity.device_id, DT_KP: kp_client, DT_STATUS: bytes([STATUS_OK])}),
    )
    session.recv_sac(APDU_SAC_SYNC_REQ)
    session.send_sac(APDU_SAC_SYNC_CNF, bytes([STATUS_OK]))


def server_update_content_key(session: SecureSession) -> None:
    nonce = random_bytes(32)
    kp = digest(nonce)
    session.send_sac(
        APDU_SAC_DATA_REQ,
        encode_data_message(
            {DT_SERVER_ID: session.identity.device_id, DT_KP: kp},
            requests=[DT_CLIENT_ID, DT_STATUS],
        ),
    )
    msg = decode_data_message(session.recv_sac(APDU_SAC_DATA_CNF))
    if msg.values.get(DT_CLIENT_ID) != session.peer_id:
        raise ProtocolError("CK update CLIENT_ID mismatch")
    if msg.values.get(DT_STATUS) != bytes([STATUS_OK]):
        raise ProtocolError("client rejected CK update")
    kp_client = msg.values[DT_KP]
    session.ck, session.civ, session.bck, session.bciv = derive_content_keys(
        kp, session.identity.device_id, kp_client, session.peer_id or b""
    )
    session.send_sac(APDU_SAC_SYNC_REQ, b"")
    status = session.recv_sac(APDU_SAC_SYNC_CNF)
    if status != bytes([STATUS_OK]):
        raise ProtocolError("client rejected CK sync")


def client_handshake(session: SecureSession, context_path: Path) -> None:
    client_authenticate(session, context_path)
    client_init_sac(session)
    client_update_content_key(session)


def server_handshake(session: SecureSession, context_path: Path) -> None:
    server_authenticate(session, context_path)
    server_init_sac(session)
    server_update_content_key(session)
