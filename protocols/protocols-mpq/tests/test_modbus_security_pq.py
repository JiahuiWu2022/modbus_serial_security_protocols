import socket
import threading
import unittest

from modbus_security_pq import (
    APDU,
    DataPayload,
    MODE_AES_GCM,
    SYSTEM_ID_VERSION_1,
    TAG_SS_DATA_REQ,
    TYPE_KEM_C,
    TYPE_MODE,
    build_encrypted_data_send,
    compute_auth_key,
    derive_pq_content_keys,
    handle_modbus_pdu,
    make_device_material,
    parse_encrypted_data_send,
    parse_register_response,
    read_holding_registers_pdu,
    recv_record,
    run_master_handshake,
    run_slave_handshake,
    send_record,
    sm3,
    verify_device_certificate,
)


class PostQuantumProtocolTests(unittest.TestCase):
    def test_sm3_known_vector(self):
        self.assertEqual(
            sm3(b"abc").hex(),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        )

    def test_apdu_and_data_payload_roundtrip(self):
        payload = DataPayload(
            system_mask=SYSTEM_ID_VERSION_1,
            send={TYPE_KEM_C: b"x" * 1088, TYPE_MODE: bytes([MODE_AES_GCM])},
            request=(TYPE_KEM_C,),
        )
        decoded_apdu = APDU.decode(APDU(TAG_SS_DATA_REQ, payload.encode_req()).encode())
        decoded_payload = DataPayload.decode_req(decoded_apdu.payload)

        self.assertEqual(decoded_apdu.tag, TAG_SS_DATA_REQ)
        self.assertEqual(decoded_payload.send[TYPE_KEM_C], b"x" * 1088)
        self.assertEqual(decoded_payload.send[TYPE_MODE], bytes([MODE_AES_GCM]))
        self.assertEqual(decoded_payload.request, (TYPE_KEM_C,))

    def test_demo_certificate_chain_verifies_device_identity(self):
        material = make_device_material("server", 0x1001000100000001)
        device_id, kem_public, cert = verify_device_certificate(
            material.device_cert,
            material.brand_cert,
            expected_role="server",
        )

        self.assertEqual(device_id, 0x1001000100000001)
        self.assertEqual(kem_public, material.kem_public)
        self.assertIn("broadcast_ml_kem_public_key", cert)

    def test_pq_key_derivation_matches_document_formula(self):
        kemsk = bytes.fromhex("11" * 32)
        kemsk_b = bytes.fromhex("22" * 32)
        server_id = 0x1001000100000001
        client_id = 0x2001000100000001

        keys = derive_pq_content_keys(kemsk, kemsk_b, server_id, client_id)
        auth_key = compute_auth_key(server_id, client_id, kemsk)

        self.assertEqual(len(keys.ck), 16)
        self.assertEqual(len(keys.civ), 16)
        self.assertEqual(len(keys.bck), 16)
        self.assertEqual(len(keys.bciv), 16)
        self.assertEqual(len(auth_key), 32)

    def test_master_slave_handshake_and_encrypted_read(self):
        master_sock, slave_sock = socket.socketpair()
        slave_id = 1
        server_id = 0x1001000100000001
        client_id = 0x2001000100000001
        result = {}

        def slave():
            context = run_slave_handshake(slave_sock, slave_id, server_id)
            frame = recv_record(slave_sock)
            request = parse_encrypted_data_send(frame, context, expected_slave_id=slave_id)
            response = handle_modbus_pdu(request, [10, 20, 30, 40])
            send_record(slave_sock, build_encrypted_data_send(slave_id, context, response))
            result["slave_ck"] = context.keys.ck
            result["slave_bck"] = context.keys.bck
            result["mode"] = context.mode

        thread = threading.Thread(target=slave)
        thread.start()
        try:
            context = run_master_handshake(master_sock, slave_id, client_id)
            self.assertEqual(context.server_id, server_id)
            self.assertEqual(context.mode, MODE_AES_GCM)
            send_record(
                master_sock,
                build_encrypted_data_send(slave_id, context, read_holding_registers_pdu(1, 2)),
            )
            response = parse_encrypted_data_send(
                recv_record(master_sock),
                context,
                expected_slave_id=slave_id,
            )
            self.assertEqual(parse_register_response(response), [20, 30])
        finally:
            master_sock.close()
            slave_sock.close()
            thread.join(timeout=5)

        self.assertEqual(result["slave_ck"], context.keys.ck)
        self.assertEqual(result["slave_bck"], context.keys.bck)
        self.assertEqual(result["mode"], MODE_AES_GCM)


if __name__ == "__main__":
    unittest.main()
