import socket
import threading
import unittest

from modbus_security_psk import (
    APDU,
    DataPayload,
    MODE_AES_GCM,
    SYSTEM_ID_VERSION_1,
    TAG_SS_SK_DATA_REQ,
    TYPE_MODE,
    TYPE_RH_RM,
    build_encrypted_data_send,
    parse_encrypted_data_send,
    parse_register_response,
    read_holding_registers_pdu,
    recv_record,
    run_master_handshake,
    run_slave_handshake,
    send_record,
    handle_modbus_pdu,
    sm3,
)
from web_frontend import read_with_embedded_slave


class ProtocolTests(unittest.TestCase):
    def test_sm3_known_vector(self):
        self.assertEqual(
            sm3(b"abc").hex(),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        )

    def test_apdu_and_data_payload_roundtrip(self):
        payload = DataPayload(
            system_mask=SYSTEM_ID_VERSION_1,
            send={TYPE_RH_RM: b"x" * 64, TYPE_MODE: bytes([MODE_AES_GCM])},
            request=(TYPE_RH_RM,),
        )
        apdu = APDU(TAG_SS_SK_DATA_REQ, payload.encode_req())
        decoded_apdu = APDU.decode(apdu.encode())
        self.assertEqual(decoded_apdu.tag, TAG_SS_SK_DATA_REQ)
        decoded_payload = DataPayload.decode_req(decoded_apdu.payload)
        self.assertEqual(decoded_payload.send[TYPE_RH_RM], b"x" * 64)
        self.assertEqual(decoded_payload.send[TYPE_MODE], bytes([MODE_AES_GCM]))
        self.assertEqual(decoded_payload.request, (TYPE_RH_RM,))

    def test_master_slave_handshake_and_encrypted_read(self):
        master_sock, slave_sock = socket.socketpair()
        password = b"shared-secret"
        slave_id = 1
        server_id = 0x1001000100000001
        client_id = 0x2001000100000001
        result = {}

        def slave():
            context = run_slave_handshake(slave_sock, slave_id, password, server_id)
            frame = recv_record(slave_sock)
            request = parse_encrypted_data_send(frame, context, expected_slave_id=slave_id)
            response = handle_modbus_pdu(request, [10, 20, 30, 40])
            send_record(slave_sock, build_encrypted_data_send(slave_id, context, response))
            result["slave_ck"] = context.keys.ck

        thread = threading.Thread(target=slave)
        thread.start()
        try:
            context = run_master_handshake(master_sock, slave_id, password, client_id)
            self.assertEqual(context.server_id, server_id)
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

    def test_web_frontend_embedded_slave_read(self):
        result = read_with_embedded_slave(
            {
                "slave_host": "127.0.0.1",
                "slave_port": "0",
                "master_host": "127.0.0.1",
                "slave_id": "1",
                "password": "shared-secret",
                "server_id": "0x1001000100000001",
                "client_id": "0x2001000100000001",
                "start": "1",
                "quantity": "3",
                "registers": "10,20,30,40",
            }
        )

        self.assertEqual([row["value"] for row in result["registers"]], [20, 30, 40])
        self.assertEqual(result["master"]["mode"], "aes_gcm")


if __name__ == "__main__":
    unittest.main()
