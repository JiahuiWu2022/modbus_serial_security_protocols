# Reference Implementation of Modbus Serial-Link Security Extension based on the "post-quantum hybrid-signature PKI public-key certificate" profile 

This project implements reference master and slave endpoints for the "post-quantum hybrid-signature PKI public-key certificate" profile. It also provides a single-page Web UI.

The current module uses ML-KEM-768 from `pqcrypto` for `KEM_C` and `KEM_BC` encapsulation and decapsulation, and ML-DSA-44 for root, brand, and device certificate-chain signature verification. The certificate container is still JSON for easier demonstration and testing. The built-in root and brand test keys are suitable only for local interoperability tests; production deployments must replace them with compliant X.509, HSM, or device-secure-storage implementations.

## Note:

If hardware UART interface is used in `modbus_security_pq.py`, the socket initialized here is only a placeholder and is not used for data transfer. Every frame is read from and sent through UART.

## Implemented Features

- `ss_open_req` / `ss_open_cnf`
- `ss_data_req` / `ss_data_cnf`
- Security APDU transport over RTU function code `0x00`
- Slave-initiated certificate-chain exchange
- `KEM_C` / `KEM_BC` / `mode` parameter exchange
- `AKH` / `AKM` authentication-key verification
- `KEMSK`, `KEMSK_B`, `CK/CIV`, and `BCK/BCIV` derivation
- `ss_data_send` with AES-GCM content encryption
- Example Modbus `0x03` read-holding-registers operation
- Single-page Web UI for parameter validation, startup-command generation, read views, and the Section 6.4 message sequence

## Project Layout

```text
.
|-- master_server.py              # Section 6.4 master command-line endpoint
|-- slave_server.py               # Section 6.4 slave command-line endpoint
|-- modbus_security_pq.py         # Section 6.4 protocol encoding/decoding, certificate/KEM demo, handshake, and encryption/decryption
|-- web_frontend.py               # Static server for the single-page Web UI
|-- web/
|   `-- index.html                # Section 6.4 single-page UI with embedded CSS/JS
|-- tests/
|   `-- test_modbus_security_pq.py
|-- requirements.txt
`-- <technical requirements document>.docx
```

## Requirements

- Python 3.10 or later
- Ability to create local TCP/socket connections
- Python dependency: `cryptography>=42`

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Command-Line Startup

Start the Section 6.4 slave first:

```bash
python3 slave_server.py --host 127.0.0.1 --port 15020
```

In a second terminal, start the master and read holding registers:

```bash
python3 master_server.py --host 127.0.0.1 --port 15020 --start 0 --quantity 4
```

Example one-shot slave:

```bash
python3 slave_server.py --host 127.0.0.1 --port 15020 --once
```

## Web UI

Start the single-page Web UI:

```bash
python3 web_frontend.py --host 127.0.0.1 --port 8080
```

Open:

```text
http://127.0.0.1:8080
```

The page can configure master and slave parameters, generate startup commands, validate the register-read range, and display the Section 6.4 handshake message sequence.

## Options

Both `master_server.py` and `slave_server.py` support:

| Option | Default | Description |
| --- | --- | --- |
| `--host` | `127.0.0.1` | TCP listen or connection address. |
| `--port` | `15020` | TCP listen or connection port. |
| `--slave-id` | `1` | Modbus slave address. Valid range: `1..247`. Decimal and `0x` hexadecimal values are supported. |

Additional master options:

| Option | Default | Description |
| --- | --- | --- |
| `--client-id` | `0x2001000100000001` | Master client ID. Decimal and `0x` hexadecimal values are supported. |
| `--start` | `0` | Starting holding-register address. |
| `--quantity` | `4` | Number of registers to read. Valid range: `1..125`. |

Additional slave options:

| Option | Default | Description |
| --- | --- | --- |
| `--server-id` | `0x1001000100000001` | Slave server ID. Decimal and `0x` hexadecimal values are supported. |
| `--registers` | `64` | Number of example holding registers. Register values are generated as `(index + 1) * 10`. |
| `--once` | Disabled | Exit after handling one master connection. |

## Tests

Run the unit tests:

```bash
python3 -m unittest discover -s tests
```

The tests cover:

- SM3 known-answer vectors
- APDU and data-payload encoding/decoding
- Section 6.4 post-quantum hybrid PKI master/slave handshake and encrypted register reads
