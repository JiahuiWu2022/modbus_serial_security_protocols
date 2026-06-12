# Reference Implementation of Modbus Serial-Link Security Extension based on the "password or pre-shared key" profile 

This project implements reference master and slave endpoints based on the "password or pre-shared key" profile. It provides command-line endpoints and a browser-based UI.

The RTU frame itself carries the slave address, function code, and CRC16. Content encryption uses the AES-GCM mode specified in the document and depends on `cryptography`.

## Note:

If a real UART interface is used in `modbus_security_psk.py`, the socket initialized here is only a placeholder and is not used for data transfer. Every frame is read from and sent through UART.

## Implemented Features

- `ss_sk_open_req` / `ss_sk_open_cnf`
- `ss_sk_data_req` / `ss_sk_data_cnf`
- Security APDU transport over RTU function code `0x00`
- SM2-curve ephemeral private-key and ECC random-point derivation from the pre-shared password
- Bidirectional `S_M` / `S_H` authentication-code verification
- `r_B` broadcast-key parameter exchange
- `ss_data_send` with AES-GCM content encryption
- Example Modbus `0x03` read-holding-registers operation
- Web page for entering master/slave parameters and displaying the slave registers read by the master

## Project Layout

```text
.
|-- master_server.py              # Master command-line endpoint
|-- slave_server.py               # Slave command-line endpoint
|-- modbus_security_psk.py        # Protocol encoding/decoding, handshake, encryption/decryption, and Modbus PDU handling
|-- web_frontend.py               # Web service and JSON API
|-- web/
|   |-- index.html                # Frontend page
|   |-- styles.css                # Page styles
|   `-- app.js                    # Frontend interaction logic
|-- tests/
|   `-- test_modbus_security_psk.py
|-- requirements.txt
`-- <technical requirements document>.docx
```

## Requirements

- Python 3.10 or later
- Ability to create local TCP/socket connections
- Python dependency: `cryptography>=42`

Using a virtual environment is recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

If you do not use a virtual environment, install the dependencies directly into the current Python environment:

```bash
python3 -m pip install -r requirements.txt
```

## Command-Line Startup

Start the slave first:

```bash
python3 slave_server.py --host 127.0.0.1 --port 15020 --password modbus-psk-demo
```

In a second terminal, start the master and read holding registers:

```bash
python3 master_server.py --host 127.0.0.1 --port 15020 --password modbus-psk-demo --start 0 --quantity 4
```

Example one-shot slave:

```bash
python3 slave_server.py --host 127.0.0.1 --port 15020 --password modbus-psk-demo --once
```

After a successful master read, the output is similar to:

```text
handshake ok server_id=0x1001000100000001 mode=aes_gcm ck=... civ=...
read holding registers start=0 quantity=4: [10, 20, 30, 40]
```

## Web UI Startup

Start the browser UI:

```bash
python3 web_frontend.py --host 127.0.0.1 --port 8080
```

Open:

```text
http://127.0.0.1:8080
```

After the page submits parameters, the backend temporarily starts a simulated slave. The master then completes the secure handshake, reads holding registers, and returns the read results, session mode, client ID, server ID, CK, and CIV to the page.

## Options

### Common Options

Both `master_server.py` and `slave_server.py` support:

| Option | Default | Description |
| --- | --- | --- |
| `--host` | `127.0.0.1` | TCP listen or connection address. |
| `--port` | `15020` | TCP listen or connection port. |
| `--slave-id` | `1` | Modbus slave address. Valid range: `1..247`. Decimal and `0x` hexadecimal values are supported. |
| `--password` | `modbus-psk-demo` | Shared password for the master and slave. Both sides must use the same value, or authentication fails. |

### Master Options

`master_server.py` also supports:

| Option | Default | Description |
| --- | --- | --- |
| `--client-id` | `0x2001000100000001` | Master client ID. Decimal and `0x` hexadecimal values are supported. |
| `--start` | `0` | Starting holding-register address. |
| `--quantity` | `4` | Number of registers to read. Valid range: `1..125`. |

### Slave Options

`slave_server.py` also supports:

| Option | Default | Description |
| --- | --- | --- |
| `--server-id` | `0x1001000100000001` | Slave server ID. Decimal and `0x` hexadecimal values are supported. |
| `--registers` | `64` | Number of example holding registers. Register values are generated as `(index + 1) * 10`. |
| `--once` | Disabled | Exit after handling one master connection. |

### Web Service Options

`web_frontend.py` supports:

| Option | Default | Description |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Web-service listen address. |
| `--port` | `8080` | Web-service listen port. |

### Web Form Fields

| Field | Default | Description |
| --- | --- | --- |
| Listen address | `127.0.0.1` | Binding address for the temporary simulated slave. |
| Listen port | `0` | Port for the temporary simulated slave. `0` lets the system allocate an available port automatically. |
| Slave address | `1` | Modbus slave address. Valid range: `1..247`. |
| Server ID | `0x1001000100000001` | Server ID for the temporary simulated slave. |
| Shared password | `modbus-psk-demo` | Shared password for the master and slave. |
| Holding registers | `10,20,30,...` | Register values for the temporary simulated slave. Values may be comma-separated or newline-separated and may be decimal or `0x` hexadecimal. |
| Target address | `127.0.0.1` | Address used by the master to connect to the temporary simulated slave. |
| Client ID | `0x2001000100000001` | Master client ID. |
| Start address | `0` | Starting holding-register address to read. |
| Quantity | `4` | Number of holding registers to read. Valid range: `1..125`. |

## Web API

The Web UI calls `POST /api/read`. The request body is JSON:

```json
{
  "slave_host": "127.0.0.1",
  "slave_port": "0",
  "master_host": "127.0.0.1",
  "slave_id": "1",
  "password": "modbus-psk-demo",
  "server_id": "0x1001000100000001",
  "client_id": "0x2001000100000001",
  "start": "0",
  "quantity": "4",
  "registers": "10,20,30,40,50,60,70,80"
}
```

Successful response:

```json
{
  "ok": true,
  "result": {
    "endpoint": "127.0.0.1:41273",
    "slave_id": 1,
    "start": 0,
    "quantity": 4,
    "registers": [
      { "address": 0, "value": 10, "hex": "0x000a" }
    ],
    "master": {
      "client_id": "0x2001000100000001",
      "server_id": "0x1001000100000001",
      "mode": "aes_gcm",
      "ck": "...",
      "civ": "..."
    }
  }
}
```

Failure response:

```json
{
  "ok": false,
  "error": "error description"
}
```

## Tests

Run the unit tests:

```bash
python3 -m unittest discover -s tests
```

The tests cover:

- SM3 known-answer vectors
- APDU and data-payload encoding/decoding
- Master/slave handshake and encrypted register reads
- Web-backend embedded-slave register-read flow

## Troubleshooting

### `ModuleNotFoundError: No module named 'cryptography'`

Install the dependencies first:

```bash
python3 -m pip install -r requirements.txt
```

### Master Authentication Fails or the Connection Fails

Check that the master and slave use the same `--password` and `--slave-id`, and confirm that the slave is listening on the configured `--host` / `--port`.

### The Web Page Reports That the Read Range Is Out of Bounds

`start address + quantity` must not exceed the number of holding registers configured on the page.
