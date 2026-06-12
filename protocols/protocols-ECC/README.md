# Reference Implementation of Modbus Serial-Link Security Extension based on the "ECC PKI certificate" profile 

This project implements reference master and slave endpoints for the "ECC PKI certificate" profile. It also provides a single-page Web UI.
The recommended approach is the "one-command UI launch" mode: start only the UI console from the command line, then complete PKI preparation, slave startup, master startup, and register read/write operations within the page.

## Note:

If hardware UART interface is used in `frame.py`, the socket initialized here is only a placeholder and is not used for data transfer. Every frame is read from and sent through UART.

## 1. Environment Preparation

Enter the project directory:

```bash
cd /home/protocols
```

Confirm Python is available:

```bash
python3 --version
```

Install dependencies:

```bash
pip install -r requirements.txt
```

The current implementation depends on `cryptography`. If this library is already preinstalled in your environment, you can skip the installation.

## 2. One-Command UI Launch

Start the UI console:

```bash
python3 -m secure_modbus.ui_server --host 127.0.0.1 --port 18080
```

Open a browser and visit:

```text
http://127.0.0.1:18080/
```

Startup parameters:

```text
--host: The IP address the UI service listens on, e.g. 127.0.0.1 or 0.0.0.0
--port: The port the UI service listens on, e.g. 18080
```

To allow other machines on the same network to access the UI, you can listen on all network interfaces:

```bash
python3 -m secure_modbus.ui_server --host 0.0.0.0 --port 18080
```

Then access it using the server's actual IP:

```text
http://<server-IP>:18080/
```

The page contains the following operation areas:

- Preparation: Enter the PKI directory and state directory, then click "Generate Demo PKI".
- Start Slave: Enter the listening address, listening port, and slave address, then click "Start Slave".
- Start Master: Enter the target slave address, port, and slave number, then click "Start Master".
- Register Operations: Perform Read Holding Registers and Write Single Register.
- Secure Link Parameters: Display master/slave IDs, function code, authentication context, and handshake phase.
- Key and Counter Output: Display the truncated digests of `AKH/DHSK/SAK/SEK/CK/CIV/BCK/BCIV`, as well as the SAC and content PDU counters.
- Latest Result: Display the result of the most recent read/write operation.
- Slave Log: Display the slave process output.
- Operation Events: Display the preparation, startup, and read/write events executed within the UI.

Default page parameters:

```text
PKI directory: demo_pki
State directory: .secure_modbus_state
Slave listening address: 127.0.0.1
Slave listening port: 15020
Slave address: 1
Master target slave: 127.0.0.1:15020 / 1
```

## 3. Operation Order Within the UI

### 3.1 Generate Demo PKI

In the "Preparation" area, click:

```text
Generate Demo PKI
```

After generation, the demo identities are displayed:

```text
CLIENT_ID = 0102030405060708
SERVER_ID = 1112131415161718
```

Generated directory structure:

```text
demo_pki/
  root_cert.json
  client/
    private_key.pem
    device_cert.json
    brand_cert.json
  server/
    private_key.pem
    device_cert.json
    brand_cert.json
```

### 3.2 Start Slave

In the "Start Slave" area, confirm the parameters:

```text
Listening address: 127.0.0.1
Listening port: 15020
Slave address: 1
```

Click:

```text
Start Slave
```

The "Run Status" section on the right side of the page will show the slave PID, and the "Slave Log" will show the listening log.

### 3.3 Start Master

In the "Start Master" area, confirm the parameters:

```text
Slave address: 127.0.0.1
Slave port: 15020
Target slave number: 1
```

Click:

```text
Start Master
```

At this point the master object has been created, but the security handshake is usually triggered on the first read/write operation.

### 3.4 Read Holding Registers

In the "Register Operations" area, fill in:

```text
Read start address: 0
Read quantity: 4
```

Click:

```text
Read
```

The first read triggers the full secure link:

```text
Slave ss_open_req
Master ss_open_cnf
Certificate authentication or AKH re-authentication
SAC initialization
Content key CK/BCK update
ss_data_send encrypted transmission of the Modbus PDU
```

Once complete, the page displays:

- The register values read
- `CLIENT_ID` and `SERVER_ID`
- Whether the four security phases are complete
- Key digests and counters
- The decrypted log of the encrypted PDU received by the slave

### 3.5 Write Single Register

In the "Register Operations" area, fill in:

```text
Write address: 3
Write value: 2468
```

Click:

```text
Write
```

After a successful write, the page automatically reads back nearby registers and displays the result in "Latest Result" and "Operation Events".

## 4. UI Control Interfaces

The UI page calls the following local interfaces:

```text
GET  /
GET  /api/status
POST /api/pki/init?pki=demo_pki
POST /api/slave/start?pki=demo_pki&state=.secure_modbus_state&host=127.0.0.1&port=15020&address=1
POST /api/slave/stop
POST /api/master/start?pki=demo_pki&state=.secure_modbus_state&slave_host=127.0.0.1&slave_port=15020&slave_address=1
POST /api/master/stop
GET  /api/read?start=0&qty=4
POST /api/write?register=3&value=2468
```

Examples:

```bash
curl -X POST 'http://127.0.0.1:18080/api/pki/init?pki=demo_pki'
curl -X POST 'http://127.0.0.1:18080/api/slave/start?pki=demo_pki&state=.secure_modbus_state&host=127.0.0.1&port=15020&address=1'
curl -X POST 'http://127.0.0.1:18080/api/master/start?pki=demo_pki&state=.secure_modbus_state&slave_host=127.0.0.1&slave_port=15020&slave_address=1'
curl 'http://127.0.0.1:18080/api/read?start=0&qty=4'
curl -X POST 'http://127.0.0.1:18080/api/write?register=3&value=2468'
```

## 5. Manual Command Mode

If you do not use the one-command UI, you can also start the master and slave separately.

### 5.1 Generate Demo PKI

```bash
python3 -m secure_modbus.pki --out demo_pki
```

### 5.2 Start the Slave Service

The slave is responsible for listening for TCP connections, initiating authentication, SAC establishment, and content key updates per the 6.2 flow, and processing encrypted Modbus PDUs.

```bash
python3 -m secure_modbus.slave_server \
  --pki demo_pki \
  --port 15020 \
  --address 1
```

Default parameters:

```text
Listening address: 127.0.0.1
Listening port: 15020
Modbus slave address: 1
```

### 5.3 Start the Master Service and Front-End UI

The master service connects to the slave and provides the HTTP API and front-end console.

```bash
python3 -m secure_modbus.master_server \
  --pki demo_pki \
  --slave-port 15020 \
  --http-port 18080
```

After startup, open:

```text
http://127.0.0.1:18080/
```

The front-end UI displays:

- Master `CLIENT_ID`
- Slave `SERVER_ID`
- Slave TCP address, Modbus address, function code `0x00`
- Certificate authentication or re-authentication status
- SAC channel establishment status
- Content key update status
- Encrypted Modbus PDU status
- Truncated digests of `AKH`, `DHSK`, `SAK`, `SEK`, `CK`, `CIV`, `BCK`, `BCIV`
- SAC send/receive counters
- Content PDU send counter
- Register read/write operation log

## 6. Front-End Operations in Manual Mode

### Read Holding Registers

In the UI, fill in:

```text
Start address: 0
Quantity: 4
```

Click "Read".

### Write Single Register

In the UI, fill in:

```text
Write address: 2
Write value: 4321
```

Click "Write". After a successful write, the page automatically reads back nearby registers.

## 7. HTTP API Verification in Manual Mode

Check the service health status:

```bash
curl 'http://127.0.0.1:18080/health'
```

Check the secure link status:

```bash
curl 'http://127.0.0.1:18080/status'
```

Read holding registers:

```bash
curl 'http://127.0.0.1:18080/read?start=0&qty=4'
```

Write a single register:

```bash
curl -X POST 'http://127.0.0.1:18080/write?register=2&value=4321'
```

Example response:

```json
{"start": 0, "quantity": 4, "values": [0, 1, 4321, 3]}
```

## 8. Authentication Context

The authentication context is saved by default in:

```text
.secure_modbus_state/
```

After the first binding, the master and slave save `DHSK`, `AKH/AKM`, the peer ID, and the encryption mode. On subsequent restarts, if the authentication context is valid, the AKH re-authentication path is preferred, reducing the certificate authentication and ECDH exchange steps.

To re-run the initial certificate authentication, delete this directory and restart the master and slave:

```bash
rm -rf .secure_modbus_state
```

## 9. Feature Scope

Implemented:

- Modbus RTU outer frame encapsulation and CRC16 verification
- Function code `0x00` security extension APDU
- ECC PKI demo certificate chain
- ECDSA certificate signature verification
- ECDH master key negotiation
- `RM` and `RH` verification
- `AKH/AKM` authentication key verification
- SAC channel authentication and encrypted encapsulation
- Content key `CK/CIV` and broadcast content key `BCK/BCIV` updates
- Encrypted transmission of raw Modbus PDUs
- `0x03` Read Holding Registers
- `0x06` Write Single Register
- Front-end UI status display and register operations

Note: The SM2/SM3/SM4, AES-XCBC-MAC, HSM, TEE, and hardware secure storage required by the specification need dedicated SM (Chinese national commercial cryptography) libraries and hardware environments. The algorithm layer in this project uses P-256 ECDSA/ECDH, SHA-256/HKDF, AES-CBC/HMAC, and AES-GCM provided by `cryptography` as a runnable reference implementation. These can later be replaced with SM cryptographic implementations in `secure_modbus/crypto.py`.

## 10. FAQ

### Port Already in Use

If `15020` or `18080` is already in use, you can switch ports:

```bash
python3 -m secure_modbus.ui_server --host 127.0.0.1 --port 18081
```

Then visit:

```text
http://127.0.0.1:18081/
```

In manual mode, you can also switch the master and slave ports separately:

```bash
python3 -m secure_modbus.slave_server --pki demo_pki --port 15021 --address 1
python3 -m secure_modbus.master_server --pki demo_pki --slave-port 15021 --http-port 18081
```

### Master Connection Failure

In the one-command UI, confirm the slave has been started and that the master's target slave port matches the slave's listening port. The first read or write triggers the secure connection and handshake.

In manual mode, you can check:

```bash
curl 'http://127.0.0.1:18080/status'
```

If `connected` is `false` in the status, performing a read operation in the UI will trigger the connection and handshake. If it still fails, confirm that the slave port, PKI directory, and slave address are consistent.

### Certificate or Authentication Failure

Regenerate the demo PKI and clear the authentication context:

```bash
rm -rf demo_pki .secure_modbus_state
python3 -m secure_modbus.pki --out demo_pki
```

Then restart the slave and master in order, or regenerate the PKI and restart the master and slave in the one-command UI.
