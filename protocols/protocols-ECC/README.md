# Reference Implementation of Modbus Serial-Link Security Extension based on the "ECC PKI certificate" profile 

This project implements reference master and slave endpoints for the "ECC PKI certificate" profile. It also provides a single-page Web UI.
It si recommended that using the "one command to start UI" mode: only start the UI console on the command line, and then complete PKI preparation, slave start, master start, and register read/write within the page.

## Note:

If a real UART interface is used in `frame.py`, the socket initialized here is only a placeholder and is not used for data transfer. Every frame is read from and sent through UART.

## 1. Requirements

Enter project directory:

```bash
cd /home/protocols
```

Confirm that Python is available:

```bash
python3 --version
```

Install dependencies:

```bash
pip install -r requirements.txt
```

The current implementation relies on cryptography. If the environment has already pre installed the library, installation can be skipped.

## 2. Command-Line Startup

Launch UI Console:

```bash
python3 -m secure_modbus.ui_server --host 127.0.0.1 --port 18080
```

Open a browser to access:

```text
http://127.0.0.1:18080/
```

Startup parameters:

```text
--Host: UI service listens for IP addresses, such as 127.0.0.1 or 0.0.0.0
--Port: UI service listening port, such as 18080
```

If you need other machines on the same network to access the UI, you can listen to all network cards:

```bash
python3 -m secure_modbus.ui_server --host 0.0.0.0 --port 18080
```

Then use the actual IP address of the server to access:

```text
Http://<Server IP>: 18080/
```

The page includes the following operational areas:

-Preparation: Enter the PKI directory and status directory, and click "Generate Demo PKI".
-Start Slave: Enter the listening address, listening port, and slave address, and click "Start Slave".
-Start the master station: Enter the target slave station address, port, and slave station number, and click "Start Master Station".
-Register operations: read and hold registers, write single registers.
-Security link parameters: display master and slave station IDs, function codes, authentication context, handshake stage.
-Key and Counter Output: Display truncated digests of AKH/DHSK/SAK/SEK/CK/CIV/BCK/BCIV, as well as SAC and content PDU counters.
-Recent results: Display the latest read and write operation results.
-Slave log: displays the output of slave processes.
-Operation events: Display the preparation, startup, and read-write events executed within the UI.

Default page parameters:

```text
PKI directory: demo_pki
Status directory:. secure_modbus_ste
Slave listening address: 127.0.0.1
Slave listening port: 15020
Slave address: 1
Main Station Target Slave Station: 127.0.0.1:15020/1
```

## 3. Operation sequence within UI

###3.1 Generate Demonstration PKI

Click on the "Preparation Work" area:

```text
Generate demonstration PKI
```

After generation, the demo identity will be displayed:

```text
CLIENT_ID = 0102030405060708
SERVER_ID = 1112131415161718
```

 Directory structure:

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

###3.2 Starting the slave station

Confirm parameters in the "Start Slave" area:

```text
Listening address: 127.0.0.1
Listening port: 15020
Slave address: 1
```

Click：

```text
Start slave station
```

The 'Running Status' on the right side of the page will display the slave PID, and the' Slave Log 'will display the listening log.

###3.3 Start the master station

Confirm parameters in the 'Start Master Station' area:

```text
Slave address: 127.0.0.1
Slave port: 15020
Target Station Number: 1
```

Click：

```text
start the master station
```

At this point, the master station object has been created, but the secure handshake is usually triggered during the first read/write operation.

###3.4 Read the Hold Register

Fill in the "Register Operations" area with:

```text
Read starting address: 0
Read quantity: 4
```

Click：

```text
read
```

The first read will trigger the complete security link:

```text
slave station ss_open_deq
Master station ss_open_cnf
Certificate authentication or AKH re authentication
SAC initialization
Content key CK/BCK update
Ss_data_Snd encrypted transmission of Modbus PDU
```

After completion, the page will display：

-Read register values
-CLIENT ID and SERVER ID`
-Have the four security stages been completed
-Key Digest and Counter
-Log of decrypted encrypted PDU received from the station

###3.5 Writing Single Register

Fill in the "Register Operations" area with:

```text
Write address: 3
Write value: 2468
```

Click：

```text
write
```

After successful writing, the page will automatically read back to nearby registers and display the results in the "Recent Results" and "Operation Events" sections.

## 4. UI Control Interface

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

Example:

```bash
curl -X POST 'http://127.0.0.1:18080/api/pki/init?pki=demo_pki'
curl -X POST 'http://127.0.0.1:18080/api/slave/start?pki=demo_pki&state=.secure_modbus_state&host=127.0.0.1&port=15020&address=1'
curl -X POST 'http://127.0.0.1:18080/api/master/start?pki=demo_pki&state=.secure_modbus_state&slave_host=127.0.0.1&slave_port=15020&slave_address=1'
curl 'http://127.0.0.1:18080/api/read?start=0&qty=4'
curl -X POST 'http://127.0.0.1:18080/api/write?register=3&value=2468'
```

## 5. Manual command mode

If you don't use a single command UI, you can also start the master and slave stations separately.

###5.1 Generate Demonstration PKI

```bash
python3 -m secure_modbus.pki --out demo_pki
```

###5.2 Starting the Slave Service

The slave is responsible for monitoring TCP connections, initiating authentication, SAC establishment, content key updates, and processing encrypted Modbus PDUs according to the process.

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

###5.3 Starting the master station service and front-end UI

The master station service connects to the slave station and provides HTTP API and front-end console.

```bash
python3 -m secure_modbus.master_server \
  --pki demo_pki \
  --slave-port 15020 \
  --http-port 18080
```

Open after startup:

```text
http://127.0.0.1:18080/
```

Front end UI display:

-Master Station ` CLIENT-ID`
-Slave Station ` SERVER ID`
-Slave TCP address, Modbus address, function code ` 0x00`
-Certificate authentication or re authentication status
-SAC channel establishment status
-Content key update status
-Encrypt Modbus PDU status
-Truncated abstracts of AKH, DHSK, SAK, SEK, CK, CIV, BCK, BCIV
-SAC sending/receiving counter
-Content PDU sending counter
-Read and write register operation log

## 6. Manual mode front-end operation

###Read the Hold Register

Fill in the following in the UI:

```text
Starting address: 0
Quantity: 4
```

Click on 'Read'.

###Write Single Register

Fill in the following in the UI:

```text
Write address: 2
Write value: 4321
```

Click on 'Write'. After successful writing, the page will automatically read back to nearby registers.

## 7. Manual mode HTTP API validation

Check the health status of the service:

```bash
curl 'http://127.0.0.1:18080/health'
```

Check the security link status:

```bash
curl 'http://127.0.0.1:18080/status'
```

Read the hold register:

```bash
curl 'http://127.0.0.1:18080/read?start=0&qty=4'
```

Write single register:

```bash
curl -X POST 'http://127.0.0.1:18080/write?register=2&value=4321'
```

Example response:

```json
{"start": 0, "quantity": 4, "values": [0, 1, 4321, 3]}
```

## 8. Authentication context

The authentication context is saved by default in:

```text
.secure_modbus_state/
```

After the first binding, the master and slave stations will save the 'DHSK', 'AKH/AKM', peer ID, and encryption mode. When restarting later, if the authentication context is valid, the AKH re authentication path will be prioritized, reducing the steps of certificate authentication and ECDH exchange.

To perform the first certificate authentication again, you can delete the directory and restart the master-slave station:

```bash
rm -rf .secure_modbus_state
```

## 9. Functional scope

Implemented:

-Modbus RTU outer frame encapsulation and CRC16 verification
-Function Code 0x00 Security Extension APDU
-ECC PKI Demonstration Certificate Chain
-ECDSA certificate signature verification
-ECDH Master Key Agreement
-RM and RH verification
-AKH/AKM authentication key verification
-SAC channel authentication and encryption encapsulation
-Content Key 'CK/COV', Broadcast Content Key 'BCK/BCIV' Update
-Encrypt transmission of raw Modbus PDU
-0x03 Read hold register
-0x06 Write Single Register
-Front end UI status display and register operation

Note: The SM2/SM3/SM4, AES-XCBC-MAC, HSM, TEE, and hardware secure storage required by the document require a dedicated national security repository and hardware environment. The algorithm layer in this project uses the P-256 ECDSA/ECDH, SHA-256/HKDF, AES-CBC/HMAC, and AES-GCM provided by Cryptography as executable reference implementations, which can be replaced with national secret implementations in secure_modbus/crypto. py in the future.

## 10. Q&R

###Port is occupied

If '15020' or '18080' is already occupied, the port can be changed:

```bash
python3 -m secure_modbus.ui_server --host 127.0.0.1 --port 18081
```

Then access:

```text
http://127.0.0.1:18081/
```

In manual mode, the master and slave station ports can also be switched separately：

```bash
python3 -m secure_modbus.slave_server --pki demo_pki --port 15021 --address 1
python3 -m secure_modbus.master_server --pki demo_pki --slave-port 15021 --http-port 18081
```

###Master station connection failed

In a command UI, confirm that the slave has been started and that the target slave port of the master is consistent with the slave listening port. The first read or write will trigger a secure connection and handshake.

Manual mode can check:

```bash
curl 'http://127.0.0.1:18080/status'
```

If 'connected' is set to 'false' in the state, performing a read operation in the UI will trigger the connection and handshake. If it still fails, confirm that the slave port, PKI directory, and slave address are consistent.

###Certificate or authentication failed

Regenerate the demonstration PKI and clean up the authentication context:

```bash
rm -rf demo_pki .secure_modbus_state
python3 -m secure_modbus.pki --out demo_pki
```

Then restart the slave and master stations in sequence, or regenerate the PKI and restart the master and slave stations in a command UI.
