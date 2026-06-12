# Protocol-Native Security Extension for Modbus Serial Links

This directory combines three independent reference implementations:

- `protocols-ECC`: A Modbus serial-link communication security extension based on ECC PKI public-key certificates.
- `protocols-psw`: A Modbus serial-link security protocol based on passwords or pre-shared keys.
- `protocols-mpq`: A Modbus serial-link security protocol based on post-quantum hybrid-signature PKI public-key certificates.

The root of this directory provides the unified launcher `unified_server.py`. It starts the Web UIs for all three subprojects and exposes a single entry point with three tabs.

## Note:

If hardware Hardware UART interface is used, the socket initialized here is only a placeholder and is not used for data transfer. Every frame is read from and sent through UART.

## Install Dependencies

```bash
python3 -m pip install -r requirements.txt
```

## Start with One Command

Run this command from the root of this directory:

```bash
python3 unified_server.py
```

Then open:

```text
http://127.0.0.1:18000/
```

Default ports:

| Service | Address |
| --- | --- |
| Unified UI | `http://127.0.0.1:18000/` |
| ECC PKI subproject | `http://127.0.0.1:18080/` |
| Password/pre-shared-key subproject | `http://127.0.0.1:18081/` |
| Post-quantum hybrid-signature PKI subproject | `http://127.0.0.1:18082/` |

The three tabs in the unified UI open the corresponding subproject pages.

## Options

```bash
python3 unified_server.py \
  --host 127.0.0.1 \
  --port 18000 \
  --ecc-port 18080 \
  --psw-port 18081 \
  --mpq-port 18082
```

If the default port for a subproject is already in use, the launcher automatically selects an available port for that subproject and prints the actual address in the terminal.

To allow other machines on the same network to access the UI, listen on all network interfaces:

```bash
python3 unified_server.py --host 0.0.0.0
```
