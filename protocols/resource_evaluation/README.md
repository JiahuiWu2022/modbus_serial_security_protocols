# Resource-cost evaluation

This directory contains a reproducible Python microbenchmark for the three
Modbus serial-link security-extension implementations:

- `protocols-ECC`: ECC PKI profile.
- `protocols-psw`: password / pre-shared-key profile.
- `protocols-mpq`: post-quantum hybrid PKI profile.

## Method

The benchmark runs each protocol for 20 trials by default.  Each trial measures:

- full security handshake wall-clock time;
- full security handshake process CPU time;
- peak traced Python allocation during handshake via `tracemalloc`;
- transmitted bytes and send calls during handshake;
- one encrypted Modbus read-holding-registers transaction after handshake;
- transaction wall-clock time, CPU time, peak traced allocation, and bytes.

The environment used for this run blocks real `socket.sendall`, so the script
uses an in-memory endpoint that implements the same `sendall` / `recv` methods
used by the protocol code.  This keeps protocol encode/decode, cryptographic
work, APDU framing, RTU framing, and application transaction behavior intact,
but excludes OS socket and serial-driver overhead.

The `protocols-mpq` implementation uses the repository's demo KEM and demo
certificate chain, preserving APDU fields and sizes from the design.  It is
not a production ML-KEM/ML-DSA implementation.

## Run

```bash
python3 resource_evaluation/evaluate_resource_cost.py --trials 20 --out resource_evaluation/results
```

## Outputs

- `results/resource_cost_raw.csv`
- `results/resource_cost_raw.json`
- `results/resource_cost_summary.csv`
- `results/resource_cost_summary.json`
- `results/handshake_wall_time.png`
- `results/transaction_wall_time.png`
- `results/handshake_cpu_time.png`
- `results/handshake_peak_memory.png`
- `results/handshake_bytes.png`
- `results/total_bytes.png`

## Summary from the current run

| Protocol | Handshake wall mean (ms) | Encrypted read wall mean (ms) | Handshake CPU mean (ms) | Handshake bytes | Transaction bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| ECC PKI | 17.62 | 1.12 | 17.39 | 2034 | 71 |
| PSK/password | 384.93 | 4.52 | 383.64 | 342 | 65 |
| Hybrid-PQ PKI | 144.79 | 4.30 | 144.11 | 3645 | 65 |

Interpretation notes:

- ECC has larger handshake traffic than PSK, but faster CPU time in this Python implementation because it uses optimized `cryptography` ECC primitives.
- PSK has the smallest handshake traffic, but highest CPU time because the reference code implements SM2 arithmetic in pure Python.
- Hybrid-PQ has the largest handshake traffic due to KEM ciphertexts and hybrid certificate material, but lower CPU time than PSK in this demo implementation.
