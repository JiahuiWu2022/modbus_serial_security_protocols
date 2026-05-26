#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import importlib
import json
import os
import shutil
import statistics
import sys
import tempfile
import threading
import time
import tracemalloc
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
ECC_DIR = ROOT / "protocols-ECC"
PSK_DIR = ROOT / "protocols-psw"
MPQ_DIR = ROOT / "protocols-mpq"


class CountingSocket:
    def __init__(self, endpoint: "MemoryEndpoint") -> None:
        self.endpoint = endpoint
        self.bytes_sent = 0
        self.bytes_received = 0
        self.send_calls = 0
        self.recv_calls = 0

    def sendall(self, data: bytes) -> None:
        self.bytes_sent += len(data)
        self.send_calls += 1
        self.endpoint.sendall(data)

    def recv(self, size: int) -> bytes:
        data = self.endpoint.recv(size)
        self.bytes_received += len(data)
        self.recv_calls += 1
        return data

    def close(self) -> None:
        self.endpoint.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.endpoint, name)


class MemoryEndpoint:
    def __init__(self) -> None:
        self.peer: "MemoryEndpoint | None" = None
        self.buffer = bytearray()
        self.closed = False
        self.condition = threading.Condition()

    def connect(self, peer: "MemoryEndpoint") -> None:
        self.peer = peer

    def sendall(self, data: bytes) -> None:
        if self.peer is None:
            raise OSError("memory endpoint is not connected")
        with self.peer.condition:
            if self.closed or self.peer.closed:
                raise EOFError("memory endpoint is closed")
            self.peer.buffer.extend(data)
            self.peer.condition.notify_all()

    def recv(self, size: int) -> bytes:
        with self.condition:
            while not self.buffer and not self.closed:
                self.condition.wait()
            if not self.buffer and self.closed:
                return b""
            chunk = bytes(self.buffer[:size])
            del self.buffer[:size]
            return chunk

    def close(self) -> None:
        with self.condition:
            self.closed = True
            self.condition.notify_all()
        if self.peer is not None:
            with self.peer.condition:
                self.peer.condition.notify_all()


def memory_socketpair() -> tuple[CountingSocket, CountingSocket]:
    left = MemoryEndpoint()
    right = MemoryEndpoint()
    left.connect(right)
    right.connect(left)
    return CountingSocket(left), CountingSocket(right)


@dataclass
class TrialResult:
    protocol: str
    trial: int
    handshake_wall_ms: float
    transaction_wall_ms: float
    total_wall_ms: float
    handshake_cpu_ms: float
    transaction_cpu_ms: float
    total_cpu_ms: float
    handshake_peak_kib: float
    transaction_peak_kib: float
    total_peak_kib: float
    handshake_bytes_sent: int
    transaction_bytes_sent: int
    total_bytes_sent: int
    handshake_send_calls: int
    transaction_send_calls: int
    total_send_calls: int
    read_values: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "trial": self.trial,
            "handshake_wall_ms": self.handshake_wall_ms,
            "transaction_wall_ms": self.transaction_wall_ms,
            "total_wall_ms": self.total_wall_ms,
            "handshake_cpu_ms": self.handshake_cpu_ms,
            "transaction_cpu_ms": self.transaction_cpu_ms,
            "total_cpu_ms": self.total_cpu_ms,
            "handshake_peak_kib": self.handshake_peak_kib,
            "transaction_peak_kib": self.transaction_peak_kib,
            "total_peak_kib": self.total_peak_kib,
            "handshake_bytes_sent": self.handshake_bytes_sent,
            "transaction_bytes_sent": self.transaction_bytes_sent,
            "total_bytes_sent": self.total_bytes_sent,
            "handshake_send_calls": self.handshake_send_calls,
            "transaction_send_calls": self.transaction_send_calls,
            "total_send_calls": self.total_send_calls,
            "read_values": self.read_values,
        }


def import_from(path: Path, module: str) -> Any:
    sys.path.insert(0, str(path))
    try:
        return importlib.import_module(module)
    finally:
        sys.path.pop(0)


def clear_secure_modbus_modules() -> None:
    for name in list(sys.modules):
        if name == "secure_modbus" or name.startswith("secure_modbus."):
            del sys.modules[name]


def measure_block(fn: Callable[[], Any]) -> tuple[Any, float, float, float]:
    tracemalloc.start()
    start_wall = time.perf_counter_ns()
    start_cpu = time.process_time_ns()
    result = fn()
    cpu_ms = (time.process_time_ns() - start_cpu) / 1_000_000
    wall_ms = (time.perf_counter_ns() - start_wall) / 1_000_000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, wall_ms, cpu_ms, peak / 1024


def socket_totals(*socks: CountingSocket) -> tuple[int, int, int]:
    return (
        sum(s.bytes_sent for s in socks),
        sum(s.bytes_received for s in socks),
        sum(s.send_calls for s in socks),
    )


def benchmark_psk(trial: int) -> TrialResult:
    psk = import_from(PSK_DIR, "modbus_security_psk")
    master, slave = memory_socketpair()
    password = b"shared-secret"
    slave_id = 1
    server_id = 0x1001000100000001
    client_id = 0x2001000100000001
    registers = [10, 20, 30, 40, 50, 60, 70, 80]
    slave_context: dict[str, Any] = {}
    errors: list[BaseException] = []

    def slave_handshake() -> None:
        try:
            slave_context["context"] = psk.run_slave_handshake(slave, slave_id, password, server_id)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=slave_handshake)
    thread.start()

    def master_handshake() -> Any:
        return psk.run_master_handshake(master, slave_id, password, client_id)

    master_context, hs_wall, hs_cpu, hs_peak = measure_block(master_handshake)
    thread.join(timeout=10)
    if thread.is_alive():
        raise RuntimeError("PSK slave handshake did not finish")
    if errors:
        raise errors[0]
    hs_sent, _, hs_calls = socket_totals(master, slave)

    def transact() -> list[int]:
        response_box: dict[str, bytes] = {}
        slave_error: list[BaseException] = []

        def slave_transaction() -> None:
            try:
                frame = psk.recv_record(slave)
                request = psk.parse_encrypted_data_send(frame, slave_context["context"], expected_slave_id=slave_id)
                response = psk.handle_modbus_pdu(request, registers)
                psk.send_record(slave, psk.build_encrypted_data_send(slave_id, slave_context["context"], response))
            except BaseException as exc:
                slave_error.append(exc)

        tx_thread = threading.Thread(target=slave_transaction)
        tx_thread.start()
        psk.send_record(
            master,
            psk.build_encrypted_data_send(slave_id, master_context, psk.read_holding_registers_pdu(1, 3)),
        )
        response_box["response"] = psk.parse_encrypted_data_send(
            psk.recv_record(master),
            master_context,
            expected_slave_id=slave_id,
        )
        tx_thread.join(timeout=10)
        if tx_thread.is_alive():
            raise RuntimeError("PSK slave transaction did not finish")
        if slave_error:
            raise slave_error[0]
        return psk.parse_register_response(response_box["response"])

    values, tx_wall, tx_cpu, tx_peak = measure_block(transact)
    total_sent, _, total_calls = socket_totals(master, slave)
    master.close()
    slave.close()
    return TrialResult(
        "PSK/password",
        trial,
        hs_wall,
        tx_wall,
        hs_wall + tx_wall,
        hs_cpu,
        tx_cpu,
        hs_cpu + tx_cpu,
        hs_peak,
        tx_peak,
        max(hs_peak, tx_peak),
        hs_sent,
        total_sent - hs_sent,
        total_sent,
        hs_calls,
        total_calls - hs_calls,
        total_calls,
        ",".join(map(str, values)),
    )


def benchmark_mpq(trial: int) -> TrialResult:
    mpq = import_from(MPQ_DIR, "modbus_security_pq")
    master, slave = memory_socketpair()
    slave_id = 1
    server_id = 0x1001000100000001
    client_id = 0x2001000100000001
    registers = [10, 20, 30, 40, 50, 60, 70, 80]
    slave_context: dict[str, Any] = {}
    errors: list[BaseException] = []

    def slave_handshake() -> None:
        try:
            slave_context["context"] = mpq.run_slave_handshake(slave, slave_id, server_id)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=slave_handshake)
    thread.start()

    def master_handshake() -> Any:
        return mpq.run_master_handshake(master, slave_id, client_id)

    master_context, hs_wall, hs_cpu, hs_peak = measure_block(master_handshake)
    thread.join(timeout=10)
    if thread.is_alive():
        raise RuntimeError("MPQ slave handshake did not finish")
    if errors:
        raise errors[0]
    hs_sent, _, hs_calls = socket_totals(master, slave)

    def transact() -> list[int]:
        response_box: dict[str, bytes] = {}
        slave_error: list[BaseException] = []

        def slave_transaction() -> None:
            try:
                frame = mpq.recv_record(slave)
                request = mpq.parse_encrypted_data_send(frame, slave_context["context"], expected_slave_id=slave_id)
                response = mpq.handle_modbus_pdu(request, registers)
                mpq.send_record(slave, mpq.build_encrypted_data_send(slave_id, slave_context["context"], response))
            except BaseException as exc:
                slave_error.append(exc)

        tx_thread = threading.Thread(target=slave_transaction)
        tx_thread.start()
        mpq.send_record(
            master,
            mpq.build_encrypted_data_send(slave_id, master_context, mpq.read_holding_registers_pdu(1, 3)),
        )
        response_box["response"] = mpq.parse_encrypted_data_send(
            mpq.recv_record(master),
            master_context,
            expected_slave_id=slave_id,
        )
        tx_thread.join(timeout=10)
        if tx_thread.is_alive():
            raise RuntimeError("MPQ slave transaction did not finish")
        if slave_error:
            raise slave_error[0]
        return mpq.parse_register_response(response_box["response"])

    values, tx_wall, tx_cpu, tx_peak = measure_block(transact)
    total_sent, _, total_calls = socket_totals(master, slave)
    master.close()
    slave.close()
    return TrialResult(
        "Hybrid-PQ PKI",
        trial,
        hs_wall,
        tx_wall,
        hs_wall + tx_wall,
        hs_cpu,
        tx_cpu,
        hs_cpu + tx_cpu,
        hs_peak,
        tx_peak,
        max(hs_peak, tx_peak),
        hs_sent,
        total_sent - hs_sent,
        total_sent,
        hs_calls,
        total_calls - hs_calls,
        total_calls,
        ",".join(map(str, values)),
    )


def benchmark_ecc(trial: int, pki_dir: Path) -> TrialResult:
    clear_secure_modbus_modules()
    sys.path.insert(0, str(ECC_DIR))
    try:
        from secure_modbus.crypto import load_identity
        from secure_modbus.session import SecureSession, client_handshake, server_handshake
    finally:
        sys.path.pop(0)

    master, slave = memory_socketpair()
    slave_id = 1
    registers = [10, 20, 30, 40, 50, 60, 70, 80]
    temp_state = Path(tempfile.mkdtemp(prefix=f"ecc_state_{trial}_"))
    client_identity = load_identity(pki_dir, "client")
    server_identity = load_identity(pki_dir, "server")
    client_session = SecureSession(master, slave_id, client_identity)
    server_session = SecureSession(slave, slave_id, server_identity)
    errors: list[BaseException] = []

    def slave_handshake() -> None:
        try:
            server_handshake(server_session, temp_state / "server_context_1.json")
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=slave_handshake)
    thread.start()

    def master_handshake() -> None:
        client_handshake(client_session, temp_state / "client_context_1.json")

    _, hs_wall, hs_cpu, hs_peak = measure_block(master_handshake)
    thread.join(timeout=10)
    if thread.is_alive():
        raise RuntimeError("ECC slave handshake did not finish")
    if errors:
        raise errors[0]
    hs_sent, _, hs_calls = socket_totals(master, slave)

    def transact() -> list[int]:
        response_box: dict[str, bytes] = {}
        slave_error: list[BaseException] = []

        def slave_transaction() -> None:
            try:
                request = server_session.recv_encrypted_pdu()
                if request[0] != 0x03:
                    raise RuntimeError("unexpected Modbus request")
                start = int.from_bytes(request[1:3], "big")
                quantity = int.from_bytes(request[3:5], "big")
                body = bytearray([0x03, quantity * 2])
                for value in registers[start : start + quantity]:
                    body.extend((value & 0xFFFF).to_bytes(2, "big"))
                server_session.send_encrypted_pdu(bytes(body))
            except BaseException as exc:
                slave_error.append(exc)

        tx_thread = threading.Thread(target=slave_transaction)
        tx_thread.start()
        client_session.send_encrypted_pdu(b"\x03" + (1).to_bytes(2, "big") + (3).to_bytes(2, "big"))
        response_box["response"] = client_session.recv_encrypted_pdu()
        tx_thread.join(timeout=10)
        if tx_thread.is_alive():
            raise RuntimeError("ECC slave transaction did not finish")
        if slave_error:
            raise slave_error[0]
        response = response_box["response"]
        return [int.from_bytes(response[2 + i * 2 : 4 + i * 2], "big") for i in range(response[1] // 2)]

    values, tx_wall, tx_cpu, tx_peak = measure_block(transact)
    total_sent, _, total_calls = socket_totals(master, slave)
    master.close()
    slave.close()
    shutil.rmtree(temp_state, ignore_errors=True)
    return TrialResult(
        "ECC PKI",
        trial,
        hs_wall,
        tx_wall,
        hs_wall + tx_wall,
        hs_cpu,
        tx_cpu,
        hs_cpu + tx_cpu,
        hs_peak,
        tx_peak,
        max(hs_peak, tx_peak),
        hs_sent,
        total_sent - hs_sent,
        total_sent,
        hs_calls,
        total_calls - hs_calls,
        total_calls,
        ",".join(map(str, values)),
    )


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * pct
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def summarize(results: list[TrialResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    protocols = sorted({r.protocol for r in results})
    metrics = [
        "handshake_wall_ms",
        "transaction_wall_ms",
        "total_wall_ms",
        "handshake_cpu_ms",
        "transaction_cpu_ms",
        "handshake_peak_kib",
        "transaction_peak_kib",
        "handshake_bytes_sent",
        "transaction_bytes_sent",
        "total_bytes_sent",
        "handshake_send_calls",
        "transaction_send_calls",
    ]
    for protocol in protocols:
        subset = [r.as_dict() for r in results if r.protocol == protocol]
        row: dict[str, Any] = {"protocol": protocol, "trials": len(subset)}
        for metric in metrics:
            values = [float(r[metric]) for r in subset]
            row[f"{metric}_mean"] = statistics.mean(values)
            row[f"{metric}_median"] = statistics.median(values)
            row[f"{metric}_stdev"] = statistics.stdev(values) if len(values) > 1 else 0.0
            row[f"{metric}_p95"] = percentile(values, 0.95)
        rows.append(row)
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def plot_results(summary: list[dict[str, Any]], output_dir: Path) -> None:
    os.environ.setdefault("MPLCONFIGDIR", str(output_dir / ".matplotlib"))
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    protocols = [row["protocol"] for row in summary]
    label_map = {
        "Hybrid-PQ PKI": "Hybrid-PQ",
        "PSK/password": "PSK",
    }
    labels = [textwrap.fill(label_map.get(protocol, protocol), width=10) for protocol in protocols]
    x_positions = list(range(len(protocols)))
    bar_width = 0.5
    colors = ["#3366aa", "#66aa55", "#aa6633"]
    charts = [
        ("handshake_wall_ms_mean", "Handshake wall time (ms)", "handshake_wall_time.png"),
        ("transaction_wall_ms_mean", "Encrypted read wall time (ms)", "transaction_wall_time.png"),
        ("handshake_cpu_ms_mean", "Handshake CPU time (ms)", "handshake_cpu_time.png"),
        ("handshake_peak_kib_mean", "Handshake peak traced memory (KiB)", "handshake_peak_memory.png"),
        ("handshake_bytes_sent_mean", "Handshake bytes transmitted", "handshake_bytes.png"),
        ("total_bytes_sent_mean", "Total bytes transmitted", "total_bytes.png"),
    ]
    for key, ylabel, filename in charts:
        values = [row[key] for row in summary]
        fig, ax = plt.subplots(figsize=(2.8, 2.2))
        bars = ax.bar(x_positions, values, width=bar_width, color=colors)
        ax.set_xticks(x_positions, labels)
        ax.set_xlim(-bar_width, x_positions[-1] + bar_width)
        ax.set_ylim(0, max(values) * 1.18)
        ax.set_ylabel(ylabel, fontsize=10)
        ax.tick_params(axis="both", labelsize=9)
        ax.grid(axis="y", linestyle="--", alpha=0.35)
        for bar, value in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                f"{value:.2f}",
                ha="center",
                va="bottom",
                fontsize=10,
            )
        fig.tight_layout()
        fig.savefig(output_dir / filename, dpi=180)
        plt.close(fig)


def ensure_ecc_pki() -> Path:
    pki_dir = ROOT / "resource_evaluation" / "ecc_demo_pki"
    if pki_dir.exists():
        return pki_dir
    clear_secure_modbus_modules()
    sys.path.insert(0, str(ECC_DIR))
    try:
        from secure_modbus.pki import init_demo_pki
    finally:
        sys.path.pop(0)
    init_demo_pki(pki_dir)
    return pki_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate resource costs of three secure Modbus serial-link protocol implementations.")
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--out", type=Path, default=ROOT / "resource_evaluation" / "results")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    pki_dir = ensure_ecc_pki()

    benchmarks: list[tuple[str, Callable[[int], TrialResult]]] = [
        ("ECC PKI", lambda trial: benchmark_ecc(trial, pki_dir)),
        ("PSK/password", benchmark_psk),
        ("Hybrid-PQ PKI", benchmark_mpq),
    ]

    results: list[TrialResult] = []
    for name, benchmark in benchmarks:
        for trial in range(1, args.trials + 1):
            print(f"[{name}] trial {trial}/{args.trials}", flush=True)
            results.append(benchmark(trial))

    raw_rows = [r.as_dict() for r in results]
    summary_rows = summarize(results)
    write_csv(args.out / "resource_cost_raw.csv", raw_rows)
    write_csv(args.out / "resource_cost_summary.csv", summary_rows)
    (args.out / "resource_cost_raw.json").write_text(json.dumps(raw_rows, indent=2), encoding="utf-8")
    (args.out / "resource_cost_summary.json").write_text(json.dumps(summary_rows, indent=2), encoding="utf-8")
    plot_results(summary_rows, args.out)
    print(f"wrote results to {args.out}")


if __name__ == "__main__":
    main()
