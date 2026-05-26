from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from .crypto import make_certificate, private_key_to_pem


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def init_demo_pki(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    root_key = ec.generate_private_key(ec.SECP256R1())
    brand_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    server_key = ec.generate_private_key(ec.SECP256R1())

    root_cert = make_certificate("ROOT-DEMO", root_key.public_key(), "ROOT-DEMO", root_key, "root")
    brand_cert = make_certificate("BRAND-DEMO", brand_key.public_key(), "ROOT-DEMO", root_key, "brand")
    client_id = "0102030405060708"
    server_id = "1112131415161718"
    client_cert = make_certificate(client_id, client_key.public_key(), "BRAND-DEMO", brand_key, "client")
    server_cert = make_certificate(server_id, server_key.public_key(), "BRAND-DEMO", brand_key, "server")

    write_json(out / "root_cert.json", root_cert)
    for role, key, cert in (("client", client_key, client_cert), ("server", server_key, server_cert)):
        role_dir = out / role
        role_dir.mkdir(exist_ok=True)
        (role_dir / "private_key.pem").write_bytes(private_key_to_pem(key))
        write_json(role_dir / "device_cert.json", cert)
        write_json(role_dir / "brand_cert.json", brand_cert)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate demo ECC PKI files for the secure Modbus prototype.")
    parser.add_argument("--out", default="demo_pki", type=Path)
    args = parser.parse_args()
    init_demo_pki(args.out)
    print(f"demo PKI written to {args.out}")


if __name__ == "__main__":
    main()
