"""
generate_vehicle_keys.py
Generates ECDSA P-256 keypairs for each vehicle and saves to CSV.
Also generates CA-signed certificates so the Controller can verify vehicle
identity during the V2CTRL_HELLO handshake.

Certificate format:
  ECDSA-P256( SHA256( vehicle_id(4B big-endian) || vehicle_pub(64B) ) )
  Verified by controller using g_caPubKey (pre-installed CA public key).

Requires ca_keys.csv in the same output directory (run generate_ca_rsu_keys.py first).

Usage:
    python3 generate_vehicle_keys.py --vehicles 8
    python3 generate_vehicle_keys.py --vehicles 8 --out sybil-attack/inputs/vehicle_keys.csv
"""

import argparse
import csv
import hashlib
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def raw_pub(pub_key) -> bytes:
    n = pub_key.public_numbers()
    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


def raw_priv(priv_key) -> bytes:
    return priv_key.private_numbers().private_value.to_bytes(32, "big")


def ecdsa_sign_raw(priv_key, data: bytes) -> bytes:
    """Sign data with ECDSA-P256/SHA-256; return raw 64-byte r||s."""
    der = priv_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def load_ca_priv(out_dir: str):
    """Read the CA private key from ca_keys.csv in the output directory."""
    ca_path = os.path.join(out_dir, "ca_keys.csv")
    if not os.path.exists(ca_path):
        print(f"ERROR: {ca_path} not found. Run generate_ca_rsu_keys.py first.",
              file=sys.stderr)
        sys.exit(1)

    with open(ca_path, newline="") as f:
        reader = csv.DictReader(f)
        row = next(reader, None)
        if row is None:
            print(f"ERROR: {ca_path} is empty.", file=sys.stderr)
            sys.exit(1)
        priv_bytes = bytes.fromhex(row["private_key_hex"].strip())

    priv_int = int.from_bytes(priv_bytes, "big")
    ca_priv  = ec.derive_private_key(priv_int, ec.SECP256R1())
    print(f"[crypto_setup] CA private key loaded from {ca_path}")
    return ca_priv


def generate_keys(n_vehicles: int, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    out_dir = os.path.dirname(output_path)

    ca_priv = load_ca_priv(out_dir)

    rows = []
    for v_id in range(n_vehicles):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key  = private_key.public_key()

        priv_int   = private_key.private_numbers().private_value
        priv_bytes = priv_int.to_bytes(32, byteorder='big')
        pub_bytes  = raw_pub(public_key)

        # CA signs: SHA256( vehicle_id(4B big-endian) || vehicle_pub(64B) )
        cert_data = v_id.to_bytes(4, "big") + pub_bytes
        cert_sig  = ecdsa_sign_raw(ca_priv, cert_data)

        rows.append({
            'vehicle_id':      v_id,
            'public_key_hex':  pub_bytes.hex(),   # 128 hex chars = 64 bytes
            'private_key_hex': priv_bytes.hex(),  #  64 hex chars = 32 bytes
            'cert_sig_hex':    cert_sig.hex(),    # 128 hex chars = 64 bytes (CA sig)
        })

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(
            f, fieldnames=['vehicle_id', 'public_key_hex', 'private_key_hex', 'cert_sig_hex'])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[crypto_setup] Generated {n_vehicles} ECDSA P-256 keypairs + CA certs → {output_path}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate ECDSA vehicle keypairs + CA certs')
    parser.add_argument('--vehicles', type=int, default=8,
                        help='Number of vehicle nodes (default: 8)')
    parser.add_argument('--out', type=str,
                        default='sybil-attack/inputs/vehicle_keys.csv',
                        help='Output CSV path')
    args = parser.parse_args()

    if args.vehicles < 1:
        print("ERROR: --vehicles must be >= 1", file=sys.stderr)
        sys.exit(1)

    generate_keys(args.vehicles, args.out)
