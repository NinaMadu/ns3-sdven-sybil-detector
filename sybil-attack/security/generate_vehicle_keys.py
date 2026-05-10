"""
generate_vehicle_keys.py
Generates ECDSA P-256 keypairs for each vehicle and saves to CSV.

Usage:
    python3 generate_vehicle_keys.py --vehicles 8
    python3 generate_vehicle_keys.py --vehicles 8 --out sybil-attack/inputs/vehicle_keys.csv
"""

import argparse
import csv
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


def generate_keys(n_vehicles: int, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    rows = []
    for v_id in range(n_vehicles):
        # Generate real ECDSA P-256 keypair
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key  = private_key.public_key()

        # Private key: raw 32-byte big-endian scalar
        priv_int   = private_key.private_numbers().private_value
        priv_bytes = priv_int.to_bytes(32, byteorder='big')

        # Public key: raw 64 bytes = x (32) || y (32), uncompressed without 0x04 prefix
        pub_numbers = public_key.public_numbers()
        x_bytes = pub_numbers.x.to_bytes(32, byteorder='big')
        y_bytes = pub_numbers.y.to_bytes(32, byteorder='big')
        pub_bytes = x_bytes + y_bytes

        rows.append({
            'vehicle_id':      v_id,
            'public_key_hex':  pub_bytes.hex(),   # 128 hex chars = 64 bytes
            'private_key_hex': priv_bytes.hex(),  #  64 hex chars = 32 bytes
        })

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(
            f, fieldnames=['vehicle_id', 'public_key_hex', 'private_key_hex'])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[crypto_setup] Generated {n_vehicles} ECDSA P-256 keypairs → {output_path}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate ECDSA vehicle keypairs')
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
