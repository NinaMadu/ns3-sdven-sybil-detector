"""
generate_vehicle_vins.py
Generates:
  - vehicle_vins.csv        → sybil-attack/inputs/vehicle_vins.csv
  - valid_vins.csv          → sybil-attack/inputs/valid_vins.csv
  - token_master_key.csv    → sybil-attack/inputs/token_master_key.csv

Usage:
    python3 generate_vehicle_vins.py --vehicles 8
    python3 generate_vehicle_vins.py --vehicles 8 --out-dir sybil-attack/inputs
"""

import argparse
import csv
import os
import sys


def generate(n_vehicles: int, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)

    rows = []
    for vid in range(n_vehicles):
        vin = os.urandom(8)
        rows.append({"vehicle_id": vid, "vin_hex": vin.hex()})

    vins_path = os.path.join(out_dir, "vehicle_vins.csv")
    with open(vins_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["vehicle_id", "vin_hex"])
        w.writeheader()
        w.writerows(rows)
    print(f"[crypto_setup] {n_vehicles} vehicle VINs → {vins_path}")

    valid_path = os.path.join(out_dir, "valid_vins.csv")
    with open(valid_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["vehicle_id", "vin_hex"])
        w.writeheader()
        w.writerows(rows)
    print(f"[crypto_setup] VIN whitelist → {valid_path}")

    tmk = os.urandom(32)
    tmk_path = os.path.join(out_dir, "token_master_key.csv")
    with open(tmk_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["token_master_key_hex"])
        w.writeheader()
        w.writerow({"token_master_key_hex": tmk.hex()})
    print(f"[crypto_setup] Token master key → {tmk_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate vehicle VINs and token master key")
    parser.add_argument("--vehicles", type=int, default=8)
    parser.add_argument("--out-dir",  type=str, default="sybil-attack/inputs")
    args = parser.parse_args()
    if args.vehicles < 1:
        print("ERROR: --vehicles must be >= 1", file=sys.stderr)
        sys.exit(1)
    generate(args.vehicles, args.out_dir)
