"""
generate_ca_rsu_keys.py
Generates:
  - CA ECDSA P-256 keypair          → sybil-attack/inputs/ca_keys.csv
  - RSU keypairs + CA-signed certs  → sybil-attack/inputs/rsu_keys.csv
  - Controller keypair + per-RSU pre-shared keys
                                    → sybil-attack/inputs/controller_keys.csv

The CA acts as an offline trust anchor.  Its public key is pre-installed on
every vehicle so vehicles can verify RSU certificates during the channel
handshake (CHAN_ACK).

The Controller↔RSU secure channel uses a pre-shared key derived offline via
ECDH: ctrl_shared_key[rsu_id] = SHA-256( ECDH(controller_priv, rsu_pub) ).
Both sides compute the same key: the RSU using ECDH(rsu_priv, controller_pub)
and the Controller using ECDH(controller_priv, rsu_pub).  Only the derived
symmetric key is loaded at runtime; the raw ECDH private keys are discarded.

Certificate format signed by CA:
  ECDSA-P256( SHA256( rsu_id(4B big-endian) || rsu_pub(64B) ) )
  Output is raw 64-byte r||s (not DER).

Usage:
    python3 generate_ca_rsu_keys.py --rsus 2
    python3 generate_ca_rsu_keys.py --rsus 2 --out-dir sybil-attack/inputs
"""

import argparse
import csv
import hashlib
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


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


def generate(n_rsus: int, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)

    # ── CA keypair ────────────────────────────────────────────────────────────
    ca_priv = ec.generate_private_key(ec.SECP256R1())
    ca_pub  = ca_priv.public_key()

    ca_path = os.path.join(out_dir, "ca_keys.csv")
    with open(ca_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["public_key_hex", "private_key_hex"])
        w.writeheader()
        w.writerow({
            "public_key_hex":  raw_pub(ca_pub).hex(),
            "private_key_hex": raw_priv(ca_priv).hex(),
        })
    print(f"[crypto_setup] CA keypair → {ca_path}")

    # ── Controller keypair ────────────────────────────────────────────────────
    # The controller's ECDH keypair is used offline only to derive per-RSU
    # pre-shared keys.  Only the derived keys are stored; the raw controller
    # private key is NOT needed at runtime and can be discarded after this script.
    ctrl_priv = ec.generate_private_key(ec.SECP256R1())
    ctrl_pub  = ctrl_priv.public_key()

    # ── RSU keypairs + CA-signed certificates + Controller shared keys ─────────
    rsu_rows  = []
    ctrl_rows = []
    for rsu_id in range(n_rsus):
        rsu_priv  = ec.generate_private_key(ec.SECP256R1())
        rsu_pub   = rsu_priv.public_key()
        pub_bytes = raw_pub(rsu_pub)

        # CA signs: SHA256( rsu_id(4B) || pub_rsu(64B) )
        cert_data = rsu_id.to_bytes(4, "big") + pub_bytes
        cert_sig  = ecdsa_sign_raw(ca_priv, cert_data)   # raw r||s, 64 bytes

        # Controller↔RSU pre-shared key:
        #   shared_xy = ECDH(controller_priv, rsu_pub)   [32-byte x-coordinate]
        #   ctrl_shared_key = SHA-256(shared_xy)
        # The RSU can compute the same value as ECDH(rsu_priv, controller_pub).
        shared_xy        = ctrl_priv.exchange(ec.ECDH(), rsu_pub)   # 32 bytes
        ctrl_shared_key  = hashlib.sha256(shared_xy).digest()        # 32 bytes

        rsu_rows.append({
            "rsu_id":              rsu_id,
            "public_key_hex":      pub_bytes.hex(),           # 128 hex = 64 bytes
            "private_key_hex":     raw_priv(rsu_priv).hex(),  #  64 hex = 32 bytes
            "cert_sig_hex":        cert_sig.hex(),             # 128 hex = 64 bytes
            "ctrl_shared_key_hex": ctrl_shared_key.hex(),     #  64 hex = 32 bytes
        })
        ctrl_rows.append({
            "rsu_id":              rsu_id,
            "ctrl_shared_key_hex": ctrl_shared_key.hex(),
        })

    rsu_path = os.path.join(out_dir, "rsu_keys.csv")
    with open(rsu_path, "w", newline="") as f:
        w = csv.DictWriter(
            f, fieldnames=["rsu_id", "public_key_hex", "private_key_hex",
                           "cert_sig_hex", "ctrl_shared_key_hex"])
        w.writeheader()
        w.writerows(rsu_rows)
    print(f"[crypto_setup] {n_rsus} RSU keypairs + CA certs + ctrl keys → {rsu_path}")

    ctrl_path = os.path.join(out_dir, "controller_keys.csv")
    with open(ctrl_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["rsu_id", "ctrl_shared_key_hex"])
        w.writeheader()
        w.writerows(ctrl_rows)
    print(f"[crypto_setup] Controller shared keys ({n_rsus} RSUs) → {ctrl_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate CA + RSU ECDSA keypairs")
    parser.add_argument("--rsus",    type=int, default=2,
                        help="Number of RSU nodes (default: 2)")
    parser.add_argument("--out-dir", type=str, default="sybil-attack/inputs",
                        help="Output directory (default: sybil-attack/inputs)")
    args = parser.parse_args()

    if args.rsus < 1:
        print("ERROR: --rsus must be >= 1", file=sys.stderr)
        sys.exit(1)

    generate(args.rsus, args.out_dir)
