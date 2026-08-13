"""Re-sign the CA certificates in vehicle_keys.csv with the CURRENT CA key.

WHY THIS EXISTS
  generate_ca_rsu_keys.py regenerates the CA keypair. generate_vehicle_keys.py
  signs each vehicle certificate with whatever CA key exists when it runs. So
  running them in the order

      generate_vehicle_keys.py   (signs 400 certs with CA_old)
      generate_ca_rsu_keys.py    (replaces ca_keys.csv with CA_new)

  leaves every vehicle certificate signed by a CA that no longer exists. At
  runtime the controller loads CA_new, every V2CTRL_HELLO is rejected with
  "certificate INVALID", no vehicle registers, no token is issued -- and every
  detector downstream of the registration/token layer (v5 malicious-RSU, v6
  malicious-controller) silently reports an empty result. The vehicle-tier
  detectors keep working, so the failure is easy to miss.

  That is exactly what happened on 2026-08-08 21:03 during the key regeneration
  for the S-SOTA-3 scalability sweep (259 -> 400 vehicles, 122 -> 128 RSUs).

WHAT IT DOES
  Recomputes ONLY the cert_sig_hex column, as
      ECDSA-P256( ca_priv, SHA256( vehicleId(4B big-endian) || vehiclePub(64B) ) )
  which is byte-for-byte the same construction generate_vehicle_keys.py uses.
  Every other column -- identity keypair, FN-DSA-1024 beacon keypair, ids -- is
  copied through untouched, so nothing tied to the existing key material is
  invalidated. Re-running generate_vehicle_keys.py would instead mint fresh
  keypairs for all 400 vehicles, including new beacon keys.

  Prefer fixing the ORDER (CA/RSU first, vehicles second) when generating from
  scratch; this script is the repair path for an already-regenerated tree.

USAGE
    python3 security/resign_vehicle_certs.py                 # in place, with backup
    python3 security/resign_vehicle_certs.py --dry-run       # report only
    python3 security/resign_vehicle_certs.py --inputs <dir>
"""

import argparse
import csv
import hashlib
import os
import shutil
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                             encode_dss_signature,
                                                             Prehashed)
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUTS = os.path.join(os.path.dirname(_HERE), "inputs")


def load_ca(inputs_dir):
    """Return (ca_private_key, ca_public_key) from ca_keys.csv."""
    with open(os.path.join(inputs_dir, "ca_keys.csv")) as fh:
        row = next(csv.DictReader(fh))
    priv_int = int(row["private_key_hex"].strip(), 16)
    ca_priv = ec.derive_private_key(priv_int, ec.SECP256R1())
    pub = bytes.fromhex(row["public_key_hex"].strip())
    ca_pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(pub[:32], "big"), int.from_bytes(pub[32:], "big"),
        ec.SECP256R1()).public_key()
    # The CSV's own pub must match the pub derived from its priv, or the file is
    # internally inconsistent and re-signing would just move the problem.
    derived = ca_priv.public_key().public_numbers()
    if (derived.x.to_bytes(32, "big") + derived.y.to_bytes(32, "big")) != pub:
        raise SystemExit("ca_keys.csv: public_key_hex does not match private_key_hex")
    return ca_priv, ca_pub


def cert_digest(vehicle_id, pub_hex):
    """SHA256( vehicleId(4B BE) || vehiclePub(64B) ) -- Sybil-...cc:11217-11221."""
    return hashlib.sha256(
        int(vehicle_id).to_bytes(4, "big") + bytes.fromhex(pub_hex)).digest()


def sign_raw(ca_priv, digest):
    """Raw r||s, 64 bytes -- what CryptoEcdsaVerify expects."""
    der = ca_priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def verifies(ca_pub, digest, sig_hex):
    sig = bytes.fromhex(sig_hex)
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"),
                               int.from_bytes(sig[32:], "big"))
    try:
        ca_pub.verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", default=DEFAULT_INPUTS)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    veh_path = os.path.join(args.inputs, "vehicle_keys.csv")
    ca_priv, ca_pub = load_ca(args.inputs)

    with open(veh_path, newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = reader.fieldnames
        rows = list(reader)
    if "cert_sig_hex" not in (fieldnames or []):
        raise SystemExit(f"{veh_path}: no cert_sig_hex column")

    already = resigned = skipped = 0
    for row in rows:
        pub_hex = (row.get("public_key_hex") or "").strip()
        if len(pub_hex) != 128:
            skipped += 1
            continue
        digest = cert_digest(row["vehicle_id"], pub_hex)
        old = (row.get("cert_sig_hex") or "").strip()
        if len(old) == 128 and verifies(ca_pub, digest, old):
            already += 1
            continue
        row["cert_sig_hex"] = sign_raw(ca_priv, digest)
        resigned += 1

    print(f"  vehicles: {len(rows)}   already-valid: {already}   "
          f"re-signed: {resigned}   skipped(malformed): {skipped}")
    if args.dry_run:
        print("  --dry-run: nothing written")
        return
    if not resigned:
        print("  nothing to do")
        return

    backup = veh_path + ".bak_resign"
    shutil.copy2(veh_path, backup)
    tmp = veh_path + ".tmp"
    with open(tmp, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, veh_path)
    print(f"  wrote {veh_path}  (previous version: {backup})")

    # Re-read from disk and verify, so the reported result reflects the file the
    # simulator will actually load rather than the in-memory rows.
    bad = 0
    with open(veh_path, newline="") as fh:
        for row in csv.DictReader(fh):
            pub_hex = (row.get("public_key_hex") or "").strip()
            if len(pub_hex) != 128:
                continue
            if not verifies(ca_pub, cert_digest(row["vehicle_id"], pub_hex),
                            row["cert_sig_hex"].strip()):
                bad += 1
    print(f"  verification after write: {'ALL VALID' if not bad else str(bad) + ' STILL INVALID'}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
