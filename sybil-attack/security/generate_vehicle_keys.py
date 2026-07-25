"""
generate_vehicle_keys.py
Generates FN-DSA-1024 (Falcon-padded-1024, FIPS 206, NIST Level 5) keypairs for
each vehicle and saves them to CSV.  These are the keys used for per-beacon V2V
signing (methodology Eq. beacon_sign).

Also generates CA-signed certificates so the Controller can verify vehicle
identity during the V2CTRL_HELLO handshake.  The CA tier is unchanged by the
FN-DSA migration and remains ECDSA P-256.

Each vehicle gets TWO keypairs:
  1. ECDSA P-256 long-term identity key — unchanged. Backs the CA certificate
     and the V2CTRL handshake proof-of-possession.
  2. FN-DSA-1024 beacon key — new. Signs per-beacon V2V messages only.

Certificate format (unchanged):
  ECDSA-P256( SHA256( vehicle_id(4B big-endian) || vehicle_pub(64B) ) )
  Verified by controller using g_caPubKey (pre-installed CA public key).

Key sizes written (hex-encoded in the CSV):
  public_key_hex          64 bytes →  128 hex chars (ECDSA P-256)
  private_key_hex         32 bytes →   64 hex chars (ECDSA P-256)
  cert_sig_hex            64 bytes →  128 hex chars (ECDSA P-256 CA signature)
  beacon_public_key_hex 1793 bytes → 3586 hex chars (FN-DSA-1024)
  beacon_private_key_hex 2305 bytes → 4610 hex chars (FN-DSA-1024)

liboqs is called directly through ctypes, so the liboqs-python binding is not
required.  The shared library is located via $LIBOQS_PATH, then ~/.local/lib,
then the system loader path.

Requires ca_keys.csv in the same output directory (run generate_ca_rsu_keys.py first).

Usage:
    python3 generate_vehicle_keys.py --vehicles 8
    python3 generate_vehicle_keys.py --vehicles 8 --out sybil-attack/inputs/vehicle_keys.csv
"""

import argparse
import csv
import ctypes
import ctypes.util
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# FN-DSA-1024 == Falcon-padded-1024 in the liboqs algorithm registry.
# The padded variant is used because it emits a constant-size signature, which
# the fixed-size ns-3 V2VSignatureTag requires.
FNDSA_ALG = b"Falcon-padded-1024"
FNDSA_PUB_BYTES = 1793
FNDSA_SEC_BYTES = 2305


class OqsSig(ctypes.Structure):
    """Mirror of the OQS_SIG struct prefix, up to the fields we read."""
    _fields_ = [
        ("method_name", ctypes.c_char_p),
        ("alg_version", ctypes.c_char_p),
        ("claimed_nist_level", ctypes.c_ubyte),
        ("euf_cma", ctypes.c_bool),
        ("sig_with_ctx_support", ctypes.c_bool),
        ("length_public_key", ctypes.c_size_t),
        ("length_secret_key", ctypes.c_size_t),
        ("length_signature", ctypes.c_size_t),
    ]


def load_liboqs():
    candidates = []
    if os.environ.get("LIBOQS_PATH"):
        candidates.append(os.environ["LIBOQS_PATH"])
    candidates.append(os.path.expanduser("~/.local/lib/liboqs.so"))
    found = ctypes.util.find_library("oqs")
    if found:
        candidates.append(found)
    candidates.append("liboqs.so")

    for path in candidates:
        try:
            return ctypes.CDLL(path)
        except OSError:
            continue

    print(
        "ERROR: could not load liboqs.so. Set LIBOQS_PATH to its full path.\n"
        "  Tried: " + ", ".join(candidates),
        file=sys.stderr,
    )
    sys.exit(1)


class FnDsa1024:
    """Minimal FN-DSA-1024 keypair generator backed by liboqs via ctypes."""

    def __init__(self):
        self.lib = load_liboqs()
        self.lib.OQS_SIG_new.argtypes = [ctypes.c_char_p]
        self.lib.OQS_SIG_new.restype = ctypes.POINTER(OqsSig)
        self.lib.OQS_SIG_free.argtypes = [ctypes.POINTER(OqsSig)]
        self.lib.OQS_SIG_free.restype = None
        self.lib.OQS_SIG_keypair.argtypes = [
            ctypes.POINTER(OqsSig),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
        ]
        self.lib.OQS_SIG_keypair.restype = ctypes.c_int

        self.sig = self.lib.OQS_SIG_new(FNDSA_ALG)
        if not self.sig:
            print(
                f"ERROR: liboqs does not provide {FNDSA_ALG.decode()}. "
                "Rebuild liboqs with OQS_ENABLE_SIG_falcon_padded_1024.",
                file=sys.stderr,
            )
            sys.exit(1)

        self.pub_len = self.sig.contents.length_public_key
        self.sec_len = self.sig.contents.length_secret_key

        if self.pub_len != FNDSA_PUB_BYTES or self.sec_len != FNDSA_SEC_BYTES:
            print(
                f"ERROR: unexpected {FNDSA_ALG.decode()} key sizes "
                f"(pk={self.pub_len}, sk={self.sec_len}); "
                f"expected pk={FNDSA_PUB_BYTES}, sk={FNDSA_SEC_BYTES}. "
                "The C++ side uses fixed-size buffers and would mismatch.",
                file=sys.stderr,
            )
            sys.exit(1)

    def keypair(self):
        pub = (ctypes.c_ubyte * self.pub_len)()
        sec = (ctypes.c_ubyte * self.sec_len)()
        if self.lib.OQS_SIG_keypair(self.sig, pub, sec) != 0:
            print("ERROR: OQS_SIG_keypair failed.", file=sys.stderr)
            sys.exit(1)
        return bytes(pub), bytes(sec)

    def close(self):
        if self.sig:
            self.lib.OQS_SIG_free(self.sig)
            self.sig = None


def raw_pub(pub_key) -> bytes:
    n = pub_key.public_numbers()
    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


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
    ca_priv = ec.derive_private_key(priv_int, ec.SECP256R1())
    print(f"[crypto_setup] CA private key loaded from {ca_path}")
    return ca_priv


def generate_keys(n_vehicles: int, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    out_dir = os.path.dirname(output_path)

    ca_priv = load_ca_priv(out_dir)
    fndsa = FnDsa1024()

    rows = []
    for v_id in range(n_vehicles):
        # 1. ECDSA P-256 long-term identity key (unchanged).
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        priv_bytes = private_key.private_numbers().private_value.to_bytes(32, "big")
        pub_bytes = raw_pub(public_key)

        # CA signs: SHA256( vehicle_id(4B big-endian) || vehicle_pub(64B) )
        cert_data = v_id.to_bytes(4, "big") + pub_bytes
        cert_sig = ecdsa_sign_raw(ca_priv, cert_data)

        # 2. FN-DSA-1024 beacon key (new).
        beacon_pub, beacon_priv = fndsa.keypair()

        rows.append({
            'vehicle_id':             v_id,
            'public_key_hex':         pub_bytes.hex(),    #  128 hex =   64 B
            'private_key_hex':        priv_bytes.hex(),   #   64 hex =   32 B
            'cert_sig_hex':           cert_sig.hex(),     #  128 hex =   64 B
            'beacon_public_key_hex':  beacon_pub.hex(),   # 3586 hex = 1793 B
            'beacon_private_key_hex': beacon_priv.hex(),  # 4610 hex = 2305 B
        })

    fndsa.close()

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(
            f, fieldnames=['vehicle_id', 'public_key_hex', 'private_key_hex',
                           'cert_sig_hex', 'beacon_public_key_hex',
                           'beacon_private_key_hex'])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[crypto_setup] Generated {n_vehicles} ECDSA P-256 identity keypairs "
          f"+ CA certs + FN-DSA-1024 (Falcon-padded-1024, FIPS 206) beacon "
          f"keypairs → {output_path}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate FN-DSA-1024 vehicle keypairs + CA certs')
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
