#!/usr/bin/env python3
"""
Three-arm security comparison: none vs classical vs post-quantum.

Reads a directory of run folders produced by the ns-3 simulation and emits the
tables the evaluation panel asked for — packet size, per-operation crypto time,
registration/authentication latency, revocation cost, and the network-level
impact (PDR / latency).

Each run folder self-identifies its arm via metrics_S_security_profile.csv, so
the arms are joined from the data rather than from folder names.

Usage:
    python3 sybil-attack/commands/compare_security_suites.py \
        sybil-attack/datasets/suite_cmp

    # restrict to one scenario, e.g. only the no-attack runs
    python3 ... suite_cmp --filter clean
"""

import argparse
import glob
import os
import re
import sys

import pandas as pd

ARM_ORDER = ["none", "classical", "pqc"]
LATENCY_RE = re.compile(r"^\[Latency\]\s+(\S+)\s+\S+\s+(\S+)\s+([0-9.eE+-]+)\s*$")


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #
def discover(root, keyword=None):
    """Return [(run_dir, arm)] for every run folder carrying a suite manifest."""
    runs = []
    for manifest in sorted(glob.glob(os.path.join(root, "**", "metrics_S_security_profile.csv"),
                                     recursive=True)):
        run_dir = os.path.dirname(manifest)
        if keyword and keyword not in os.path.basename(run_dir):
            continue
        try:
            arm = pd.read_csv(manifest).iloc[0]["security_suite"]
        except Exception as exc:                       # noqa: BLE001
            print(f"  ! skipping {run_dir}: unreadable manifest ({exc})", file=sys.stderr)
            continue
        runs.append((run_dir, str(arm)))
    return runs


def arm_sort(frame, col="arm"):
    frame = frame.copy()
    frame["_o"] = frame[col].map({a: i for i, a in enumerate(ARM_ORDER)}).fillna(99)
    return frame.sort_values(["_o"] + [c for c in frame.columns
                                       if c not in (col, "_o")]).drop(columns="_o")


def ratio_column(frame, value_col, base_arm="none"):
    """Add a x-vs-baseline column; falls back to classical when none is absent."""
    frame = frame.copy()
    base = frame.loc[frame["arm"] == base_arm, value_col]
    if base.empty or float(base.iloc[0]) == 0.0:
        base = frame.loc[frame["arm"] == "classical", value_col]
        label = "x_vs_classical"
    else:
        label = f"x_vs_{base_arm}"
    if base.empty or float(base.iloc[0]) == 0.0:
        return frame
    frame[label] = frame[value_col] / float(base.iloc[0])
    return frame


# --------------------------------------------------------------------------- #
# S — declared primitive sizes
# --------------------------------------------------------------------------- #
def table_declared_sizes(runs):
    rows = []
    for run_dir, arm in runs:
        r = pd.read_csv(os.path.join(run_dir, "metrics_S_security_profile.csv")).iloc[0]
        rows.append(r)
    if not rows:
        return None
    df = pd.DataFrame(rows).drop_duplicates(subset=["security_suite"])
    df = df.rename(columns={"security_suite": "arm"})
    cols = ["arm", "beacon_sig_bytes", "beacon_pub_bytes", "auth_sig_bytes",
            "auth_pub_bytes", "kem_pub_bytes", "kem_ct_bytes",
            "wire_overhead_v2v_beacon", "wire_overhead_chan_hello",
            "wire_overhead_chan_ack"]
    return arm_sort(df[[c for c in cols if c in df.columns]])


# --------------------------------------------------------------------------- #
# S1 — measured bytes on the wire, per message class
# --------------------------------------------------------------------------- #
def table_packet_bytes(runs):
    rows = []
    for run_dir, arm in runs:
        f = os.path.join(run_dir, "communication_log.csv")
        if not os.path.exists(f):
            continue
        df = pd.read_csv(f, on_bad_lines="skip")
        if "flow" not in df or "packet_size" not in df:
            continue
        g = df.groupby("flow")["packet_size"].agg(["count", "mean", "sum"]).reset_index()
        g["arm"] = arm
        g["run"] = os.path.basename(run_dir)
        rows.append(g)
    if not rows:
        return None, None
    allrows = pd.concat(rows, ignore_index=True)

    # average across seeds within an arm
    per_flow = (allrows.groupby(["flow", "arm"])
                       .agg(n_msgs=("count", "mean"),
                            mean_bytes=("mean", "mean"),
                            total_bytes=("sum", "mean"))
                       .reset_index())

    wide = per_flow.pivot(index="flow", columns="arm", values="mean_bytes")
    wide = wide[[a for a in ARM_ORDER if a in wide.columns]]
    for a in ("classical", "pqc"):
        if a in wide.columns and "none" in wide.columns:
            wide[f"{a}_x"] = wide[a] / wide["none"].replace(0, pd.NA)

    totals = per_flow.pivot(index="flow", columns="arm", values="total_bytes")
    totals = totals[[a for a in ARM_ORDER if a in totals.columns]]
    return wide, totals


# --------------------------------------------------------------------------- #
# T3-T6 — crypto operation wall-clock cost
# --------------------------------------------------------------------------- #
def table_crypto_ops(runs):
    rows = []
    for run_dir, arm in runs:
        log = os.path.join(run_dir, "run.log")
        if not os.path.exists(log):
            continue
        acc = {}
        with open(log, "r", errors="ignore") as fh:
            for line in fh:
                if not line.startswith("[Latency]"):
                    continue
                m = LATENCY_RE.match(line.strip())
                if not m:
                    continue
                flow, op, ms = m.group(1), m.group(2), float(m.group(3))
                key = (flow, op)
                s, n, mx = acc.get(key, (0.0, 0, 0.0))
                acc[key] = (s + ms, n + 1, max(mx, ms))
        for (flow, op), (s, n, mx) in acc.items():
            rows.append({"arm": arm, "flow": flow, "op": op,
                         "n": n, "mean_ms": s / n, "max_ms": mx})
    if not rows:
        return None
    df = pd.DataFrame(rows)
    agg = (df.groupby(["flow", "op", "arm"])
             .agg(n=("n", "sum"), mean_ms=("mean_ms", "mean"), max_ms=("max_ms", "max"))
             .reset_index())
    wide = agg.pivot(index=["flow", "op"], columns="arm", values="mean_ms")
    return wide[[a for a in ARM_ORDER if a in wide.columns]]


# --------------------------------------------------------------------------- #
# T1/T2 — registration and authentication latency (simulated time)
# --------------------------------------------------------------------------- #
SPANS = {
    "registration":  ("reg_request", "reg_confirm"),
    "v2i_auth":      ("v2i_auth_hello", "v2i_auth_proof"),
    "chan_handshake": ("chan_hello", "chan_ack"),
}


def table_protocol_latency(runs):
    rows = []
    for run_dir, arm in runs:
        f = os.path.join(run_dir, "communication_log.csv")
        if not os.path.exists(f):
            continue
        df = pd.read_csv(f, on_bad_lines="skip")
        if "flow" not in df:
            continue
        for name, (a, b) in SPANS.items():
            s = df[df.flow == a].groupby("real_node_id").receive_time.min()
            e = df[df.flow == b].groupby("real_node_id").receive_time.min()
            j = (e - s).dropna()
            j = j[j >= 0]
            rows.append({"arm": arm, "phase": name, "n": len(j),
                         "mean_ms": j.mean() * 1000 if len(j) else float("nan"),
                         "p95_ms": j.quantile(.95) * 1000 if len(j) else float("nan")})
    if not rows:
        return None
    df = pd.DataFrame(rows)
    agg = (df.groupby(["phase", "arm"])
             .agg(n=("n", "sum"), mean_ms=("mean_ms", "mean"), p95_ms=("p95_ms", "mean"))
             .reset_index())
    return agg.pivot(index="phase", columns="arm", values=["n", "mean_ms"])


# --------------------------------------------------------------------------- #
# T7/S2 — revocation cost
# --------------------------------------------------------------------------- #
def table_revocation(runs):
    rows = []
    for run_dir, arm in runs:
        f = os.path.join(run_dir, "metrics_E1_revocation_cost.csv")
        if not os.path.exists(f):
            continue
        df = pd.read_csv(f)
        if df.empty:
            continue
        rows.append({"arm": arm, "run": os.path.basename(run_dir), "events": len(df),
                     "sign_us": df.authority_sign_us.mean(),
                     "total_us": df.total_us.mean(),
                     "manifest_bytes": df.manifest_bytes.mean(),
                     "isolation_bytes": df.isolation_bytes.mean()})
    if not rows:
        return None
    df = pd.DataFrame(rows)
    return arm_sort(df.groupby("arm").agg(
        events=("events", "sum"), sign_us=("sign_us", "mean"),
        total_us=("total_us", "mean"), manifest_bytes=("manifest_bytes", "mean"),
        isolation_bytes=("isolation_bytes", "mean")).reset_index())


# --------------------------------------------------------------------------- #
# C — network impact
# --------------------------------------------------------------------------- #
def table_network(runs):
    rows = []
    for run_dir, arm in runs:
        rec = {"arm": arm, "run": os.path.basename(run_dir)}
        pdr = os.path.join(run_dir, "metrics_M1_PDR.csv")
        lat = os.path.join(run_dir, "metrics_M2_Latency.csv")
        if os.path.exists(pdr):
            d = pd.read_csv(pdr)
            if not d.empty and "cumulative_PDR" in d:
                rec["final_PDR"] = d.cumulative_PDR.iloc[-1]
        if os.path.exists(lat):
            d = pd.read_csv(lat)
            if not d.empty:
                if "cumulative_avg_latency_ms" in d:
                    rec["avg_latency_ms"] = d.cumulative_avg_latency_ms.iloc[-1]
                if "cumulative_p95_latency_ms" in d:
                    rec["p95_latency_ms"] = d.cumulative_p95_latency_ms.iloc[-1]
        if len(rec) > 2:
            rows.append(rec)
    if not rows:
        return None
    df = pd.DataFrame(rows)
    return arm_sort(df.groupby("arm").mean(numeric_only=True).reset_index())


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="directory containing the run folders")
    ap.add_argument("--filter", dest="keyword", default=None,
                    help="only include run folders whose name contains this substring")
    ap.add_argument("--csv-out", default=None,
                    help="also write each table to <dir>/<table>.csv")
    args = ap.parse_args()

    runs = discover(args.root, args.keyword)
    if not runs:
        print(f"No runs with metrics_S_security_profile.csv under {args.root}.\n"
              "Runs made before the three-arm instrumentation landed do not carry it "
              "and cannot be compared — re-run them.", file=sys.stderr)
        return 1

    print(f"Found {len(runs)} run(s):")
    for d, a in runs:
        print(f"  [{a:9s}] {d}")
    print()

    tables = {
        "declared_sizes": ("Declared primitive sizes (bytes)", table_declared_sizes(runs)),
        "protocol_latency": ("T1/T2 — registration & authentication latency (simulated)",
                             table_protocol_latency(runs)),
        "crypto_ops": ("T3-T6 — crypto operation wall-clock cost (mean ms)",
                       table_crypto_ops(runs)),
        "revocation": ("T7/S2 — revocation cost", table_revocation(runs)),
        "network": ("C — network impact", table_network(runs)),
    }
    wide, totals = table_packet_bytes(runs)
    tables["packet_bytes_mean"] = ("S1 — mean bytes per message, by class", wide)
    tables["packet_bytes_total"] = ("S1 — total bytes per run, by class", totals)

    for name, (title, tbl) in tables.items():
        print("=" * 78)
        print(title)
        print("=" * 78)
        if tbl is None or (hasattr(tbl, "empty") and tbl.empty):
            print("  (no data — the metric did not fire in these runs)\n")
            continue
        print(tbl.to_string(float_format=lambda v: f"{v:,.3f}"))
        print()
        if args.csv_out:
            os.makedirs(args.csv_out, exist_ok=True)
            tbl.to_csv(os.path.join(args.csv_out, f"{name}.csv"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
