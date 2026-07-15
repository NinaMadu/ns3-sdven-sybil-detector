"""
Pre-flight HPC memory check — run BEFORE launching any of the three v2 notebooks.

Projects peak RAM for each model's data spine (streamed reads + window tensor) and
compares against available RAM, so you never repeat the earlier stall. Fast: it uses
file sizes + a sampled avg-row width + the shared KEEP_FRAC (no full-file scan).

    ml/.venv/bin/python ml/fusion/preflight_memory.py
    ml/.venv/bin/python ml/fusion/preflight_memory.py --scan   # exact kept-row counts (slow, reads all logs)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import identity_manifest as IDM

GB = 1024 ** 3


def avg_row_bytes(path, sample=100_000):
    b = n = 0
    with open(path, "rb") as fh:
        for i, line in enumerate(fh):
            if i == 0:
                continue
            b += len(line); n += 1
            if n >= sample:
                break
    return b / max(n, 1)


def est_rows(path):
    return os.path.getsize(path) / max(avg_row_bytes(path), 1)


def mem_available_gb():
    # MemAvailable correctly counts reclaimable page cache (the `free -h` "available"
    # column), unlike SC_AVPHYS_PAGES which is only the "free" column.
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024 / GB
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_AVPHYS_PAGES") / GB


# per-model window/tensor cost model
MODELS = {
    "GRU  (temporal_vehicle_tier)": dict(
        log="communication_log.csv", win_bytes=10 * 10 * 4,   # W×feat×f32
        step=1, copies=2.2, cap=18_000_000),
    "RSSI (rssi_vehicle_tier)": dict(
        log="rssi_verification_log.csv", win_bytes=2 * 10 * 4,
        step=1, copies=2.0, cap=18_000_000),
    "Trust (trust_vehicle_tier)": dict(
        log="vehicle_neighbor_table_log.csv", win_bytes=30 * 8,        # ~30 feat cols f64
        step=10, copies=1.5, cap=None),                                # tumbling + 1 run at a time
}
LIST_OVERHEAD = 1.9   # python list-of-ndarrays spike vs the final contiguous array


def main(scan=False):
    man = IDM.load_manifest()
    avail = mem_available_gb()
    print(f"Available RAM now: {avail:.1f} GB | KEEP_FRAC={IDM.KEEP_FRAC} | runs={[os.path.basename(d) for d in IDM.RUN_DIRS]}\n")
    print(f"{'model':30} {'kept rows':>12} {'windows':>12} {'read GB':>8} {'tensor GB':>10} {'peak GB':>8}  verdict")
    print("-" * 100)
    worst = 0.0
    for name, m in MODELS.items():
        kept_rows = 0
        for rd in IDM.RUN_DIRS:
            p = os.path.join(rd, m["log"])
            if not os.path.exists(p):
                continue
            if scan:
                claimed = "claimed_node_id" if "comm" in m["log"] else "observed_claimed_id"
                _, k = IDM.count_kept_rows(p, [claimed], claimed, os.path.basename(rd), man)
            else:
                k = est_rows(p) * IDM.KEEP_FRAC   # KEEP_FRAC of ids ≈ upper bound on kept-row frac
            kept_rows += k
        wins = kept_rows / m["step"]
        if m["cap"]:
            wins = min(wins, m["cap"])
        # streamed read peak ≈ chunk + kept DF (~kept_rows × ~15 cols × 5 B, one run at a time)
        read_gb = (IDM.READ_CHUNK * 15 * 8 + (kept_rows / len(IDM.RUN_DIRS)) * 15 * 5) / GB
        tensor_gb = wins * m["win_bytes"] * m["copies"] / GB
        build_spike = wins * m["win_bytes"] * LIST_OVERHEAD / GB   # list-of-arrays before np.stack
        peak = max(tensor_gb, build_spike) + read_gb
        worst = max(worst, peak)
        verdict = "OK" if peak < avail * 0.7 else ("TIGHT" if peak < avail * 0.9 else "RISK")
        print(f"{name:30} {kept_rows:12,.0f} {wins:12,.0f} {read_gb:8.1f} {tensor_gb:10.1f} {peak:8.1f}  {verdict}")
    print("-" * 100)
    head = avail - worst
    print(f"\nWorst-case single-model peak ≈ {worst:.1f} GB, headroom ≈ {head:.1f} GB "
          f"({'SAFE — run one notebook at a time' if head > 8 else 'LOW — lower MAX_WINDOWS or KEEP_FRAC'}).")
    print("Note: run the three notebooks SEQUENTIALLY (not concurrently); each frees before the next.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", action="store_true", help="exact kept-row counts (reads all logs; slow)")
    main(**vars(ap.parse_args()))
