#!/usr/bin/env python3
"""Builds the S-SOTA-3 network-scalability sweep: mobility modes 10/11/12/13.

N_V in {100, 200, 300, 400} with RSUs = floor(64 * N_V / 200) = 32/64/96/128.
Population size is the ONLY variable: the road net (klbb2km.net.xml), the vTypes,
the rerouter hub set and the 50/10/10/10/10/10 % class mix are all mode 5's,
unchanged.

NESTING.  The route sets are strictly nested (100 subset 200 subset 300 subset
400) and all four levels come from ONE toolchain:

  * level 200 is regenerated from mode 5's own klbb2km.rou.xml (read verbatim,
    never written to) with mode 5's own keepalive, so it is mode 5's exact
    vehicle population -- but re-exported with the CURRENT SUMO.
    ####################################################################
    # WHY mobility_mode=11 does NOT just point at klbb2km_mobility.tcl #
    ####################################################################
    The committed klbb2km_mobility.tcl carries 259 contiguous ns-2 node ids
    even though klbb2km.rou.xml defines 200 vehicles and the committed
    klbb2km_fcd.xml contains exactly 200 distinct vehicle ids.  The 59 extra
    nodes are an artefact of the older traceExporter that produced that file;
    re-exporting the same FCD with SUMO 1.27 yields exactly 200.  Pointing the
    anchor at it would make sumoAutoConfig read N_Vehicles=259 and turn the
    S-SOTA-3 x-axis into 100/259/300/400.  So the anchor is regenerated here.
    Mode 5 itself is left completely alone and still uses the 259-node trace,
    so no existing baseline run changes behaviour.
  * levels 300 and 400 keep mode 5's 200 vehicles at their original ids 0..199
    and append fresh routes as ids 200+.  So node i is the same vehicle at
    N=200, 300 and 400.
  * level 100 is a per-class subset of mode 5's own 200 vehicles, taken in
    original id order, then recompacted to contiguous ids 0..99 (the ns-2 trace
    format requires contiguous node ids, so a subset cannot keep its ids).

Only the ADDED vehicles come from a fresh randomTrips draw (seed 43); the
inherited ones are mode 5's literal route strings.

The rerouter for levels 300/400 reuses mode 5's 60 destination hubs VERBATIM --
only the trigger-edge set is widened to cover edges the new routes touch, so the
added vehicles get re-destined like everyone else instead of driving off the map.
Changing the hub count would change the mobility character, so it is not done.
Level 100's routes are a subset of mode 5's, so it reuses mode 5's keepalive.

NOTHING in the parent directory is written to.

Usage:  python3 build_sota3_scale.py [--fcd-dir DIR] [--only 100,400]
"""
import argparse
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)                      # kuala-lumpur-bb/ (mode 5, read-only)
SUMO_HOME = os.environ.get("SUMO_HOME", "/usr/share/sumo")
RANDOM_TRIPS = os.path.join(SUMO_HOME, "tools", "randomTrips.py")
TRACE_EXPORTER = os.path.join(SUMO_HOME, "tools", "traceExporter.py")

SRC_NET = os.path.join(BASE, "klbb2km.net.xml")
SRC_ROU = os.path.join(BASE, "klbb2km.rou.xml")
SRC_VTYPES = os.path.join(BASE, "klbb2km_vtypes.add.xml")
SRC_KEEPALIVE = os.path.join(BASE, "klbb2km_keepalive.add.xml")

SIM_END = 300.0
STEP = 0.1
SEED_EXTRA = 43            # mode 5 used 42; a distinct seed for the ADDED vehicles
STEADY_FROM = 100.0

# class -> (SUMO vClass, share of N_V).  Mirrors mode 5's car100/bus20/van20/
# motorcycle20/lorry20/truck20 out of 200.
SPEC = OrderedDict([("car", ("passenger", 0.50)), ("bus", ("bus", 0.10)),
                    ("van", ("delivery", 0.10)), ("motorcycle", ("motorcycle", 0.10)),
                    ("lorry", ("truck", 0.10)), ("truck", ("truck", 0.10))])

ANCHOR_N = 200
LEVELS = [100, 200, 300, 400]
MAX_N = 400

# N_V -> (n_rsu, cols, rows).  Rectangular factorisation closest to square,
# centred on the net's 2454.78 x 2612.27 m bbox, same convention as the
# committed klbb2km_rsus_8x8.csv (x = W(i+0.5)/cols, y = H(j+0.5)/rows).
GRIDS = {100: (32, 8, 4), 200: (64, 8, 8), 300: (96, 12, 8), 400: (128, 16, 8)}

BBOX_W, BBOX_H = 2454.78, 2612.27


def quota(n_v):
    return {k: int(round(share * n_v)) for k, (_, share) in SPEC.items()}


def read_mode5_routes():
    """mode 5's 200 vehicles, in file order, as (type, edges)."""
    root = ET.parse(SRC_ROU).getroot()
    veh = []
    for v in root.findall("vehicle"):
        veh.append((v.get("type"), v.find("route").get("edges")))
    got = Counter(t for t, _ in veh)
    want = quota(ANCHOR_N)
    if len(veh) != ANCHOR_N or dict(got) != want:
        sys.exit(f"[anchor] klbb2km.rou.xml mix {dict(got)} != expected {want}")
    print(f"[anchor] mode 5: {len(veh)} vehicles, mix={dict(got)}")
    return veh


def gen_extra(vtype, vclass, need, tmpdir):
    """Fresh validated routes for the vehicles ADDED beyond mode 5's 200."""
    if need <= 0:
        return []
    over = max(need * 8, 40)
    rou = os.path.join(tmpdir, f"extra_{vtype}.rou.xml")
    cmd = [sys.executable, RANDOM_TRIPS, "-n", SRC_NET, "--vehicle-class", vclass,
           "--prefix", f"x{vtype}", "-o", os.path.join(tmpdir, f"extra_{vtype}.trips.xml"),
           "-r", rou, "-b", "0", "-e", "1", "--period", str(1.0 / over),
           "--intermediate", "3", "--fringe-factor", "5", "--speed-exponent", "2.0",
           "--validate", "--seed", str(SEED_EXTRA)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if not os.path.exists(rou):
        print(r.stderr[-1500:])
        sys.exit(f"randomTrips failed for {vtype}")
    routes = [v.find("route").get("edges") for v in ET.parse(rou).getroot().findall("vehicle")
              if v.find("route") is not None and v.find("route").get("edges")]
    if len(routes) < need:
        sys.exit(f"{vtype}: only {len(routes)} valid routes (< {need} needed)")
    print(f"[extra] {vtype:11s} need={need:3d} valid={len(routes)}")
    return routes[:need]


def build_route_pools(tmpdir):
    """Per-type ordered lists of length quota(400): mode 5's first, then new."""
    m5 = read_mode5_routes()
    pools = OrderedDict()
    q400 = quota(MAX_N)
    for vtype, (vclass, _) in SPEC.items():
        inherited = [e for t, e in m5 if t == vtype]
        need = q400[vtype] - len(inherited)
        pools[vtype] = inherited + gen_extra(vtype, vclass, need, tmpdir)
        assert len(pools[vtype]) == q400[vtype]
    return m5, pools


def write_routes(n_v, m5, pools):
    """Emit the level's .rou.xml.  Ids 0..199 stay mode 5's for n_v >= 200."""
    dst = os.path.join(HERE, f"klbb2km_n{n_v}.rou.xml")
    q = quota(n_v)
    anchor_count = Counter(t for t, _ in m5)
    if n_v >= ANCHOR_N:
        veh = list(m5)                                   # ids 0..199 preserved
        for vtype in SPEC:
            have = anchor_count[vtype]
            veh += [(vtype, e) for e in pools[vtype][have:q[vtype]]]
    else:
        taken = Counter()
        veh = []
        for vtype, edges in m5:                          # original order, recompacted
            if taken[vtype] < q[vtype]:
                veh.append((vtype, edges))
                taken[vtype] += 1
    got = Counter(t for t, _ in veh)
    if len(veh) != n_v or dict(got) != q:
        sys.exit(f"[routes {n_v}] got {len(veh)} {dict(got)}, want {n_v} {q}")

    with open(dst, "w") as f:
        f.write(f"<!-- S-SOTA-3 N_V={n_v}: generated by sota3_scale/build_sota3_scale.py.\n"
                f"     Vehicles 0..{min(n_v, ANCHOR_N) - 1} are mode 5's, verbatim. -->\n")
        f.write("<routes>\n")
        for vid, (vtype, edges) in enumerate(veh):
            f.write(f'  <vehicle id="{vid}" type="{vtype}" depart="0.00" '
                    f'departLane="best" departSpeed="0"><route edges="{edges}"/>'
                    f'<param key="has.rerouting.device" value="true"/></vehicle>\n')
        f.write("</routes>\n")
    print(f"[routes] {os.path.basename(dst)}: {n_v} vehicles, mix={dict(got)}")
    return dst, veh


def build_keepalive(all_veh):
    """Mode 5's 60 hubs verbatim; trigger set widened to the new routes' edges."""
    text = open(SRC_KEEPALIVE).read()
    hubs = re.findall(r'<destProbReroute id="([^"]+)"/>', text)
    triggers = set(re.search(r'edges="([^"]*)"', text).group(1).split())
    before = len(triggers)
    for _, edges in all_veh:
        triggers.update(edges.split())
    dst = os.path.join(HERE, "klbb2km_keepalive_n400.add.xml")
    with open(dst, "w") as f:
        f.write("<!-- S-SOTA-3: mode 5's 60 destination hubs, VERBATIM. Only the\n"
                "     trigger-edge set is widened so the added vehicles are also\n"
                "     re-destined instead of leaving the map. -->\n<additional>\n")
        f.write(f'  <rerouter id="keepalive" edges="{" ".join(sorted(triggers))}" '
                f'probability="1.0">\n    <interval begin="0" end="100000">\n')
        for h in hubs:
            f.write(f'      <destProbReroute id="{h}"/>\n')
        f.write("    </interval>\n  </rerouter>\n</additional>\n")
    print(f"[keepalive] {os.path.basename(dst)}: {len(hubs)} hubs (unchanged), "
          f"triggers {before} -> {len(triggers)}")
    return dst


def write_rsu_csv(n_v):
    n_rsu, cols, rows = GRIDS[n_v]
    assert cols * rows == n_rsu
    dst = os.path.join(HERE, f"klbb2km_rsus_{cols}x{rows}.csv")
    dx, dy = BBOX_W / cols, BBOX_H / rows
    with open(dst, "w") as f:
        f.write("rsu_id,x,y\n")
        rid = 0
        for j in range(rows):
            for i in range(cols):
                f.write(f"{rid},{dx * (i + 0.5):.2f},{dy * (j + 0.5):.2f}\n")
                rid += 1
    print(f"[rsu] {os.path.basename(dst)}: {n_rsu} RSUs {cols}x{rows}, "
          f"dx={dx:.2f} dy={dy:.2f}")
    return dst


def verify_anchor_csv():
    """The 8x8 grid we would generate must match the committed one exactly."""
    n_rsu, cols, rows = GRIDS[ANCHOR_N]
    dx, dy = BBOX_W / cols, BBOX_H / rows
    want = [f"{r},{dx * (r % cols + 0.5):.2f},{dy * (r // cols + 0.5):.2f}"
            for r in range(n_rsu)]
    have = [l.strip() for l in open(os.path.join(BASE, "klbb2km_rsus_8x8.csv"))
            if l.strip()][1:]
    if want != have:
        bad = next(i for i, (a, b) in enumerate(zip(want, have)) if a != b)
        sys.exit(f"[rsu] grid convention mismatch at row {bad}: {want[bad]!r} vs {have[bad]!r}")
    print(f"[rsu] convention check OK: regenerating 8x8 reproduces the committed CSV")


def run_sumo(n_v, rou, keepalive, fcd_dir):
    fcd = os.path.join(fcd_dir, f"klbb2km_n{n_v}_fcd.xml")
    tcl = os.path.join(HERE, f"klbb2km_n{n_v}_mobility.tcl")
    print(f"[sumo] N_V={n_v} ...", flush=True)
    r = subprocess.run(
        ["sumo", "-n", SRC_NET, "-r", rou,
         "--additional-files", f"{SRC_VTYPES},{keepalive}",
         "--fcd-output", fcd, "--begin", "0", "--end", str(SIM_END),
         "--step-length", str(STEP), "--time-to-teleport", "60",
         "--no-step-log", "true", "--max-depart-delay", "300"],
        capture_output=True, text=True)
    if not os.path.exists(fcd):
        print(r.stdout[-2000:], r.stderr[-2000:])
        sys.exit(f"sumo failed for N_V={n_v}")
    subprocess.run([sys.executable, TRACE_EXPORTER, "--fcd-input", fcd,
                    "--ns2mobility-output", tcl], check=True)
    return fcd, tcl, r.stdout.count("Teleporting")


def validate(n_v, fcd, tcl, teleports, rsu_csv):
    present, mean_speed, first_pos = {}, {}, {}
    for ts in ET.parse(fcd).getroot().findall("timestep"):
        t = round(float(ts.get("time")), 1)
        vs = ts.findall("vehicle")
        present[t] = len(vs)
        if vs:
            mean_speed[t] = sum(float(v.get("speed")) for v in vs) / len(vs)
        for v in vs:
            first_pos.setdefault(v.get("id"), (float(v.get("x")), float(v.get("y"))))

    steady = [t for t in sorted(present) if t >= STEADY_FROM]
    min_steady = min((present[t] for t in steady), default=0)
    mean_present = (sum(present[t] for t in steady) / len(steady)) if steady else 0.0
    ach = [mean_speed[t] for t in steady if t in mean_speed]
    achieved = sum(ach) / len(ach) if ach else 0.0
    warmup95 = next((t for t in sorted(present) if present[t] >= 0.95 * n_v), None)

    with open(tcl) as f:
        nodes = len(set(re.findall(r"\$node_\((\d+)\)", f.read())))

    rsus = [tuple(map(float, l.split(",")[1:3]))
            for l in open(rsu_csv).read().splitlines()[1:] if l.strip()]
    d = sorted(min(((x - rx) ** 2 + (y - ry) ** 2) ** 0.5 for rx, ry in rsus)
               for x, y in first_pos.values())
    med_d = d[len(d) // 2] if d else 0.0

    n_rsu, cols, rows = GRIDS[n_v]
    print(f"  [check N_V={n_v}] nodes={nodes} RSUs={len(rsus)} ({cols}x{rows})  "
          f"warmup95={warmup95}s  steady min/mean={min_steady}/{mean_present:.0f}  "
          f"achieved={achieved:.2f} m/s  end={max(present):.1f}s  teleports={teleports}")
    print(f"                  vehicle->nearest-RSU at spawn: median={med_d:.0f} m  "
          f"max={d[-1]:.0f} m  |  inter-RSU dx={BBOX_W/cols:.2f} dy={BBOX_H/rows:.2f}")
    if nodes != n_v:
        sys.exit(f"[check {n_v}] tcl has {nodes} nodes, expected {n_v}")
    if len(rsus) != n_rsu:
        sys.exit(f"[check {n_v}] RSU csv has {len(rsus)} rows, expected {n_rsu}")
    if max(present) < SIM_END - 1.0:
        sys.exit(f"[check {n_v}] trace ends at {max(present)}s")
    return dict(n_v=n_v, n_rsu=n_rsu, nodes=nodes, achieved=achieved,
                min_steady=min_steady, mean_present=mean_present, med_d=med_d,
                max_d=d[-1], dx=BBOX_W / cols, dy=BBOX_H / rows, teleports=teleports)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fcd-dir", default=os.environ.get("SOTA3_FCD_DIR", "/tmp"))
    ap.add_argument("--only", default="", help="comma-separated N_V subset")
    args = ap.parse_args()
    os.makedirs(args.fcd_dir, exist_ok=True)
    tmpdir = os.path.join(args.fcd_dir, "sota3_tmp")
    os.makedirs(tmpdir, exist_ok=True)

    for p in (SRC_NET, SRC_ROU, SRC_VTYPES, SRC_KEEPALIVE):
        if not os.path.exists(p):
            sys.exit(f"missing mode-5 input: {p}")

    verify_anchor_csv()
    m5, pools = build_route_pools(tmpdir)
    _, veh400 = write_routes(MAX_N, m5, pools)
    keepalive = build_keepalive(veh400)

    wanted = {int(x) for x in args.only.split(",") if x.strip()}
    results = []
    for n_v in LEVELS:
        if wanted and n_v not in wanted:
            continue
        print(f"\n=== S-SOTA-3  N_V={n_v}  RSUs={GRIDS[n_v][0]} ===")
        if n_v == ANCHOR_N:
            # Reuse the parent 8x8 CSV rather than duplicating it; verify_anchor_csv()
            # has already proven our grid convention reproduces it exactly.
            rsu_csv = os.path.join(BASE, "klbb2km_rsus_8x8.csv")
            print(f"[rsu] anchor reuses {os.path.relpath(rsu_csv, HERE)} (64 RSUs 8x8)")
        else:
            rsu_csv = write_rsu_csv(n_v)
        rou = os.path.join(HERE, f"klbb2km_n{n_v}.rou.xml")
        if n_v == MAX_N and os.path.exists(rou):
            pass
        else:
            rou, _ = write_routes(n_v, m5, pools)
        # Levels <= 200 are exactly mode 5's routes, so mode 5's own keepalive covers
        # every edge they touch; only 300/400 need the widened trigger set.
        ka = SRC_KEEPALIVE if n_v <= ANCHOR_N else keepalive
        fcd, tcl, tp = run_sumo(n_v, rou, ka, args.fcd_dir)
        results.append(validate(n_v, fcd, tcl, tp, rsu_csv))

    print("\n=== S-SOTA-3 summary ===")
    print(f"{'N_V':>5} {'RSUs':>5} {'nodes':>6} {'min_st':>7} {'achieved':>9} "
          f"{'med_d':>7} {'dx':>8} {'dy':>8}")
    for r in results:
        print(f"{r['n_v']:>5} {r['n_rsu']:>5} {r['nodes']:>6} {r['min_steady']:>7} "
              f"{r['achieved']:>9.2f} {r['med_d']:>6.0f}m {r['dx']:>7.2f}m {r['dy']:>7.2f}m")
    print("\nInter-RSU spacing shrinks as N_V grows (RSUs = 64*N_V/200), so registration\n"
          "coverage improves partly BECAUSE RSUs get closer, not only because the system\n"
          "scales. Report the dx/dy column with the results.")


if __name__ == "__main__":
    main()
