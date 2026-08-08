#!/usr/bin/env python3
# Builds mode-5 mobility for klbb2km: exactly 200 vehicles
# (car100 bus20 van20 motorcycle20 lorry20 truck20).
# Supervisor recommendations:
#   * roads >=60 km/h (netconvert --speed.minimum 16.67) + vType caps >=60.
#   * ALL 200 depart at t=0 (spawn together); spawn-in time = WARMUP.
#   * a REROUTER gives each vehicle a fresh random destination whenever it nears
#     one -> vehicles circulate forever -> 200 stay constant the whole sim.
#   * dynamic rerouting + 0.1 s trace resolution.
import os, subprocess, sys, xml.etree.ElementTree as ET, random
from collections import Counter

SUMO_HOME = os.environ["SUMO_HOME"]
RT  = os.path.join(SUMO_HOME, "tools", "randomTrips.py")
TE  = os.path.join(SUMO_HOME, "tools", "traceExporter.py")
NET = "klbb2km.net.xml"
VTYPES = "klbb2km_vtypes.add.xml"
KEEPALIVE = "klbb2km_keepalive.add.xml"

SIM_END = 300.0
STEP    = 0.1
SEED    = 42
N_HUBS  = 60              # spread-out destinations vehicles bounce between

SPEC = [("car","passenger",100),("bus","bus",20),("van","delivery",20),
        ("motorcycle","motorcycle",20),("lorry","truck",20),("truck","truck",20)]

random.seed(SEED)
veh = []                 # (type, edges_str)
edgesets = {}            # type -> set of edges it can use (from validated routes)
for vtype, vclass, count in SPEC:
    over = count * 6
    rou = f"/tmp/{vtype}.rou.xml"
    cmd = [sys.executable, RT, "-n", NET, "--vehicle-class", vclass, "--prefix", vtype,
           "-o", f"/tmp/{vtype}.trips.xml", "-r", rou, "-b","0","-e","1",
           "--period", str(1.0/over), "--intermediate","3",
           "--fringe-factor","5","--speed-exponent","2.0","--validate","--seed",str(SEED)]
    print(f"[gen] {vtype:11s} want={count} over={over}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if not os.path.exists(rou): print(r.stderr[-1500:]); sys.exit(f"randomTrips failed {vtype}")
    routes = [v.find("route").get("edges") for v in ET.parse(rou).getroot().findall("vehicle")
              if v.find("route") is not None and v.find("route").get("edges")]
    if len(routes) < count: sys.exit(f"{vtype}: only {len(routes)} valid (<{count})")
    veh += [(vtype, e) for e in routes[:count]]
    es=set()
    for e in routes: es.update(e.split())
    edgesets[vtype]=es
    print(f"      valid={len(routes)} -> kept {count}")

# ---- destination hubs: edges usable by the most-restrictive classes (bus &
#      truck) so ANY vehicle can route to them. Triggers = ALL travelled edges,
#      so every vehicle is redirected to a fresh hub long before it could exit. ----
hub_pool = sorted(edgesets["bus"] & edgesets["truck"] & edgesets["car"])
random.shuffle(hub_pool)
hubs = hub_pool[:N_HUBS]
triggers = sorted(set().union(*edgesets.values()))   # every edge any vehicle drives
print(f"[hubs] {len(hubs)} destinations, {len(triggers)} trigger edges")

with open(KEEPALIVE,"w") as f:
    f.write("<additional>\n")
    f.write(f'  <rerouter id="keepalive" edges="{" ".join(triggers)}" probability="1.0">\n')
    f.write(f'    <interval begin="0" end="100000">\n')
    for h in hubs: f.write(f'      <destProbReroute id="{h}"/>\n')
    f.write('    </interval>\n  </rerouter>\n</additional>\n')
print(f"[keepalive] wrote {KEEPALIVE}")

random.shuffle(veh)
with open("klbb2km.rou.xml","w") as f:
    f.write("<routes>\n")
    for vid,(vtype,edges) in enumerate(veh):
        f.write(f'  <vehicle id="{vid}" type="{vtype}" depart="0.00" departLane="best" departSpeed="0">'
                f'<route edges="{edges}"/>'
                f'<param key="has.rerouting.device" value="true"/></vehicle>\n')
    f.write("</routes>\n")
print(f"[routes] 200 vehicles all depart=0, mix={dict(Counter(v[0] for v in veh))}")

print("\n[sumo] running (0.1s, spawn@0, perpetual rerouter)...")
r = subprocess.run(["sumo","-n",NET,"-r","klbb2km.rou.xml",
     "--additional-files",f"{VTYPES},{KEEPALIVE}",
     "--fcd-output","klbb2km_fcd.xml","--begin","0","--end",str(SIM_END),
     "--step-length",str(STEP),"--time-to-teleport","60","--no-step-log","true",
     "--max-depart-delay","300"], capture_output=True, text=True)
print("  teleports:", r.stdout.count("Teleporting"), "| stderr:", r.stderr[-150:].replace("\n"," "))
subprocess.run([sys.executable,TE,"--fcd-input","klbb2km_fcd.xml",
                "--ns2mobility-output","klbb2km_mobility.tcl"], check=True)

present = {round(float(ts.get("time")),1): len(ts.findall("vehicle"))
           for ts in ET.parse("klbb2km_fcd.xml").getroot().findall("timestep")}
warmup = next((t for t in sorted(present) if present[t]>=200), None)
print(f"\n[done] peak concurrent = {max(present.values())}/200")
print(f"[WARMUP] all 200 present from t = {warmup} s" if warmup else "[WARMUP] never hit 200")
for t in [1,3,5,10,17,30,60,150,250,299]:
    print(f"    t={t:3d}s : {present.get(float(t),0):3d}")
