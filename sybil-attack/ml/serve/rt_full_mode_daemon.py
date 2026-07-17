"""
rt_full_mode_daemon.py — the persistent real-time full-mode Sybil detector.

Loads ALL trained models ONCE (3 vehicle-tier predictors on CPU + the 3 LoRA agents
on one warm GPU base), then answers per-window SCORE requests: score the run's logs
causally up to t, assemble one cᵢ (Eq 3.31), run the 3 agents (Eq 3.21) and the
frozen trust-weighted consensus (Eq 3.22), and emit a verdict per (claimed_id, window).

Chain per SCORE t:
  logs<=t → {GRU,RSSI,trust}.predict → build_context_live.assemble_ci (GRU-anchored,
  nullable) → build_messages → 3 agents (shared cᵢ, role prompts) → Eq 3.22 consensus
  → verdict rows (protocol.verdict_line).

Frozen params only (no runtime training): ω/θ from consensus_infer.load_config().
ŷ_ens/mobility are nullable enrichment (not wired yet). The heavy Python runs while the
single-threaded ns-3 sim BLOCKS on the socket, so there is no log read/write race.

Modes:
  --once <t>   score once against --run-dir, print verdicts (no socket) — for testing.
  --serve      Unix-socket server (protocol.py): READY, SCORE <t>, verdicts+END, SHUTDOWN.

Run in ml/.venv with TF_USE_LEGACY_KERAS=1 TOKENIZERS_PARALLELISM=false MPLBACKEND=Agg.
"""

import argparse
import importlib.util
import json
import os
import socket
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                                     # build_context_live, protocol
sys.path.insert(0, os.path.join(_HERE, "..", "fusion"))      # identity_manifest (snap_grid)
sys.path.insert(0, os.path.join(_HERE, "..", "llm", "common"))   # constants
sys.path.insert(0, os.path.join(_HERE, "..", "llm", "stage2_agents"))  # consensus_infer, agents

import build_context_live as BC          # noqa: E402
import ensemble_live as EL               # noqa: E402  (Eq 3.18 head + Eq 3.20 ŷ_ens)
import log_cache as LC                    # noqa: E402  (incremental tail reader)
import protocol as PROTO                 # noqa: E402
import consensus_infer as CI             # noqa: E402
import agents as A                       # noqa: E402
import constants as C                    # noqa: E402


def _load_predictor(name, relpath):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_HERE, "..", relpath))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _confidence(d_row, dg):
    """Consensus-strength confidence: unanimous -> high, split -> medium."""
    fired = int(d_row.sum())
    if dg == 1:
        return "high" if fired == 3 else "medium"
    return "high" if fired == 0 else "medium"


class Daemon:
    def __init__(self, run_dir, cap=None, carry_forward=True, tol=20.0,
                 batch=16, max_new=128, agent_device=0, max_identities=None,
                 window_margin=30.0):
        self.run_dir = run_dir
        self.run_id = os.path.basename(os.path.normpath(run_dir))
        self.cap = cap
        self.carry_forward = carry_forward
        self.tol = tol
        self.window_margin = window_margin     # bounded incremental windowing lookback (s)
        self.batch = batch
        self.max_new = max_new
        self.max_identities = max_identities   # cap rows scored per window (testing/throttle)
        self.last_t = float("-inf")

        t0 = time.time()
        print("[daemon] loading 3 vehicle-tier predictors (CPU) ...", flush=True)
        gru = _load_predictor("gru_predict", "analyzers/temporal_gru/predict.py")
        rssi = _load_predictor("rssi_predict", "analyzers/rssi_cnn/predict.py")
        trust = _load_predictor("trust_predict", "analyzers/vehicle_trust/predict.py")
        txgb = _load_predictor("txgb_predict", "analyzers/temporal_xgb_rsu/predict.py")
        rxgb = _load_predictor("rxgb_predict", "analyzers/rssi_xgb_rsu/predict.py")
        self.gru = gru.TemporalPredictor.load()
        self.rssi = rssi.RSSIPredictor.load()
        self.trust = trust.TrustPredictor.load()
        self.txgb = txgb.TemporalXGBPredictor.load()  # RSU-tier p̄_temp (Eq 3.19)
        self.rxgb = rxgb.RSSIXGBPredictor.load()       # RSU-tier p̄_rssi (Eq 3.19)
        self.head = EL.FusionHeadLive.load()          # Eq 3.18 head (weights, no refit)
        # ŷ_ens (Eq 3.20) now blends all 3 terms: ŷ_i + p̄_temp + p̄_rssi (λ 0.3/0.5/0.2).

        # incremental log caches: parse each physical log ONCE, then per-SCORE ingest
        # only the appended tail (kills the ~60 s/SCORE full re-read). comm feeds GRU +
        # temporal-XGB; rssi feeds the CNN + rssi-XGB (union cols); neighbor feeds trust.
        rd = self.run_dir
        self.comm_cache = LC.LogCache(os.path.join(rd, "communication_log.csv"),
                                      (lambda c: c in set(txgb.USE_COLS)), "receive_time", nrows=cap)
        _rssi_cols = set(rssi.RSSI_USE) | set(rxgb.RSSI_USE)   # CNN needs 5, XGB needs 7
        self.rssi_cache = LC.LogCache(os.path.join(rd, "rssi_verification_log.csv"),
                                      (lambda c: c in _rssi_cols), "time", nrows=cap)
        self.nb_cache = LC.LogCache(os.path.join(rd, trust.T.NEIGHBOR_LOG),
                                    (lambda c: c in trust.T.NEIGHBOR_COLS), "time", nrows=cap)

        print("[daemon] loading frozen consensus config + 3 LoRA agents (GPU) ...", flush=True)
        self.cfg = CI.load_config()
        self.tok, self.model = CI.load_agents(self.cfg["base"], self.cfg["adapters"],
                                              device=agent_device)
        self.sysmsg = {a: A.AGENTS[a]["system"] for a in A.AGENT_ORDER}
        print(f"[daemon] READY in {time.time() - t0:.0f}s "
              f"(θ={self.cfg['theta']}, ω={self.cfg['omega']})", flush=True)

    # -- the full chain for one scoring window -------------------------------
    def score(self, t, only_new=True, max_identities=None):
        max_identities = self.max_identities if max_identities is None else max_identities
        # ingest appended log tails; then take views. Bounded incremental windowing:
        # with only_new we only keep windows > last_t, so the SLICE-SAFE vehicle-tier
        # predictors (GRU/CNN/trust — their history features come from log columns, and
        # trust's T_hist recursion re-warms within the margin) window only the recent
        # slice [last_t - margin, t] instead of all history. The RSU temporal-XGB needs
        # full history (claimed-id age / beacons-so-far) but is cheap, so it gets upto(t).
        self.comm_cache.refresh(); self.rssi_cache.refresh(); self.nb_cache.refresh()
        lo = (self.last_t - self.window_margin) \
            if (only_new and self.last_t != float("-inf")) else float("-inf")
        comm_full = self.comm_cache.upto(t)
        if len(comm_full) == 0:
            return []
        comm_recent = self.comm_cache.between(lo, t)
        rssi_recent = self.rssi_cache.between(lo, t)
        nb_recent = self.nb_cache.between(lo, t)
        t_df = self.gru.score_logs(self.run_dir, t=t, run_id=self.run_id, rows=comm_recent)
        if len(t_df) == 0:
            return []
        r_df = self.rssi.score_logs(self.run_dir, t=t, run_id=self.run_id, rows=rssi_recent)
        # trust neighbor read cached (rows=); its internal rssi/consensus merges still
        # read from disk (capped) — a secondary follow-up to cache too.
        u_df = self.trust.score_logs(self.run_dir, t=t, run_id=self.run_id,
                                     nrows=self.cap, rows=nb_recent)
        # RSU-tier XGBs (Eq 3.19): p̄_temp from the comm log, p̄_rssi from the rssi log.
        # Both need full history (claimed-id age / observer stats) but are cheap.
        x_df = self.txgb.score_logs(self.run_dir, t=t, run_id=self.run_id, rows=comm_full)
        rssi_full = self.rssi_cache.upto(t)
        rx_df = self.rxgb.score_logs(self.run_dir, t=t, run_id=self.run_id, rows=rssi_full)
        pbar = []
        if len(x_df):
            pbar.append(x_df[["run_id", "claimed_node_id", "window_start_seconds", "p_bar_temp"]])
        if len(rx_df):
            pbar.append(rx_df[["run_id", "claimed_node_id", "window_start_seconds", "p_bar_rssi"]])
        ci = BC.assemble_ci(t_df, rssi=r_df, trust=u_df, extra=(pbar or None),
                            carry_forward=self.carry_forward,
                            tol=(self.tol if self.carry_forward else None))
        # Eq 3.18 ŷ_i (from live φ) + Eq 3.20 ŷ_ens = renorm(λ1·ŷ_i + λ2·p̄_temp + λ3·p̄_rssi)
        # over the terms present for each window (all 3 now wired).
        ci = EL.enrich(ci, head=self.head)
        if only_new:
            ci = ci[ci["window_start_seconds"] > self.last_t]
        self.last_t = max(self.last_t, t)
        if max_identities:
            ci = ci.head(max_identities)
        if len(ci) == 0:
            return []

        msgs = BC.build_messages(ci)
        contexts = [json.dumps(m["context"]) for m in msgs]

        # Eq 3.21 — three agents on the SAME contexts, distinct role prompt
        preds_by_agent = {}
        for a in A.AGENT_ORDER:
            self.model.set_adapter(a)
            prompts = [[{"role": "system", "content": self.sysmsg[a]},
                        {"role": "user", "content": ctx}] for ctx in contexts]
            preds, _, _ = CI.agent_generate(self.model, self.tok, prompts,
                                            self.batch, self.max_new)
            preds_by_agent[a] = preds

        # Eq 3.22 — frozen trust-weighted consensus + variant vote
        D, PT, CF = CI.build_decision_matrices(preds_by_agent, conf_w=self.cfg["conf_w"])
        Dg, yv = CI.consensus(D, PT, CF, self.cfg["omega"], self.cfg["theta"],
                              self.cfg["tie_break_idx"])

        verdicts = []
        for i, m in enumerate(msgs):
            at = yv[i]
            reason = self._reason(preds_by_agent, i, at, int(Dg[i]))
            yhe = m["context"].get("y_hat_ensemble")
            verdicts.append(PROTO.verdict_line(
                claimed_id=m["claimed_node_id"], window_start=m["window_start_seconds"],
                d=int(Dg[i]), attack_type=at, attack_type_id=C.class_id(at),
                confidence=_confidence(D[i], Dg[i]), y_hat_ens=yhe, reason=reason))
        return verdicts

    @staticmethod
    def _reason(preds_by_agent, i, at, dg):
        """Reasoning CONSISTENT with the consensus verdict: for a sybil verdict, a
        firing agent (matching the voted type if possible); for a legit verdict, a
        legit-voting agent. Falls back to a3."""
        want = "sybil" if dg == 1 else "legitimate"
        if dg == 1:
            for a in A.AGENT_ORDER:
                p = preds_by_agent[a][i]
                if p and p.get("verdict") == "sybil" and p.get("attack_type") == at:
                    return str(p.get("reasoning", ""))[:300]
        for a in A.AGENT_ORDER:
            p = preds_by_agent[a][i]
            if p and p.get("verdict") == want:
                return str(p.get("reasoning", ""))[:300]
        p3 = preds_by_agent["a3"][i]
        return str((p3 or {}).get("reasoning", ""))[:300]

    # -- socket server (protocol.py) -----------------------------------------
    def serve(self, sock_path):
        if os.path.exists(sock_path):
            os.remove(sock_path)
        os.makedirs(os.path.dirname(os.path.abspath(sock_path)), exist_ok=True)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)
        print(f"[daemon] listening on {sock_path}", flush=True)
        conn, _ = srv.accept()
        f = conn.makefile("rw")
        f.write(PROTO.TOK_READY + "\n")
        f.flush()
        try:
            while True:
                raw = f.readline()
                if not raw:                       # client closed
                    break
                line = raw.strip()
                if not line:
                    continue
                if line == PROTO.TOK_SHUTDOWN:
                    print("[daemon] shutdown", flush=True)
                    break
                if line.startswith(PROTO.TOK_SCORE):
                    t, _rsu, _ids = PROTO.parse_score_request(line)
                    t0 = time.time()
                    verdicts = self.score(t)
                    for v in verdicts:
                        f.write(v + "\n")
                    f.write(PROTO.TOK_END + "\n")
                    f.flush()
                    print(f"[daemon] SCORE {t}: {len(verdicts)} verdicts "
                          f"({time.time() - t0:.1f}s)", flush=True)
        finally:
            conn.close()
            srv.close()
            os.path.exists(sock_path) and os.remove(sock_path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True, help="run log dir to score")
    ap.add_argument("--sock", default=os.path.join(_HERE, "..", "..", "outputs", "rt_detect.sock"))
    ap.add_argument("--cap", type=int, default=None, help="nrows cap on raw log reads (testing)")
    ap.add_argument("--no-carry-forward", dest="carry_forward", action="store_false", default=True)
    ap.add_argument("--tol", type=float, default=20.0)
    ap.add_argument("--window-margin", type=float, default=30.0,
                    help="bounded incremental windowing lookback (s) for GRU/CNN/trust")
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--max-new", type=int, default=128)
    ap.add_argument("--once", type=float, default=None, help="score once at t and print (no socket)")
    ap.add_argument("--max-identities", type=int, default=None, help="cap rows scored (testing)")
    ap.add_argument("--serve", action="store_true")
    args = ap.parse_args()

    d = Daemon(args.run_dir, cap=args.cap, carry_forward=args.carry_forward,
               tol=args.tol, batch=args.batch, max_new=args.max_new,
               max_identities=args.max_identities, window_margin=args.window_margin)
    if args.once is not None:
        vs = d.score(args.once, only_new=False, max_identities=args.max_identities)
        print(f"\n=== {len(vs)} verdicts @ t={args.once} ===")
        for v in vs[:20]:
            print(v)
    elif args.serve:
        d.serve(args.sock)
    else:
        ap.error("choose --once <t> or --serve")


if __name__ == "__main__":
    main()
