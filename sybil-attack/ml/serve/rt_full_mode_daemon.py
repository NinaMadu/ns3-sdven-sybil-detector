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
import csv
import importlib.util
import json
import math
import os
import socket
import sys
import time

import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                                     # build_context_live, protocol
sys.path.insert(0, os.path.join(_HERE, "..", "fusion"))      # identity_manifest (snap_grid)
sys.path.insert(0, os.path.join(_HERE, "..", "llm", "common"))   # constants
sys.path.insert(0, os.path.join(_HERE, "..", "llm", "stage2_agents"))  # consensus_infer, agents

import build_context_live as BC          # noqa: E402
import ensemble_live as EL               # noqa: E402  (Eq 3.18 head + Eq 3.20 ŷ_ens)
import log_cache as LC                    # noqa: E402  (incremental tail reader)
import mobility_live as ML               # noqa: E402  (Eq 3.31 {v_rel,rho_c,dt_sync})
import protocol as PROTO                 # noqa: E402
import consensus_infer as CI             # noqa: E402
import agents as A                       # noqa: E402
import constants as C                    # noqa: E402


# Lower-bound pad on the trust analyzer's rssi slice. Its as-of merge tolerance is 0.5 s
# (vehicle_trust/predict.py); padding wider than that guarantees a neighbor row sitting
# exactly at `lo` still sees an rssi row just below it, so the cached slice reproduces the
# full-history read exactly. -inf - pad is still -inf, so the uncapped path is unaffected.
RSSI_ASOF_TOL = 1.0

# C1 ablation (LLM tier vs ML-FL only): decision threshold on ŷ_ens for the
# mlfl_only condition. The report specifies "a scalar calibrated on the validation
# set"; ablation/C1/c1_llm_vs_mlfl.py performs that calibration offline and writes
# it to ablation/C1/results/mlfl_tau.json, which is read here so the in-sim
# condition uses the SAME scalar as the offline one. This constant is only the
# fallback when that file is absent; --mlfl-tau overrides both.
# Unused unless --ablate-llm mlfl_only is given.
MLFL_TAU_FALLBACK = 0.5
MLFL_TAU_FILE = os.path.join(_HERE, "..", "..", "ablation", "C1", "results", "mlfl_tau.json")


def _calibrated_mlfl_tau():
    """Read the val-calibrated tau written by the offline C1 scorer; fall back to
    MLFL_TAU_FALLBACK if it has not been run yet."""
    try:
        with open(MLFL_TAU_FILE) as f:
            return float(json.load(f)["tau"]), MLFL_TAU_FILE
    except (OSError, KeyError, ValueError, TypeError):
        return MLFL_TAU_FALLBACK, "built-in fallback (offline C1 not run)"


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
                 batch=64, max_new=128, agent_device=0, max_identities=None,
                 window_margin=30.0, ensemble_gate=0.5, max_llm_candidates=2000,
                 ablate_analyzer=None, ablate_stream=None, ablate_llm=None,
                 mlfl_tau=None, consensus_config=None, txgb_min_beacons=None,
                 agent_stage=None, temporal_gate=True):
        # Withhold the GRU's class tokens from the LLM prompt when the analyzer flags
        # itself degenerate. On by default; --no-temporal-gate restores the old
        # behaviour for A/B. Prompt-only — phi_temp still feeds Eq 3.18/3.20.
        self.temporal_gate = temporal_gate
        self.run_dir = run_dir
        self.run_id = os.path.basename(os.path.normpath(run_dir))
        self.cap = cap
        self.carry_forward = carry_forward
        self.tol = tol
        self.window_margin = window_margin     # bounded incremental windowing lookback (s)
        self.batch = batch
        self.max_new = max_new
        self.max_identities = max_identities   # hard ceiling on rows considered per window
        # Ensemble pre-filter (A): the cheap RSU-tier ŷ_ens gates the expensive 3-agent LLM.
        # Only identities the ensemble finds suspicious (ŷ_ens >= gate, or ŷ_ens missing)
        # are adjudicated by the agents; the rest are ensemble-cleared as legit with NO LLM
        # call — the paper's design (the LLM is the costly last stage over candidates only).
        self.ensemble_gate = ensemble_gate     # ŷ_ens threshold to become an LLM candidate
        self.max_llm_candidates = max_llm_candidates   # (B) top-K by ŷ_ens per window to LLM
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
        self._txgb_mod = txgb                          # module (for ingest_history)
        # D-stack contingency: the per-window two-beacon floor is what prevents p̄_temp
        # aggregating for short-lived v3 (non-simultaneous rotation) identities. Rebinding
        # the module global works because build_feature_table resolves it at call time.
        self.txgb_min_beacons = txgb.MIN_BEACONS_WINDOW
        if txgb_min_beacons is not None:
            if txgb_min_beacons < 1:
                raise ValueError("--txgb-min-beacons must be >= 1")
            txgb.MIN_BEACONS_WINDOW = int(txgb_min_beacons)
            self.txgb_min_beacons = int(txgb_min_beacons)
        self.rxgb = rxgb.RSSIXGBPredictor.load()       # RSU-tier p̄_rssi (Eq 3.19)
        # temporal-XGB incremental cumulative state: lets us feed a BOUNDED comm slice each
        # window yet keep claimed_id_age_s / beacons_so_far globally exact (see predict.py).
        self._txgb_first_seen = {}     # cid -> global earliest deduped-beacon receive_time
        self._txgb_cum = {}            # cid -> deduped-beacon count with time < _txgb_upto
        self._txgb_upto = float("-inf")  # cumulative state has folded in all beacons < this
        self.head = EL.FusionHeadLive.load()          # Eq 3.18 head (weights, no refit)
        # ŷ_ens (Eq 3.20) now blends all 3 terms: ŷ_i + p̄_temp + p̄_rssi (λ 0.3/0.5/0.2).
        # ── ablations (default None = the proposed pipeline, byte-identical to before) ──
        # B1: drop one vehicle-tier analyzer from the Eq 3.18 head (renormalised survivors).
        # B2: pin the Eq 3.20 λ to a single evidence stream. Both are inference-time only —
        # nothing is retrained, matching the offline b1_/b2_ scorers.
        # C1: "mlfl_only" removes the LLM tier altogether — no Eq 3.21 agents, no Eq 3.22
        # consensus. ŷ_ens (Eq 3.20) is thresholded directly at a scalar calibrated on the
        # val split (mlfl_tau). Upstream (analyzers, Eq 3.18 head, Eq 3.20 ensemble) is
        # untouched, which is what the report requires: "all upstream components are
        # identical across conditions".
        self.ablate_analyzer = ablate_analyzer
        self.ablate_stream = ablate_stream
        self.ablate_llm = ablate_llm
        # D5/D6: which LoRA adapter set the Eq 3.21 agents load. None = the frozen
        # Stage-2 CENTRALLY trained adapters (D5); a config path swaps in the Stage-3
        # LLM-FL federated adapters (D6) without touching anything upstream.
        # `agent_stage` is the NAMED form of the same switch ('2'/'3'/'stage3_h0'),
        # resolved against consensus_infer.AGENT_STAGES. The two are mutually
        # exclusive; load_config raises if both arrive. Only the adapters change —
        # role prompts, base, ω and θ are identical across stages.
        self.consensus_config = consensus_config
        self.agent_stage = agent_stage
        self.mlfl_only = (ablate_llm == "mlfl_only")
        if mlfl_tau is not None:
            self.mlfl_tau, self.mlfl_tau_src = float(mlfl_tau), "--mlfl-tau"
        else:
            self.mlfl_tau, self.mlfl_tau_src = _calibrated_mlfl_tau()
        if ablate_analyzer:
            self.head.ablate_block(ablate_analyzer)
        self.lam = EL.STREAM_LAMBDAS[ablate_stream] if ablate_stream else None

        # incremental log caches: parse each physical log ONCE, then per-SCORE ingest
        # only the appended tail (kills the ~60 s/SCORE full re-read). comm feeds GRU +
        # temporal-XGB; rssi feeds the CNN + rssi-XGB (union cols); neighbor feeds trust.
        rd = self.run_dir
        # comm_cache serves both temporal_xgb (USE_COLS) and the Eq 3.31 mobility tokens,
        # which additionally need observer_obu_id (absent from USE_COLS) for rho_c churn.
        _comm_cols = set(txgb.USE_COLS) | set(ML.MOBILITY_COLS)
        self.comm_cache = LC.LogCache(os.path.join(rd, "communication_log.csv"),
                                      (lambda c: c in _comm_cols), "receive_time", nrows=cap)
        # CNN needs 5, XGB needs 7, and the trust analyzer's RSSI as-of merge needs
        # T.RSSI_COLS — folding the union in here lets trust read the SAME cache instead
        # of re-parsing the (several-hundred-MB) rssi CSV from disk on every window.
        _rssi_cols = set(rssi.RSSI_USE) | set(rxgb.RSSI_USE) | set(trust.T.RSSI_COLS)
        self.rssi_cache = LC.LogCache(os.path.join(rd, "rssi_verification_log.csv"),
                                      (lambda c: c in _rssi_cols), "time", nrows=cap)
        self.nb_cache = LC.LogCache(os.path.join(rd, trust.T.NEIGHBOR_LOG),
                                    (lambda c: c in trust.T.NEIGHBOR_COLS), "time", nrows=cap)

        if self.mlfl_only:
            # No LLM tier in this condition: skip the GPU base + adapters entirely, so the
            # ML-FL-only run also reflects the real cost of dropping the LLM stage.
            self.cfg, self.tok, self.model, self.sysmsg = None, None, None, None
            print(f"[daemon] READY in {time.time() - t0:.0f}s "
                  f"(C1 ABLATION mlfl_only: LLM tier DISABLED, no agents loaded; "
                  f"ŷ_ens thresholded at τ={self.mlfl_tau} (from {self.mlfl_tau_src}); "
                  f"ablate_analyzer={self.ablate_analyzer or 'none'}, "
                  f"ablate_stream={self.ablate_stream or 'tuned-lambda'}, "
                  f"txgb_min_beacons={self.txgb_min_beacons})",
                  flush=True)
        else:
            print("[daemon] loading frozen consensus config + 3 LoRA agents (GPU) ...", flush=True)
            self.cfg = CI.load_config(self.consensus_config, stage=self.agent_stage)
            self.tok, self.model = CI.load_agents(self.cfg["base"], self.cfg["adapters"],
                                                  device=agent_device)
            self.sysmsg = {a: A.AGENTS[a]["system"] for a in A.AGENT_ORDER}
            print(f"[daemon] READY in {time.time() - t0:.0f}s "
                  f"(θ={self.cfg['theta']}, ω={self.cfg['omega']}; "
                  f"ensemble_gate={self.ensemble_gate}, max_llm_candidates={self.max_llm_candidates}; "
                  f"ablate_analyzer={self.ablate_analyzer or 'none'}, "
                  f"ablate_stream={self.ablate_stream or 'tuned-lambda'}, "
                  f"txgb_min_beacons={self.txgb_min_beacons}; "
                  f"agent_stage={self.cfg['stage']}; "
                  f"consensus_config={self.consensus_config or 'FROZEN_DEFAULTS (central)'}; "
                  f"adapters={ {a: os.path.join(*p.split(os.sep)[-2:]) for a, p in self.cfg['adapters'].items()} })",
                  flush=True)

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
        # trust reads BOTH its logs from cache now (neighbor via rows=, rssi via
        # rssi_rows=). The rssi slice is padded below `lo` by RSSI_ASOF_TOL so the 0.5 s
        # as-of merge sees every match the old full-history disk read would have — the
        # bounded slice is exactly equivalent, not an approximation. Only the tiny
        # (~200 KB) consensus logs are still read from disk per window.
        rssi_trust = self.rssi_cache.between(lo - RSSI_ASOF_TOL, t)
        u_df = self.trust.score_logs(self.run_dir, t=t, run_id=self.run_id,
                                     nrows=self.cap, rows=nb_recent, rssi_rows=rssi_trust)
        # RSU-tier XGBs (Eq 3.19): p̄_temp from the comm log, p̄_rssi from the rssi log.
        # Both are now BOUNDED-incremental like the vehicle-tier models. rssi-XGB features are
        # all window-local → the recent slice suffices. temporal-XGB has two cumulative features
        # (age, beacons-so-far); we advance a running first_seen/count over the gap since the
        # last slice start and inject them, so the bounded slice stays globally exact.
        if only_new and lo != float("-inf"):
            gap = self.comm_cache.between(self._txgb_upto, lo)   # beacons since last slice start
            self._txgb_mod.ingest_history(gap, self._txgb_first_seen, self._txgb_cum, lo)
            self._txgb_upto = lo
            # anchor the window grid to the GLOBAL earliest beacon (not the slice's) so bounded
            # windows land on the same grid the full-history run used.
            anchor = (float(math.floor(min(self._txgb_first_seen.values())))
                      if self._txgb_first_seen else None)
            x_df = self.txgb.score_logs(self.run_dir, t=t, run_id=self.run_id, rows=comm_recent,
                                        first_seen_override=self._txgb_first_seen,
                                        cum_before=self._txgb_cum, grid_anchor=anchor)
        else:
            x_df = self.txgb.score_logs(self.run_dir, t=t, run_id=self.run_id, rows=comm_full)
        rx_df = self.rxgb.score_logs(self.run_dir, t=t, run_id=self.run_id, rows=rssi_recent)
        pbar = []
        if len(x_df):
            pbar.append(x_df[["run_id", "claimed_node_id", "window_start_seconds", "p_bar_temp"]])
        if len(rx_df):
            pbar.append(rx_df[["run_id", "claimed_node_id", "window_start_seconds", "p_bar_rssi"]])
        # Eq 3.31 mobility tokens {v_rel, rho_c, dt_sync} from the same bounded comm slice.
        mob_df = ML.build_mobility_live(comm_recent, self.run_id)
        ci = BC.assemble_ci(t_df, rssi=r_df, trust=u_df, mobility=mob_df, extra=(pbar or None),
                            carry_forward=self.carry_forward,
                            tol=(self.tol if self.carry_forward else None))
        # Eq 3.18 ŷ_i (from live φ) + Eq 3.20 ŷ_ens = renorm(λ1·ŷ_i + λ2·p̄_temp + λ3·p̄_rssi)
        # over the terms present for each window (all 3 now wired).
        ci = EL.enrich(ci, head=self.head, lam=self.lam)
        if only_new:
            ci = ci[ci["window_start_seconds"] > self.last_t]
        self.last_t = max(self.last_t, t)
        if max_identities:
            ci = ci.head(max_identities)
        if len(ci) == 0:
            return []

        # ── C1 ablation: ML-FL only — threshold ŷ_ens, no LLM tier ──────────────
        # Condition (ii) of C1: the Eq 3.20 ensemble score IS the decision. No agents,
        # no consensus, no top-K gating (the gate exists only to bound LLM cost, which
        # is zero here). Rows with a missing ŷ_ens cannot be decided by this condition
        # and are emitted d=0, matching the offline scorer's treatment.
        if self.mlfl_only:
            # A bare threshold on ŷ_ens is a BINARY detector: it yields no attack
            # variant. Seven-class classification is exactly what the LLM tier adds
            # (report §5.2), so this condition must not invent one. A positive is
            # therefore labelled "sybil_unclassified" / id -1 — deliberately outside
            # the 0..6 label space so it can never be mistaken for legitimate(0) or
            # for a real variant. attack_type_id is log-only in the .cc (the verdict
            # sink drives off d), so this affects reporting, not detection.
            verdicts = []
            for _, r in ci.iterrows():
                y = r.get("y_hat_ens")
                has_y = y is not None and not pd.isna(y)
                d = int(has_y and float(y) >= self.mlfl_tau)
                verdicts.append(PROTO.verdict_line(
                    claimed_id=int(r["claimed_node_id"]),
                    window_start=float(r["window_start_seconds"]),
                    d=d,
                    attack_type=("sybil_unclassified" if d else "legitimate"),
                    attack_type_id=(-1 if d else C.class_id("legitimate")),
                    confidence="medium",
                    y_hat_ens=(float(y) if has_y else None),
                    reason=f"C1 mlfl_only: y_hat_ens="
                           f"{f'{float(y):.3f}' if has_y else 'nan'}"
                           f" vs tau={self.mlfl_tau} (no LLM tier, no variant class)"))
            return verdicts

        # ── Ensemble pre-filter (A) + bounded LLM (B) ────────────────────────────
        # Split ci by the cheap ŷ_ens: below the gate → ensemble-cleared (d=0, no LLM);
        # at/above the gate (or ŷ_ens missing) → LLM candidate. Among candidates only the
        # top-K by ŷ_ens are adjudicated by the agents; any overflow in an overloaded
        # window is emitted d=0 with a warning (never auto-revoked without LLM — keeps the
        # P4 FP-safety contract). This turns a hundreds-of-identities LLM pass into a
        # bounded top-K pass, which is what makes full-scale trace runs tractable.
        yhe = ci["y_hat_ens"] if "y_hat_ens" in ci.columns else None
        if yhe is None:
            cand_mask = ci.index == ci.index          # no ensemble at all → all candidates
        else:
            cand_mask = (yhe >= self.ensemble_gate) | yhe.isna()
        cleared = ci[~cand_mask]
        cand = ci[cand_mask]
        if yhe is not None and len(cand):
            cand = cand.sort_values("y_hat_ens", ascending=False, na_position="first")
        overflow = cand.iloc[self.max_llm_candidates:] if self.max_llm_candidates else cand.iloc[0:0]
        cand = cand.iloc[:self.max_llm_candidates] if self.max_llm_candidates else cand
        if len(overflow):
            print(f"[daemon] WARNING: {len(overflow)} candidate(s) over LLM cap "
                  f"({self.max_llm_candidates}) at t={t} — emitted d=0 (raise "
                  f"--max-llm-candidates or --ensemble-gate)", flush=True)

        # ensemble-cleared + overflow → cheap d=0 verdicts, no LLM
        verdicts = self._skip_verdicts(cleared, reason="ensemble<gate: LLM skipped")
        verdicts += self._skip_verdicts(overflow, reason="LLM cap exceeded: deferred")
        if len(cand) == 0:
            return verdicts

        msgs = BC.build_messages(cand, gate_degenerate_temporal=self.temporal_gate)
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

    def _skip_verdicts(self, df, reason):
        """Emit d=0 (legitimate) verdicts for rows the LLM did NOT adjudicate — the
        ensemble-cleared majority and any over-cap overflow. No agent calls; the ŷ_ens
        is carried through so the CSV/metrics still record why the id was cleared."""
        out = []
        if df is None or len(df) == 0:
            return out
        for _, r in df.iterrows():
            yhe = r.get("y_hat_ens")
            try:
                yhe = float(yhe)
            except (TypeError, ValueError):
                yhe = None
            out.append(PROTO.verdict_line(
                claimed_id=int(r["claimed_node_id"]),
                window_start=float(r["window_start_seconds"]),
                d=0, attack_type="legitimate", attack_type_id=C.class_id("legitimate"),
                confidence="high", y_hat_ens=yhe, reason=reason))
        return out

    # -- reasoning sidecar ----------------------------------------------------
    def _log_reasoning(self, t, verdicts):
        """Persist each verdict's generated reasoning to <run_dir>/full_mode_reasoning.csv.

        RC (Eq 3.74) scores the MODEL'S OWN reasoning against the signature vocabulary, so
        it needs the generated string. The C++ verdict sink parses only the decision fields
        out of the socket JSON and drops `reason`, and its CSV schema has other consumers —
        hence a sidecar rather than a schema change. Written by the daemon, keyed the same
        way (claimed_id, window_start) so it joins straight onto full_mode_verdicts.csv.

        Skipped entirely for mlfl_only: there is no LLM, so there is no reasoning to score
        and an empty-reason file would make RC look like 0 rather than n/a.
        """
        if self.mlfl_only or not verdicts:
            return
        path = os.path.join(self.run_dir, "full_mode_reasoning.csv")
        new = not os.path.exists(path)
        try:
            with open(path, "a", newline="") as fh:
                w = csv.writer(fh)
                if new:
                    w.writerow(["score_time", "claimed_id", "window_start", "d",
                                "attack_type_id", "attack_type", "confidence",
                                "y_hat_ens", "reason"])
                for v in verdicts:
                    try:
                        d = PROTO.parse_verdict(v)
                    except (ValueError, TypeError):
                        continue
                    w.writerow([f"{t:.3f}", d["claimed_id"], d["window_start"], d["d"],
                                d["attack_type_id"], d["attack_type"], d["confidence"],
                                "" if d["y_hat_ens"] is None else d["y_hat_ens"],
                                d["reason"]])
        except OSError as e:
            # Never let a sidecar write failure take down a scoring window.
            print(f"[daemon] WARNING: reasoning sidecar write failed: {e}", flush=True)

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
                    self._log_reasoning(t, verdicts)
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
    ap.add_argument("--batch", type=int, default=64,
                    help="LLM generation batch size (measured sweet spot on RTX 5090; "
                         "16->64 ~1.9x throughput, 64->96 only +11%%)")
    ap.add_argument("--max-new", type=int, default=128)
    ap.add_argument("--once", type=float, default=None, help="score once at t and print (no socket)")
    ap.add_argument("--max-identities", type=int, default=None, help="hard ceiling on rows/window")
    ap.add_argument("--ensemble-gate", type=float, default=0.5,
                    help="ŷ_ens threshold to send an identity to the LLM (below = ensemble-cleared d=0)")
    ap.add_argument("--max-llm-candidates", type=int, default=2000,
                    help="max identities/window adjudicated by the 3 agents (top-K by ŷ_ens); "
                         "effectively uncapped at this scale — a low cap throttles recall "
                         "(cap=48 gave in-sim recall 0.19 vs 0.96 uncapped)")
    ap.add_argument("--ablate-analyzer", default=None,
                    help="zero one or more vehicle-tier φ-blocks in the Eq 3.18 head and "
                         "renormalise the survivors. A single name (B1 leave-one-out: "
                         "trust|rssi|temp) or a comma-separated subset (D-stack ladder: "
                         "'rssi,trust' = temporal-GRU-only). Omit = full head")
    ap.add_argument("--ablate-stream", default=None,
                    choices=list(EL.STREAM_LAMBDAS),
                    help="ablation B2: pin the Eq 3.20 λ to one evidence stream "
                         "(omit = jointly-tuned λ)")
    ap.add_argument("--ablate-llm", default=None, choices=["mlfl_only"],
                    help="ablation C1: drop the LLM tier — no Eq 3.21 agents, no Eq 3.22 "
                         "consensus; threshold ŷ_ens directly (omit = full LLM tier)")
    ap.add_argument("--mlfl-tau", type=float, default=None,
                    help=f"C1 mlfl_only decision threshold on ŷ_ens "
                         f"(default: read from ablation/C1/results/mlfl_tau.json, else "
                         f"{MLFL_TAU_FALLBACK}; calibrated on the val split by "
                         f"ablation/C1/c1_llm_vs_mlfl.py)")
    ap.add_argument("--agent-stage", default=None,
                    choices=sorted(set(CI.STAGE_ALIASES)),
                    help="LLM AGENT SHIFTER: select the Eq 3.21 agents' LoRA adapter set "
                         "by NAME. '2'/'stage2' = Stage-2 CENTRALLY trained (default, D5); "
                         "'3'/'stage3' = Stage-3 LLM-FL FEDERATED, Hmax partition (D6); "
                         "'stage3_h0' = the H0/IID federated contingency set. Only the "
                         "adapters change — base model, the three role prompts, ω, θ and "
                         "the confidence weights are identical across stages. Mutually "
                         "exclusive with --consensus-config. Omit = Stage-2")
    ap.add_argument("--consensus-config", default=None,
                    help="path to a consensus config JSON overriding the frozen Stage-2 "
                         "deployment defaults — chiefly `adapters` (a1/a2/a3 LoRA paths) "
                         "and ω/θ. Used by the D-stack ladder to swap the CENTRALLY "
                         "trained adapters (D5, the default) for the Stage-3 LLM-FL "
                         "federated ones (D6). Prefer --agent-stage for the plain "
                         "Stage-2/Stage-3 switch; this stays for bespoke configs that "
                         "also move ω/θ. Omit = FROZEN_DEFAULTS")
    ap.add_argument("--txgb-min-beacons", type=int, default=None,
                    help="override the RSU temporal-XGB per-window minimum deduped-beacon "
                         "count (default 2). Lowering to 1 restores p̄_temp coverage for "
                         "short-lived v3 rotation identities that never emit 2 beacons in "
                         "one window")
    ap.add_argument("--no-temporal-gate", dest="temporal_gate", action="store_false",
                    default=True,
                    help="keep feeding the LLM the GRU's class tokens even when the "
                         "analyzer reports itself degenerate (pre-2026-08-05 behaviour; "
                         "for A/B only)")
    ap.add_argument("--serve", action="store_true")
    args = ap.parse_args()
    # Fail before the (expensive) predictor load rather than after: both switches name
    # the adapter set, so accepting both would silently honour one and drop the other.
    if args.agent_stage and args.consensus_config:
        ap.error("--agent-stage and --consensus-config both select the LoRA adapter set; "
                 "pass only one")
    if args.agent_stage and args.ablate_llm == "mlfl_only":
        ap.error("--agent-stage is meaningless with --ablate-llm mlfl_only (that condition "
                 "loads no LLM agents at all)")

    d = Daemon(args.run_dir, cap=args.cap, carry_forward=args.carry_forward,
               tol=args.tol, batch=args.batch, max_new=args.max_new,
               max_identities=args.max_identities, window_margin=args.window_margin,
               ensemble_gate=args.ensemble_gate, max_llm_candidates=args.max_llm_candidates,
               ablate_analyzer=args.ablate_analyzer, ablate_stream=args.ablate_stream,
               ablate_llm=args.ablate_llm, mlfl_tau=args.mlfl_tau,
               consensus_config=args.consensus_config,
               temporal_gate=args.temporal_gate,
               txgb_min_beacons=args.txgb_min_beacons,
               agent_stage=args.agent_stage)
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
