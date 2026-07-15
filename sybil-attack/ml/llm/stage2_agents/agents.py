"""
The three RSU-edge LLM agents (paper §3.4.3 / §4.6, "LLM Agent Architecture").

All three share ONE frozen base model and see the SAME shared context vector c_i
(Eq 3.31) — the specialization lives in each agent's ROLE prompt and in the
evidence its LoRA adapter is trained to emphasize when reasoning:

  a1  Message Pattern Detection Agent — beacon frequency / entropy / inter-arrival
      anomalies and RSSI signal–position consistency (feature + rssi tokens).
  a2  Trust Scoring Agent — the cumulative trust token T(i,t) with its
      signal / behaviour / history sub-scores and corroboration evidence.
  a3  Temporal Data Analyzer Agent — the temporal class-probability trajectory,
      RSSI time-series evolution, and mobility (v_rel, topology churn, handoff-sync).

Every agent emits the SAME JSON schema {verdict, attack_type, confidence,
reasoning} so a downstream binary decision d_a = 1[verdict==sybil] (Eq 3.21) and
the 7-class variant can be read off uniformly, then combined by the trust-weighted
consensus of Eq 3.22.
"""

_SCHEMA = (
    ' Respond ONLY with JSON: {"verdict": "legitimate"|"sybil", '
    '"attack_type": one of ["legitimate","outsider","sim","nonsim","indirect",'
    '"malicious_rsu","malicious_controller"], "confidence": "low"|"medium"|"high", '
    '"reasoning": "<one or two sentences citing the evidence>"}.'
)

_SHARED = (
    "You are one of three specialized Sybil-attack detection agents at an RSU edge "
    "server in a vehicular network. You receive the SAME shared context vector for "
    "one claimed vehicle identity over a short window (detector scores, per-attack "
    "signature scores, a cumulative trust token with signal/behaviour/history "
    "sub-scores, mobility measures, and the RSU ensemble score y_hat_ensemble). "
    "Weigh the whole context, but you are the specialist for "
)

AGENTS = {
    "a1": {
        "name": "Message Pattern Detection Agent",
        "focus": "message",
        "system": (
            _SHARED
            + "MESSAGE PATTERNS: beacon frequency, inter-arrival timing, entropy, and "
            "RSSI signal-vs-position consistency. Abnormal beacon cadence, duplicated "
            "or implausible signal patterns, and RSSI/position mismatch are your primary "
            "cues; a fast honest vehicle can still show shifting signal, so do not flag on "
            "mobility alone. Decide whether the identity is legitimate or which Sybil type "
            "it is." + _SCHEMA
        ),
    },
    "a2": {
        "name": "Trust Scoring Agent",
        "focus": "trust",
        "system": (
            _SHARED
            + "TRUST SCORING: the cumulative trust token T_composite and its T_RSSI / "
            "T_behav / T_hist sub-scores, plus corroboration evidence (identity lifetime, "
            "RSU report count, verified probability, controller trust). Low or collapsing "
            "trust, short identity lifetime, and weak RSU corroboration are your primary "
            "cues. Decide whether the identity is legitimate or which Sybil type it is."
            + _SCHEMA
        ),
    },
    "a3": {
        "name": "Temporal Data Analyzer Agent",
        "focus": "temporal",
        "system": (
            _SHARED
            + "TEMPORAL ANALYSIS: the temporal detector's per-class probability trajectory, "
            "RSSI time-series evolution, and mobility dynamics (relative velocity, topology "
            "churn, handoff-sync gap). Identity rotation over time, temporal-model class "
            "probabilities, and churn inconsistent with claimed motion are your primary "
            "cues. Decide whether the identity is legitimate or which Sybil type it is."
            + _SCHEMA
        ),
    },
}

AGENT_ORDER = ["a1", "a2", "a3"]


def concl(label):
    return {
        "legitimate": "Evidence is consistent with a genuine vehicle. Verdict: legitimate.",
        "outsider": "Foreign identity without corroboration. Verdict: outsider Sybil.",
        "sim": "Concurrent pseudonyms from one node. Verdict: simultaneous (sim) Sybil.",
        "nonsim": "Sequential pseudonym cycling. Verdict: non-simultaneous (nonsim) Sybil.",
        "indirect": "Anomaly relayed through a compromised node. Verdict: indirect Sybil.",
        "malicious_rsu": "RSU-tier fabrication of vehicle records. Verdict: malicious RSU.",
        "malicious_controller": "Control-plane fabrication. Verdict: malicious controller.",
    }.get(label, f"Verdict: '{label}'.")


def agent_reasoning(agent, label, ci):
    """Reasoning target emphasizing THIS agent's evidence, then the shared conclusion."""
    feat = ci.get("features", {})
    tr = ci.get("trust", {})
    mob = ci.get("mobility", {})
    ens = ci.get("y_hat_ensemble")
    parts = []

    if agent == "a1":  # message pattern: beacon + rssi + ensemble
        b = feat.get("beacon", {})
        if b:
            parts.append("Beacon pattern: " + ", ".join(f"{k}={v}" for k, v in b.items()) + ".")
        if "rssi" in feat:
            parts.append(f"RSSI signal-consistency detector p_sybil={feat['rssi']['p_sybil']:.3f}.")
        e = tr.get("evidence", {})
        if e.get("rssi_mismatch_frac", 0) > 0.3:
            parts.append(f"RSSI/position mismatch {e['rssi_mismatch_frac']:.2f}.")
        if not parts:
            parts.append("Message-pattern signals are within normal range.")

    elif agent == "a2":  # trust scoring
        tc = tr.get("T_composite")
        subs = [f"{k}={tr[k]:.3f}" for k in ("T_RSSI", "T_behav", "T_hist") if k in tr]
        if tc is not None:
            parts.append(f"Trust T_composite={tc:.3f}" + (f" ({', '.join(subs)})" if subs else "") + ".")
        e = tr.get("evidence", {})
        cues = []
        if e.get("identity_lifetime_s") is not None and e["identity_lifetime_s"] < 5:
            cues.append(f"short identity lifetime {e['identity_lifetime_s']:.1f}s")
        if e.get("rsu_report_count") is not None and e["rsu_report_count"] < 5:
            cues.append(f"weak RSU corroboration ({e['rsu_report_count']:.0f} reports)")
        if cues:
            parts.append("Corroboration: " + ", ".join(cues) + ".")
        if not parts:
            parts.append("Trust evidence is nominal.")

    else:  # a3 temporal
        t = feat.get("temporal", {})
        if t.get("p_sybil") is not None:
            tag = "high" if t["p_sybil"] > 0.6 else "low" if t["p_sybil"] < 0.4 else "mid"
            parts.append(f"Temporal detector p_sybil={t['p_sybil']:.3f} ({tag}), pred='{t.get('pred')}'.")
        if mob:
            parts.append(f"Mobility v_rel={mob.get('v_rel')}, churn={mob.get('topology_churn')} — "
                         + ("consistent with honest travel" if label == "legitimate"
                            else "inconsistent with claimed motion") + ".")
        if not parts:
            parts.append("Temporal trajectory shows no rotation anomaly.")

    if ens is not None:
        parts.append(f"RSU ensemble score={ens:.3f}.")
    parts.append(concl(label))
    return " ".join(parts)
