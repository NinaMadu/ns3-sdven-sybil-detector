"""
Shared C++<->daemon contract for real-time full-mode detection (Phase 0).

ONE source of truth for the IPC message format and the per-window verdict schema,
imported by the Python daemon (ml/serve/rt_full_mode_daemon.py, Phase 2) and
mirrored by the C++ hook (scratch/llm_realtime_detection.h, Phase 4). Kept
dependency-free (stdlib only) so either side can import it without pulling torch.

Transport: Unix-domain stream socket, newline-delimited messages.

  daemon -> client   READY\n                 (once, after models are warm)
  client -> daemon   SCORE <t> [rsu=<id>] [ids=<csv>]\n
  daemon -> client   <verdict-json>\n  ...  END\n   (0+ verdict lines, then END)
  client -> daemon   SHUTDOWN\n

Blocking request/response: the single-threaded ns-3 sim sends SCORE and reads
until END while simulation time is frozen, so there is no concurrent log
read/write race (same safety property as the existing ml_realtime_detection.h
system() hook).

Causal windowing rule (fixed here so both sides agree):
  * an identity is scored at window time t only from rows with receive_time <= t
    (no future leakage);
  * it needs >= MIN_BEACONS beacons in [.., t] to be scorable (a DPM/temporal
    window needs >=2 observations) — fewer -> skipped this window;
  * the LAST verdict emitted for an identity over the run is its mature decision.
"""

import json

# ── socket + control tokens ──────────────────────────────────────────────────
DEFAULT_SOCK = "sybil-attack/outputs/rt_detect.sock"   # relative to ns-3 root
TOK_READY = "READY"
TOK_END = "END"
TOK_SHUTDOWN = "SHUTDOWN"
TOK_SCORE = "SCORE"

# ── causal windowing ─────────────────────────────────────────────────────────
MIN_BEACONS = 2            # identity needs >=2 causal beacons to be scorable

# ── verdict record schema (crosses the boundary; C++ mirrors these keys) ──────
# claimed_id        int    claimed vehicle identity
# window_start      float  sim-time t of the scoring window
# d                 int    1[verdict == sybil]  (the RSU-local detection vote)
# attack_type       str    7-class name (constants.CLASS_NAMES value)
# attack_type_id    int    0..6 (index; C++ maps this to SdvenSuspicionFlags in P5)
# confidence        str    "low"|"medium"|"high"
# y_hat_ens         float  Eq 3.20 RSU ensemble score (may be None)
# reason            str    agent-consensus reasoning (provenance / logging)
VERDICT_FIELDS = ("claimed_id", "window_start", "d", "attack_type",
                  "attack_type_id", "confidence", "y_hat_ens", "reason")


def verdict_line(claimed_id, window_start, d, attack_type, attack_type_id,
                 confidence, y_hat_ens=None, reason=""):
    """Serialize one verdict to a single newline-free JSON string."""
    return json.dumps({
        "claimed_id": int(claimed_id),
        "window_start": round(float(window_start), 3),
        "d": int(d),
        "attack_type": str(attack_type),
        "attack_type_id": int(attack_type_id),
        "confidence": str(confidence),
        "y_hat_ens": (None if y_hat_ens is None else round(float(y_hat_ens), 6)),
        "reason": str(reason),
    })


def parse_verdict(line):
    """Inverse of verdict_line."""
    return json.loads(line)


def parse_score_request(line):
    """Parse 'SCORE <t> [rsu=<id>] [ids=<csv>]' -> (t, rsu|None, ids|None)."""
    parts = line.strip().split()
    if not parts or parts[0] != TOK_SCORE:
        raise ValueError(f"not a SCORE request: {line!r}")
    t = float(parts[1])
    rsu, ids = None, None
    for tokn in parts[2:]:
        if tokn.startswith("rsu="):
            rsu = int(tokn[4:])
        elif tokn.startswith("ids="):
            ids = [int(x) for x in tokn[4:].split(",") if x != ""]
    return t, rsu, ids
