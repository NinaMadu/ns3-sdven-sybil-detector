# Head refit (2026-08-05)

Re-fits the two frozen linear heads on current-distribution φ. **The encoders are not
touched** — the bi-GRU, RSSI CNN, trust MLP and every scaler are byte-identical to July.

## Why

The GRU encoder still works: a fresh probe on live `phi_temp` reaches MCC 0.906. The two
linear maps on top of it were fitted on July's φ cloud, which has since translated 3.74 in
L2 (training centroid norm: 1.884) because of our own sim changes — PQC wire overhead
(`packet_size` 120 → 3193), the `BindToNetDevice` beacon dedup (`observer_count` 46 → 1.7),
and the klbb2km map (`bsm_x/y` ~170 → ~1000). Linear separability survives translation; a
fixed decision boundary does not. Hence: refit the boundaries, keep the instrument.

## Result (held-out test identities, 297 identities / 1,666 windows)

| head | metric | OLD (July) | NEW (refit) |
|---|---|---:|---:|
| GRU softmax | binary MCC | −0.061 | **0.805** |
| GRU softmax | 7-class macro-MCC | −0.041 | **0.681** |
| GRU softmax | AUC of `1 − p_temp_0` | 0.274 | **0.977** |
| GRU softmax | mean `p_temp_0` on legitimate | 0.008 | **0.794** |
| Eq 3.18 fusion | binary MCC (ŷ_i ≥ 0.5) | 0.482 | **0.911** |
| Eq 3.18 fusion | AUC of ŷ_i | 0.845 | **0.991** |

Per-class MCC old → new: legitimate −0.061→0.805, outsider 0.009→0.636, sim −0.096→0.732,
nonsim −0.151→0.618, indirect 0.092→0.615.

## Using it (opt-in; default is unchanged)

```bash
export SYBIL_GRU_MODEL_DIR=<repo>/ml/analyzers/temporal_gru/outputs/temporal_vehicle_tier_refit_20260805
export SYBIL_FUSION_HEAD_WEIGHTS=<repo>/ml/fusion/outputs/fusion_head_weights_refit_20260805.json
```

**Revert: unset both variables.** Nothing was overwritten — with no env vars set, both
loaders resolve to the July files exactly as before (verified). These artifacts are
git-ignored, so a checksummed copy also sits in `ml/_prerefit_backup_20260805/`
(`sha256sum -c SHA256SUMS.txt`).

## Reproduce

```bash
ml/.venv/bin/python ml/refit/build_phi_dataset.py   # 6 runs -> outputs/phi_current.parquet
ml/.venv/bin/python ml/refit/refit_heads.py         # refit + old-vs-new report + export
```

Split is by **identity** (60/20/20, stratified per run), never by window — one identity's
overlapping windows are near-duplicates and would leak.

## Two known limits

1. **Classes 5/6 remain unlearnable at this tier.** Types 5 and 6 produce 0.00% vehicle-tier
   forgeries (the malicious entity is an RSU/controller, not a vehicle claiming a false ID),
   so there is no positive support. Their runs are still included as legitimate windows. The
   July model had the same structural gap (test support: malicious_controller 0).
2. **The scaler was deliberately left alone.** Its near-zero training variances are a real
   separate defect (`packet_size` var\_=0; `temp_id_change_flag` scale\_=0.00635, so one
   pseudonym change reads as z=157; `delay` scale\_=0.00179). φ is still ~28% saturated and
   the saturation half of the degeneracy warning still fires — correctly. Fixing the scaler
   changes φ itself and **invalidates this refit**, so do it second and then re-run both
   scripts.
