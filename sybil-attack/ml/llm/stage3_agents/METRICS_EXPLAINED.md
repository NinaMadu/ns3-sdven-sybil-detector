# Evaluation metrics — what each number means

Every metric this experiment reports, explained in plain language, using the **real
numbers** from the completed H0 / LLM-FL run (`runs/H0_llm_fl_seed42/round_005/metrics.json`).

```json
{ "n_eval": 4000,
  "mcc_macro": 0.7794,          <- MCC-V  (variant-level)
  "binary_mcc": 0.9972,         <- binary (attack vs not)
  "fpr": 0.0004,
  "macro_f1": 0.5114,
  "per_class_recall": { ... },
  "json_valid_rate": 0.9998,
  "rc_mean": 0.9175 }
```

---

## 1. First: what is MCC?

**MCC = Matthews Correlation Coefficient.** It is a single score for "how good is this
classifier", on a scale:

```
 -1.0            0.0                      +1.0
  |---------------|------------------------|
 perfectly      random                  perfect
  wrong         guessing
```

**Why we use MCC instead of accuracy.** Our data is imbalanced — most vehicles are
legitimate. A lazy model that labels *everything* "legitimate" would score ~70%
accuracy and look decent, while catching **zero** attacks. MCC would score that model
**0.0** — correctly calling it worthless. MCC only goes high if the model gets *both*
the attacks and the legitimate vehicles right. That is why it is the paper's headline
metric.

---

## 2. The main confusion: binary MCC vs MCC-V

These are the **same MCC formula applied to two different questions.**

| | Question being asked | Number of classes | Our score |
|---|---|---|---|
| **Binary MCC** | "Is this vehicle an attacker, yes or no?" | 2 | **0.9972** |
| **MCC-V** (`mcc_macro`) | "*Which specific attack variant* is this?" | 7 | **0.7794** |

**"V" stands for Variant.** MCC-V is the stricter, variant-level score.

### Why binary is higher than MCC-V

Because identifying *that* something is an attack is much easier than identifying
*which kind* of attack it is. An example with one window:

- True label: `sim` (simultaneous Sybil)
- Model says: `nonsim` (non-simultaneous Sybil)

→ **Binary MCC: correct ✅** (it said "attack", and it *is* an attack)
→ **MCC-V: wrong ❌** (it named the wrong variant)

So our model almost never *misses* an attack (binary 0.997), but it sometimes confuses
*which type* of Sybil attack it is (MCC-V 0.779). Both numbers are real and both are
reported — binary shows detection strength, MCC-V shows diagnostic precision.

> **MCC-V is the headline metric for Ablation D1.** Binary MCC is reported alongside as
> a supporting summary.

---

## 3. The other metrics

### FPR — False Positive Rate → **0.0004**
Of all the genuinely **legitimate** vehicles, what fraction did we wrongly accuse?

```
FPR = legitimate vehicles flagged as attackers / all legitimate vehicles
```

0.0004 = about **4 in 10,000** honest vehicles falsely accused. This matters enormously
in a vehicular network — false alarms would eject innocent drivers from the network, so
low FPR is a safety requirement, not just a nicety.

### Per-class recall → e.g. `outsider: 0.8939`
Of all the windows that were *truly* class X, what fraction did we catch?

```
recall(X) = correctly identified X / all actual X
```

Our results:

| Variant | Recall | Reading |
|---|---|---|
| legitimate | 1.00 | we almost never mislabel honest vehicles |
| outsider | 0.89 | we catch 89% of outsider attacks |
| nonsim | 0.83 | strong |
| indirect | 0.71 | good |
| malicious_rsu | 0.43 | weaker — only ~120 training examples exist |
| sim | 0.41 | weaker — often confused with other variants |
| malicious_controller | 0.00 | **structural**: this is a control-plane attack that never appears in vehicle beacons, so vehicle-tier detectors cannot see it (handled at the RSU tier) |

This table is why we report per-class numbers: a single strong average must not hide a
weak class.

### Macro-F1 → **0.5114**
F1 is a balance of precision and recall. **Macro** means: compute F1 for each of the 7
classes, then average them **treating every class as equally important**, regardless of
how rare it is.

That is why it looks low (0.51) even though the model is strong: the two weak rare
classes (`sim`, `malicious_rsu`) and the impossible one (`malicious_controller`, which
scores 0) each count for a full 1/7 of the average, exactly the same as `legitimate`
which scores 1.00. It is a deliberately harsh, honest metric.

### JSON-valid rate → **0.9998**
LLM-specific reliability check. Our agents must reply in strict JSON
(`{"verdict":..., "attack_type":..., ...}`). This measures the fraction of replies that
actually parsed. 0.9998 = essentially every response was well-formed — the fine-tuning
successfully taught the output format.

### RC — Reasoning Consistency (Eq 3.74) → **0.9175**
Unique to the LLM approach: does the model's **written explanation** actually cite the
**right evidence** for the attack it detected?

```
attack case:      RC = (evidence cited that should be cited) / (evidence that should be cited)
legitimate case:  RC = 1 if no attack-evidence was cited, else 0
```

0.9175 means the explanations are ~92% consistent with the true underlying signature —
i.e. the model is not just guessing the right answer for the wrong reasons. This
supports the explainability claim.

---

## 4. Federation-specific metrics

### κ_conv (kappa_conv) — convergence round (Eq 3.73)
"At which round did the model stop improving?" Formally: the first round `T` where the
validation MCC-V over **5 consecutive rounds** varies by less than 0.001.

Our H0/LLM-FL curve:
```
round:      0      1       2       3      4       5
MCC-V:     0.0   0.6879  0.7318  0.7333  0.763  0.7794
                                                  ^ still rising
```
Result: **`"not converged by round 5"`**. The score was still climbing, so no 5-round
plateau existed. Reporting this honestly (rather than substituting the best round) is
required by the report's own rule.

### Ω_LLM-FL and ζ_LoRA — communication cost (Eq 3.71 / 3.72)
How much data must be transmitted each federation round.

| Quantity | Value | Meaning |
|---|---|---|
| `Ω_LLM-FL` | **55.4 MB** | what we actually transmit per round (3 agents × LoRA A/B matrices, bf16) |
| `Ω_full-weight` | **7,861 MB** | what it *would* cost to transmit full model weights |
| **`ζ_LoRA`** | **99.30%** | the saving — we transmit only 0.7% of a full-weight update |

We also record **measured** bytes (all 12 zone uploads + the global download to every
zone) alongside the analytical formula, so both the theoretical and the real network
figure are available.

---

## 5. Quick reference

| Metric | Question it answers | Good value | Ours |
|---|---|---|---|
| **Binary MCC** | Did we spot the attack at all? | → 1.0 | 0.9972 |
| **MCC-V** | Did we name the right attack variant? | → 1.0 | 0.7794 |
| **FPR** | How often do we accuse innocents? | → 0.0 | 0.0004 |
| **Per-class recall** | Do we catch *each* variant? | → 1.0 each | 0.00–1.00 |
| **Macro-F1** | Balanced score, all classes equal weight | → 1.0 | 0.5114 |
| **JSON-valid** | Did the LLM answer in valid format? | → 1.0 | 0.9998 |
| **RC** | Did it explain itself with the right evidence? | → 1.0 | 0.9175 |
| **κ_conv** | Which round did it converge? | lower = faster | not converged by 5 |
| **ζ_LoRA** | How much bandwidth did LoRA save? | → 100% | 99.30% |

## 6. Where each metric lives

```
runs/<exp>/round_<N>/metrics.json         MCC-V, binary MCC, FPR, macro-F1,
                                          per-class recall, JSON-valid, RC
runs/<exp>/history.json                   MCC-V curve across rounds + kappa_conv
runs/<exp>/round_<N>/communication.json   Omega, zeta_LoRA, measured bytes
runs/D1_results.md                        final collated table (all 4 experiments)
```
