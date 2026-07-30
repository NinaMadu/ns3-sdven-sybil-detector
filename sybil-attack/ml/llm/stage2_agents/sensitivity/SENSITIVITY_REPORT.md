# Stage-2 LLM sensitivity analysis (Table 4.9)

- base model: `Qwen/Qwen2.5-1.5B-Instruct`
- swept agent: **a2** (Trust Scoring Agent)
- train subsample: 10000 | val subsample: 2000
- primary metric: **macro-F1 over 6 classes**, excluding `malicious_controller` (structurally empty at this tier)

## Noise floor

Baseline trained at seeds [42, 43, 44]: macro_f1_6cls = [0.919, 0.9798, 0.9273], **sigma = 0.03297**.
Differences smaller than 2.0*sigma = 0.06594 are NOT interpretable.

## Selection

Rule (pre-registered): lowest deployment cost (adapter MB, then latency, then VRAM) among configs within 2.0 noise-SD of the best macro_f1_6cls.

Best macro_f1_6cls 0.9895; acceptance band >= 0.92356; 6 configs eligible.

**Selected: `p0:baseline_seed43`** — `{"dropout": 0.05, "eff_batch": 16, "epochs": 2, "lr": 0.0002, "max_len": 1024, "max_new": 128, "quant": "bf16", "r": 8, "target": "all"}`

## All runs

| Config | macroF1-6 | binMCC | JSON | lat ms | tok/s | VRAM GB | adpt MB | train s |
|---|---|---|---|---|---|---|---|---|
| p0:baseline | 0.919 | 0.9978 | 1.0 | 157.4 | 742.6 | 4.7 | 52.9 | 1631.7 |
| p0:baseline_seed43 | 0.9798 | 0.9989 | 1.0 | 158.6 | 737.0 | 4.7 | 52.9 | 1586.3 |
| p0:baseline_seed44 | 0.9273 | 0.9989 | 1.0 | 159.0 | 735.2 | 4.7 | 52.9 | 1586.3 |
| p1:max_new-128 | 0.9975 | 1.0 | 1.0 | 161.9 | 722.1 | 4.69 | 307.2 |  |
| p1:max_new-32 | 0.1314 | 0.0 | 0.0 | 53.7 | 595.5 | 4.69 | 307.2 |  |
| p1:max_new-64 | 0.1369 | 0.0611 | 0.0025 | 89.8 | 712.4 | 4.69 | 307.2 |  |
| p2:dropout-0.0 | 0.9027 | 0.9978 | 1.0 | 166.8 | 700.7 | 4.7 | 52.9 | 1723.0 |
| p2:dropout-0.1 | 0.9022 | 0.9989 | 1.0 | 169.4 | 690.2 | 4.7 | 52.9 | 1714.1 |
| p2:effbatch-32 | 0.5251 | 0.9945 | 1.0 | 171.4 | 682.3 | 4.7 | 52.9 | 1850.6 |
| p2:effbatch-8 | 0.9789 | 0.9978 | 1.0 | 173.8 | 672.6 | 4.7 | 52.9 | 1827.1 |
| p2:epochs-1 | 0.4672 | 0.9945 | 1.0 | 174.5 | 670.2 | 4.7 | 52.9 | 876.9 |
| p2:epochs-3 | 0.9773 | 0.9989 | 1.0 | 173.9 | 672.0 | 4.7 | 52.9 | 2754.8 |
| p2:lr-0.0001 | 0.6918 | 0.9923 | 1.0 | 170.6 | 685.4 | 4.7 | 52.9 | 1727.4 |
| p2:lr-0.0005 | 0.9695 | 0.9989 | 1.0 | 169.2 | 691.0 | 4.7 | 52.9 | 1726.0 |
| p2:maxlen-256 | 0.1283 | -0.0882 | 0.5795 | 181.9 | 583.0 | 4.7 | 52.9 | 611.1 |
| p2:maxlen-512 | 0.2199 | 0.3745 | 0.5715 | 179.7 | 571.6 | 4.7 | 52.9 | 1160.7 |
| p2:quant-int8 | 0.8325 | 0.9989 | 1.0 | 624.1 | 187.4 | 3.39 | 52.9 | 2404.4 |
| p2:quant-nf4 | 0.8109 | 0.9956 | 1.0 | 298.9 | 391.3 | 2.76 | 52.9 | 2393.2 |
| p2:r-16 | 0.9895 | 0.9978 | 1.0 | 239.4 | 488.2 | 4.74 | 89.8 | 1993.0 |
| p2:r-4 | 0.8395 | 0.9967 | 1.0 | 508.6 | 229.9 | 4.68 | 34.4 | 1664.9 |
| p2:target-qv | 0.5708 | 0.989 | 0.9995 | 117.6 | 995.5 | 4.07 | 20.3 | 1278.5 |

## Disclosure sentence for the methodology section

> The hyperparameter sweep was conducted on a 10,000-sample stratified subset of the training corpus and a 2,000-window validation subset for tractability, using agent a2 as the representative endpoint; the selected configuration was then retrained on the full 45,239-sample corpus across all three agents and evaluated on the held-out 7,938-window test set. Run-to-run variance was estimated from 3 seeds at the baseline configuration (sigma = 0.03297).
