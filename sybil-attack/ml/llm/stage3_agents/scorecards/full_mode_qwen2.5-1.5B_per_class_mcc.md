# Per-class MCC_k (Eq 3.64) — full_mode_qwen2.5-1.5B

n = 7,938 windows

| Variant | MCC_k | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|---:|
| legitimate | 0.9991 | 0.9995 | 1.0000 | 0.9997 | 5510 |
| outsider | 0.9958 | 0.9963 | 0.9963 | 0.9963 | 801 |
| sim | 0.9976 | 1.0000 | 0.9958 | 0.9979 | 956 |
| nonsim | 0.9983 | 0.9968 | 1.0000 | 0.9984 | 312 |
| indirect | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 326 |
| malicious_rsu | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 33 |
| malicious_controller | n/a* | 0.0000 | 0.0000 | 0.0000 | 0 |

\* class has zero windows in the evaluation set (malicious_controller is a control-plane attack with no vehicle-tier beacons, so it is absent by construction).

Macro MCC_k (present classes) = 0.9985
