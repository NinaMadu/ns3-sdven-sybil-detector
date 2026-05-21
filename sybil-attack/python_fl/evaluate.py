"""
evaluate.py — Post-FL evaluation metrics and plots for FLEMDS.

Computes: accuracy, precision, recall, F1-score, AUC-ROC.
Plots:    training loss curve, confusion matrix, ROC curve,
          FLBFLVS score distribution.
"""

from __future__ import annotations

import os
from typing import Dict, List

import matplotlib.pyplot as plt
import numpy as np
import torch
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    auc,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from local_model import SybilLSTM, DEFAULT_BATCH_SIZE


# ---------------------------------------------------------------------------
# Model evaluation
# ---------------------------------------------------------------------------

def evaluate_global_model(
    model:   SybilLSTM,
    X_val:   np.ndarray,
    y_val:   np.ndarray,
    threshold: float = 0.5,
    batch_size: int  = DEFAULT_BATCH_SIZE,
    device:  str     = "cpu",
) -> Dict[str, float]:
    """
    Run the global model over all validation sequences and return metrics.

    Returns
    -------
    dict with keys: accuracy, precision, recall, f1, auc_roc,
                    sybil_detection_rate, false_positive_rate
    """
    model.to(device)
    model.eval()

    X_t = torch.tensor(X_val, dtype=torch.float32)
    y_t = torch.tensor(y_val, dtype=torch.float32)

    all_probs: List[float] = []
    all_preds: List[int]   = []

    with torch.no_grad():
        for i in range(0, len(X_t), batch_size):
            xb = X_t[i : i + batch_size].to(device)
            probs = torch.sigmoid(model(xb)).cpu().numpy()
            preds = (probs >= threshold).astype(int)
            all_probs.extend(probs.tolist())
            all_preds.extend(preds.tolist())

    y_true = y_val.astype(int)
    y_pred = np.array(all_preds)
    y_prob = np.array(all_probs)

    metrics: Dict[str, float] = {
        "accuracy":              accuracy_score(y_true, y_pred),
        "precision":             precision_score(y_true, y_pred, zero_division=0),
        "recall":                recall_score(y_true, y_pred, zero_division=0),
        "f1":                    f1_score(y_true, y_pred, zero_division=0),
        "auc_roc":               roc_auc_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else 0.5,
        # FLEMDS-paper-aligned naming
        "sybil_detection_rate":  recall_score(y_true, y_pred, zero_division=0),  # TPR
        "false_positive_rate":   _fpr(y_true, y_pred),
    }
    return metrics


def _fpr(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """False positive rate = FP / (FP + TN)."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    if cm.shape == (2, 2):
        tn, fp = cm[0, 0], cm[0, 1]
        return float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    return 0.0


# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------

def plot_results(
    history,                        # flwr.server.History
    metrics:    Dict[str, float],
    scores:     Dict[int, float],   # FLBFLVS scores per vehicle
    output_dir: str = "results",
) -> None:
    """Generate and save all FLEMDS evaluation plots."""
    os.makedirs(output_dir, exist_ok=True)

    _plot_training_curve(history, output_dir)
    _plot_flbflvs_distribution(scores, output_dir)
    _print_metrics_bar(metrics, output_dir)

    plt.close("all")
    print(f"Plots saved to {output_dir}/")


def _plot_training_curve(history, output_dir: str) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    # Distributed (fit) losses reported by clients
    if history.losses_distributed:
        rounds = [r for r, _ in history.losses_distributed]
        losses = [l for _, l in history.losses_distributed]
        axes[0].plot(rounds, losses, marker="o", linewidth=2)
        axes[0].set_xlabel("FL Round")
        axes[0].set_ylabel("Avg Loss")
        axes[0].set_title("FLEMDS — Distributed Training Loss")
        axes[0].grid(True, alpha=0.3)

    # Distributed (evaluate) accuracy
    if history.metrics_distributed and "accuracy" in history.metrics_distributed:
        acc_data = history.metrics_distributed["accuracy"]
        rounds = [r for r, _ in acc_data]
        accs   = [a for _, a in acc_data]
        axes[1].plot(rounds, accs, marker="s", color="green", linewidth=2)
        axes[1].set_xlabel("FL Round")
        axes[1].set_ylabel("Accuracy")
        axes[1].set_title("FLEMDS — Global Validation Accuracy")
        axes[1].set_ylim([0, 1.05])
        axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    fig.savefig(os.path.join(output_dir, "training_curve.png"), dpi=150)


def _plot_flbflvs_distribution(scores: Dict[int, float], output_dir: str) -> None:
    if not scores:
        return
    vals = list(scores.values())
    vids = list(scores.keys())

    fig, ax = plt.subplots(figsize=(10, 4))
    bars = ax.bar(
        [str(v) for v in vids], vals,
        color=["#d62728" if s < 0.4 else "#2ca02c" if s >= 0.7 else "#1f77b4"
               for s in vals],
    )
    ax.axhline(y=0.7, color="green",  linestyle="--", label="High threshold (0.7)")
    ax.axhline(y=0.4, color="orange", linestyle="--", label="Low threshold (0.4)")
    ax.set_xlabel("Vehicle ID")
    ax.set_ylabel("FLBFLVS Selection Score")
    ax.set_title("FLEMDS — FLBFLVS Client Selection Scores")
    ax.legend()
    ax.set_ylim([0, 1.05])
    plt.tight_layout()
    fig.savefig(os.path.join(output_dir, "flbflvs_scores.png"), dpi=150)


def _print_metrics_bar(metrics: Dict[str, float], output_dir: str) -> None:
    key_metrics = {
        k: metrics[k]
        for k in ["accuracy", "precision", "recall", "f1", "auc_roc"]
        if k in metrics
    }
    if not key_metrics:
        return

    fig, ax = plt.subplots(figsize=(8, 4))
    keys = list(key_metrics.keys())
    vals = [key_metrics[k] for k in keys]
    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"]
    ax.bar(keys, vals, color=colors[: len(keys)])
    for i, v in enumerate(vals):
        ax.text(i, v + 0.01, f"{v:.3f}", ha="center", fontsize=9)
    ax.set_ylim([0, 1.15])
    ax.set_title("FLEMDS — Global Model Performance Metrics")
    ax.set_ylabel("Score")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    fig.savefig(os.path.join(output_dir, "performance_metrics.png"), dpi=150)
