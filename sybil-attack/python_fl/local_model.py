"""
local_model.py — On-vehicle LSTM Sybil-detection model (FLEMDS Tier-1).

Architecture (FLEMDS paper §IV-C):
    Input  : (batch, seq_len=10, n_features=17)  — normalised BSM time-series
    LSTM   : 2 layers, hidden_size=64, dropout=0.3
    FC head: Linear(64 → 1) + Sigmoid → P(sybil)
    Loss   : Binary cross-entropy (weighted for class imbalance)

The model is designed to be small enough to run on an embedded vehicle ECU
and to serialise its parameters as flat numpy arrays for Flower aggregation.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# ---------------------------------------------------------------------------
# Hyper-parameters (FLEMDS Table III defaults)
# ---------------------------------------------------------------------------
DEFAULT_SEQ_LEN     = 10
DEFAULT_N_FEATURES  = 17   # len(FEATURE_COLS) from data_prep.py
DEFAULT_HIDDEN_SIZE = 64
DEFAULT_N_LAYERS    = 2
DEFAULT_DROPOUT     = 0.3
DEFAULT_LR          = 1e-3
DEFAULT_BATCH_SIZE  = 32
DEFAULT_LOCAL_EPOCHS = 3    # epochs per FL round per vehicle


# ---------------------------------------------------------------------------
# Model definition
# ---------------------------------------------------------------------------

class SybilLSTM(nn.Module):
    """
    2-layer LSTM for binary Sybil detection on BSM time-series.

    Outputs a single logit (pre-sigmoid) per sample.
    Use `predict_proba` for probabilities or `predict` for hard labels.
    """

    def __init__(
        self,
        n_features:  int = DEFAULT_N_FEATURES,
        hidden_size: int = DEFAULT_HIDDEN_SIZE,
        n_layers:    int = DEFAULT_N_LAYERS,
        dropout:     float = DEFAULT_DROPOUT,
    ) -> None:
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=n_features,
            hidden_size=hidden_size,
            num_layers=n_layers,
            batch_first=True,
            dropout=dropout if n_layers > 1 else 0.0,
        )
        self.head = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_size, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, T, F)
        out, _ = self.lstm(x)
        last    = out[:, -1, :]        # take last timestep
        return self.head(last).squeeze(-1)  # (B,) logit

    @torch.no_grad()
    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self(x))

    @torch.no_grad()
    def predict(self, x: torch.Tensor, threshold: float = 0.5) -> torch.Tensor:
        return (self.predict_proba(x) >= threshold).long()


# ---------------------------------------------------------------------------
# Parameter utilities (Flower-compatible numpy serialisation)
# ---------------------------------------------------------------------------

def get_parameters(model: nn.Module) -> List[np.ndarray]:
    """Extract model weights as a list of numpy arrays (for Flower)."""
    return [p.detach().cpu().numpy() for p in model.parameters()]


def set_parameters(model: nn.Module, parameters: List[np.ndarray]) -> None:
    """Load numpy arrays back into model parameters (from Flower server)."""
    params_dict = zip(model.parameters(), parameters)
    for param, new_val in params_dict:
        param.data = torch.tensor(new_val, dtype=param.data.dtype)


# ---------------------------------------------------------------------------
# Training / evaluation helpers
# ---------------------------------------------------------------------------

def _make_dataloader(
    X: np.ndarray,
    y: np.ndarray,
    batch_size: int,
    shuffle: bool = True,
) -> DataLoader:
    ds = TensorDataset(
        torch.tensor(X, dtype=torch.float32),
        torch.tensor(y, dtype=torch.float32),
    )
    return DataLoader(ds, batch_size=batch_size, shuffle=shuffle)


def local_train(
    model: nn.Module,
    X_train: np.ndarray,
    y_train: np.ndarray,
    epochs: int = DEFAULT_LOCAL_EPOCHS,
    lr: float = DEFAULT_LR,
    batch_size: int = DEFAULT_BATCH_SIZE,
    pos_weight: Optional[float] = None,
    device: str = "cpu",
) -> float:
    """
    Run `epochs` of local SGD and return the final training loss.

    pos_weight: BCE loss weight for the positive (Sybil) class.
                Set to (n_normal / n_sybil) to handle class imbalance.
    """
    model.to(device)
    model.train()

    loader = _make_dataloader(X_train, y_train, batch_size)
    weight = torch.tensor([pos_weight or 1.0], dtype=torch.float32).to(device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=weight)
    optimiser = torch.optim.Adam(model.parameters(), lr=lr)

    total_loss = 0.0
    n_batches   = 0
    for _ in range(epochs):
        for X_batch, y_batch in loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            optimiser.zero_grad()
            logits = model(X_batch)
            loss   = criterion(logits, y_batch)
            loss.backward()
            optimiser.step()
            total_loss += loss.item()
            n_batches  += 1

    return total_loss / max(n_batches, 1)


def local_evaluate(
    model: nn.Module,
    X_val: np.ndarray,
    y_val: np.ndarray,
    batch_size: int = DEFAULT_BATCH_SIZE,
    device: str = "cpu",
) -> Tuple[float, float]:
    """
    Evaluate the model on validation data.

    Returns
    -------
    (loss, accuracy)
    """
    model.to(device)
    model.eval()

    loader = _make_dataloader(X_val, y_val, batch_size, shuffle=False)
    criterion = nn.BCEWithLogitsLoss()

    total_loss   = 0.0
    total_correct = 0
    total_samples = 0
    with torch.no_grad():
        for X_batch, y_batch in loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            logits  = model(X_batch)
            loss    = criterion(logits, y_batch)
            preds   = (torch.sigmoid(logits) >= 0.5).long()
            total_loss    += loss.item() * len(y_batch)
            total_correct += (preds == y_batch.long()).sum().item()
            total_samples += len(y_batch)

    avg_loss = total_loss / max(total_samples, 1)
    accuracy = total_correct / max(total_samples, 1)
    return avg_loss, accuracy


def compute_pos_weight(y: np.ndarray) -> float:
    """Compute BCE pos_weight = n_normal / n_sybil for imbalanced datasets."""
    n_sybil  = int(y.sum())
    n_normal = len(y) - n_sybil
    if n_sybil == 0:
        return 1.0
    return float(n_normal) / float(n_sybil)
