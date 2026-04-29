"""LSTM Autoencoder — deep learning anomaly detection for log sequences.

Why an LSTM Autoencoder?
------------------------
Log data is *sequential*: events at time T depend on what happened at T-1.
The six existing models (Isolation Forest, LOF, One-Class SVM, DBSCAN,
Random Forest, Z-Score) are all *instance-based* — they evaluate each record
independently and are blind to temporal patterns such as:

  * A slow-and-low port scan spread across hundreds of log lines
  * A lateral-movement chain: recon → auth failure → privilege escalation
  * Burst-then-silence patterns characteristic of exfiltration beaconing

An LSTM Autoencoder addresses this gap:

  1. **Sequence awareness** — a sliding window of W consecutive feature vectors
     is fed to the LSTM encoder, which learns what *normal temporal patterns*
     look like.
  2. **Unsupervised** — the decoder tries to reconstruct the input window from
     the encoder's latent representation.  No labels required.
  3. **Anomaly score = reconstruction error** — sequences the model has never
     seen before (novel attacks, rare events) produce high MSE.
  4. **GPU / CPU flexible** — uses PyTorch; falls back to CPU automatically.
  5. **Lightweight** — the default architecture (hidden=64, layers=2) trains
     in seconds on typical log batches (<50 k records).

Architecture
~~~~~~~~~~~~
::

    Input  [W × F]  →  LSTM Encoder (hidden=64, layers=2)
                     →  Latent vector (last hidden state)
                     →  LSTM Decoder (hidden=64, layers=2)
                     →  Linear projection back to F per time-step
                     →  Reconstructed [W × F]

    Anomaly score for record i = mean MSE over all windows containing i.

Public API
~~~~~~~~~~
``run_lstm_autoencoder(records, ...)``  — mirrors the standard pipeline result
shape used by :func:`src.pipeline.run_all_models`.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("logbot.deep_detector")

# ---------------------------------------------------------------------------
# Constants / defaults
# ---------------------------------------------------------------------------

_DEFAULT_WINDOW = 10          # number of consecutive log records per sequence
_DEFAULT_HIDDEN = 64          # LSTM hidden size
_DEFAULT_LAYERS = 2           # stacked LSTM layers
_DEFAULT_EPOCHS = 20          # training epochs (fast; data is repeated many times)
_DEFAULT_BATCH  = 64          # mini-batch size
_DEFAULT_LR     = 1e-3        # Adam learning rate
_DEFAULT_CONTAM = 0.10        # fraction of records to flag as anomalies
_MIN_RECORDS    = 30          # need at least this many records to train meaningfully


# ---------------------------------------------------------------------------
# Model definition
# ---------------------------------------------------------------------------

def _build_model(input_size: int, hidden_size: int, num_layers: int):
    """Return an LSTMAutoencoder nn.Module."""
    import torch
    import torch.nn as nn

    class LSTMAutoencoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.encoder = nn.LSTM(
                input_size=input_size,
                hidden_size=hidden_size,
                num_layers=num_layers,
                batch_first=True,
                dropout=0.1 if num_layers > 1 else 0.0,
            )
            self.decoder = nn.LSTM(
                input_size=hidden_size,
                hidden_size=hidden_size,
                num_layers=num_layers,
                batch_first=True,
                dropout=0.1 if num_layers > 1 else 0.0,
            )
            self.output_layer = nn.Linear(hidden_size, input_size)

        def forward(self, x):
            # x: (batch, window, features)
            _, (h_n, c_n) = self.encoder(x)

            # Repeat last hidden state across the window to seed decoder
            batch_size = x.size(0)
            window_size = x.size(1)
            latent = h_n[-1].unsqueeze(1).repeat(1, window_size, 1)

            decoded, _ = self.decoder(latent, (h_n, c_n))
            reconstructed = self.output_layer(decoded)
            return reconstructed

    return LSTMAutoencoder()


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def _train(
    model,
    X_windows,       # np.ndarray (N_windows, window, features)
    epochs: int,
    batch_size: int,
    lr: float,
    device,
):
    """Train the autoencoder on *X_windows* and return per-epoch losses."""
    import torch
    import torch.nn as nn
    import numpy as np

    model = model.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()

    dataset = torch.tensor(X_windows, dtype=torch.float32)
    loader = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(dataset),
        batch_size=batch_size,
        shuffle=True,
    )

    model.train()
    losses = []
    for epoch in range(epochs):
        epoch_loss = 0.0
        for (batch,) in loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            recon = model(batch)
            loss = criterion(recon, batch)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            epoch_loss += loss.item() * len(batch)
        losses.append(epoch_loss / len(dataset))
    return losses


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _reconstruction_errors(
    model,
    X_windows,       # (N_windows, window, features)
    device,
    batch_size: int,
) -> list:
    """Return per-window MSE reconstruction errors."""
    import torch
    import torch.nn as nn
    import numpy as np

    model.eval()
    errors = []
    dataset = torch.tensor(X_windows, dtype=torch.float32)
    loader = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(dataset),
        batch_size=batch_size,
        shuffle=False,
    )
    criterion = nn.MSELoss(reduction="none")

    with torch.no_grad():
        for (batch,) in loader:
            batch = batch.to(device)
            recon = model(batch)
            mse = criterion(recon, batch)           # (B, W, F)
            per_window = mse.mean(dim=(1, 2))       # (B,)
            errors.extend(per_window.cpu().tolist())
    return errors


def _window_errors_to_record_scores(
    window_errors: list,
    n_records: int,
    window_size: int,
) -> list:
    """Aggregate per-window errors into per-record scores.

    Each record i contributes to windows that start at positions
    max(0, i - window_size + 1) … i.  We take the *mean* of all
    window errors that cover each record.
    """
    score_sum = [0.0] * n_records
    score_cnt = [0]   * n_records

    for w_idx, err in enumerate(window_errors):
        for r_idx in range(w_idx, min(w_idx + window_size, n_records)):
            score_sum[r_idx] += err
            score_cnt[r_idx] += 1

    return [
        score_sum[i] / score_cnt[i] if score_cnt[i] else 0.0
        for i in range(n_records)
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_lstm_autoencoder(
    records: List[Dict[str, Any]],
    window_size: int = _DEFAULT_WINDOW,
    hidden_size: int = _DEFAULT_HIDDEN,
    num_layers: int = _DEFAULT_LAYERS,
    epochs: int = _DEFAULT_EPOCHS,
    batch_size: int = _DEFAULT_BATCH,
    lr: float = _DEFAULT_LR,
    contamination: float = _DEFAULT_CONTAM,
) -> Dict[str, Any]:
    """Run LSTM Autoencoder anomaly detection on *records*.

    Returns the standard pipeline result dict:
    ``anomaly_indices``, ``anomaly_scores``, ``anomaly_count``,
    ``total_records``, ``feature_names``, ``feature_importances``,
    ``anomaly_records``, ``method``.

    Parameters
    ----------
    records:
        Normalized log records (output of ``src.normalizer.normalize``).
    window_size:
        Number of consecutive records per sliding-window sequence.
    hidden_size:
        LSTM hidden dimension.
    num_layers:
        Number of stacked LSTM layers.
    epochs:
        Training epochs.
    batch_size:
        Mini-batch size for training and inference.
    lr:
        Adam learning rate.
    contamination:
        Expected fraction of anomalies; used to set the score threshold.
    """
    _err_base: Dict[str, Any] = {
        "anomaly_indices": [],
        "anomaly_scores": [],
        "anomaly_count": 0,
        "total_records": len(records),
        "feature_names": [],
        "feature_importances": {},
        "anomaly_records": [],
        "method": "LSTM Autoencoder",
    }

    if len(records) < _MIN_RECORDS:
        return {
            **_err_base,
            "error": f"Need at least {_MIN_RECORDS} records to train LSTM Autoencoder "
                     f"(got {len(records)}).",
        }

    # --- Import heavy deps (graceful degradation) --------------------------
    try:
        import torch
        import numpy as np
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:
        return {**_err_base, "error": f"Missing dependency: {exc}. "
                "Install with: pip install torch numpy scikit-learn"}

    # --- Feature extraction ------------------------------------------------
    from .pipeline import extract_numeric_features

    feature_names, matrix = extract_numeric_features(records)
    if not feature_names or not matrix:
        return {**_err_base, "error": "No numeric features could be extracted."}

    import numpy as np
    X = np.array(matrix, dtype=np.float64)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # Standardize so all features are on the same scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X).astype(np.float32)

    n_records, n_features = X_scaled.shape

    # --- Build sliding windows ---------------------------------------------
    # Cap window to avoid degenerate case where window > records
    win = min(window_size, n_records)
    n_windows = n_records - win + 1

    if n_windows < 1:
        return {**_err_base, "error": "Not enough records to form a single window."}

    X_windows = np.stack([X_scaled[i: i + win] for i in range(n_windows)])
    # Shape: (n_windows, win, n_features)

    # --- Device selection --------------------------------------------------
    if torch.cuda.is_available():
        device = torch.device("cuda")
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        device = torch.device("mps")
    else:
        device = torch.device("cpu")

    logger.debug("LSTM Autoencoder: device=%s, records=%d, windows=%d, features=%d",
                 device, n_records, n_windows, n_features)

    # --- Build & train model -----------------------------------------------
    model = _build_model(
        input_size=n_features,
        hidden_size=hidden_size,
        num_layers=num_layers,
    )

    try:
        train_losses = _train(model, X_windows, epochs, batch_size, lr, device)
    except Exception as exc:
        logger.warning("LSTM Autoencoder training failed: %s", exc)
        return {**_err_base, "error": f"Training failed: {exc}"}

    # --- Score records -----------------------------------------------------
    try:
        window_errors = _reconstruction_errors(model, X_windows, device, batch_size)
    except Exception as exc:
        logger.warning("LSTM Autoencoder scoring failed: %s", exc)
        return {**_err_base, "error": f"Scoring failed: {exc}"}

    record_scores = _window_errors_to_record_scores(window_errors, n_records, win)

    # --- Threshold & flag anomalies ----------------------------------------
    scores_arr = np.array(record_scores, dtype=np.float64)
    threshold_pct = max(0.0, min(100.0, (1.0 - contamination) * 100.0))
    threshold = float(np.percentile(scores_arr, threshold_pct))
    anomaly_indices = [i for i, s in enumerate(record_scores) if s > threshold]
    anomaly_records = [records[i] for i in anomaly_indices]

    # --- Feature importance via gradient-based sensitivity -----------------
    # For each feature, measure how much a unit perturbation raises the loss.
    importances: Dict[str, float] = {}
    try:
        import torch

        model.eval()
        # Use a representative sample window
        sample_win = torch.tensor(X_windows[:min(50, n_windows)], dtype=torch.float32).to(device)
        sample_win.requires_grad_(True)

        recon = model(sample_win)
        loss = torch.nn.functional.mse_loss(recon, sample_win)
        loss.backward()

        # Mean absolute gradient per feature across all time steps and windows
        grad = sample_win.grad.abs().mean(dim=(0, 1)).cpu().numpy()
        total = float(grad.sum()) or 1.0
        importances = {
            fname: round(float(g / total), 6)
            for fname, g in zip(feature_names, grad)
        }
        importances = dict(sorted(importances.items(), key=lambda kv: -kv[1]))
    except Exception:
        importances = {fname: 0.0 for fname in feature_names}

    return {
        "anomaly_indices": anomaly_indices,
        "anomaly_scores": [round(float(s), 6) for s in record_scores],
        "anomaly_count": len(anomaly_indices),
        "total_records": n_records,
        "feature_names": feature_names,
        "feature_importances": importances,
        "anomaly_records": anomaly_records[:100],
        "method": "LSTM Autoencoder",
        "window_size": win,
        "hidden_size": hidden_size,
        "num_layers": num_layers,
        "epochs_trained": epochs,
        "final_train_loss": round(train_losses[-1], 6) if train_losses else None,
        "threshold": round(threshold, 6),
        "device": str(device),
    }
