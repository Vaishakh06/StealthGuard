"""
StealthGuard - 3-Class Model Training (Colab-Compatible)
=========================================================

Trains a CNN + BiLSTM + Attention model for 3-class classification:
    BENIGN / TCP_DDoS / UDP_DDoS

Architecture (matches Notebook 05 exactly):
    Conv1d(1, 64, k=3, p=1) -> BatchNorm -> ReLU -> MaxPool1d(2)
    Conv1d(64, 128, k=3, p=1) -> BatchNorm -> ReLU
    permute(0, 2, 1)
    BiLSTM(128 -> 128, bidirectional=True, batch_first=True)
    Attention(256 -> 1) -> softmax -> weighted sum
    Dropout(0.3) -> Linear(256 -> 64) -> ReLU -> Dropout(0.2) -> Linear(64 -> 3)

Input shape:  (batch_size, 1, 48)
Output shape: (batch_size, 3)

Features:
  - Chunked CSV loading (RAM-efficient for 3.38M rows)
  - Class-weighted CrossEntropyLoss
  - Adam optimizer + ReduceLROnPlateau scheduler
  - Checkpoint after every epoch (latest + best)
  - Optimizer + scheduler state in checkpoint
  - Resume from interrupted checkpoint
  - Training history saved after every epoch
  - Auto-detects CUDA; uses GPU when available
  - Colab/Google Drive compatible paths

Output directory: models/threeclass/
"""

import os
import sys
import json
import time
import warnings
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from collections import Counter

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score,
    accuracy_score
)

warnings.filterwarnings('ignore')

# ============================================================
# PATHS AND CONFIGURATION
# ============================================================

# Detect Colab environment
IN_COLAB = False
try:
    from google.colab import drive
    IN_COLAB = True
except ImportError:
    pass

if IN_COLAB:
    # Colab + Google Drive paths
    MOUNT_POINT = '/content/drive'
    DRIVE_PROJECT_DIR = 'MyDrive/StealthGuard'
    PROJECT_ROOT = os.path.join(MOUNT_POINT, DRIVE_PROJECT_DIR)
else:
    # Local Windows paths
    PROJECT_ROOT = r'C:\CSBS\major_project_git\StealthGuard'

ENGINEERED_3CLASS_CSV = os.path.join(
    PROJECT_ROOT, 'dataset', 'engineered', 'engineered_3class.csv'
)
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models', 'threeclass')
os.makedirs(MODELS_DIR, exist_ok=True)

# Class mapping (3 classes)
CLASS_MAP = {
    0: 'BENIGN',
    1: 'TCP_DDoS',
    2: 'UDP_DDoS'
}
NUM_CLASSES = 3

LABEL_MAP = {
    'BENIGN': 0,
    'TCP_DDoS': 1,
    'UDP_DDoS': 2
}

# Feature columns (48 features, must match inference_adapter.py)
STAT_FEATURES = [
    'Flow Duration_Mean', 'Flow Duration_Std', 'Flow Duration_Variance',
    'Flow Duration_Min', 'Flow Duration_Max', 'Flow Duration_Renyi',
    'Flow Bytes/s_Mean', 'Flow Bytes/s_Std', 'Flow Bytes/s_Variance',
    'Flow Bytes/s_Min', 'Flow Bytes/s_Max', 'Flow Bytes/s_Renyi',
    'Flow Packets/s_Mean', 'Flow Packets/s_Std', 'Flow Packets/s_Variance',
    'Flow Packets/s_Min', 'Flow Packets/s_Max', 'Flow Packets/s_Renyi',
    'Packet Length Mean_Mean', 'Packet Length Mean_Std',
    'Packet Length Mean_Variance', 'Packet Length Mean_Min',
    'Packet Length Mean_Max', 'Packet Length Mean_Renyi',
    'Packet Length Std_Mean', 'Packet Length Std_Std',
    'Packet Length Std_Variance', 'Packet Length Std_Min',
    'Packet Length Std_Max', 'Packet Length Std_Renyi',
    'Total Fwd Packets_Mean', 'Total Fwd Packets_Std',
    'Total Fwd Packets_Variance', 'Total Fwd Packets_Min',
    'Total Fwd Packets_Max', 'Total Fwd Packets_Renyi',
    'Total Backward Packets_Mean', 'Total Backward Packets_Std',
    'Total Backward Packets_Variance', 'Total Backward Packets_Min',
    'Total Backward Packets_Max', 'Total Backward Packets_Renyi',
    'Average Packet Size_Mean', 'Average Packet Size_Std',
    'Average Packet Size_Variance', 'Average Packet Size_Min',
    'Average Packet Size_Max', 'Average Packet Size_Renyi'
]

NUM_FEATURES = len(STAT_FEATURES)  # Should be 48
WINDOW_SIZE = 100   # preserved for documentation; not used in dataset class
WINDOW_STRIDE = 20  # preserved for documentation; not used in dataset class
CHUNK_SIZE = 50000  # Rows to read at once from CSV

# Training hyperparameters (matches Notebook 05 configuration)
BATCH_SIZE = 512
NUM_EPOCHS = 30
LEARNING_RATE = 1e-3
WEIGHT_DECAY = 1e-4
EARLY_STOPPING_PATIENCE = 5
SCHEDULER_PATIENCE = 3
SCHEDULER_FACTOR = 0.5
GRADIENT_CLIP_VALUE = 1.0
SEED = 42


# ============================================================
# DEVICE
# ============================================================

def get_device():
    """Return the best available device (CUDA > CPU)."""
    if torch.cuda.is_available():
        device = torch.device('cuda')
        print(f"Device: CUDA ({torch.cuda.get_device_name(0)})")
        print(f"CUDA memory: {torch.cuda.get_device_properties(0).total_memory / (1024**3):.2f} GB")
    else:
        device = torch.device('cpu')
        print("Device: CPU (CUDA not available)")
    return device


# ============================================================
# MEMORY-EFFICIENT DATA LOADING
# ============================================================

def load_3class_dataset(csv_path, chunk_size=CHUNK_SIZE):
    """
    Load 3-class dataset in chunks to avoid memory exhaustion.

    Returns:
        X: np.ndarray of shape (n_samples, 48), dtype=float32
        y: np.ndarray of shape (n_samples,), dtype=int64
    """
    print(f"Loading dataset from {csv_path}")
    print(f"Chunk size: {chunk_size:,} rows")

    feature_cols = STAT_FEATURES
    label_col = 'Label'

    X_chunks = []
    y_chunks = []
    total_rows = 0

    chunk_idx = 0
    for chunk in pd.read_csv(csv_path, chunksize=chunk_size,
                             usecols=STAT_FEATURES + [label_col]):
        # Map labels
        chunk['Label'] = chunk['Label'].map(LABEL_MAP)

        # Verify no NaN labels
        nan_count = chunk['Label'].isna().sum()
        if nan_count > 0:
            print(f"WARNING: {nan_count} rows have unmapped labels in this chunk")

        X_chunk = chunk[STAT_FEATURES].to_numpy(dtype=np.float32)
        y_chunk = chunk['Label'].to_numpy(dtype=np.int64)

        X_chunks.append(X_chunk)
        y_chunks.append(y_chunk)

        total_rows += len(chunk)
        chunk_idx += 1

        if chunk_idx % 10 == 0:
            print(f"  Loaded {total_rows:,} rows...", end='\r')

    print(f"\nTotal rows loaded: {total_rows:,}")

    # Concatenate all chunks
    print("Concatenating chunks...")
    X = np.concatenate(X_chunks, axis=0)
    y = np.concatenate(y_chunks, axis=0)

    # Free chunk lists
    del X_chunks, y_chunks

    print(f"Final X shape: {X.shape}, dtype: {X.dtype}")
    print(f"Final y shape: {y.shape}, dtype: {y.dtype}")
    print(f"Label distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

    return X, y


# ============================================================
# PYTORCH DATASET AND MODEL
# ============================================================

class DDoSDataset(Dataset):
    """Dataset for individual 48-feature engineered samples.

    Each row of the engineered CSV is one sample (48 statistical features
    extracted from a 100-flow window). No additional windowing is applied.
    """

    def __init__(self, X, y):
        self.X = X
        self.y = y

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        x = torch.tensor(self.X[idx], dtype=torch.float32).unsqueeze(0)  # (1, 48)
        y = torch.tensor(self.y[idx], dtype=torch.long)
        return x, y


class Attention(nn.Module):
    """Attention layer (matches Notebook 05)."""

    def __init__(self, hidden_size: int):
        super().__init__()
        self.attention = nn.Linear(hidden_size * 2, 1)

    def forward(self, lstm_output):
        """
        lstm_output: (batch_size, sequence_length, hidden_size * 2)
        Returns: context (batch_size, hidden_size * 2), weights
        """
        scores = self.attention(lstm_output)
        weights = torch.softmax(scores, dim=1)
        context = torch.sum(weights * lstm_output, dim=1)
        return context, weights


class HybridCNNBiLSTMAttention(nn.Module):
    """
    Hybrid CNN + BiLSTM + Attention model.
    Exact architecture from Notebook 05, with num_classes=3.
    """

    def __init__(self, input_channels=1, num_classes=3):
        super().__init__()

        # CNN layers
        self.cnn = nn.Sequential(
            nn.Conv1d(input_channels, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2),

            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),
        )

        # Bi-LSTM
        self.lstm = nn.LSTM(
            input_size=128,
            hidden_size=128,
            num_layers=1,
            batch_first=True,
            bidirectional=True
        )

        # Attention
        self.attention = Attention(hidden_size=128)

        # Classifier
        self.classifier = nn.Sequential(
            nn.Dropout(0.3),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes)
        )

    def forward(self, x):
        # x shape: (batch, 1, 48)

        # CNN: (batch, 128, 24) after conv+pool
        x = self.cnn(x)

        # Reshape for LSTM: (batch, 24, 128)
        x = x.permute(0, 2, 1)

        # Bi-LSTM: (batch, 24, 256)
        lstm_out, _ = self.lstm(x)

        # Attention: (batch, 256)
        context, _ = self.attention(lstm_out)

        # Classifier: (batch, num_classes)
        output = self.classifier(context)

        return output


# ============================================================
# CHECKPOINTING
# ============================================================

CHECKPOINT_PATH = os.path.join(MODELS_DIR, 'training_checkpoint.pth')
BEST_MODEL_PATH = os.path.join(MODELS_DIR, 'best_model.pth')
FINAL_MODEL_PATH = os.path.join(MODELS_DIR, 'hybrid_model_3class.pth')
MODEL_CONFIG_PATH = os.path.join(MODELS_DIR, 'model_config.json')
SCALER_PATH = os.path.join(MODELS_DIR, 'scaler_3class.pkl')
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, 'label_encoder_3class.pkl')
TRAINING_HISTORY_PATH = os.path.join(MODELS_DIR, 'training_history_3class.pkl')


def save_checkpoint(epoch, model, optimizer, scheduler, scaler_amp,
                    history, best_val_loss, patience_counter):
    """Save full training state for resume."""
    checkpoint = {
        'epoch': epoch,
        'model_state_dict': model.state_dict(),
        'optimizer_state_dict': optimizer.state_dict(),
        'scheduler_state_dict': scheduler.state_dict(),
        'scaler_amp_state_dict': scaler_amp.state_dict()
        if scaler_amp is not None else None,
        'history': history,
        'best_val_loss': best_val_loss,
        'patience_counter': patience_counter,
    }
    torch.save(checkpoint, CHECKPOINT_PATH)
    print(f"  Checkpoint saved: epoch {epoch+1}")


def load_checkpoint(model, optimizer, scheduler, scaler_amp, device):
    """Load checkpoint and return training state. Returns None if no checkpoint."""
    if not os.path.exists(CHECKPOINT_PATH):
        return None

    print(f"Checkpoint found: {CHECKPOINT_PATH}")
    checkpoint = torch.load(CHECKPOINT_PATH, map_location=device)

    model.load_state_dict(checkpoint['model_state_dict'])
    optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
    scheduler.load_state_dict(checkpoint['scheduler_state_dict'])

    if scaler_amp is not None and checkpoint.get('scaler_amp_state_dict') is not None:
        scaler_amp.load_state_dict(checkpoint['scaler_amp_state_dict'])

    history = checkpoint['history']
    best_val_loss = checkpoint['best_val_loss']
    patience_counter = checkpoint['patience_counter']
    start_epoch = checkpoint['epoch'] + 1

    print(f"  Resuming from epoch {start_epoch}")
    print(f"  Best val loss so far: {best_val_loss:.4f}")

    return {
        'start_epoch': start_epoch,
        'history': history,
        'best_val_loss': best_val_loss,
        'patience_counter': patience_counter,
    }


# ============================================================
# TRAINING / VALIDATION STEPS
# ============================================================

def train_one_epoch(model, data_loader, criterion, optimizer, device,
                    scaler_amp, gradient_clip_value):
    """Train for one epoch."""
    model.train()
    running_loss = 0.0
    correct_predictions = 0
    total_samples = 0

    for inputs, labels in data_loader:
        inputs = inputs.to(device, non_blocking=True)
        labels = labels.to(device, non_blocking=True)

        optimizer.zero_grad(set_to_none=True)

        with torch.cuda.amp.autocast(enabled=torch.cuda.is_available()):
            outputs = model(inputs)
            loss = criterion(outputs, labels)

        scaler_amp.scale(loss).backward()
        scaler_amp.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), gradient_clip_value)
        scaler_amp.step(optimizer)
        scaler_amp.update()

        batch_size = labels.size(0)
        running_loss += loss.item() * batch_size

        predictions = torch.argmax(outputs, dim=1)
        correct_predictions += (predictions == labels).sum().item()
        total_samples += batch_size

    epoch_loss = running_loss / total_samples
    epoch_accuracy = correct_predictions / total_samples
    return epoch_loss, epoch_accuracy


def validate_one_epoch(model, data_loader, criterion, device, scaler_amp):
    """Validate for one epoch."""
    model.eval()
    running_loss = 0.0
    correct_predictions = 0
    total_samples = 0

    with torch.no_grad():
        for inputs, labels in data_loader:
            inputs = inputs.to(device, non_blocking=True)
            labels = labels.to(device, non_blocking=True)

            with torch.cuda.amp.autocast(enabled=torch.cuda.is_available()):
                outputs = model(inputs)
                loss = criterion(outputs, labels)

            batch_size = labels.size(0)
            running_loss += loss.item() * batch_size

            predictions = torch.argmax(outputs, dim=1)
            correct_predictions += (predictions == labels).sum().item()
            total_samples += batch_size

    epoch_loss = running_loss / total_samples
    epoch_accuracy = correct_predictions / total_samples
    return epoch_loss, epoch_accuracy


# ============================================================
# MAIN TRAINING
# ============================================================

def main():
    print("=" * 70)
    print("STEALTHGUARD 3-CLASS MODEL TRAINING (Colab)")
    print("=" * 70)
    print(f"PyTorch version: {torch.__version__}")
    print(f"Window size: {WINDOW_SIZE}, Stride: {WINDOW_STRIDE}")
    print(f"Classes: {CLASS_MAP}")
    print(f"Batch size: {BATCH_SIZE}")
    print(f"Max epochs: {NUM_EPOCHS}")
    print(f"Output dir: {MODELS_DIR}")
    print("=" * 70)

    device = get_device()

    # ---- Load data ----
    print("\nLoading dataset...")
    X, y = load_3class_dataset(ENGINEERED_3CLASS_CSV, chunk_size=CHUNK_SIZE)

    # ---- Train/validation/test split (80/10/10, stratified) ----
    print("\nSplitting dataset (80/10/10, stratified)...")
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=SEED
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=SEED
    )

    print(f"Training set:   {X_train.shape[0]:,} samples")
    print(f"Validation set: {X_val.shape[0]:,} samples")
    print(f"Test set:       {X_test.shape[0]:,} samples")

    for name, y_data in [('Train', y_train), ('Val', y_val), ('Test', y_test)]:
        counts = np.bincount(y_data)
        print(f"  {name}: BENIGN={counts[0]:,}, TCP_DDoS={counts[1]:,}, UDP_DDoS={counts[2]:,}")

    # ---- Feature scaling (fit on train, transform all splits) ----
    # This is required: raw engineered features contain variance values
    # up to ~1e17 which cause NaN in Conv1d + BatchNorm without scaling.
    # Matches Notebook 05: scaler.fit_transform(X_train) before training.
    print("\nFitting StandardScaler on training data...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train).astype(np.float32)
    X_val = scaler.transform(X_val).astype(np.float32)
    X_test = scaler.transform(X_test).astype(np.float32)

    # Save scaler immediately so it exists even if training fails later
    joblib.dump(scaler, SCALER_PATH)
    print(f"  Scaler saved to: {SCALER_PATH}")

    # ---- Datasets and DataLoaders ----
    train_dataset = DDoSDataset(X_train, y_train)
    val_dataset = DDoSDataset(X_val, y_val)
    test_dataset = DDoSDataset(X_test, y_test)

    num_workers = 2 if not IN_COLAB else 0  # Colab: num_workers=0 to avoid issues
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True,
                              num_workers=num_workers, pin_memory=False)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False,
                            num_workers=num_workers, pin_memory=False)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False,
                             num_workers=num_workers, pin_memory=False)

    print(f"\nTrain batches: {len(train_loader)}, Val batches: {len(val_loader)}, Test batches: {len(test_loader)}")

    # ---- Model ----
    model = HybridCNNBiLSTMAttention(input_channels=1, num_classes=NUM_CLASSES)
    model = model.to(device)
    print(f"\nModel parameters: {sum(p.numel() for p in model.parameters()):,}")

    # ---- Loss and optimizer ----
    class_counts = np.bincount(y_train, minlength=NUM_CLASSES)
    # Guard against zero-count classes (avoid 1/0 = inf, inf/inf = nan)
    class_counts_safe = np.where(class_counts == 0, 1, class_counts)
    class_weights = 1.0 / torch.tensor(class_counts_safe, dtype=torch.float32)
    class_weights = class_weights / class_weights.sum() * len(class_counts)
    class_weights = class_weights.to(device)

    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='min', factor=SCHEDULER_FACTOR, patience=SCHEDULER_PATIENCE
    )
    scaler_amp = torch.cuda.amp.GradScaler(enabled=torch.cuda.is_available())

    # ---- Checkpoint resume ----
    start_epoch = 0
    history = {
        'train_loss': [], 'train_accuracy': [],
        'val_loss': [], 'val_accuracy': [],
        'learning_rate': []
    }
    best_val_loss = float('inf')
    patience_counter = 0

    checkpoint_state = load_checkpoint(model, optimizer, scheduler, scaler_amp, device)
    if checkpoint_state is not None:
        start_epoch = checkpoint_state['start_epoch']
        history = checkpoint_state['history']
        best_val_loss = checkpoint_state['best_val_loss']
        patience_counter = checkpoint_state['patience_counter']

    # ---- Training loop ----
    print("\nStarting training...")
    start_time = time.time()

    for epoch in range(start_epoch, NUM_EPOCHS):
        epoch_start = time.time()

        train_loss, train_acc = train_one_epoch(
            model, train_loader, criterion, optimizer, device,
            scaler_amp, GRADIENT_CLIP_VALUE
        )

        val_loss, val_acc = validate_one_epoch(
            model, val_loader, criterion, device, scaler_amp
        )

        scheduler.step(val_loss)
        current_lr = optimizer.param_groups[0]['lr']

        # Store history
        history['train_loss'].append(train_loss)
        history['train_accuracy'].append(train_acc)
        history['val_loss'].append(val_loss)
        history['val_accuracy'].append(val_acc)
        history['learning_rate'].append(current_lr)

        epoch_time = time.time() - epoch_start

        print(f"Epoch {epoch+1:2d}/{NUM_EPOCHS} | "
              f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f} | "
              f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f} | "
              f"LR: {current_lr:.6f} | {epoch_time:.1f}s")

        # Detect non-finite loss and stop with clear error
        if not np.isfinite(train_loss) or not np.isfinite(val_loss):
            print("\n" + "!" * 70)
            print("NUMERICAL INSTABILITY DETECTED")
            print("!" * 70)
            print(f"  Epoch: {epoch+1}")
            print(f"  Train Loss: {train_loss}")
            print(f"  Val Loss:   {val_loss}")
            print("  Training stopped to prevent NaN propagation.")
            print("  Latest checkpoint preserved for debugging.")
            print("!" * 70 + "\n")
            break

        # Save checkpoint after every epoch
        save_checkpoint(epoch, model, optimizer, scheduler, scaler_amp,
                        history, best_val_loss, patience_counter)

        # Save training history after every epoch
        joblib.dump(history, TRAINING_HISTORY_PATH)

        # Early stopping + best model
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            torch.save(model.state_dict(), BEST_MODEL_PATH)
            print(f"  >> Best model saved (val_loss={val_loss:.4f})")
        else:
            patience_counter += 1
            if patience_counter >= EARLY_STOPPING_PATIENCE:
                print(f"  >> Early stopping at epoch {epoch+1}")
                break

    training_time = time.time() - start_time
    print(f"\nTraining completed in {training_time:.1f} seconds")

    # ---- Load best model ----
    if os.path.exists(BEST_MODEL_PATH):
        model.load_state_dict(torch.load(BEST_MODEL_PATH, map_location=device))
        print(f"\nLoaded best model from: {BEST_MODEL_PATH}")
    else:
        print(f"\nWARNING: {BEST_MODEL_PATH} not found. "
              f"Using model from last completed epoch.")
    model.eval()

    # ---- Final test evaluation ----
    print("\n" + "=" * 70)
    print("FINAL TEST EVALUATION")
    print("=" * 70)

    test_preds = []
    test_targets = []
    test_correct = 0
    test_total = 0

    with torch.no_grad():
        for X_batch, y_batch in test_loader:
            X_batch = X_batch.to(device)
            y_batch = y_batch.to(device)
            outputs = model(X_batch)
            _, predicted = torch.max(outputs, 1)
            test_preds.extend(predicted.cpu().numpy())
            test_targets.extend(y_batch.cpu().numpy())
            test_correct += (predicted == y_batch).sum().item()
            test_total += y_batch.size(0)

    test_acc = test_correct / test_total
    print(f"\nTest Accuracy: {test_acc:.4f} ({test_correct}/{test_total})")

    print("\nClassification Report:")
    print(classification_report(test_targets, test_preds,
                                target_names=['BENIGN', 'TCP_DDoS', 'UDP_DDoS'],
                                digits=4))

    cm = confusion_matrix(test_targets, test_preds)
    print("\nConfusion Matrix:")
    print(cm)
    print("Row labels: BENIGN, TCP_DDoS, UDP_DDoS")
    print("Column labels: BENIGN, TCP_DDoS, UDP_DDoS")

    precision = precision_score(test_targets, test_preds, average=None)
    recall = recall_score(test_targets, test_preds, average=None)
    f1 = f1_score(test_targets, test_preds, average=None)
    macro_f1 = f1_score(test_targets, test_preds, average='macro')

    print(f"\nPer-Class Metrics:")
    print(f"{'Class':<15} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    for i, class_name in enumerate(['BENIGN', 'TCP_DDoS', 'UDP_DDoS']):
        print(f"{class_name:<15} {precision[i]:>10.4f} {recall[i]:>10.4f} {f1[i]:>10.4f}")

    print(f"\nMacro F1: {macro_f1:.4f}")

    # ---- Save model artifacts ----
    print("\nSaving model artifacts...")

    # Final model
    torch.save(model.state_dict(), FINAL_MODEL_PATH)

    # Model config
    model_config = {
        'input_channels': 1,
        'num_classes': NUM_CLASSES,
        'architecture': 'CNN + BiLSTM + Attention',
        'input_shape': [1, 48],
        'class_map': CLASS_MAP,
        'training_samples': int(X_train.shape[0]),
        'validation_samples': int(X_val.shape[0]),
        'test_samples': int(X_test.shape[0]),
        'training_time_seconds': training_time,
        'test_accuracy': float(test_acc),
        'macro_f1': float(macro_f1),
    }
    with open(MODEL_CONFIG_PATH, 'w') as f:
        json.dump(model_config, f, indent=2)

    # Scaler was already fit and saved before training (see above)

    # Label encoder
    label_encoder_map = {0: 'BENIGN', 1: 'TCP_DDoS', 2: 'UDP_DDoS'}
    joblib.dump(label_encoder_map, LABEL_ENCODER_PATH)

    print(f"\nAll artifacts saved to: {MODELS_DIR}")
    print("  - hybrid_model_3class.pth (final model)")
    print("  - best_model.pth (best validation model)")
    print("  - model_config.json")
    print("  - scaler_3class.pkl")
    print("  - label_encoder_3class.pkl")
    print("  - training_history_3class.pkl")
    print("  - training_checkpoint.pth (latest checkpoint for resume)")

    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)


if __name__ == '__main__':
    main()
