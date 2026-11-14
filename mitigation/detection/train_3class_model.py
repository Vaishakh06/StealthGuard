"""
StealthGuard - 3-Class DDoS Detection Model Training
====================================================

Trains a CNN + BiLSTM + Attention model for 3-class classification:
    BENIGN / TCP_DDoS / UDP_DDoS

Input: engineered_dataset_3class.csv (3,384,445 rows, 48 features + label)
Output: Trained model + scaler + label encoder saved separately

Memory-optimized: Reads CSV in chunks to avoid loading full dataset into RAM.
System: 1.05 GB RAM available - must be memory-efficient.
"""

import os
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

PROJECT_ROOT = r'C:\CSBS\major_project_git\StealthGuard'
ENGINEERED_3CLASS_CSV = os.path.join(
    PROJECT_ROOT, 'dataset', 'engineered', 'engineered_3class.csv'
)
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models', 'threeglass')
os.makedirs(MODELS_DIR, exist_ok=True)

# Class mapping (must match dashboard expectation)
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
WINDOW_SIZE = 100
WINDOW_STRIDE = 20
CHUNK_SIZE = 50000  # Rows to read at once from CSV


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
    for chunk in pd.read_csv(csv_path, chunksize=chunk_size, usecols=STAT_FEATURES + [label_col]):
        # Map labels
        label_map = {
            'BENIGN': 0,
            'TCP_DDoS': 1,
            'UDP_DDoS': 2
        }
        chunk['Label'] = chunk['Label'].map(LABEL_MAP)
        
        # Verify no NaN labels
        nan_count = chunk['Label'].isna().sum()
        if nan_count > 0:
            print(f"WARNING: {nan_count} rows have unmapped labels in this chunk")
        
        # Convert to float32 immediately to save memory
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
    """Dataset for individual 48-feature engineered samples."""

    def __init__(self, X, y):
        self.X = X
        self.y = y

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        x = torch.tensor(self.X[idx], dtype=torch.float32).unsqueeze(0)  # (1, 48)
        y = torch.tensor(self.y[idx], dtype=torch.long)
        return x, y


class HybridCNNBiLSTMAttention(nn.Module):
    """Hybrid CNN + BiLSTM + Attention model (same architecture as original)."""
    
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
        self.attention = nn.Linear(128 * 2, 1)
        
        # Classifier
        self.classifier = nn.Sequential(
            nn.Dropout(0.3),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes)
        )
    
    def forward(self, x):
        # x shape: (batch, 1, 48, 100)
        
        # CNN: (batch, 128, 100) after conv+pool
        x = self.cnn(x)
        
        # Reshape for LSTM: (batch, 100, 128)
        x = x.permute(0, 2, 1)
        
        # Bi-LSTM: (batch, 100, 256)
        lstm_out, _ = self.lstm(x)
        
        # Attention: (batch, 256)
        scores = self.attention(lstm_out)
        weights = torch.softmax(scores, dim=1)
        context = torch.sum(weights * lstm_out, dim=1)
        
        # Classifier: (batch, num_classes)
        output = self.classifier(context)
        
        return output


# ============================================================
# MAIN TRAINING
# ============================================================

def main():
    print("=" * 70)
    print("STEALTHGUARD 3-CLASS MODEL TRAINING")
    print("=" * 70)
    print(f"PyTorch version: {torch.__version__}")
    print(f"Device: {'CUDA' if torch.cuda.is_available() else 'CPU'}")
    print(f"Window size: {WINDOW_SIZE}, Stride: {WINDOW_STRIDE}")
    print(f"Classes: {CLASS_MAP}")
    print("=" * 70)
    
    # Load data
    print("\nLoading dataset...")
    X, y = load_3class_dataset(ENGINEERED_3CLASS_CSV, chunk_size=CHUNK_SIZE)
    
    # Train/validation/test split (80/10/10)
    print("\nSplitting dataset...")
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42
    )
    
    print(f"Training set:   {X_train.shape[0]:,} windows")
    print(f"Validation set: {X_val.shape[0]:,} windows")
    print(f"Test set:       {X_test.shape[0]:,} windows")
    
    # Show class distribution in each split
    for name, y_data in [('Train', y_train), ('Val', y_val), ('Test', y_test)]:
        counts = np.bincount(y_data)
        print(f"  {name}: BENIGN={counts[0]:,}, TCP_DDoS={counts[1]:,}, UDP_DDoS={counts[2]:,}")
    
    # Create datasets and dataloaders
    train_dataset = DDoSDataset(X_train, y_train)
    val_dataset = DDoSDataset(X_val, y_val)
    test_dataset = DDoSDataset(X_test, y_test)
    
    BATCH_SIZE = 512
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True,
                              num_workers=2, pin_memory=False)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False,
                            num_workers=2, pin_memory=False)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False,
                             num_workers=2, pin_memory=False)
    
    print(f"\nTrain batches: {len(train_loader)}, Val batches: {len(val_loader)}, Test batches: {len(test_loader)}")
    
    # Initialize model
    model = HybridCNNBiLSTMAttention(input_channels=1, num_classes=NUM_CLASSES)
    print(f"\nModel parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Loss and optimizer
    # Use class weights to handle imbalance
    class_counts = np.bincount(y_train)
    class_weights = 1.0 / torch.tensor(class_counts, dtype=torch.float32)
    class_weights = class_weights / class_weights.sum() * len(class_counts)
    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='min', factor=0.5, patience=3
    )
    
    # Training loop
    num_epochs = 30
    patience = 5
    best_val_loss = float('inf')
    patience_counter = 0
    
    train_losses, val_losses = [], []
    train_accs, val_accs = [], []
    
    print("\nStarting training...")
    start_time = time.time()
    
    for epoch in range(num_epochs):
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        
        for X_batch, y_batch in train_loader:
            optimizer.zero_grad()
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item() * X_batch.size(0)
            _, predicted = torch.max(outputs, 1)
            train_correct += (predicted == y_batch).sum().item()
            train_total += y_batch.size(0)
        
        train_loss = train_loss / len(train_loader)
        train_acc = train_correct / train_total
        
        # Validation
        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                outputs = model(X_batch)
                loss = criterion(outputs, y_batch)
                val_loss += loss.item() * X_batch.size(0)
                _, predicted = torch.max(outputs, 1)
                val_correct += (predicted == y_batch).sum().item()
                val_total += y_batch.size(0)
        
        val_loss = val_loss / len(val_loader)
        val_acc = val_correct / val_total
        
        train_losses.append(train_loss)
        val_losses.append(val_loss)
        train_accs.append(train_acc)
        val_accs.append(val_acc)
        
        scheduler.step(val_loss)
        
        print(f"Epoch {epoch+1:2d}/{num_epochs} | "
              f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f} | "
              f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}")
        
        # Early stopping
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            # Save best model
            torch.save(model.state_dict(), os.path.join(MODELS_DIR, 'best_model.pth'))
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"Early stopping at epoch {epoch+1}")
                break
    
    training_time = time.time() - start_time
    print(f"\nTraining completed in {training_time:.1f} seconds")
    
    # Load best model
    model.load_state_dict(torch.load(os.path.join(MODELS_DIR, 'best_model.pth')))
    
    # Final test evaluation
    print("\n" + "=" * 70)
    print("FINAL TEST EVALUATION")
    print("=" * 70)
    
    model.eval()
    test_preds = []
    test_targets = []
    test_correct = 0
    test_total = 0
    
    with torch.no_grad():
        for X_batch, y_batch in test_loader:
            outputs = model(X_batch)
            _, predicted = torch.max(outputs, 1)
            test_preds.extend(predicted.cpu().numpy())
            test_targets.extend(y_batch.cpu().numpy())
            test_correct += (predicted == y_batch).sum().item()
            test_total += y_batch.size(0)
    
    test_acc = test_correct / test_total
    print(f"\nTest Accuracy: {test_acc:.4f} ({test_correct}/{test_total})")
    
    # Classification report
    print("\nClassification Report:")
    print(classification_report(test_targets, test_preds,
                                target_names=['BENIGN', 'TCP_DDoS', 'UDP_DDoS'],
                                digits=4))
    
    # Confusion matrix
    cm = confusion_matrix(test_targets, test_preds)
    print("\nConfusion Matrix:")
    print(cm)
    print(f"\nRow labels: BENIGN, TCP_DDoS, UDP_DDoS")
    print(f"Column labels: BENIGN, TCP_DDoS, UDP_DDoS")
    
    # Per-class metrics
    precision = precision_score(test_targets, test_preds, average=None)
    recall = recall_score(test_targets, test_preds, average=None)
    f1 = f1_score(test_targets, test_preds, average=None)
    macro_f1 = f1_score(test_targets, test_preds, average='macro')
    
    print(f"\nPer-Class Metrics:")
    print(f"{'Class':<15} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    for i, class_name in enumerate(['BENIGN', 'TCP_DDoS', 'UDP_DDoS']):
        print(f"{class_name:<15} {precision[i]:>10.4f} {recall[i]:>10.4f} {f1[i]:>10.4f}")
    
    print(f"\nMacro F1: {macro_f1:.4f}")
    
    # SYN_DDoS to BENIGN misclassification rate
    # SYN_DDoS is class index 1 (TCP_DDoS), BENIGN is class index 0
    syn_as_benign = cm[1, 0]  # True SYN_DDoS predicted as BENIGN
    syn_total = cm[1, :].sum()
    syn_as_benign_rate = syn_as_benign / syn_total if syn_total > 0 else 0
    print(f"\nSYN_DDoS misclassified as BENIGN: {syn_as_benign}/{syn_total} ({syn_as_benign/syn_total:.4f})")
    
    # BENIGN false positive rate (BENIGN predicted as attack)
    benign_as_attack = cm[0, 1] + cm[0, 2]
    benign_total = cm[0, :].sum()
    benign_fp_rate = benign_as_attack / benign_total if benign_total > 0 else 0
    print(f"BENIGN false positive rate: {benign_as_attack}/{benign_total} = {benign_fp_rate:.4f}")
    
    # Save model artifacts
    print("\nSaving model artifacts...")
    
    # Save model
    torch.save(model.state_dict(), os.path.join(MODELS_DIR, 'hybrid_model_3class.pth'))
    
    # Save model config
    model_config = {
        'input_channels': 1,
        'num_classes': NUM_CLASSES,
        'architecture': 'CNN + BiLSTM + Attention',
        'input_shape': [1, 48, 100],
        'class_map': {0: 'BENIGN', 1: 'TCP_DDoS', 2: 'UDP_DDoS'},
        'training_samples': int(X_train.shape[0]),
        'validation_samples': int(X_val.shape[0]),
        'test_samples': int(X_test.shape[0]),
        'training_time_seconds': training_time,
        'test_accuracy': float(test_acc),
        'macro_f1': float(macro_f1),
        'syn_as_benign_rate': float(syn_as_benign / syn_total),
        'benign_fp_rate': float(benign_fp_rate)
    }
    with open(os.path.join(MODELS_DIR, 'model_config.json'), 'w') as f:
        json.dump(model_config, f, indent=2)
    
    # Save scaler (fit on training data)
    scaler = StandardScaler()
    scaler.fit(X_train)
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'scaler_3class.pkl'))
    
    # Save label encoder
    label_encoder_map = {0: 'BENIGN', 1: 'TCP_DDoS', 2: 'UDP_DDoS'}
    joblib.dump(label_encoder_map, os.path.join(MODELS_DIR, 'label_encoder_3class.pkl'))
    
    # Save training history
    training_history = {
        'train_losses': train_losses,
        'val_losses': val_losses,
        'train_accs': train_accs,
        'val_accs': val_accs
    }
    joblib.dump(training_history, os.path.join(MODELS_DIR, 'training_history_3class.pkl'))
    
    print(f"\nAll artifacts saved to: {MODELS_DIR}")
    print("  - hybrid_model_3class.pth")
    print("  - model_config.json")
    print("  - scaler_3class.pkl")
    print("  - label_encoder_3class.pkl")
    print("  - training_history_3class.pkl")
    
    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)


if __name__ == '__main__':
    main()