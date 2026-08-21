"""
evaluate_isolation_proper.py
============================
Proper 3-way evaluation of the trained Isolation Forest.

Methodology (no data leakage):
  - BENIGN:  60% train (already used to fit IF) / 20% val / 20% test
  - Attacks: 50% val / 50% test  (never seen during training)
  - Threshold is selected ONLY on the val set
  - Final metrics are reported ONLY on the held-out test set

This script does NOT retrain the model — it evaluates the already-saved
models/isolation_forest.pkl and models/isolation_scaler.pkl.

Outputs
-------
  - Printed val + test metrics
  - models/isolation_threshold.txt  (the selected threshold)
"""

import sys
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)

# Import canonical feature schema
import feature_schema as fs


# ---------------------------------------------------------------------------
# 1. Load dataset
# ---------------------------------------------------------------------------

print("=" * 60)
print("ThreatScope — Isolation Forest Proper Evaluation")
print("=" * 60)

print("\n[1/6] Loading training dataset...")

df = pd.read_csv("training_data/cicids2017_training.csv")

print(f"  Total records  : {len(df):,}")
print(f"  Columns        : {list(df.columns)}")

# Validate features
fs.validate_dataframe(df, context="dataset")
print("  Feature schema : OK")

# ---------------------------------------------------------------------------
# 2. Split BENIGN into train / val / test (60 / 20 / 20)
#    We reproduce the SAME train split used in train_isolation_forest.py
#    (test_size=0.20, random_state=42) then split the leftover val/test.
# ---------------------------------------------------------------------------

print("\n[2/6] Splitting BENIGN traffic (60/20/20)...")

benign  = df[df[fs.LABEL_COLUMN] == "BENIGN"]
attacks = df[df[fs.LABEL_COLUMN] != "BENIGN"]

print(f"  BENIGN records : {len(benign):,}")
print(f"  Attack records : {len(attacks):,}")

# Reproduce original 80/20 split (train=80%, holdout=20%)
benign_train, benign_holdout = train_test_split(
    benign, test_size=0.20, random_state=42
)

# Split the holdout 50/50 into val and test
benign_val, benign_test = train_test_split(
    benign_holdout, test_size=0.50, random_state=42
)

print(f"  BENIGN train   : {len(benign_train):,}  (used to fit IF — not re-used here)")
print(f"  BENIGN val     : {len(benign_val):,}  (threshold selection)")
print(f"  BENIGN test    : {len(benign_test):,}  (final reporting only)")

# ---------------------------------------------------------------------------
# 3. Split attacks 50/50 into val / test
# ---------------------------------------------------------------------------

print("\n[3/6] Splitting attack traffic (50/50 val/test)...")

attacks_val, attacks_test = train_test_split(
    attacks, test_size=0.50, random_state=42
)

print(f"  Attack val     : {len(attacks_val):,}")
print(f"  Attack test    : {len(attacks_test):,}")

# Build val set and test set
val_df  = pd.concat([benign_val,  attacks_val],  ignore_index=True)
test_df = pd.concat([benign_test, attacks_test], ignore_index=True)

X_val  = val_df[fs.FEATURES]
y_val  = (val_df[fs.LABEL_COLUMN]  != "BENIGN").astype(int).values

X_test  = test_df[fs.FEATURES]
y_test  = (test_df[fs.LABEL_COLUMN] != "BENIGN").astype(int).values

print(f"\n  Val set size   : {len(X_val):,}  (attack ratio: {y_val.mean():.1%})")
print(f"  Test set size  : {len(X_test):,}  (attack ratio: {y_test.mean():.1%})")

# ---------------------------------------------------------------------------
# 4. Load saved scaler + model
# ---------------------------------------------------------------------------

print("\n[4/6] Loading saved scaler and Isolation Forest...")

scaler = joblib.load("models/isolation_scaler.pkl")
model  = joblib.load("models/isolation_forest.pkl")

X_val_scaled  = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

print("  Scaler loaded  : OK")
print("  IF model loaded: OK")

# ---------------------------------------------------------------------------
# 5. Compute anomaly scores on val set → select best threshold
# ---------------------------------------------------------------------------

print("\n[5/6] Selecting threshold on VALIDATION set only...")

val_scores = model.decision_function(X_val_scaled)

# Sweep 200 thresholds across the val score range
thresholds = np.linspace(val_scores.min(), val_scores.max(), 200)

best_threshold = None
best_f1        = -1.0
best_val_stats = None

for thr in thresholds:
    y_pred_val = (val_scores < thr).astype(int)

    prec = precision_score(y_val, y_pred_val, zero_division=0)
    rec  = recall_score(   y_val, y_pred_val, zero_division=0)
    f1   = f1_score(       y_val, y_pred_val, zero_division=0)
    acc  = accuracy_score( y_val, y_pred_val)

    if f1 > best_f1:
        best_f1        = f1
        best_threshold = thr
        best_val_stats = dict(
            accuracy=acc, precision=prec, recall=rec, f1=f1,
            threshold=thr
        )

print(f"  Best val threshold : {best_threshold:.6f}")
print(f"  Val Precision      : {best_val_stats['precision']:.4f}")
print(f"  Val Recall         : {best_val_stats['recall']:.4f}")
print(f"  Val F1             : {best_val_stats['f1']:.4f}")
print(f"  Val Accuracy       : {best_val_stats['accuracy']:.4f}")
print("\n  NOTE: Val metrics are for threshold selection only.")
print("        Do NOT report these as final results.")

# Save threshold
with open("models/isolation_threshold.txt", "w") as fh:
    fh.write(f"{best_threshold:.10f}\n")
print(f"\n  Threshold saved -> models/isolation_threshold.txt")

# ---------------------------------------------------------------------------
# 6. Evaluate on HELD-OUT TEST SET (final, reportable metrics)
# ---------------------------------------------------------------------------

print("\n[6/6] Evaluating on HELD-OUT TEST SET...")
print("      (This data was never used for training or threshold selection)")

test_scores = model.decision_function(X_test_scaled)

y_pred_test = (test_scores < best_threshold).astype(int)

acc  = accuracy_score( y_test, y_pred_test)
prec = precision_score(y_test, y_pred_test, zero_division=0)
rec  = recall_score(   y_test, y_pred_test, zero_division=0)
f1   = f1_score(       y_test, y_pred_test, zero_division=0)
cm   = confusion_matrix(y_test, y_pred_test)

# ROC-AUC and PR-AUC (negate scores because lower = more anomalous)
anomaly_prob = -test_scores
roc_auc = roc_auc_score(y_test, anomaly_prob)
pr_auc  = average_precision_score(y_test, anomaly_prob)

print("\n" + "=" * 60)
print("ISOLATION FOREST — FINAL TEST SET RESULTS")
print("(threshold selected on validation set, reported on test set)")
print("=" * 60)

print(f"\n  Threshold   : {best_threshold:.6f}")
print(f"  Accuracy    : {acc:.4f}  ({acc*100:.2f}%)")
print(f"  Precision   : {prec:.4f}  ({prec*100:.2f}%)")
print(f"  Recall      : {rec:.4f}  ({rec*100:.2f}%)")
print(f"  F1 Score    : {f1:.4f}  ({f1*100:.2f}%)")
print(f"  ROC-AUC     : {roc_auc:.4f}")
print(f"  PR-AUC      : {pr_auc:.4f}")

print("\n  Confusion Matrix:")
print("  (rows=actual, cols=predicted)")
print("  Labels: 0=Normal, 1=Attack")
print(f"\n  {cm[0][0]:>10,}  {cm[0][1]:>10,}   <- Actual Normal")
print(f"  {cm[1][0]:>10,}  {cm[1][1]:>10,}   <- Actual Attack")
print(f"  {'Pred Normal':>10}  {'Pred Attack':>10}")

tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

print(f"\n  True Negatives  (normal correctly identified) : {tn:,}")
print(f"  False Positives (normal flagged as attack)     : {fp:,}")
print(f"  False Negatives (attacks missed)               : {fn:,}")
print(f"  True Positives  (attacks correctly detected)   : {tp:,}")
print(f"\n  False Positive Rate : {fpr:.4f}  ({fpr*100:.2f}%)")
print(f"  Detection Rate      : {rec:.4f}  ({rec*100:.2f}%)")

print("\n" + "=" * 60)
print("EVALUATION COMPLETE")
print("=" * 60)
print("\nLimitations:")
print("  - IF trained on BENIGN only -> anomaly scores overlap")
print("  - 6 features limit discriminative power vs 78-feature model")
print("  - Threshold optimized for F1; a different threshold may suit")
print("    operational needs (e.g. higher recall at cost of precision)")
