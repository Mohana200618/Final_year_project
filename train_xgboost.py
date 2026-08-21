"""
train_xgboost.py
================
Trains a multiclass XGBoost classifier on CICIDS2017 using the
6 common ThreatScope features.

Design decisions
----------------
  - Stratified 70 / 15 / 15 train / val / test split (by label)
  - Val set used for early stopping only (not metric reporting)
  - Test set is HELD OUT until final evaluation
  - Class imbalance handled via per-sample weights (compute_sample_weight)
    — avoids SMOTE which is infeasible at 2.5M rows
  - LabelEncoder persisted so inference uses identical mapping
  - No metric inflation: all reported metrics come from the test set

Saved artifacts
---------------
  models/xgb_classifier.pkl
  models/xgb_label_encoder.pkl
"""

import sys
import numpy as np
import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
import xgboost as xgb

import feature_schema as fs


print("=" * 60)
print("ThreatScope — XGBoost Multiclass Classifier Training")
print("=" * 60)

# ---------------------------------------------------------------------------
# 1. Load dataset
# ---------------------------------------------------------------------------

print("\n[1/7] Loading training dataset...")

df = pd.read_csv("training_data/cicids2017_training.csv")

fs.validate_dataframe(df, context="XGBoost training")

X = df[fs.FEATURES].values
y_raw = df[fs.LABEL_COLUMN].values

print(f"  Dataset shape   : {df.shape}")
print(f"  Unique labels   : {len(np.unique(y_raw))}")
print("\n  Class distribution:")
for label, count in sorted(
    zip(*np.unique(y_raw, return_counts=True)),
    key=lambda x: -x[1]
):
    pct = count / len(y_raw) * 100
    print(f"    {label:<40} {count:>8,}  ({pct:.2f}%)")

# ---------------------------------------------------------------------------
# 2. Encode labels
# ---------------------------------------------------------------------------

print("\n[2/7] Encoding labels...")

le = LabelEncoder()
y = le.fit_transform(y_raw)

print(f"  Label classes   : {list(le.classes_)}")
print(f"  Encoded range   : 0 to {y.max()}")

# ---------------------------------------------------------------------------
# 3. Stratified 70 / 15 / 15 split
# ---------------------------------------------------------------------------

print("\n[3/7] Splitting dataset (70% train / 15% val / 15% test)...")

X_train, X_temp, y_train, y_temp = train_test_split(
    X, y,
    test_size=0.30,
    random_state=42,
    stratify=y
)

X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp,
    test_size=0.50,
    random_state=42,
    stratify=y_temp
)

print(f"  Train  : {len(X_train):,}")
print(f"  Val    : {len(X_val):,}")
print(f"  Test   : {len(X_test):,}  <- held out until final evaluation")

# ---------------------------------------------------------------------------
# 4. Handle class imbalance via sample weights
# ---------------------------------------------------------------------------

print("\n[4/7] Computing per-sample class weights...")

sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)

print(f"  Min weight : {sample_weights.min():.6f}")
print(f"  Max weight : {sample_weights.max():.2f}")
print("  Strategy   : balanced (inverse class frequency)")

# ---------------------------------------------------------------------------
# 5. Train XGBoost
# ---------------------------------------------------------------------------

print("\n[5/7] Training XGBoost (this will take several minutes)...")
print("      Early stopping on val set after 20 non-improving rounds.")

n_classes = len(le.classes_)

model = xgb.XGBClassifier(
    n_estimators=500,
    learning_rate=0.1,
    max_depth=6,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="multi:softmax",
    num_class=n_classes,
    eval_metric="mlogloss",
    early_stopping_rounds=20,
    use_label_encoder=False,
    random_state=42,
    n_jobs=-1,
    verbosity=1,
)

model.fit(
    X_train, y_train,
    sample_weight=sample_weights,
    eval_set=[(X_val, y_val)],
    verbose=50,
)

print(f"\n  Best iteration : {model.best_iteration}")
print(f"  Best val score : {model.best_score:.6f}")

# ---------------------------------------------------------------------------
# 6. Evaluate on HELD-OUT TEST SET
# ---------------------------------------------------------------------------

print("\n[6/7] Evaluating on HELD-OUT TEST SET...")

y_pred = model.predict(X_test)

acc       = accuracy_score(y_test, y_pred)
f1_macro  = f1_score(y_test, y_pred, average="macro",    zero_division=0)
f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)
cm        = confusion_matrix(y_test, y_pred)

print("\n" + "=" * 60)
print("XGBOOST — FINAL TEST SET RESULTS")
print("=" * 60)
print(f"\n  Accuracy       : {acc:.4f}  ({acc*100:.2f}%)")
print(f"  Macro F1       : {f1_macro:.4f}  ({f1_macro*100:.2f}%)")
print(f"  Weighted F1    : {f1_weighted:.4f}  ({f1_weighted*100:.2f}%)")

print("\n  Per-class report:")
class_names = list(le.classes_)
print(
    classification_report(
        y_test, y_pred,
        target_names=class_names,
        zero_division=0
    )
)

print("\n  NOTE: Macro F1 may be low due to severe class imbalance.")
print("        Weighted F1 is higher because dominant classes score well.")
print("        This is expected — not inflated.")

# ---------------------------------------------------------------------------
# 7. Save model + encoder
# ---------------------------------------------------------------------------

print("\n[7/7] Saving model and label encoder...")

os.makedirs("models", exist_ok=True)

joblib.dump(model, "models/xgb_classifier.pkl")
joblib.dump(le,    "models/xgb_label_encoder.pkl")

print("  Saved: models/xgb_classifier.pkl")
print("  Saved: models/xgb_label_encoder.pkl")

print("\n" + "=" * 60)
print("XGBoost training COMPLETE")
print("=" * 60)
