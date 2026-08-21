import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

print("Loading dataset...")

df = pd.read_csv(
    "training_data/cicids2017_training.csv"
)

# Separate BENIGN and attack traffic
benign = df[df["Label"] == "BENIGN"]
attacks = df[df["Label"] != "BENIGN"]

# IMPORTANT:
# Use the same benign split used during training.
_, benign_test = train_test_split(
    benign,
    test_size=0.20,
    random_state=42
)

print("Unseen BENIGN test records:", len(benign_test))
print("Attack records:", len(attacks))

# ------------------------------------------------
# Build evaluation set
# ------------------------------------------------

test_df = pd.concat(
    [benign_test, attacks],
    ignore_index=True
)

# Ground truth:
# 0 = Normal
# 1 = Attack
y_true = (test_df["Label"] != "BENIGN").astype(int)

X_test = test_df.drop(columns=["Label"])

print("\nTotal evaluation records:", len(X_test))

# ------------------------------------------------
# Load saved scaler and model
# ------------------------------------------------

print("\nLoading scaler and Isolation Forest...")

scaler = joblib.load(
    "models/isolation_scaler.pkl"
)

model = joblib.load(
    "models/isolation_forest.pkl"
)

# Apply SAME scaler used during training
X_test_scaled = scaler.transform(X_test)

# ------------------------------------------------
# Prediction
# ------------------------------------------------

print("Running anomaly detection...")

predictions = model.predict(X_test_scaled)

# Isolation Forest returns:
#  1  = normal
# -1  = anomaly

# Convert to:
# 0 = normal
# 1 = attack/anomaly

y_pred = (predictions == -1).astype(int)

# ------------------------------------------------
# Metrics
# ------------------------------------------------

accuracy = accuracy_score(y_true, y_pred)

precision = precision_score(
    y_true,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_true,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_true,
    y_pred,
    zero_division=0
)

cm = confusion_matrix(y_true, y_pred)

print("\n" + "=" * 50)
print("ISOLATION FOREST RESULTS")
print("=" * 50)

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nMatrix format:")
print("[[True Normal   False Alarm]")
print(" [Missed Attack Detected Attack]]")

print("\nEvaluation completed successfully!")