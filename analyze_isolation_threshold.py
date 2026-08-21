import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score
)

print("Loading dataset...")

df = pd.read_csv(
    "training_data/cicids2017_training.csv"
)

# -----------------------------------
# Separate benign and attack traffic
# -----------------------------------

benign = df[df["Label"] == "BENIGN"]
attacks = df[df["Label"] != "BENIGN"]

# Same benign split used previously
_, benign_test = train_test_split(
    benign,
    test_size=0.20,
    random_state=42
)

# -----------------------------------
# Build evaluation dataset
# -----------------------------------

test_df = pd.concat(
    [benign_test, attacks],
    ignore_index=True
)

X_test = test_df.drop(columns=["Label"])

y_true = (
    test_df["Label"] != "BENIGN"
).astype(int).values

print("Evaluation records:", len(X_test))

# -----------------------------------
# Load model + scaler
# -----------------------------------

scaler = joblib.load(
    "models/isolation_scaler.pkl"
)

model = joblib.load(
    "models/isolation_forest.pkl"
)

X_scaled = scaler.transform(X_test)

# -----------------------------------
# Get anomaly scores
# -----------------------------------

print("\nCalculating anomaly scores...")

scores = model.decision_function(X_scaled)

# Lower score = more anomalous

benign_scores = scores[y_true == 0]
attack_scores = scores[y_true == 1]

print("\nBENIGN SCORE STATISTICS")

print("Mean   :", benign_scores.mean())
print("Median :", np.median(benign_scores))
print("Min    :", benign_scores.min())
print("Max    :", benign_scores.max())

print("\nATTACK SCORE STATISTICS")

print("Mean   :", attack_scores.mean())
print("Median :", np.median(attack_scores))
print("Min    :", attack_scores.min())
print("Max    :", attack_scores.max())

# -----------------------------------
# Test different thresholds
# -----------------------------------

print("\nTesting thresholds...\n")

thresholds = np.linspace(
    scores.min(),
    scores.max(),
    100
)

best_threshold = None
best_f1 = 0
best_results = None

for threshold in thresholds:

    # Lower score = anomaly
    y_pred = (scores < threshold).astype(int)

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

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

    if f1 > best_f1:

        best_f1 = f1
        best_threshold = threshold

        best_results = (
            accuracy,
            precision,
            recall,
            f1
        )

# -----------------------------------
# Display best result
# -----------------------------------

print("=" * 50)
print("BEST THRESHOLD RESULT")
print("=" * 50)

print("Threshold:", best_threshold)

print(
    "Accuracy :",
    round(best_results[0], 4)
)

print(
    "Precision:",
    round(best_results[1], 4)
)

print(
    "Recall   :",
    round(best_results[2], 4)
)

print(
    "F1 Score :",
    round(best_results[3], 4)
)

print("\nThreshold analysis completed!")