import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest


print("Loading CICIDS2017 training dataset...")

df = pd.read_csv(
    "training_data/cicids2017_training.csv"
)

# ------------------------------------
# Select BENIGN traffic only
# ------------------------------------

benign = df[df["Label"] == "BENIGN"]

print("Total BENIGN records:", len(benign))

# Use same split as previous steps
benign_train, benign_test = train_test_split(
    benign,
    test_size=0.20,
    random_state=42
)

X_train = benign_train.drop(columns=["Label"])

print("Training records:", len(X_train))


# ------------------------------------
# Load previously saved scaler
# ------------------------------------

print("\nLoading scaler...")

scaler = joblib.load(
    "models/isolation_scaler.pkl"
)

X_train_scaled = scaler.transform(X_train)

print("Scaling completed.")


# ------------------------------------
# Train Isolation Forest
# ------------------------------------

print("\nTraining Isolation Forest...")
print("This may take some time.")

model = IsolationForest(
    n_estimators=100,
    contamination="auto",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_scaled)

print("\nIsolation Forest training completed!")


# ------------------------------------
# Save model
# ------------------------------------

os.makedirs("models", exist_ok=True)

joblib.dump(
    model,
    "models/isolation_forest.pkl"
)

print("\nModel saved successfully!")
print("Location: models/isolation_forest.pkl")