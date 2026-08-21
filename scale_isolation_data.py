import pandas as pd
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


print("Loading dataset...")

df = pd.read_csv(
    "training_data/cicids2017_training.csv"
)

# Select only BENIGN traffic
benign = df[df["Label"] == "BENIGN"]

# Same split used previously
benign_train, benign_test = train_test_split(
    benign,
    test_size=0.20,
    random_state=42
)

# Remove Label
X_train = benign_train.drop(columns=["Label"])

print("Training data shape:", X_train.shape)

# Create scaler
scaler = StandardScaler()

print("\nFitting scaler...")

X_train_scaled = scaler.fit_transform(X_train)

print("Scaling completed!")

print("\nScaled data shape:")
print(X_train_scaled.shape)

print("\nFirst scaled record:")
print(X_train_scaled[0])

# Create model storage folder
os.makedirs("models", exist_ok=True)

# Save scaler
joblib.dump(
    scaler,
    "models/isolation_scaler.pkl"
)

print("\nScaler saved successfully!")
print("Location: models/isolation_scaler.pkl")