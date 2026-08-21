import pandas as pd
from sklearn.model_selection import train_test_split

print("Loading training dataset...")

df = pd.read_csv(
    "training_data/cicids2017_training.csv"
)

print("Dataset shape:", df.shape)

# --------------------------------
# Separate BENIGN and attack data
# --------------------------------

benign = df[df["Label"] == "BENIGN"]
attacks = df[df["Label"] != "BENIGN"]

print("\nBENIGN records:", len(benign))
print("Attack records:", len(attacks))

# --------------------------------
# Split benign traffic
# --------------------------------

benign_train, benign_test = train_test_split(
    benign,
    test_size=0.20,
    random_state=42
)

print("\nBenign training records:")
print(len(benign_train))

print("Benign testing records:")
print(len(benign_test))

# --------------------------------
# Prepare Isolation Forest X data
# --------------------------------

X_isolation_train = benign_train.drop(
    columns=["Label"]
)

print("\nIsolation Forest training shape:")
print(X_isolation_train.shape)

print("\nFeatures used:")

for feature in X_isolation_train.columns:
    print("-", feature)

print(
    "\nIsolation Forest data prepared successfully!"
)