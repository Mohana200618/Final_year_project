import pandas as pd
from sklearn.model_selection import train_test_split

file_path = "training_data/cicids2017_training.csv"

print("Loading ML-ready dataset...")

df = pd.read_csv(file_path)

print("Dataset loaded!")
print("Shape:", df.shape)

# ----------------------------
# Separate features and labels
# ----------------------------

X = df.drop(columns=["Label"])
y = df["Label"]

print("\nFeature matrix shape:", X.shape)
print("Label vector shape:", y.shape)

# ----------------------------
# Train/Test Split
# ----------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTRAINING SET")
print("X_train:", X_train.shape)
print("y_train:", y_train.shape)

print("\nTEST SET")
print("X_test:", X_test.shape)
print("y_test:", y_test.shape)

print("\nTraining class distribution:")
print(y_train.value_counts())

print("\nTesting class distribution:")
print(y_test.value_counts())

print("\nTrain/Test split completed successfully!")