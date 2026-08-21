import pandas as pd
import glob

# Features selected for our common CICIDS2017 <-> Zeek schema
selected_features = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s"
]

# Find first cleaned CSV
csv_files = glob.glob("cleaned_dataset/**/*.csv", recursive=True)

df = pd.read_csv(csv_files[0], nrows=5)

print("=" * 60)
print("CHECKING SELECTED FEATURES")
print("=" * 60)

missing_features = []

for feature in selected_features:
    if feature in df.columns:
        print("[OK]", feature)
    else:
        print("[MISSING]", feature)
        missing_features.append(feature)

print("\nSelected features:", len(selected_features))
print("Missing features:", len(missing_features))

if len(missing_features) == 0:
    print("\nSUCCESS: Common feature schema is available in CICIDS2017.")
else:
    print("\nSome selected features are missing.")