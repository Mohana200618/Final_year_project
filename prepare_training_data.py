import pandas as pd
import numpy as np
import glob
import os

selected_features = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s"
]

columns_needed = selected_features + ["Label"]

# Find cleaned CICIDS2017 files
csv_files = glob.glob("cleaned_dataset/**/*.csv", recursive=True)

print("CSV files found:", len(csv_files))
print("Preparing training data...\n")

dataframes = []

for file in csv_files:

    print("Reading:", os.path.basename(file))

    # Load only the columns required for ML
    df = pd.read_csv(
        file,
        usecols=columns_needed
    )

    dataframes.append(df)

print("\nCombining datasets...")

combined_df = pd.concat(
    dataframes,
    ignore_index=True
)

# Safety check
combined_df.replace([np.inf, -np.inf], np.nan, inplace=True)
combined_df.dropna(inplace=True)

# Clean labels
combined_df["Label"] = combined_df["Label"].astype(str).str.strip()

print("\nTraining dataset shape:")
print(combined_df.shape)

print("\nFeatures:")
for feature in selected_features:
    print("-", feature)

print("\nNumber of classes:")
print(combined_df["Label"].nunique())

print("\nClass distribution:")
print(combined_df["Label"].value_counts())

# Create output folder
os.makedirs("training_data", exist_ok=True)

output_file = "training_data/cicids2017_training.csv"

combined_df.to_csv(
    output_file,
    index=False
)

print("\nTraining dataset saved successfully!")
print("Location:", output_file)