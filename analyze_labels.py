import pandas as pd
import glob

csv_files = glob.glob("dataset/**/*.csv", recursive=True)

all_labels = []

print("Reading labels from CICIDS2017...\n")

for file in csv_files:

    df = pd.read_csv(
        file,
        usecols=lambda col: col.strip() == "Label"
    )

    df.columns = df.columns.str.strip()

    all_labels.append(df["Label"])

# Combine labels from all CSV files
combined_labels = pd.concat(all_labels, ignore_index=True)

# Remove unnecessary spaces
combined_labels = combined_labels.astype(str).str.strip()

print("=" * 60)
print("TOTAL RECORDS:", len(combined_labels))
print("=" * 60)

print("\nATTACK CLASS DISTRIBUTION:\n")
print(combined_labels.value_counts())

print("\nTotal unique classes:")
print(combined_labels.nunique())

print("\nClass names:")
for label in sorted(combined_labels.unique()):
    print("-", label)