import pandas as pd
import glob
import os

csv_files = glob.glob("dataset/**/*.csv", recursive=True)

print("Total CSV files found:", len(csv_files))
print("=" * 70)

for file in csv_files:

    print("\nFILE:", os.path.basename(file))

    # Read only the Label column
    df = pd.read_csv(file, usecols=lambda col: col.strip() == "Label")

    # Remove spaces from column names
    df.columns = df.columns.str.strip()

    print("Total rows:", len(df))

    print("\nAttack labels:")
    print(df["Label"].value_counts())

    print("-" * 70)