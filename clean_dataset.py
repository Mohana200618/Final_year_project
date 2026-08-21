import pandas as pd
import numpy as np
import glob
import os

csv_files = glob.glob("dataset/**/*.csv", recursive=True)

print("Total CSV files found:", len(csv_files))
print("=" * 60)

# Create folder for cleaned files
os.makedirs("cleaned_dataset", exist_ok=True)

for file in csv_files:

    filename = os.path.basename(file)

    print("\nProcessing:", filename)

    # Load CSV
    df = pd.read_csv(file)

    original_rows = len(df)

    # 1. Remove spaces from column names
    df.columns = df.columns.str.strip()

    # 2. Replace infinity values with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # 3. Remove rows containing NaN
    df.dropna(inplace=True)

    # 4. Remove duplicate rows
    df.drop_duplicates(inplace=True)

    # 5. Clean label values
    df["Label"] = df["Label"].astype(str).str.strip()

    # Fix encoding issue in Web Attack labels
    df["Label"] = df["Label"].str.replace(
        r"Web Attack .* Brute Force",
        "Web Attack - Brute Force",
        regex=True
    )

    df["Label"] = df["Label"].str.replace(
        r"Web Attack .* Sql Injection",
        "Web Attack - SQL Injection",
        regex=True
    )

    df["Label"] = df["Label"].str.replace(
        r"Web Attack .* XSS",
        "Web Attack - XSS",
        regex=True
    )

    cleaned_rows = len(df)

    # Save cleaned file
    output_path = os.path.join(
        "cleaned_dataset",
        filename
    )

    df.to_csv(output_path, index=False)

    print("Original rows :", original_rows)
    print("Cleaned rows  :", cleaned_rows)
    print("Removed rows  :", original_rows - cleaned_rows)

print("\n" + "=" * 60)
print("Cleaning completed successfully!")