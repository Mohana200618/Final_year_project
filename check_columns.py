import pandas as pd
import glob
import os

csv_files = glob.glob("dataset/**/*.csv", recursive=True)

reference_columns = None
all_same = True

print("Checking column structure of all CICIDS2017 files...\n")

for file in csv_files:

    # Read only the header
    df = pd.read_csv(file, nrows=0)

    # Clean spaces from column names
    columns = [col.strip() for col in df.columns]

    print(
        os.path.basename(file),
        "->",
        len(columns),
        "columns"
    )

    if reference_columns is None:
        reference_columns = columns

    elif columns != reference_columns:
        all_same = False
        print("⚠ Column structure differs!")

print("\n" + "=" * 60)

if all_same:
    print("SUCCESS: All CSV files have the same column structure.")
else:
    print("WARNING: Some CSV files have different column structures.")