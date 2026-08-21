import pandas as pd
import numpy as np
import glob
import os

# Find all CSV files
csv_files = glob.glob("dataset/**/*.csv", recursive=True)

# Use the first CSV file for inspection
file = csv_files[0]

print("Inspecting:", os.path.basename(file))
print("Loading dataset...")

df = pd.read_csv(file)

# Remove leading/trailing spaces from column names
df.columns = df.columns.str.strip()

print("\nDataset Shape:")
print(df.shape)

print("\nMissing Values:")
print(df.isnull().sum().sum())

# Check numeric columns for infinity
numeric_df = df.select_dtypes(include=[np.number])

print("\nPositive/Negative Infinity Values:")
print(np.isinf(numeric_df).sum().sum())

print("\nDuplicate Rows:")
print(df.duplicated().sum())

print("\nData Types:")
print(df.dtypes.value_counts())