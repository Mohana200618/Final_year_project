import pandas as pd
import glob

# Find cleaned CSV files
csv_files = glob.glob("cleaned_dataset/**/*.csv", recursive=True)

# Read only the header from the first cleaned file
df = pd.read_csv(csv_files[0], nrows=0)

columns = df.columns.tolist()

print("=" * 60)
print("CICIDS2017 FEATURE LIST")
print("=" * 60)

for number, column in enumerate(columns, start=1):
    print(f"{number}. {column}")

print("\nTotal columns:", len(columns))

# Separate input features and target
features = [col for col in columns if col != "Label"]

print("Input features:", len(features))
print("Target column: Label")