import os
import numpy as np
import pandas as pd

# Paths
RAW_DATASET_PATH = "../dataset/raw"
PROCESSED_DATASET_PATH = "../dataset/processed"

# Create processed folder if it doesn't exist
os.makedirs(PROCESSED_DATASET_PATH, exist_ok=True)

# Columns to remove
COLUMNS_TO_DROP = [
    "Unnamed: 0",
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
    "SimillarHTTP"
]

# Constant columns identified during EDA
CONSTANT_COLUMNS = [
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "FIN Flag Count",
    "PSH Flag Count",
    "ECE Flag Count",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate"
]

# Redundant columns
REDUNDANT_COLUMNS = [
    "Fwd Header Length.1",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes"
]

def load_dataset(file_path):
    """
    Load a CSV file and clean column names.
    """
    df = pd.read_csv(file_path, low_memory=False)
    df.columns = df.columns.str.strip()

    # Remove leading/trailing spaces from string values
    for col in df.select_dtypes(include="object").columns:
        df[col] = df[col].str.strip()

    return df

def clean_dataset(df):
    """
    Clean the dataset by removing duplicates, handling missing values,
    and dropping unnecessary features.
    """

    # Remove duplicate rows
    df = df.drop_duplicates()

    # Replace infinite values with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Remove rows with missing values
    df.dropna(inplace=True)

    # Drop unnecessary columns
    df.drop(columns=COLUMNS_TO_DROP, errors="ignore", inplace=True)

    # Drop constant columns
    df.drop(columns=CONSTANT_COLUMNS, errors="ignore", inplace=True)

    # Drop redundant columns
    df.drop(columns=REDUNDANT_COLUMNS, errors="ignore", inplace=True)

    return df

def save_dataset(df, output_path):
    """
    Save the cleaned dataset.
    """
    df.to_csv(output_path, index=False)


def main():

    csv_files = [f for f in os.listdir(RAW_DATASET_PATH) if f.endswith(".csv")]

    print(f"Found {len(csv_files)} CSV files.\n")

    for file_name in csv_files:

        input_path = os.path.join(RAW_DATASET_PATH, file_name)
        output_path = os.path.join(PROCESSED_DATASET_PATH, file_name)

        print(f"Processing: {file_name}")

        print("Loading...")
        df = load_dataset(input_path)

        print("Loaded!")

        original_shape = df.shape

        print("Cleaning...")
        df = clean_dataset(df)

        print("Cleaned!")

        print(f"Original Shape : {original_shape}")
        print(f"Final Shape    : {df.shape}")

        print("Saving...")
        save_dataset(df, output_path)

        print("Saved!")

        print(f"Saved to: {output_path}")
        print("-" * 50)

def merge_datasets():

    csv_files = [f for f in os.listdir(PROCESSED_DATASET_PATH) if f.endswith(".csv")]

    dataframes = []

    for file in csv_files:
        print(f"Reading {file}")
        df = pd.read_csv(os.path.join(PROCESSED_DATASET_PATH, file), low_memory=False)
        dataframes.append(df)

    merged_df = pd.concat(dataframes, ignore_index=True)

    output_file = os.path.join(PROCESSED_DATASET_PATH, "final_dataset.csv")

    merged_df.to_csv(output_file, index=False)

    print("\nMerged dataset saved successfully!")
    print(f"Final Shape: {merged_df.shape}")        


if __name__ == "__main__":
    # main()
    merge_datasets()
