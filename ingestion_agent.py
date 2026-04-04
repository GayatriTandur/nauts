import os
import pandas as pd

def ingest_logs(log_file):
    """
    Ingestion Agent
    Reads CSV logs into a pandas DataFrame and validates required schema.
    """

    if not os.path.exists(log_file):
        raise FileNotFoundError(f"Log file not found: {log_file}")

    # Read CSV
    df = pd.read_csv(log_file)

    # Validate required columns
    required_cols = ["timestamp", "user", "ip", "event"]
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns in CSV: {missing}")

    # Convert timestamp to datetime
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if df["timestamp"].isna().any():
        raise ValueError("Some timestamp values could not be parsed as datetime.")

    return df


