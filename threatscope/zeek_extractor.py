"""
threatscope/zeek_extractor.py
==============================
Parses Zeek conn.log (TSV format) and produces a DataFrame with the
six ThreatScope common features.

Zeek conn.log reference fields used
-------------------------------------
  uid          - unique flow identifier
  id.resp_p    - destination port
  duration     - flow duration in seconds
  orig_pkts    - originator packet count  (Total Fwd Packets)
  resp_pkts    - responder packet count   (Total Backward Packets)
  orig_bytes   - originator bytes
  resp_bytes   - responder bytes

Derived features
-----------------
  Flow Bytes/s   = (orig_bytes + resp_bytes) / duration
  Flow Packets/s = (orig_pkts  + resp_pkts)  / duration

Notes
------
  - Duration is stored in seconds by Zeek; CICIDS2017 stores it in
    microseconds.  We convert: duration_us = duration_s * 1_000_000
  - Rows with missing or zero duration are dropped (division guard).
  - Rows with '-' (Zeek null) in any required field are dropped.
"""

import sys
import os
import pandas as pd
import numpy as np

# Allow running from parent dir in dev/demo mode
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import feature_schema as fs


# Zeek conn.log field names we need
_ZEEK_REQUIRED_FIELDS = [
    "uid",
    "id.resp_p",
    "duration",
    "orig_pkts",
    "resp_pkts",
    "orig_bytes",
    "resp_bytes",
]

# Zeek null sentinel
_ZEEK_NULL = "-"


def parse_conn_log(filepath: str) -> pd.DataFrame:
    """
    Parse a Zeek conn.log file and return a DataFrame with the
    ThreatScope 6-feature schema.

    Parameters
    ----------
    filepath : str
        Absolute or relative path to a Zeek conn.log file.

    Returns
    -------
    pd.DataFrame
        Columns matching fs.FEATURES.  May be empty if no valid rows.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Zeek conn.log not found: {filepath}")

    # ------------------------------------------------------------------
    # Read Zeek TSV log, skipping comment lines that start with '#'
    # and extracting column names from the #fields line.
    # ------------------------------------------------------------------
    header = []
    data_lines = []

    with open(filepath, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                # e.g. "#fields\tts\tuid\t..."
                header = line.split("\t")[1:]  # drop '#fields' token
            elif line.startswith("#"):
                continue  # other metadata lines
            else:
                data_lines.append(line.split("\t"))

    if not header:
        raise ValueError(
            f"No #fields header found in Zeek log: {filepath}"
        )

    df_raw = pd.DataFrame(data_lines, columns=header)

    # Check required fields exist
    missing = [f for f in _ZEEK_REQUIRED_FIELDS if f not in df_raw.columns]
    if missing:
        raise ValueError(
            f"Zeek conn.log missing required fields: {missing}\n"
            f"Available: {list(df_raw.columns)}"
        )

    # ------------------------------------------------------------------
    # Extract and clean required columns
    # ------------------------------------------------------------------
    df = df_raw[_ZEEK_REQUIRED_FIELDS].copy()

    # Replace Zeek null '-' with NaN
    df.replace(_ZEEK_NULL, np.nan, inplace=True)

    # Cast to numeric (errors → NaN)
    for col in ["id.resp_p", "duration", "orig_pkts",
                 "resp_pkts", "orig_bytes", "resp_bytes"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Drop rows with any NaN in required fields
    before = len(df)
    df.dropna(subset=["id.resp_p", "duration", "orig_pkts",
                       "resp_pkts", "orig_bytes", "resp_bytes"],
              inplace=True)

    # Drop zero-duration flows (division by zero guard)
    df = df[df["duration"] > 0.0]
    after = len(df)

    dropped = before - after
    if dropped > 0:
        print(f"  [ZeekExtractor] Dropped {dropped:,} rows "
              f"(missing/zero-duration) from {os.path.basename(filepath)}")

    if df.empty:
        print("  [ZeekExtractor] WARNING: No valid rows after cleaning.")
        return pd.DataFrame(columns=fs.FEATURES)

    # ------------------------------------------------------------------
    # Build ThreatScope features
    # ------------------------------------------------------------------
    out = pd.DataFrame()

    # Destination Port (as-is, integer)
    out["Destination Port"] = df["id.resp_p"].astype(int)

    # Flow Duration: convert seconds -> microseconds to match CICIDS2017
    out["Flow Duration"] = (df["duration"] * 1_000_000).astype(float)

    # Packet counts
    out["Total Fwd Packets"]      = df["orig_pkts"].astype(int)
    out["Total Backward Packets"] = df["resp_pkts"].astype(int)

    # Derived: bytes/s and packets/s
    total_bytes   = df["orig_bytes"] + df["resp_bytes"]
    total_packets = df["orig_pkts"]  + df["resp_pkts"]

    out["Flow Bytes/s"]   = total_bytes   / df["duration"]
    out["Flow Packets/s"] = total_packets / df["duration"]

    out.reset_index(drop=True, inplace=True)

    # Validate against schema
    fs.validate_dataframe(out, context="ZeekExtractor")

    return out


def extract_from_conn_log(filepath: str) -> pd.DataFrame:
    """
    Convenience alias for parse_conn_log().
    """
    return parse_conn_log(filepath)

def parse_single_line(line: str, header: list) -> dict:
    """
    Parse a single Zeek conn.log TSV line and return the ThreatScope feature dict.
    Returns None if the line is invalid or missing required data (e.g., duration = 0).
    """
    fields = line.split('\t')
    if len(fields) != len(header):
        return None
        
    row = dict(zip(header, fields))
    
    # Check required fields
    for f in _ZEEK_REQUIRED_FIELDS:
        if f not in row or row[f] == _ZEEK_NULL:
            return None
            
    try:
        dest_port = int(row['id.resp_p'])
        duration_s = float(row['duration'])
        orig_pkts = int(row['orig_pkts'])
        resp_pkts = int(row['resp_pkts'])
        orig_bytes = float(row['orig_bytes'])
        resp_bytes = float(row['resp_bytes'])
        
        if duration_s <= 0.0:
            return None
            
        total_pkts = orig_pkts + resp_pkts
        total_bytes_all = orig_bytes + resp_bytes
        
        features = {
            "Destination Port": dest_port,
            "Flow Duration": duration_s * 1_000_000.0,
            "Total Fwd Packets": orig_pkts,
            "Total Backward Packets": resp_pkts,
            "Flow Bytes/s": total_bytes_all / duration_s,
            "Flow Packets/s": total_pkts / duration_s
        }
        return features
    except ValueError:
        return None


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python zeek_extractor.py <path/to/conn.log>")
        sys.exit(1)

    path = sys.argv[1]
    print(f"Parsing: {path}")
    df = parse_conn_log(path)
    print(f"Extracted {len(df):,} flows")
    print(df.head())
    print("\nFeature stats:")
    print(df.describe())
