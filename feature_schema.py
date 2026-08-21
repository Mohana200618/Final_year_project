"""
feature_schema.py
=================
Single source of truth for ThreatScope's common feature schema.

These six features are reproducible from both CICIDS2017 and live
Zeek conn.log traffic, making them the only safe common ground for
training and inference.

Import this module in every script that uses features — do NOT
redefine the list elsewhere.
"""

# ---------------------------------------------------------------------------
# Common 6-feature schema
# ---------------------------------------------------------------------------

FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
]

LABEL_COLUMN = "Label"

# Convenience: full column list including label (for CSV loading)
COLUMNS = FEATURES + [LABEL_COLUMN]

# Number of features (useful for shape assertions)
N_FEATURES = len(FEATURES)


# ---------------------------------------------------------------------------
# Zeek conn.log → feature name mapping
# ---------------------------------------------------------------------------
# Maps Zeek TSV field names to ThreatScope feature names.
# Used by zeek_extractor.py.

ZEEK_FIELD_MAP = {
    "id.resp_p":   "Destination Port",          # responder port
    "duration":    "Flow Duration",              # flow duration (seconds → µs)
    "orig_pkts":   "Total Fwd Packets",          # originator packets
    "resp_pkts":   "Total Backward Packets",     # responder packets
    # Flow Bytes/s and Flow Packets/s are derived — see zeek_extractor.py
}

# Zeek fields needed to compute the derived features
ZEEK_BYTES_FIELDS  = ("orig_bytes", "resp_bytes")   # → Flow Bytes/s
ZEEK_DURATION_FIELD = "duration"                    # denominator


# ---------------------------------------------------------------------------
# Validation helper
# ---------------------------------------------------------------------------

def validate_dataframe(df, context: str = ""):
    """
    Assert that a DataFrame contains exactly the 6 required feature columns.
    Raises ValueError with a clear message if any column is missing.
    """
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        tag = f"[{context}] " if context else ""
        raise ValueError(
            f"{tag}Missing required features: {missing}\n"
            f"DataFrame has: {list(df.columns)}"
        )
    return True


if __name__ == "__main__":
    print("ThreatScope — Feature Schema")
    print("=" * 40)
    print(f"Feature count : {N_FEATURES}")
    print(f"Label column  : {LABEL_COLUMN}")
    print("\nFeatures:")
    for i, f in enumerate(FEATURES, 1):
        print(f"  {i}. {f}")
    print("\nZeek field map:")
    for zeek_field, ts_field in ZEEK_FIELD_MAP.items():
        print(f"  {zeek_field:<20} -> {ts_field}")
