"""
build_markov_matrix.py
=======================
Builds a DATA-DRIVEN first-order Markov Chain transition matrix from the
CICIDS2017 dataset.

Approach
--------
  The CICIDS2017 dataset is organised as one CSV file per attack-scenario day.
  Each file's name encodes its chronological position in the experiment week:

    Monday    (Day 1) : BENIGN only - baseline
    Tuesday   (Day 2) : FTP-Patator, SSH-Patator
    Wednesday (Day 3) : DoS Hulk, DoS GoldenEye, DoS slowloris,
                        DoS Slowhttptest, Heartbleed
    Thursday  (Day 4) : Web Attack - Brute Force, XSS, SQL Injection,
                        Infiltration
    Friday    (Day 5) : Bot, PortScan, DDoS

  Within each file, consecutive attack-labelled rows (non-BENIGN) represent
  flows recorded during the same attack campaign.  We extract consecutive
  stage pairs (S_t, S_{t+1}) from these attack rows and accumulate counts.

  We do NOT cross file boundaries - the last row of one file does NOT
  transition to the first row of the next file, because the files capture
  different attack scenarios on different days.

  BENIGN rows are excluded from transition counting because they represent
  normal background traffic, not attack-stage progression.

Smoothing
---------
  Laplace (add-1) smoothing is applied so that every state pair has a
  non-zero probability even if it was never observed.

  P(i -> j) = (C_ij + 1) / sum_k(C_ik + 1)

Output
------
  models/markov_transition_matrix.json

  Contains:
    matrix            - {stage: {stage: probability}}
    raw_counts        - {stage: {stage: int}} before smoothing
    total_transitions - total transition pairs extracted
    source            - human-readable provenance string
    build_timestamp   - ISO-8601 UTC timestamp
    smoothing         - "Laplace (add-1)"

Limitations disclosed
---------------------
  - No timestamp column exists in the dataset; file-level ordering is used.
  - Consecutive rows within a file are from the same attack campaign but
    may not be from the same attacker host or session.
  - Self-loop counts (e.g. IMPACT->IMPACT) will be high because DoS attacks
    generate hundreds of thousands of consecutive flows.  This accurately
    reflects the dataset, not a modelling error.

Run
---
  python build_markov_matrix.py
"""

import os
import sys
import json
import datetime
import glob

import pandas as pd

# ---------------------------------------------------------------------------
# Allow import of project modules
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threatscope.attack_chain import label_to_stage, ALL_STAGES, STAGE_NORMAL


# ---------------------------------------------------------------------------
# Chronologically ordered file list
# Monday -> Friday, exactly as documented by CICIDS2017
# ---------------------------------------------------------------------------

_RAW_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "dataset", "MachineLearningCVE")

_ORDERED_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",                          # Day 1 BENIGN
    "Tuesday-WorkingHours.pcap_ISCX.csv",                         # Day 2 Brute force
    "Wednesday-workingHours.pcap_ISCX.csv",                       # Day 3 DoS
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",     # Day 4a Web attacks
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",# Day 4b Infiltration
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",                  # Day 5a Bot
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",       # Day 5b PortScan
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",           # Day 5c DDoS
]

_LABEL_COL = " Label"          # raw CSV has a leading space in header


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _init_count_matrix():
    """Return a nested dict of zeros for all stage pairs."""
    return {s: {t: 0 for t in ALL_STAGES} for s in ALL_STAGES}


def _extract_label_column(df: pd.DataFrame) -> pd.Series:
    """
    Return the label column regardless of leading/trailing whitespace in
    the column name.
    """
    for col in df.columns:
        if col.strip().lower() == "label":
            return df[col].astype(str).str.strip()
    raise KeyError(f"No 'Label' column found. Available: {list(df.columns)}")


# ---------------------------------------------------------------------------
# Main build routine
# ---------------------------------------------------------------------------

def build():
    print("=" * 70)
    print("ThreatScope - Data-Driven Markov Transition Matrix Builder")
    print("=" * 70)
    print()
    print("Method : File-level chronological ordering (Mon -> Fri)")
    print("Filter : BENIGN (NORMAL) rows excluded from transition counting")
    print("Smoothing : Laplace add-1")
    print()

    counts = _init_count_matrix()
    total_transitions = 0
    total_attack_rows = 0

    for fname in _ORDERED_FILES:
        fpath = os.path.join(_RAW_DIR, fname)

        if not os.path.exists(fpath):
            print(f"[SKIP] File not found: {fname}")
            continue

        print(f"[READ] {fname}")

        # ----------------------------------------------------------------
        # Read only the Label column - memory efficient on large CSVs
        # ----------------------------------------------------------------
        try:
            df = pd.read_csv(
                fpath,
                usecols=lambda c: c.strip().lower() == "label",
                dtype=str,
            )
        except Exception as exc:
            print(f"  ERROR reading file: {exc}")
            continue

        labels = _extract_label_column(df)

        # ----------------------------------------------------------------
        # Map labels to stages
        # ----------------------------------------------------------------
        stages = labels.map(label_to_stage)

        # ----------------------------------------------------------------
        # Filter out NORMAL (BENIGN background traffic)
        # We keep only rows where the stage is an attack stage.
        # ----------------------------------------------------------------
        attack_mask = stages != STAGE_NORMAL
        attack_stages = stages[attack_mask].reset_index(drop=True)

        file_attack_rows = len(attack_stages)
        total_attack_rows += file_attack_rows

        print(f"  Total rows      : {len(df):>10,}")
        print(f"  Attack rows     : {file_attack_rows:>10,}")

        if file_attack_rows < 2:
            print("  Transitions     :          0  (< 2 attack rows, skip)")
            print()
            continue

        # ----------------------------------------------------------------
        # Extract consecutive pairs within this file only
        # ----------------------------------------------------------------
        file_transitions = 0
        for t in range(len(attack_stages) - 1):
            s_curr = attack_stages[t]
            s_next = attack_stages[t + 1]
            counts[s_curr][s_next] += 1
            file_transitions += 1

        total_transitions += file_transitions
        print(f"  Transitions     : {file_transitions:>10,}")
        print()

    # -----------------------------------------------------------------------
    # Print raw count matrix
    # -----------------------------------------------------------------------
    print("=" * 70)
    print(f"TOTAL ATTACK ROWS  : {total_attack_rows:,}")
    print(f"TOTAL TRANSITIONS  : {total_transitions:,}")
    print()
    hdr = "FROM \ TO"
    print("RAW TRANSITION COUNTS (before smoothing):")
    print(f"  {hdr:<24}", end="")
    for s in ALL_STAGES:
        print(f"  {s[:12]:>12}", end="")
    print()
    for s_from in ALL_STAGES:
        print(f"  {s_from:<24}", end="")
        for s_to in ALL_STAGES:
            cnt = counts[s_from][s_to]
            print(f"  {cnt:>12,}", end="")
        print()
    print()

    # -----------------------------------------------------------------------
    # Apply Laplace (add-1) smoothing and normalise
    # -----------------------------------------------------------------------
    print("Applying Laplace (add-1) smoothing and normalising...")
    print()

    matrix = {}
    for s_from in ALL_STAGES:
        row_counts = {s_to: counts[s_from][s_to] + 1 for s_to in ALL_STAGES}
        row_total  = sum(row_counts.values())
        matrix[s_from] = {s_to: round(row_counts[s_to] / row_total, 6)
                          for s_to in ALL_STAGES}

    # -----------------------------------------------------------------------
    # Print final probability matrix
    # -----------------------------------------------------------------------
    print("FINAL PROBABILITY MATRIX (Laplace-smoothed):")
    print(f"  {hdr:<24}", end="")
    for s in ALL_STAGES:
        print(f"  {s[:12]:>12}", end="")
    print()
    for s_from in ALL_STAGES:
        print(f"  {s_from:<24}", end="")
        for s_to in ALL_STAGES:
            prob = matrix[s_from][s_to]
            print(f"  {prob:>12.4f}", end="")
        row_sum = sum(matrix[s_from].values())
        print(f"   (sum={row_sum:.4f})")
    print()

    # -----------------------------------------------------------------------
    # Sanity check: each row must sum to ≈1.0
    # -----------------------------------------------------------------------
    for s_from in ALL_STAGES:
        row_sum = sum(matrix[s_from].values())
        if abs(row_sum - 1.0) > 1e-4:
            print(f"[WARNING] Row {s_from} sums to {row_sum:.6f} - rounding issue!")

    # -----------------------------------------------------------------------
    # Save to JSON
    # -----------------------------------------------------------------------
    os.makedirs("models", exist_ok=True)
    output_path = os.path.join("models", "markov_transition_matrix.json")

    payload = {
        "matrix":             matrix,
        "raw_counts":         counts,
        "total_transitions":  total_transitions,
        "total_attack_rows":  total_attack_rows,
        "source": (
            "CICIDS2017 data-driven - transition counts extracted from "
            "consecutive attack-labelled rows within each scenario file, "
            "processed in documented chronological order (Mon-Fri). "
            "BENIGN rows excluded. Laplace (add-1) smoothing applied."
        ),
        "smoothing":        "Laplace (add-1)",
        "stage_order":      ALL_STAGES,
        "build_timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    print(f"Saved: {output_path}")
    print()
    print("=" * 70)
    print("Markov transition matrix build COMPLETE")
    print("=" * 70)

    return matrix


if __name__ == "__main__":
    build()
