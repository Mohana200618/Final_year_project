"""
threatscope/attack_chain.py
============================
Attack chain prediction using a DATA-DRIVEN first-order Markov Chain.

Approach
--------
  The transition probability matrix is NOT hardcoded.  It is loaded from
  models/markov_transition_matrix.json, which was built by
  build_markov_matrix.py from the real CICIDS2017 dataset.

  build_markov_matrix.py extracts consecutive attack-stage pairs from
  the CICIDS2017 files in documented chronological order (Monday -> Friday),
  counts transitions, applies Laplace (add-1) smoothing, and normalises
  each row to produce probabilities.

  This module is therefore a data-driven probabilistic state-transition
  model, NOT a trained ML model.  The probabilities reflect empirical
  attack-stage patterns observed in CICIDS2017, not expert assumptions.

Attack stages (ordered by kill-chain position)
-----------------------------------------------
  NORMAL          - No attack activity
  RECONNAISSANCE  - Scanning / information gathering
  INITIAL_ACCESS  - Brute force / exploit / web attack
  C2              - Command & Control / botnet
  LATERAL_MOVE    - Lateral movement / infiltration
  IMPACT          - DoS / DDoS disruption

Stage assignment
----------------
  The current stage is derived from the XGBoost attack label by the
  label_to_stage() function.  Transitions are then looked up in the
  loaded data-driven matrix.

Output contract
---------------
  predict() returns a dict:
    {
      "current_stage"   : str,
      "next_stage"      : str,      # most probable next stage
      "next_probability": float,    # 0.0-1.0
      "alt_stage"       : str|None, # second-most probable next stage
      "alt_probability" : float,    # 0.0-1.0 (0 if none)
      "note"            : str       # provenance disclosure
    }
"""

import os
import json
from typing import Optional

# ---------------------------------------------------------------------------
# Stage constants
# ---------------------------------------------------------------------------

STAGE_NORMAL = "NORMAL"
STAGE_RECON = "RECONNAISSANCE"
STAGE_RESOURCE_DEVELOPMENT = "RESOURCE_DEVELOPMENT"
STAGE_INITIAL_ACCESS = "INITIAL_ACCESS"
STAGE_EXECUTION = "EXECUTION"
STAGE_PERSISTENCE = "PERSISTENCE"
STAGE_PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
STAGE_STEALTH = "STEALTH"
STAGE_DEFENSE_IMPAIRMENT = "DEFENSE_IMPAIRMENT"
STAGE_CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
STAGE_DISCOVERY = "DISCOVERY"
STAGE_LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
STAGE_COLLECTION = "COLLECTION"
STAGE_COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
STAGE_EXFILTRATION = "EXFILTRATION"
STAGE_IMPACT = "IMPACT"

MITRE_TACTICS = [
    STAGE_RECON,
    STAGE_RESOURCE_DEVELOPMENT,
    STAGE_INITIAL_ACCESS,
    STAGE_EXECUTION,
    STAGE_PERSISTENCE,
    STAGE_PRIVILEGE_ESCALATION,
    STAGE_STEALTH,
    STAGE_DEFENSE_IMPAIRMENT,
    STAGE_CREDENTIAL_ACCESS,
    STAGE_DISCOVERY,
    STAGE_LATERAL_MOVEMENT,
    STAGE_COLLECTION,
    STAGE_COMMAND_AND_CONTROL,
    STAGE_EXFILTRATION,
    STAGE_IMPACT,
]

# Backwards-compatible aliases for callers using previous short names
STAGE_ACCESS = STAGE_INITIAL_ACCESS
STAGE_C2 = STAGE_COMMAND_AND_CONTROL
STAGE_LATERAL = STAGE_LATERAL_MOVEMENT

ALL_STAGES = [STAGE_NORMAL] + MITRE_TACTICS

# ---------------------------------------------------------------------------
# CICIDS2017 label -> attack stage mapping
# ---------------------------------------------------------------------------

_LABEL_TO_STAGE = {
    "BENIGN":                      STAGE_NORMAL,
    "PortScan":                    STAGE_RECON,
    "FTP-Patator":                 STAGE_CREDENTIAL_ACCESS,
    "SSH-Patator":                 STAGE_CREDENTIAL_ACCESS,
    "Web Attack - Brute Force":    STAGE_CREDENTIAL_ACCESS,
    "Web Attack - XSS":            STAGE_INITIAL_ACCESS,
    "Web Attack - SQL Injection":  STAGE_COLLECTION,
    "Heartbleed":                  STAGE_COLLECTION,
    "Bot":                         STAGE_C2,
    "Infiltration":                STAGE_LATERAL,
    "DoS Hulk":                    STAGE_IMPACT,
    "DoS GoldenEye":               STAGE_IMPACT,
    "DoS slowloris":               STAGE_IMPACT,
    "DoS Slowhttptest":            STAGE_IMPACT,
    "DDoS":                        STAGE_IMPACT,
}

# ---------------------------------------------------------------------------
# Data-driven transition matrix — loaded from JSON at import time
# ---------------------------------------------------------------------------

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MATRIX_PATH  = os.path.join(_PROJECT_ROOT, "models", "markov_transition_matrix.json")

# Uniform fallback (equal probability) used only if the JSON is missing.
# Each row sums to 1.0 exactly.
_UNIFORM_PROB = round(1.0 / len(ALL_STAGES), 6)
_FALLBACK_MATRIX = {s: {t: _UNIFORM_PROB for t in ALL_STAGES} for s in ALL_STAGES}

_MATRIX_NOTE = ""   # filled in by _load_matrix()


def _load_matrix() -> dict:
    """
    Load the data-driven transition matrix from
    models/markov_transition_matrix.json.

    Falls back to a uniform matrix with a warning if the file is missing.
    """
    global _MATRIX_NOTE
    if os.path.exists(_MATRIX_PATH):
        with open(_MATRIX_PATH, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        matrix = payload.get("matrix", {})
        if payload.get("stage_order") == ALL_STAGES and set(matrix) == set(ALL_STAGES):
            source = payload.get("source", "unknown source")
            total  = payload.get("total_transitions", "unknown")
            _MATRIX_NOTE = (
                f"Data-driven Markov chain. Transition probabilities learned from "
                f"{total:,} stage-transition pairs extracted from CICIDS2017 "
                f"({source}). "
                f"High self-loop probabilities (e.g. IMPACT->IMPACT) reflect "
                f"DoS/DDoS attack patterns in the dataset and are empirically "
                f"accurate, not a modelling error."
                if isinstance(total, int) else
                f"Data-driven Markov chain loaded from {_MATRIX_PATH}."
            )
            return matrix
        else:
            _MATRIX_NOTE = (
                "Notice: Existing markov_transition_matrix.json uses an earlier stage list. "
                "Using fallback until build_markov_matrix.py is run."
            )
            print(f"[attack_chain] {_MATRIX_NOTE}")
            return _FALLBACK_MATRIX
    else:
        _MATRIX_NOTE = (
            "WARNING: markov_transition_matrix.json not found. "
            "Run build_markov_matrix.py to generate the data-driven matrix. "
            "Using uniform fallback (equal probabilities) until then."
        )
        print(f"[attack_chain] {_MATRIX_NOTE}")
        return _FALLBACK_MATRIX


# Load once at module import time
_TRANSITION_MATRIX = _load_matrix()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def label_to_stage(label: str) -> str:
    """
    Map a CICIDS2017 / XGBoost predicted label to an attack stage.
    Falls back to STAGE_RECON for unknown labels (conservative assumption).
    """
    return _LABEL_TO_STAGE.get(label.strip(), STAGE_RECON)


def predict(current_stage: str) -> dict:
    """
    Given the current attack stage, return the predicted next stage(s)
    using the data-driven Markov transition matrix.

    Parameters
    ----------
    current_stage : str
        One of the ALL_STAGES constants.

    Returns
    -------
    dict with keys:
        current_stage, next_stage, next_probability,
        alt_stage, alt_probability, note
    """
    if current_stage not in _TRANSITION_MATRIX:
        current_stage = STAGE_RECON  # safe fallback for unknown stages

    transitions = _TRANSITION_MATRIX[current_stage]

    # Sort by probability descending
    ranked = sorted(transitions.items(), key=lambda kv: kv[1], reverse=True)

    next_stage, next_prob = ranked[0]
    alt_stage, alt_prob   = ranked[1] if len(ranked) > 1 else (None, 0.0)

    return {
        "current_stage":    current_stage,
        "next_stage":       next_stage,
        "next_probability": round(next_prob, 4),
        "alt_stage":        alt_stage,
        "alt_probability":  round(alt_prob, 4),
        "note":             _MATRIX_NOTE,
    }


def predict_from_label(label: str) -> dict:
    """
    Convenience: map label -> stage -> predict().
    Includes the resolved stage in the returned dict.
    """
    stage = label_to_stage(label)
    result = predict(stage)
    result["resolved_from_label"] = label
    return result


def reload_matrix():
    """
    Re-load the transition matrix from disk.
    Call this after running build_markov_matrix.py if the server is already
    running and you want to pick up a freshly built matrix without restarting.
    """
    global _TRANSITION_MATRIX
    _TRANSITION_MATRIX = _load_matrix()
    print("[attack_chain] Transition matrix reloaded.")


if __name__ == "__main__":
    print("Attack Chain Prediction - Data-Driven Markov Chain Demo")
    print("=" * 55)

    labels = [
        "BENIGN", "PortScan", "FTP-Patator",
        "Bot", "Infiltration", "DDoS"
    ]
    for lbl in labels:
        r = predict_from_label(lbl)
        print(f"\n  Label   : {lbl}")
        print(f"  Stage   : {r['current_stage']}")
        print(f"  Next    : {r['next_stage']}  ({r['next_probability']*100:.2f}%)")
        print(f"  Alt     : {r['alt_stage']}   ({r['alt_probability']*100:.2f}%)")
    print()
    print(f"  Note: {_MATRIX_NOTE[:120]}...")
