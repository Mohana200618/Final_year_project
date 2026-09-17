"""
threatscope/mitre_mapper.py
============================
Loads the MITRE ATT&CK mapping from config/mitre_mapping.json and
provides lookup functions for attack class -> technique info.

All technique data comes from the config file — nothing is hardcoded
in this module.  To add or update a mapping, edit mitre_mapping.json.
"""

import os
import json
from typing import Optional

from threatscope.attack_chain import MITRE_TACTICS

# Default config path relative to the project root
_DEFAULT_CONFIG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config",
    "mitre_mapping.json",
)


class MitreMapper:
    """
    Looks up MITRE ATT&CK technique information for a given attack label.

    Parameters
    ----------
    config_path : str, optional
        Path to mitre_mapping.json.  Defaults to config/mitre_mapping.json
        relative to the project root.
    """

    def __init__(self, config_path: Optional[str] = None):
        path = config_path or _DEFAULT_CONFIG
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"MITRE mapping config not found: {path}"
            )
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        # Remove the comment key if present
        self._mapping = {
            k: v for k, v in raw.items() if not k.startswith("_")
        }
        invalid_tactics = sorted({
            value.get("tactic")
            for value in self._mapping.values()
            if value.get("tactic") is not None
            and value.get("tactic").upper().replace(" ", "_") not in MITRE_TACTICS
        })
        if invalid_tactics:
            raise ValueError(
                "MITRE mapping contains unsupported tactics: "
                f"{invalid_tactics}"
            )

    def get(self, label: str) -> dict:
        """
        Return the MITRE mapping dict for the given attack label.

        Falls back to a generic 'UNKNOWN' entry if the label is not found.
        """
        if label in self._mapping:
            return self._mapping[label]

        # Try case-insensitive match
        label_lower = label.strip().lower()
        for key, val in self._mapping.items():
            if key.lower() == label_lower:
                return val

        # Unknown label
        return {
            "tactic": "Unknown",
            "technique_id": "T????",
            "technique_name": "Unknown Technique",
            "sub_technique_id": None,
            "sub_technique_name": None,
            "description": f"No MITRE mapping found for label: '{label}'",
            "reference": None,
        }

    def get_tactic(self, label: str) -> Optional[str]:
        return self.get(label).get("tactic")

    def get_technique_id(self, label: str) -> Optional[str]:
        return self.get(label).get("technique_id")

    def get_technique_name(self, label: str) -> Optional[str]:
        return self.get(label).get("technique_name")

    def get_reference(self, label: str) -> Optional[str]:
        return self.get(label).get("reference")

    def list_labels(self) -> list:
        return list(self._mapping.keys())

    def summary(self, label: str) -> str:
        """Return a compact human-readable summary string."""
        m = self.get(label)
        tid = m.get("technique_id") or "N/A"
        tname = m.get("technique_name") or "N/A"
        tactic = m.get("tactic") or "N/A"
        sub_id = m.get("sub_technique_id") or ""
        sub_name = m.get("sub_technique_name") or ""
        sub_str = f" / {sub_id} {sub_name}" if sub_id else ""
        return f"[{tactic}] {tid} {tname}{sub_str}"


if __name__ == "__main__":
    mapper = MitreMapper()
    print("Mapped labels:", len(mapper.list_labels()))
    print()
    test_labels = [
        "DDoS", "PortScan", "FTP-Patator", "Bot",
        "Web Attack - SQL Injection", "BENIGN", "UnknownAttack"
    ]
    for lbl in test_labels:
        print(f"  {lbl:<35} -> {mapper.summary(lbl)}")
