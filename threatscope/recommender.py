"""
threatscope/recommender.py
===========================
Rule-based advisory recommendation engine.

Generates human-readable, actionable recommendations for SOC analysts
based on:
  - Attack label (XGBoost classification)
  - MITRE technique
  - Current attack stage
  - Risk severity

All recommendations are ADVISORY ONLY.
This engine never executes any destructive or automated action.
All decisions remain with the human analyst.
"""

from typing import Optional


# ---------------------------------------------------------------------------
# Recommendation rules
# Each rule is a dict with:
#   labels   : list of attack labels it applies to (or ["__ANY__"])
#   stages   : list of stages it applies to (or ["__ANY__"])
#   severity : minimum severity to trigger ("Low"/"Medium"/"High"/"Critical")
#   actions  : list of recommended action strings
#   priority : int, lower = higher priority (shown first)
# ---------------------------------------------------------------------------

_RULES = [
    # BENIGN
    {
        "labels":   ["BENIGN"],
        "stages":   ["__ANY__"],
        "severity": "Low",
        "priority": 100,
        "actions": [
            "No action required — traffic classified as BENIGN.",
            "Continue routine monitoring.",
        ],
    },

    # Port Scan
    {
        "labels":   ["PortScan"],
        "stages":   ["__ANY__"],
        "severity": "Low",
        "priority": 10,
        "actions": [
            "Investigate source IP: identify whether internal or external.",
            "Check for associated vulnerability scan tools (Nmap, Masscan).",
            "Block or rate-limit the source IP at the perimeter firewall if unauthorised.",
            "Review firewall/IDS rules for port-scan detection.",
            "Correlate with recent asset inventory changes.",
        ],
    },

    # Brute Force / Credential Attacks
    {
        "labels":   [
            "FTP-Patator", "SSH-Patator", "Web Attack - Brute Force"
        ],
        "stages":   ["__ANY__"],
        "severity": "Medium",
        "priority": 10,
        "actions": [
            "Identify and block the source IP at the firewall/WAF.",
            "Check target account(s) for successful logins — look for login success after repeated failures.",
            "Temporarily lock targeted accounts if policy permits (confirm with account owner first).",
            "Enable or verify account-lockout policies are active.",
            "Review authentication logs for the past 24–72 hours for the same source.",
            "Consider enforcing MFA on targeted services.",
            "Notify the account owner of the attempted compromise.",
        ],
    },

    # Web Attacks
    {
        "labels":   ["Web Attack - XSS", "Web Attack - SQL Injection"],
        "stages":   ["__ANY__"],
        "severity": "Medium",
        "priority": 10,
        "actions": [
            "Identify the targeted web endpoint and application.",
            "Block the source IP at the WAF immediately.",
            "Review WAF logs for the full session to identify what data may have been accessed.",
            "Check application logs for any successful injection results or data exfiltration.",
            "Notify the application/web team to patch the vulnerable parameter.",
            "Conduct a brief impact assessment — was any PII or sensitive data exposed?",
            "Preserve logs for forensic investigation.",
        ],
    },

    # Heartbleed
    {
        "labels":   ["Heartbleed"],
        "stages":   ["__ANY__"],
        "severity": "High",
        "priority": 5,
        "actions": [
            "URGENT: Determine if the target server is running a vulnerable OpenSSL version (CVE-2014-0160).",
            "Block traffic from the source IP immediately.",
            "If server is vulnerable: rotate ALL private keys and certificates on the affected service.",
            "Invalidate all active session tokens for the affected service.",
            "Check memory dump logs if available for signs of data leakage.",
            "Escalate to senior security engineer / CISO depending on service criticality.",
            "Apply OpenSSL patch or upgrade immediately.",
        ],
    },

    # Bot / C2
    {
        "labels":   ["Bot"],
        "stages":   ["__ANY__"],
        "severity": "High",
        "priority": 5,
        "actions": [
            "Identify the infected endpoint from the source IP.",
            "Isolate the endpoint from the network to prevent lateral spread (confirm with IT ops).",
            "Capture network traffic from the endpoint for C2 domain/IP extraction.",
            "Block identified C2 destinations at the DNS / firewall layer.",
            "Initiate endpoint forensic investigation (EDR scan, memory analysis).",
            "Check for persistence mechanisms (registry, scheduled tasks, startup entries).",
            "Review all accounts authenticated from this endpoint in the last 72 hours.",
            "Preserve disk image before remediation for forensic evidence.",
        ],
    },

    # Infiltration / Lateral Movement
    {
        "labels":   ["Infiltration"],
        "stages":   ["__ANY__"],
        "severity": "High",
        "priority": 3,
        "actions": [
            "ESCALATE: Possible active intrusion — notify SOC lead immediately.",
            "Identify source and destination hosts involved in the lateral movement.",
            "Isolate affected hosts from the network (coordinate with IT ops before action).",
            "Review all administrative/privileged activity from involved accounts.",
            "Check for credential dumping tools (Mimikatz signatures in process/EDR logs).",
            "Audit recently accessed file shares and databases from the affected hosts.",
            "Preserve all relevant logs (network, authentication, endpoint) immediately.",
            "Begin full incident response procedure if not already active.",
        ],
    },

    # DoS attacks
    {
        "labels":   [
            "DoS Hulk", "DoS GoldenEye",
            "DoS slowloris", "DoS Slowhttptest"
        ],
        "stages":   ["__ANY__"],
        "severity": "Medium",
        "priority": 10,
        "actions": [
            "Confirm service impact — check if target service is degraded or unavailable.",
            "Identify source IP(s) and block at upstream firewall/CDN.",
            "Enable rate-limiting on the affected service/endpoint.",
            "Contact upstream ISP or CDN provider if attack volume is high.",
            "Consider activating DDoS mitigation service if available.",
            "Monitor service recovery and alert if attack resumes.",
        ],
    },

    # DDoS
    {
        "labels":   ["DDoS"],
        "stages":   ["__ANY__"],
        "severity": "High",
        "priority": 5,
        "actions": [
            "URGENT: Confirm service impact and declare DDoS event if sustained.",
            "Engage DDoS mitigation provider / scrubbing service immediately.",
            "Apply upstream traffic filtering — coordinate with ISP.",
            "Identify attack vector (volumetric, protocol, application layer).",
            "Notify NOC and management of potential service disruption.",
            "Document attack timeline for post-incident review.",
            "Consider geo-blocking if traffic originates from unexpected regions.",
        ],
    },

    # High/Critical risk catch-all
    {
        "labels":   ["__ANY__"],
        "stages":   ["IMPACT", "LATERAL_MOVEMENT"],
        "severity": "High",
        "priority": 20,
        "actions": [
            "Elevated risk level detected — consider escalating to incident response.",
            "Document all investigative steps taken.",
            "Preserve logs and evidence before any remediation.",
        ],
    },
]


def get_recommendations(
    attack_label: str,
    current_stage: str,
    severity: str,
) -> dict:
    """
    Return a list of advisory recommendations for the analyst.

    Parameters
    ----------
    attack_label  : str  — XGBoost predicted label
    current_stage : str  — attack stage string
    severity      : str  — Low / Medium / High / Critical

    Returns
    -------
    dict:
      {
        "actions"   : list[str],   # ordered list of recommended actions
        "disclaimer": str,         # mandatory advisory disclaimer
      }
    """
    severity_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    sev_level = severity_order.get(severity, 0)

    matched_rules = []

    for rule in _RULES:
        # Check label match
        label_match = (
            "__ANY__" in rule["labels"] or
            attack_label in rule["labels"]
        )
        # Check stage match
        stage_match = (
            "__ANY__" in rule["stages"] or
            current_stage in rule["stages"]
        )
        # Check severity threshold
        rule_sev = severity_order.get(rule["severity"], 0)
        sev_match = sev_level >= rule_sev

        if label_match and stage_match and sev_match:
            matched_rules.append(rule)

    # Sort by priority (lower number = higher priority = first)
    matched_rules.sort(key=lambda r: r["priority"])

    # Collect unique actions (preserve order, deduplicate)
    seen = set()
    actions = []
    for rule in matched_rules:
        for action in rule["actions"]:
            if action not in seen:
                seen.add(action)
                actions.append(action)

    if not actions:
        actions = [
            "No specific recommendation available for this classification.",
            "Continue monitoring and review alerts manually.",
        ]

    return {
        "actions": actions,
        "disclaimer": (
            "These recommendations are ADVISORY ONLY. "
            "All actions must be approved and executed by a qualified "
            "SOC analyst. ThreatScope does not take automated "
            "remediation actions."
        ),
    }


if __name__ == "__main__":
    test_cases = [
        ("BENIGN",       "NORMAL",             "Low"),
        ("PortScan",     "RECONNAISSANCE",     "Low"),
        ("SSH-Patator",  "INITIAL_ACCESS",     "Medium"),
        ("Bot",          "COMMAND_AND_CONTROL","High"),
        ("Infiltration", "LATERAL_MOVEMENT",   "Critical"),
        ("DDoS",         "IMPACT",             "Critical"),
    ]

    print("Recommendation Engine — Self Test")
    print("=" * 60)
    for label, stage, severity in test_cases:
        rec = get_recommendations(label, stage, severity)
        print(f"\n  Label    : {label}")
        print(f"  Stage    : {stage}")
        print(f"  Severity : {severity}")
        print("  Actions  :")
        for a in rec["actions"]:
            print(f"    - {a}")
