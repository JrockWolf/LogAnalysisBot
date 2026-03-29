"""MITRE ATT&CK framework mapping for detected security events.

Maps attack categories and specific findings to MITRE ATT&CK technique IDs,
tactics, and descriptions.  This enables security analysts to cross-reference
detected events with the ATT&CK knowledge base.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    url: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "url": self.url,
        }


# ---- ATT&CK Technique Catalogue (subset relevant to CIC-IDS2017) ----

TECHNIQUES: Dict[str, MitreTechnique] = {
    "T1110": MitreTechnique(
        "T1110",
        "Brute Force",
        "Credential Access",
        "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "https://attack.mitre.org/techniques/T1110/",
    ),
    "T1110.001": MitreTechnique(
        "T1110.001",
        "Password Guessing",
        "Credential Access",
        "Adversaries may guess passwords to attempt access to accounts, such as SSH or FTP brute force.",
        "https://attack.mitre.org/techniques/T1110/001/",
    ),
    "T1110.003": MitreTechnique(
        "T1110.003",
        "Password Spraying",
        "Credential Access",
        "Adversaries may use a single or small list of commonly used passwords against many different accounts.",
        "https://attack.mitre.org/techniques/T1110/003/",
    ),
    "T1498": MitreTechnique(
        "T1498",
        "Network Denial of Service",
        "Impact",
        "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources.",
        "https://attack.mitre.org/techniques/T1498/",
    ),
    "T1498.001": MitreTechnique(
        "T1498.001",
        "Direct Network Flood",
        "Impact",
        "Adversaries may attempt to cause a denial of service by directly sending a high volume of network traffic to a target.",
        "https://attack.mitre.org/techniques/T1498/001/",
    ),
    "T1499": MitreTechnique(
        "T1499",
        "Endpoint Denial of Service",
        "Impact",
        "Adversaries may perform Endpoint DoS attacks to degrade or block the availability of services to users.",
        "https://attack.mitre.org/techniques/T1499/",
    ),
    "T1499.001": MitreTechnique(
        "T1499.001",
        "OS Exhaustion Flood",
        "Impact",
        "Adversaries may exhaust OS resources through SYN floods, connection floods, or other mechanisms.",
        "https://attack.mitre.org/techniques/T1499/001/",
    ),
    "T1499.002": MitreTechnique(
        "T1499.002",
        "Service Exhaustion Flood",
        "Impact",
        "Adversaries may target service-level resources with floods of requests (e.g., HTTP floods, Slowloris).",
        "https://attack.mitre.org/techniques/T1499/002/",
    ),
    "T1046": MitreTechnique(
        "T1046",
        "Network Service Scanning",
        "Discovery",
        "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.",
        "https://attack.mitre.org/techniques/T1046/",
    ),
    "T1595": MitreTechnique(
        "T1595",
        "Active Scanning",
        "Reconnaissance",
        "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
        "https://attack.mitre.org/techniques/T1595/",
    ),
    "T1595.001": MitreTechnique(
        "T1595.001",
        "Scanning IP Blocks",
        "Reconnaissance",
        "Adversaries may scan IP blocks to gather information about the victim network for targeting.",
        "https://attack.mitre.org/techniques/T1595/001/",
    ),
    "T1071": MitreTechnique(
        "T1071",
        "Application Layer Protocol",
        "Command and Control",
        "Adversaries may communicate using OSI application layer protocols to avoid detection and blend with normal network traffic.",
        "https://attack.mitre.org/techniques/T1071/",
    ),
    "T1571": MitreTechnique(
        "T1571",
        "Non-Standard Port",
        "Command and Control",
        "Adversaries may communicate using a protocol and port pairing not typically associated with that protocol.",
        "https://attack.mitre.org/techniques/T1571/",
    ),
    "T1190": MitreTechnique(
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
        "https://attack.mitre.org/techniques/T1190/",
    ),
    "T1059": MitreTechnique(
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "https://attack.mitre.org/techniques/T1059/",
    ),
    "T1078": MitreTechnique(
        "T1078",
        "Valid Accounts",
        "Persistence",
        "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.",
        "https://attack.mitre.org/techniques/T1078/",
    ),
    "T1048": MitreTechnique(
        "T1048",
        "Exfiltration Over Alternative Protocol",
        "Exfiltration",
        "Adversaries may steal data by exfiltrating it over a different protocol than the existing command and control channel.",
        "https://attack.mitre.org/techniques/T1048/",
    ),
}


# ---- Category → Technique mapping ----

CATEGORY_TECHNIQUES: Dict[str, List[str]] = {
    "Brute Force": ["T1110", "T1110.001"],
    "DoS": ["T1499", "T1499.001", "T1499.002"],
    "DDoS": ["T1498", "T1498.001"],
    "Reconnaissance": ["T1046", "T1595", "T1595.001"],
    "Botnet": ["T1071", "T1571"],
    "Web Attack": ["T1190", "T1059"],
    "Infiltration": ["T1078", "T1048"],
    # Syslog-based detections
    "SSH Brute Force": ["T1110", "T1110.001"],
    "Privilege Escalation": ["T1078"],
    "Unauthorized Access": ["T1078"],
}

# ---- Finding pattern → Technique mapping (for heuristic/syslog findings) ----

FINDING_PATTERNS: Dict[str, List[str]] = {
    "failed SSH logins": ["T1110", "T1110.001"],
    "privilege escalation": ["T1078"],
    "sensitive files": ["T1078"],
    "/etc/shadow": ["T1078"],
    "unauthorized access": ["T1078"],
    "brute force": ["T1110", "T1110.003"],
    "DoS": ["T1499"],
    "DDoS": ["T1498", "T1498.001"],
    "port scan": ["T1046", "T1595"],
    "bot": ["T1071"],
    "web attack": ["T1190"],
    "SQL injection": ["T1190"],
    "XSS": ["T1190"],
}


def map_category_to_mitre(category: str) -> List[MitreTechnique]:
    """Map an attack category to relevant MITRE ATT&CK techniques."""
    technique_ids = CATEGORY_TECHNIQUES.get(category, [])
    return [TECHNIQUES[tid] for tid in technique_ids if tid in TECHNIQUES]


def map_finding_to_mitre(finding: str) -> List[MitreTechnique]:
    """Map a finding string to relevant MITRE ATT&CK techniques via pattern matching."""
    matched_ids: set = set()
    finding_lower = finding.lower()
    for pattern, technique_ids in FINDING_PATTERNS.items():
        if pattern.lower() in finding_lower:
            matched_ids.update(technique_ids)
    return [TECHNIQUES[tid] for tid in sorted(matched_ids) if tid in TECHNIQUES]


def enrich_findings_with_mitre(
    findings: List[str],
    categories: Optional[List[str]] = None,
) -> List[Dict]:
    """Enrich a list of findings with MITRE ATT&CK mappings.

    Returns a list of dicts: {finding, mitre_techniques: [{technique_id, name, tactic, description, url}]}
    """
    enriched = []
    all_category_techniques: set = set()
    if categories:
        for cat in categories:
            for t in map_category_to_mitre(cat):
                all_category_techniques.add(t.technique_id)

    for finding in findings:
        techniques = map_finding_to_mitre(finding)
        # also include category techniques if available
        if categories:
            for tid in all_category_techniques:
                if tid in TECHNIQUES and tid not in {t.technique_id for t in techniques}:
                    techniques.append(TECHNIQUES[tid])

        enriched.append({
            "finding": finding,
            "mitre_techniques": [t.to_dict() for t in techniques],
        })
    return enriched


def get_technique_summary(technique_ids: List[str]) -> str:
    """Produce a human-readable summary of MITRE techniques."""
    lines = []
    for tid in technique_ids:
        t = TECHNIQUES.get(tid)
        if t:
            lines.append(f"  {t.technique_id} - {t.name} ({t.tactic}): {t.description}")
    return "\n".join(lines) if lines else "  No MITRE ATT&CK mappings found."
