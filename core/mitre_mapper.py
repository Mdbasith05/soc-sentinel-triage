from typing import Dict, List, Any

MITRE_ENTERPRISE_MAP = {
    "url": {
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries send malicious links via electronic messaging to lure victims into executing code or credentials."
    },
    "domain": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries communicate using application layer protocols (HTTP/HTTPS) to avoid network detection."
    },
    "ipv4": {
        "technique_id": "T1071",
        "technique_name": "Standard Application Layer Protocol / Direct IP C2",
        "tactic": "Command and Control",
        "description": "Adversaries communicate directly with C2 infrastructure or exfiltrate data to actor-controlled IP endpoints."
    },
    "file_hash": {
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "An adversary relies on the target user executing a malicious attachment or secondary binary."
    }
}

TAG_BASED_TECHNIQUES = {
    "tor-exit-node": {
        "technique_id": "T1090.003",
        "technique_name": "Proxy: Multi-hop Proxy (Tor)",
        "tactic": "Command and Control"
    },
    "c2": {
        "technique_id": "T1071",
        "technique_name": "Command and Control: Web Protocols",
        "tactic": "Command and Control"
    },
    "cobalt-strike": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter (Cobalt Strike Beacon)",
        "tactic": "Execution"
    },
    "phish": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access"
    },
    "stealer": {
        "technique_id": "T1555",
        "technique_name": "Credentials from Password Stores / InfoStealer",
        "tactic": "Credential Access"
    }
}

def map_ioc_to_mitre(ioc_type: str, tags: List[str] = None) -> List[Dict[str, str]]:
    """
    Correlates an IOC and its observed threat tags to MITRE ATT&CK techniques.
    """
    mapped: List[Dict[str, str]] = []
    tags = tags or []

    # Baseline mapping from IOC Type
    if ioc_type in ["sha256", "sha1", "md5"]:
        base = MITRE_ENTERPRISE_MAP["file_hash"]
        mapped.append(base)
    elif ioc_type in MITRE_ENTERPRISE_MAP:
        mapped.append(MITRE_ENTERPRISE_MAP[ioc_type])

    # Tag-based mapping
    for tag in tags:
        tag_lower = tag.lower()
        for key, tech in TAG_BASED_TECHNIQUES.items():
            if key in tag_lower:
                if tech not in mapped:
                    mapped.append(tech)

    return mapped
