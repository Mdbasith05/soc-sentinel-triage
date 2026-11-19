import json
from datetime import datetime, timezone
from typing import Dict, Any, List
from .ioc_parser import defang

def generate_incident_ticket(vt_data: Dict[str, Any], risk_data: Dict[str, Any], mitre_data: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Constructs a structured enterprise SOC incident record and containment playbook.
    """
    now = datetime.now(timezone.utc)
    ticket_id = f"INC-SOC-{now.strftime('%Y%m%d')}-{abs(hash(vt_data.get('ioc', ''))) % 10000:04d}"
    
    ioc = vt_data.get("ioc", "")
    ioc_type = vt_data.get("ioc_type", "unknown")
    defanged = defang(ioc)
    severity = risk_data.get("severity", "LOW")
    score = risk_data.get("score", 0)

    # Containment Playbook Actions based on IOC Type and Severity
    actions = []
    if severity in ["CRITICAL", "HIGH"]:
        if ioc_type == "ipv4":
            actions.append("Perimeter Firewall: Apply perimeter ACL / Palo Alto / Fortinet block rule to drop all inbound and outbound traffic to " + defanged)
            actions.append("SIEM Threat Hunt: Query firewall logs for previous 30 days to identify any internal endpoints that initiated outbound handshakes to this IP.")
        elif ioc_type in ["domain", "url"]:
            actions.append("DNS Sinkholing & Web Proxy: Add " + defanged + " to corporate DNS RPZ and proxy blocklists (Zscaler / BlueCoat / FortiProxy).")
            actions.append("Email Gateway (M365/Proofpoint): Search and purge all inbound messages containing references to " + defanged)
        elif ioc_type in ["sha256", "sha1", "md5"]:
            actions.append("EDR Containment: Blacklist file hash " + defanged + " in CrowdStrike Falcon / Microsoft Defender for Endpoint.")
            actions.append("Host Isolation: Isolate any endpoints where hash execution was observed pending forensic memory snapshot.")

        actions.append("Identity & Access: Reset credentials and revoke active Azure AD / Okta sessions for users associated with this telemetry stream.")
    elif severity == "MEDIUM":
        actions.append("Enhanced Monitoring: Tag indicator for 7-day automated watchlist in SIEM; alert on secondary beaconing.")
    else:
        actions.append("Standard Resolution: No containment required. Mark alert as Closed - Benign / False Positive.")

    mitre_techniques = [f"{m['technique_id']} ({m['technique_name']})" for m in mitre_data]

    ticket_dict = {
        "ticket_id": ticket_id,
        "created_at_utc": now.isoformat(),
        "severity": severity,
        "risk_score": f"{score}/100",
        "verdict": risk_data.get("verdict"),
        "indicator": {
            "raw": ioc,
            "defanged": defanged,
            "type": ioc_type
        },
        "threat_intelligence": {
            "malicious_engines": f"{vt_data.get('malicious', 0)} / {vt_data.get('malicious', 0) + vt_data.get('harmless', 0) + vt_data.get('undetected', 0)}",
            "as_owner": vt_data.get("as_owner", "N/A"),
            "tags": vt_data.get("tags", []),
            "source": vt_data.get("source")
        },
        "mitre_attck_mapping": mitre_techniques,
        "l1_containment_actions": actions,
        "assigned_analyst": "Mohammed Basith (L1 SOC Operations)"
    }

    # Markdown Representation
    md_lines = [
        f"# [SOC TICKET] {ticket_id} — {severity} Alert Triage",
        f"**Date:** {now.strftime('%Y-%m-%d %H:%M:%S UTC')} | **Analyst:** Mohammed Basith (L1 SOC) | **Status:** Escalated / Action Required\n",
        "## 1. Executive Summary",
        f"- **Defanged Indicator:** `{defanged}`",
        f"- **IOC Type:** `{ioc_type.upper()}`",
        f"- **Calculated SOC Risk Score:** **{score}/100** ({severity})",
        f"- **Threat Assessment:** {risk_data.get('verdict')}\n",
        "## 2. Threat Intelligence Telemetry",
        f"- **Detection Consensus:** `{vt_data.get('malicious', 0)}` security engines flagged as malicious",
        f"- **Autonomous System / Network:** `{vt_data.get('as_owner', 'N/A')}`",
        f"- **Identified Tags:** {', '.join([f'`{t}`' for t in vt_data.get('tags', [])]) or 'None'}\n",
        "## 3. MITRE ATT&CK Framework Correlation",
    ]
    for m in mitre_data:
        md_lines.append(f"- **{m.get('technique_id')} — {m.get('technique_name')}** (*{m.get('tactic')}*)")

    md_lines.append("\n## 4. L1 Immediate Containment Recommendations")
    for act in actions:
        md_lines.append(f"- [ ] {act}")

    ticket_dict["markdown_export"] = "\n".join(md_lines)
    return ticket_dict
