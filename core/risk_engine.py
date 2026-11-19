from typing import Dict, Any, List

BENIGN_WHITELIST = {
    "127.0.0.1", "0.0.0.0", "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "google.com", "microsoft.com", "cloudflare.com", "github.com", "apple.com"
}

def calculate_soc_risk_score(vt_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes normalized SOC risk score (0-100) and severity rating
    based on engine consensus, vendor reputation, and false-positive suppression.
    """
    ioc = vt_data.get("ioc", "")
    malicious = vt_data.get("malicious", 0)
    suspicious = vt_data.get("suspicious", 0)
    harmless = vt_data.get("harmless", 0)
    undetected = vt_data.get("undetected", 0)
    tags = [t.lower() for t in vt_data.get("tags", [])]
    total_engines = malicious + suspicious + harmless + undetected

    # 1. Whitelist Suppression
    if ioc.lower() in BENIGN_WHITELIST or "safe" in tags:
        return {
            "score": 0,
            "severity": "BENIGN",
            "verdict": "False Positive / Known Benign Asset",
            "color": "#10b981", # Emerald
            "action_code": "CLOSE_FALSE_POSITIVE"
        }

    # 2. Engine Consensus Ratio (up to 75 points)
    if total_engines > 0:
        ratio = (malicious * 1.0 + suspicious * 0.4) / total_engines
        raw_score = min(75.0, ratio * 200.0)
    else:
        raw_score = 0.0

    # 3. High-Confidence Threat Tags Multiplier (up to 25 points)
    critical_tags = ["c2", "cobalt-strike", "ransom", "stealer", "trojan", "tor-exit-node", "botnet"]
    tag_score = 0
    for ct in critical_tags:
        if ct in tags:
            tag_score += 10
    raw_score += min(25, tag_score)

    # 4. Strict Overrides based on absolute malicious detections
    if malicious >= 15:
        raw_score = max(raw_score, 85.0)
    elif malicious >= 5:
        raw_score = max(raw_score, 65.0)
    elif malicious >= 1:
        raw_score = max(raw_score, 35.0)

    final_score = int(min(100, max(0, round(raw_score))))

    # 5. Severity Categorization
    if final_score >= 75:
        severity = "CRITICAL"
        color = "#ef4444" # Red
        verdict = "Confirmed Malicious Infrastructure / Active Threat"
        action = "IMMEDIATE_CONTAINMENT_REQUIRED"
    elif final_score >= 50:
        severity = "HIGH"
        color = "#f97316" # Orange
        verdict = "High-Risk Suspicious Indicator"
        action = "BLOCK_AND_ESCALATE_L2"
    elif final_score >= 25:
        severity = "MEDIUM"
        color = "#eab308" # Yellow
        verdict = "Potentially Unwanted / Grayware Indicator"
        action = "MONITOR_AND_INVESTIGATE"
    elif final_score > 0:
        severity = "LOW"
        color = "#3b82f6" # Blue
        verdict = "Low-Severity / Informational Indicator"
        action = "LOG_EVENT_NO_ACTION"
    else:
        severity = "BENIGN"
        color = "#10b981" # Green
        verdict = "Clean / No Known Threats Detected"
        action = "CLOSE_ALERT"

    return {
        "score": final_score,
        "severity": severity,
        "verdict": verdict,
        "color": color,
        "action_code": action
    }
