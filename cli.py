#!/usr/bin/env python3
"""
SOC Sentinel — Command-Line Interface (CLI)
Automated L1 Alert Triage & Threat Intelligence Enrichment Engine
"""

import argparse
import sys
import json
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

from core.ioc_parser import detect_ioc_type, extract_all_iocs, defang, refang
from core.vt_client import VirusTotalClient
from core.mitre_mapper import map_ioc_to_mitre
from core.risk_engine import calculate_soc_risk_score
from core.incident_ticket import generate_incident_ticket

def print_banner():
    banner = """
================================================================================
   [+] SOC SENTINEL — L1 ALERT TRIAGE & THREAT ENRICHMENT ENGINE
   Author: Mohammed Basith | UAE & Placement Security Operations
================================================================================
    """
    print(banner)

def triage_single_ioc(ioc: str, vt_client: VirusTotalClient, export_path: str = None):
    clean_ioc = refang(ioc)
    ioc_type = detect_ioc_type(clean_ioc)
    
    if ioc_type == "unknown":
        print(f"[!] Unable to classify indicator: {ioc}")
        return

    print(f"[*] Analyzing Indicator: {defang(clean_ioc)} (Type: {ioc_type.upper()})")
    
    # 1. Threat Intel Query
    vt_data = vt_client.query_ioc(clean_ioc, ioc_type)
    
    # 2. Risk Calculation
    risk = calculate_soc_risk_score(vt_data)
    
    # 3. MITRE Correlation
    mitre = map_ioc_to_mitre(ioc_type, vt_data.get("tags", []))
    
    # 4. Ticket Generation
    ticket = generate_incident_ticket(vt_data, risk, mitre)

    # Console Output
    print("-" * 80)
    print(f"  SEVERITY:       [{risk['severity']}]  (SOC Risk Score: {risk['score']}/100)")
    print(f"  VERDICT:        {risk['verdict']}")
    print(f"  DETECTIONS:     {vt_data.get('malicious', 0)} malicious engines flagged")
    print(f"  INFRASTRUCTURE: {vt_data.get('as_owner', 'N/A')}")
    print(f"  MITRE ATT&CK:   {', '.join([m['technique_id'] for m in mitre]) or 'N/A'}")
    print("-" * 80)
    print("  RECOMMENDED L1 CONTAINMENT ACTIONS:")
    for act in ticket["l1_containment_actions"]:
        print(f"    [ ] {act}")
    print("-" * 80)

    if export_path:
        out_file = Path(export_path)
        if out_file.suffix.lower() == ".json":
            out_file.write_text(json.dumps(ticket, indent=2), encoding="utf-8")
        else:
            out_file.write_text(ticket["markdown_export"], encoding="utf-8")
        print(f"[+] Incident ticket exported to: {out_file.resolve()}\n")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="SOC Sentinel: Automated L1 Alert Triage Engine")
    parser.add_argument("--ioc", help="Single indicator of compromise (IP, Domain, URL, or Hash)")
    parser.add_argument("--text", help="Raw log string or alert payload containing multiple IOCs")
    parser.add_argument("--output", help="Path to export structured incident ticket (.json or .md)")
    parser.add_argument("--api-key", help="Optional VirusTotal API key (or set VT_API_KEY environment variable)")
    
    args = parser.parse_args()

    vt_client = VirusTotalClient(api_key=args.api_key)

    if args.ioc:
        triage_single_ioc(args.ioc, vt_client, args.output)
    elif args.text:
        extracted = extract_all_iocs(args.text)
        total = sum(len(v) for v in extracted.values())
        print(f"[*] Extracted {total} indicators from input payload:")
        for k, v in extracted.items():
            if v:
                print(f"    - {k.upper()}: {len(v)} items")
        print("=" * 80)
        for ioc_type, ioc_list in extracted.items():
            for ioc in ioc_list:
                triage_single_ioc(ioc, vt_client)
    else:
        # Default sample run
        sample = "45.154.255.88"
        print(f"[*] No arguments provided. Running default L1 SOC triage demonstration on: {sample}\n")
        triage_single_ioc(sample, vt_client)
        print("[*] Usage: python cli.py --ioc <IP/DOMAIN/HASH> [--output ticket.md]")

if __name__ == "__main__":
    main()
