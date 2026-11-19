import streamlit as st
import json
from datetime import datetime, timezone

from core.ioc_parser import detect_ioc_type, extract_all_iocs, defang, refang
from core.vt_client import VirusTotalClient
from core.mitre_mapper import map_ioc_to_mitre
from core.risk_engine import calculate_soc_risk_score
from core.incident_ticket import generate_incident_ticket

st.set_page_config(
    page_title="SOC Sentinel | L1 Alert Triage Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber SOC Dark Mode CSS
st.markdown("""
<style>
    .main {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    .stMetric {
        background-color: #131c2e;
        padding: 12px;
        border-radius: 8px;
        border: 1px solid #1e293b;
    }
    .soc-card {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 10px;
        padding: 18px;
        margin-bottom: 16px;
    }
    .badge-critical {
        background-color: #7f1d1d;
        color: #fca5a5;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 13px;
        border: 1px solid #ef4444;
    }
    .badge-high {
        background-color: #7c2d12;
        color: #fdba74;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 13px;
        border: 1px solid #f97316;
    }
    .badge-medium {
        background-color: #713f12;
        color: #fde047;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 13px;
        border: 1px solid #eab308;
    }
    .badge-benign {
        background-color: #064e3b;
        color: #6ee7b7;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 13px;
        border: 1px solid #10b981;
    }
    .mitre-pill {
        display: inline-block;
        background-color: #1e1b4b;
        color: #a5b4fc;
        border: 1px solid #4338ca;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 12px;
        margin: 2px;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.title("🛡️ SOC Sentinel")
    st.markdown("**Automated L1 Alert Triage Engine**")
    st.markdown("Designed by **Mohammed Basith**  \n*MCA Cyber Security & Forensics*")
    st.markdown("---")
    
    api_key_input = st.text_input("VirusTotal API Key (Optional)", type="password", help="Leave blank to use intelligent offline heuristic telemetry mode.")
    st.markdown("---")
    st.markdown("### Quick Sample Test Cases")
    sample_btn_mal = st.button("⚠️ Load High-Risk C2 IP")
    sample_btn_phish = st.button("🎣 Load Phishing URL")
    sample_btn_clean = st.button("✅ Load Benign DNS Asset")

st.title("🛡️ Enterprise SOC L1 Alert Triage & Threat Intelligence Workbench")
st.markdown("Automated enrichment, normalized risk scoring, MITRE ATT&CK correlation, and incident ticket packaging for SOC analysts.")

# Initialize client
vt_client = VirusTotalClient(api_key=api_key_input)

# Handle Sample Buttons
default_text = ""
if sample_btn_mal:
    default_text = "45.154.255.88"
elif sample_btn_phish:
    default_text = "hxxps://secure-banking-login-auth[.]com/verification/update.php"
elif sample_btn_clean:
    default_text = "1.1.1.1"

# Main Tabs
tab1, tab2 = st.tabs(["🎯 Single IOC Deep-Dive", "📋 Raw Alert / Log Batch Extractor"])

with tab1:
    col_input, col_action = st.columns([4, 1])
    with col_input:
        target_ioc = st.text_input("Enter Indicator (IP, Domain, URL, or File Hash):", value=default_text, placeholder="e.g. 185.220.101.5, evil[.]com, or 44d88612fea8a8f36de82e1278abb02f")
    with col_action:
        st.write("")
        st.write("")
        run_btn = st.button("⚡ Triage Alert", type="primary", use_container_width=True)

    if target_ioc and (run_btn or default_text):
        clean_ioc = refang(target_ioc)
        ioc_type = detect_ioc_type(clean_ioc)

        if ioc_type == "unknown":
            st.error(f"Unrecognized indicator format: {target_ioc}")
        else:
            with st.spinner("Querying threat telemetry and correlating MITRE techniques..."):
                vt_data = vt_client.query_ioc(clean_ioc, ioc_type)
                risk = calculate_soc_risk_score(vt_data)
                mitre = map_ioc_to_mitre(ioc_type, vt_data.get("tags", []))
                ticket = generate_incident_ticket(vt_data, risk, mitre)

            # Executive Summary Cards
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric("Defanged Indicator", defang(clean_ioc), ioc_type.upper())
            with m2:
                st.metric("SOC Risk Score", f"{risk['score']} / 100", risk['severity'])
            with m3:
                st.metric("Malicious Engines", f"{vt_data.get('malicious', 0)} Detections", vt_data.get("as_owner", "N/A")[:22])
            with m4:
                st.metric("Triage Action Code", risk['action_code'])

            st.markdown("---")

            col_left, col_right = st.columns([1, 1])

            with col_left:
                st.subheader("📊 Threat Intelligence & Infrastructure")
                st.markdown(f"**Threat Assessment:** {risk['verdict']}")
                st.markdown(f"**Autonomous System / Org:** `{vt_data.get('as_owner', 'N/A')}`")
                st.markdown(f"**Telemetry Source:** `{vt_data.get('source')}`")
                
                tags = vt_data.get("tags", [])
                if tags:
                    st.markdown("**Threat Tags:** " + " ".join([f"`{t}`" for t in tags]))

                st.subheader("🎯 MITRE ATT&CK Correlation")
                for m in mitre:
                    st.markdown(f"<span class='mitre-pill'><strong>{m['technique_id']}</strong> {m['technique_name']}</span> &bull; <em>{m['tactic']}</em>", unsafe_allow_html=True)

            with col_right:
                st.subheader("🚨 L1 Incident Containment Playbook")
                for act in ticket["l1_containment_actions"]:
                    st.checkbox(act, value=True if risk['score'] >= 50 else False)

                st.subheader("📥 Export Incident Record")
                c1, c2 = st.columns(2)
                with c1:
                    st.download_button(
                        "📄 Download Markdown Ticket",
                        data=ticket["markdown_export"],
                        file_name=f"{ticket['ticket_id']}.md",
                        mime="text/markdown",
                        use_container_width=True
                    )
                with c2:
                    st.download_button(
                        "💾 Download JSON Record",
                        data=json.dumps(ticket, indent=2),
                        file_name=f"{ticket['ticket_id']}.json",
                        mime="application/json",
                        use_container_width=True
                    )

with tab2:
    st.subheader("Batch Extraction & Triage from Raw SIEM / EDR Logs")
    log_text = st.text_area(
        "Paste Raw Incident Logs, SIEM Alerts, or Phishing Email Headers:",
        height=180,
        placeholder="e.g. Inbound SMTP connection from 45.154.255.88 payload attachment dropped hash 44d88612fea8a8f36de82e1278abb02f contacting hxxps://c2-malware[.]ru/beacon"
    )
    if st.button("🔍 Extract & Triage All IOCs"):
        if log_text:
            extracted = extract_all_iocs(log_text)
            total = sum(len(v) for v in extracted.values())
            st.success(f"Discovered {total} distinct indicators across raw log stream.")
            
            summary_rows = []
            for i_type, items in extracted.items():
                for item in items:
                    data = vt_client.query_ioc(item, i_type)
                    r = calculate_soc_risk_score(data)
                    summary_rows.append({
                        "Type": i_type.upper(),
                        "Defanged Indicator": defang(item),
                        "Risk Score": f"{r['score']}/100",
                        "Severity": r['severity'],
                        "Detections": data.get("malicious", 0),
                        "Action": r['action_code']
                    })
            if summary_rows:
                st.dataframe(summary_rows, use_container_width=True)
