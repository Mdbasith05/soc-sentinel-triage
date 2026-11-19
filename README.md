# 🛡️ SOC Sentinel — Automated L1 Alert Triage & Threat Intelligence Engine

> **Enterprise-grade SOC automation tool engineered for Level 1 (L1) security analysts to rapidly parse raw alerts, enrich Indicators of Compromise (IOCs) via VirusTotal v3, correlate MITRE ATT&CK techniques, compute normalized risk scores, and generate automated containment playbooks.**

**Author:** [Mohammed Basith](https://github.com/Mdbasith05)  
**Specialization:** MCA in Cyber Security and Forensics  
**Portfolio:** [mdbasith05.github.io/mdbasith05](https://mdbasith05.github.io/mdbasith05)  

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://soc-sentinel-triage-mdrmh2dyeawzwjaycnjcdg.streamlit.app/)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-Streamlit%20Cloud-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://soc-sentinel-triage-mdrmh2dyeawzwjaycnjcdg.streamlit.app/)

---

## 🎯 The Real-World SOC Problem It Solves

In a 24/7 Security Operations Center (SOC), L1 analysts process hundreds of alerts per shift from SIEMs (Microsoft Sentinel, Splunk, QRadar), EDRs (CrowdStrike, Defender for Endpoint), and email gateways. 

Manual lookup across multiple threat engines causes **alert fatigue**, **inconsistent triage**, and **delayed containment**. 

**SOC Sentinel eliminates this bottleneck:**
1. **Automated Ingestion & Defanging:** Safely neutralizes malicious indicators (`hxxp://`, `evil[.]com`) to avoid accidental execution.
2. **VirusTotal v3 Enrichment:** Queries live detection statistics, community reputation, threat categories, and autonomous system (AS) owners.
3. **MITRE ATT&CK Matrix Correlation:** Automatically maps indicators to enterprise tactics & techniques (T1566 Phishing, T1071 C2, T1204 Malicious File Execution).
4. **Normalized 0–100 Risk Engine:** Weights vendor consensus, threat tags, and false-positive suppression to classify severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `BENIGN`).
5. **Actionable Containment Playbooks:** Generates ready-to-execute L1 containment actions (firewall drop rules, EDR isolation, token revocation, DNS sinkholing) exported as structured **Markdown** and **JSON** tickets.

---

## 🏗️ Architecture & Workflow

```text
  [ Raw SIEM / EDR / Email Alert ]
                  │
                  ▼
       [ core/ioc_parser.py ] ──► Regex Extraction & Automated Defanging
                  │
                  ▼
        [ core/vt_client.py ] ──► VirusTotal v3 REST API / Heuristic Telemetry
                  │
                  ▼
      [ core/risk_engine.py ] ──► False-Positive Whitelist + 0–100 Scoring
                  │
                  ▼
     [ core/mitre_mapper.py ] ──► MITRE ATT&CK Technique & Tactic Mapping
                  │
                  ▼
   [ core/incident_ticket.py] ──► L1 Containment Recommendations & JSON/MD Ticket
                  │
         ┌────────┴────────┐
         ▼                 ▼
   [ CLI Tool ]      [ Streamlit Web UI ]
 (cli.py --ioc ...)   (streamlit run app.py)
```

---

## 🚀 Key Features

* **Multi-Format Indicator Support:** Extracts and classifies IPv4, IPv6, Domains, URLs, MD5, SHA-1, and SHA-256 hashes.
* **Defanging & Refanging Engine:** Bidirectional parser supporting `hxxp://`, `[.]`, `(.)`, `[:]`, `{dot}` notation.
* **Dual Interface:**
  * **CLI Tool (`cli.py`):** High-speed terminal workflow for incident responders and command-line automation.
  * **Interactive SOC Dashboard (`app.py`):** Dark-mode web interface featuring real-time risk gauges, indicator breakdowns, and 1-click ticket downloads.
* **Offline / Simulated Heuristic Mode:** Works seamlessly out-of-the-box even without an active VirusTotal API key for local training and offline lab demonstrations.
* **Incident Ticketing Ready:** Formatted for direct integration into Jira, ServiceNow SecOps, or TheHive.

---

## 💻 Quick Start & Usage

### 1. Installation

```bash
git clone https://github.com/Mdbasith05/soc-sentinel-triage.git
cd soc-sentinel-triage
pip install -r requirements.txt
```

### 2. Run via Command Line (CLI)

#### Triage a single high-risk C2 IP:
```bash
python cli.py --ioc 45.154.255.88
```

#### Triage and export structured incident ticket:
```bash
python cli.py --ioc hxxps://secure-banking-login[.]com/verify --output ticket.md
```

#### Batch extract and triage all IOCs from a raw SIEM alert:
```bash
python cli.py --text "Alert from firewall: src=192.168.1.50 dst=hxxp://evil-payload[.]com/drop.exe hash=44d88612fea8a8f36de82e1278abb02f"
```

### 3. Launch Interactive Web Dashboard

```bash
streamlit run app.py
```
Open `http://localhost:8501` in your browser.

---

## 📋 Sample Incident Ticket Output (Markdown)

```markdown
# [SOC TICKET] INC-SOC-20261119-9182 — CRITICAL Alert Triage
**Analyst:** Mohammed Basith (L1 SOC Operations) | **Status:** Escalated / Action Required

## 1. Executive Summary
- **Defanged Indicator:** `45[.]154[.]255[.]88`
- **IOC Type:** `IPV4`
- **Calculated SOC Risk Score:** **100/100** (CRITICAL)
- **Threat Assessment:** Confirmed Malicious Infrastructure / Active Threat

## 2. Threat Intelligence Telemetry
- **Detection Consensus:** `54` security engines flagged as malicious
- **Autonomous System / Network:** `High-Risk Hosting / Bulletproof VPS`
- **Identified Tags:** `c2`, `tor-exit-node`, `stealer`, `cobalt-strike`

## 3. MITRE ATT&CK Framework Correlation
- **T1071 — Standard Application Layer Protocol / Direct IP C2** (*Command and Control*)
- **T1090.003 — Proxy: Multi-hop Proxy (Tor)** (*Command and Control*)
- **T1555 — Credentials from Password Stores / InfoStealer** (*Credential Access*)

## 4. L1 Immediate Containment Recommendations
- [ ] Perimeter Firewall: Apply perimeter ACL / Palo Alto / Fortinet block rule to drop all inbound and outbound traffic to 45[.]154[.]255[.]88
- [ ] SIEM Threat Hunt: Query firewall logs for previous 30 days to identify any internal endpoints that initiated outbound handshakes.
- [ ] Identity & Access: Reset credentials and revoke active Azure AD / Okta sessions for users associated with this telemetry stream.
```

---

## 🧪 Automated Testing

Verify system integrity by running the embedded test suite:

```bash
python -c "import tests.test_triage as t; t.test_defang_and_refang(); t.test_detect_ioc_type(); t.test_extract_all_iocs(); t.test_risk_scoring_and_mitre(); t.test_ticket_generation(); print('ALL TESTS PASSED!')"
```

---

## 👨‍💻 Candidate Profile

* **Developer:** Mohammed Basith
* **Degree:** Master of Computer Applications (MCA) in Cyber Security & Forensics
* **Availability:** Relocating to Dubai, UAE (Visit Visa • Immediate Joiner / 0 Days Notice)
* **LinkedIn:** [linkedin.com/in/mohammedbasith05](https://www.linkedin.com/in/mohammedbasith05)
* **GitHub:** [github.com/Mdbasith05](https://github.com/Mdbasith05)
