#!/usr/bin/env python3
"""
SOC Sentinel — Native Lightweight Web Server & REST API
Zero external dependencies (Pure Python Standard Library).
Serves an interactive Dark-Mode SOC Analyst Workbench at http://localhost:8080
"""

import sys
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

from core.ioc_parser import detect_ioc_type, defang, refang, extract_all_iocs
from core.vt_client import VirusTotalClient
from core.mitre_mapper import map_ioc_to_mitre
from core.risk_engine import calculate_soc_risk_score
from core.incident_ticket import generate_incident_ticket

vt_client = VirusTotalClient()

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Sentinel — L1 Alert Triage Engine</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-base: #090d16;
    --bg-card: #0f172a;
    --bg-card-hover: #1e293b;
    --border: rgba(255, 255, 255, 0.1);
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --accent-blue: #38bdf8;
    --accent-red: #ef4444;
    --accent-orange: #f97316;
    --accent-green: #10b981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg-base);
    color: var(--text-primary);
    font-family: 'Plus Jakarta Sans', sans-serif;
    padding: 24px;
    line-height: 1.5;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 16px;
    margin-bottom: 24px;
  }
  h1 { font-size: 24px; font-weight: 800; color: var(--text-primary); display: flex; align-items: center; gap: 8px; }
  .badge-analyst { font-size: 13px; color: var(--accent-blue); background: rgba(56, 189, 248, 0.1); padding: 4px 10px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.2); }
  
  .triage-input-box {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 24px;
  }
  .input-row { display: flex; gap: 12px; margin-top: 12px; }
  input[type="text"] {
    flex: 1;
    background: #060911;
    border: 1px solid var(--border);
    color: #fff;
    padding: 12px 16px;
    border-radius: 8px;
    font-size: 15px;
    font-family: 'JetBrains Mono', monospace;
  }
  input[type="text"]:focus { outline: none; border-color: var(--accent-blue); }
  button {
    background: #2563eb;
    color: white;
    border: none;
    padding: 12px 24px;
    border-radius: 8px;
    font-weight: 700;
    cursor: pointer;
    transition: 0.2s;
  }
  button:hover { background: #1d4ed8; }
  
  .sample-pills { display: flex; gap: 8px; margin-top: 12px; align-items: center; font-size: 13px; color: var(--text-secondary); }
  .sample-btn { background: #1e293b; color: #cbd5e1; border: 1px solid var(--border); padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; }
  .sample-btn:hover { background: #334155; }

  .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .metric-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    padding: 16px;
    border-radius: 10px;
  }
  .metric-label { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; font-weight: 700; }
  .metric-value { font-size: 22px; font-weight: 800; margin-top: 4px; }
  
  .split-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .panel {
    background: var(--bg-card);
    border: 1px solid var(--border);
    padding: 20px;
    border-radius: 12px;
  }
  h2 { font-size: 17px; font-weight: 700; margin-bottom: 14px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
  
  .mitre-badge {
    display: inline-block;
    background: rgba(99, 102, 241, 0.15);
    color: #c7d2fe;
    border: 1px solid #4f46e5;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    margin: 4px 4px 4px 0;
    font-family: 'JetBrains Mono', monospace;
  }
  ul.action-list { list-style: none; }
  ul.action-list li {
    padding: 8px 12px;
    background: rgba(255, 255, 255, 0.02);
    border-left: 3px solid var(--accent-blue);
    margin-bottom: 8px;
    font-size: 13px;
    border-radius: 0 6px 6px 0;
  }
  pre {
    background: #060911;
    padding: 12px;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    overflow-x: auto;
    border: 1px solid var(--border);
    color: #e2e8f0;
  }
  .badge-critical { color: #fca5a5; background: #7f1d1d; padding: 2px 8px; border-radius: 4px; }
  .badge-benign { color: #86efac; background: #14532d; padding: 2px 8px; border-radius: 4px; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>🛡️ SOC Sentinel</h1>
      <p style="color: var(--text-secondary); font-size: 13px;">Automated L1 Alert Triage & Threat Intelligence Engine (Zero External Dependencies)</p>
    </div>
    <div class="badge-analyst">Analyst: Mohammed Basith (L1 SOC)</div>
  </header>

  <div class="triage-input-box">
    <label style="font-weight: 600; font-size: 14px;">Enter Indicator of Compromise (IP, Domain, URL, or File Hash):</label>
    <div class="input-row">
      <input type="text" id="iocInput" placeholder="e.g. 45.154.255.88, evil[.]com, or 44d88612fea8a8f36de82e1278abb02f" value="45.154.255.88">
      <button onclick="runTriage()">⚡ Triage Indicator</button>
    </div>
    <div class="sample-pills">
      <span>Sample Test Cases:</span>
      <span class="sample-btn" onclick="setIoc('45.154.255.88')">⚠️ High-Risk C2 IP</span>
      <span class="sample-btn" onclick="setIoc('hxxps://banking-update[.]com/login')">🎣 Phishing URL</span>
      <span class="sample-btn" onclick="setIoc('1.1.1.1')">✅ Benign DNS</span>
    </div>
  </div>

  <div id="resultsArea">
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-label">Defanged Indicator</div>
        <div class="metric-value" id="valIoc" style="font-size: 18px; font-family: 'JetBrains Mono';">45[.]154[.]255[.]88</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">SOC Risk Score</div>
        <div class="metric-value" id="valScore" style="color: var(--accent-red);">100 / 100</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Severity Level</div>
        <div class="metric-value" id="valSeverity"><span class="badge-critical">CRITICAL</span></div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Engine Consensus</div>
        <div class="metric-value" id="valDetections" style="color: var(--accent-orange);">54 Flags</div>
      </div>
    </div>

    <div class="split-grid">
      <div class="panel">
        <h2>📊 Threat Intelligence & MITRE ATT&CK</h2>
        <p style="margin-bottom: 8px;"><strong>Threat Assessment:</strong> <span id="valVerdict">Confirmed Malicious Infrastructure</span></p>
        <p style="margin-bottom: 8px;"><strong>Infrastructure / AS:</strong> <span id="valOwner">High-Risk Hosting / Bulletproof VPS</span></p>
        <p style="margin-bottom: 12px;"><strong>Telemetry Source:</strong> <span id="valSource">VirusTotal v3 / Heuristic Engine</span></p>
        
        <h3 style="font-size: 14px; margin-bottom: 8px; color: var(--text-secondary);">MITRE ATT&CK Enterprise Techniques:</h3>
        <div id="valMitre">
          <span class="mitre-badge">T1071 C2 Protocols</span>
          <span class="mitre-badge">T1090.003 Tor Proxy</span>
          <span class="mitre-badge">T1555 Credential Access</span>
        </div>
      </div>

      <div class="panel">
        <h2>🚨 L1 Containment Recommendations</h2>
        <ul class="action-list" id="valActions">
          <li>Perimeter Firewall: Apply ACL rule dropping all inbound/outbound packets to 45[.]154[.]255[.]88</li>
          <li>SIEM Threat Hunt: Query 30-day perimeter logs for internal endpoints initiating connections to this host</li>
          <li>Identity: Reset credentials and revoke active Azure AD / Okta sessions for affected users</li>
        </ul>
      </div>
    </div>
  </div>
</div>

<script>
function setIoc(val) {
  document.getElementById('iocInput').value = val;
  runTriage();
}

async function runTriage() {
  const ioc = document.getElementById('iocInput').value.trim();
  if (!ioc) return;
  
  try {
    const res = await fetch('/api/triage?ioc=' + encodeURIComponent(ioc));
    const data = await res.json();
    
    if (data.error) {
      alert(data.error);
      return;
    }

    document.getElementById('valIoc').innerText = data.indicator.defanged;
    document.getElementById('valScore').innerText = data.risk_score;
    document.getElementById('valScore').style.color = data.severity === 'CRITICAL' ? 'var(--accent-red)' : (data.severity === 'HIGH' ? 'var(--accent-orange)' : 'var(--accent-green)');
    document.getElementById('valSeverity').innerHTML = `<span class="${data.severity === 'CRITICAL' ? 'badge-critical' : 'badge-benign'}">${data.severity}</span>`;
    document.getElementById('valDetections').innerText = data.threat_intelligence.malicious_engines;
    document.getElementById('valVerdict').innerText = data.verdict;
    document.getElementById('valOwner').innerText = data.threat_intelligence.as_owner;
    document.getElementById('valSource').innerText = data.threat_intelligence.source;
    
    const mitreDiv = document.getElementById('valMitre');
    mitreDiv.innerHTML = data.mitre_attck_mapping.map(m => `<span class="mitre-badge">${m}</span>`).join('');
    
    const actUl = document.getElementById('valActions');
    actUl.innerHTML = data.l1_containment_actions.map(a => `<li>${a}</li>`).join('');
  } catch (err) {
    console.error(err);
  }
}
</script>
</body>
</html>
"""

class SOCHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
            
        elif parsed.path == "/api/triage":
            params = urllib.parse.parse_qs(parsed.query)
            ioc = params.get("ioc", [""])[0].strip()
            
            clean_ioc = refang(ioc)
            ioc_type = detect_ioc_type(clean_ioc)
            
            if ioc_type == "unknown":
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Unknown IOC format: {ioc}"}).encode("utf-8"))
                return
                
            vt_data = vt_client.query_ioc(clean_ioc, ioc_type)
            risk = calculate_soc_risk_score(vt_data)
            mitre = map_ioc_to_mitre(ioc_type, vt_data.get("tags", []))
            ticket = generate_incident_ticket(vt_data, risk, mitre)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(ticket).encode("utf-8"))
            
        elif parsed.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "service": "SOC Sentinel Engine"}).encode("utf-8"))
            
        else:
            self.send_response(404)
            self.end_headers()

def run_server(port=8080):
    server = HTTPServer(("0.0.0.0", port), SOCHandler)
    print(f"[*] SOC Sentinel Web Server running at: http://localhost:{port}")
    print("[*] Press Ctrl+C to stop.")
    server.serve_forever()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
