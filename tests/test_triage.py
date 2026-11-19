# Standard Python Test Suite for SOC Sentinel
from core.ioc_parser import detect_ioc_type, defang, refang, extract_all_iocs
from core.vt_client import VirusTotalClient
from core.mitre_mapper import map_ioc_to_mitre
from core.risk_engine import calculate_soc_risk_score
from core.incident_ticket import generate_incident_ticket

def test_defang_and_refang():
    raw_url = "https://evil.com/payload.exe"
    defanged = defang(raw_url)
    assert "[.]" in defanged
    assert "hxxps://" in defanged

    refanged = refang(defanged)
    assert refanged == raw_url

def test_detect_ioc_type():
    assert detect_ioc_type("192.168.1.1") == "ipv4"
    assert detect_ioc_type("evil-domain.com") == "domain"
    assert detect_ioc_type("https://phishing.ru/login") == "url"
    assert detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
    assert detect_ioc_type("44d88612fea8a8f36de82e1278abb02f") == "md5"

def test_extract_all_iocs():
    sample_log = "Inbound connection from 185.220.101.5 to hxxp://c2-bot[.]com/drop with hash 44d88612fea8a8f36de82e1278abb02f"
    iocs = extract_all_iocs(sample_log)
    assert "185.220.101.5" in iocs["ipv4"]
    assert "c2-bot.com" in iocs["domain"] or any("c2-bot" in u for u in iocs["url"])
    assert "44d88612fea8a8f36de82e1278abb02f" in iocs["md5"]

def test_risk_scoring_and_mitre():
    client = VirusTotalClient()
    vt_data = client.query_ioc("45.154.255.88", "ipv4")
    risk = calculate_soc_risk_score(vt_data)
    assert risk["score"] >= 75
    assert risk["severity"] == "CRITICAL"

    mitre = map_ioc_to_mitre("ipv4", vt_data.get("tags", []))
    assert any("T1071" in m["technique_id"] for m in mitre)

def test_ticket_generation():
    client = VirusTotalClient()
    vt_data = client.query_ioc("evil-domain.com", "domain")
    risk = calculate_soc_risk_score(vt_data)
    mitre = map_ioc_to_mitre("domain", vt_data.get("tags", []))
    ticket = generate_incident_ticket(vt_data, risk, mitre)

    assert "INC-SOC-" in ticket["ticket_id"]
    assert len(ticket["l1_containment_actions"]) > 0
    assert "Mohammed Basith" in ticket["assigned_analyst"]
