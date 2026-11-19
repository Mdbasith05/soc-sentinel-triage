import os
import time
import base64
import requests
from typing import Dict, Any, Optional

VT_API_V3_BASE = "https://www.virustotal.com/api/v3"

class VirusTotalClient:
    """
    Robust REST client for VirusTotal API v3.
    Includes automated caching and offline/demo fallback mode.
    """
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VT_API_KEY", "").strip()
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                "x-apikey": self.api_key,
                "Accept": "application/json"
            })

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _url_to_id(self, url: str) -> str:
        """Converts raw URL to base64 unpadded string required by VT API v3."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def query_ioc(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """
        Queries VirusTotal API v3 for the given indicator.
        Returns standardized verdict dictionary.
        """
        cache_key = f"{ioc_type}:{ioc.lower()}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        if not self.is_configured():
            return self._generate_offline_mock(ioc, ioc_type)

        endpoint_map = {
            "ipv4": f"{VT_API_V3_BASE}/ip_addresses/{ioc}",
            "domain": f"{VT_API_V3_BASE}/domains/{ioc}",
            "md5": f"{VT_API_V3_BASE}/files/{ioc}",
            "sha1": f"{VT_API_V3_BASE}/files/{ioc}",
            "sha256": f"{VT_API_V3_BASE}/files/{ioc}",
            "url": f"{VT_API_V3_BASE}/urls/{self._url_to_id(ioc)}"
        }

        url = endpoint_map.get(ioc_type)
        if not url:
            return {"error": f"Unsupported IOC type: {ioc_type}", "status": "failed"}

        try:
            response = self.session.get(url, timeout=12)
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                
                result = {
                    "ioc": ioc,
                    "ioc_type": ioc_type,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("reputation", 0),
                    "tags": data.get("tags", []),
                    "categories": data.get("categories", {}),
                    "as_owner": data.get("as_owner", data.get("network", "N/A")),
                    "country": data.get("country", "N/A"),
                    "last_analysis_date": data.get("last_analysis_date"),
                    "source": "VirusTotal v3 Live API",
                    "status": "success"
                }
                self.cache[cache_key] = result
                return result

            elif response.status_code == 404:
                result = {
                    "ioc": ioc,
                    "ioc_type": ioc_type,
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "reputation": 0,
                    "tags": ["unseen-by-vt"],
                    "source": "VirusTotal v3 Live API",
                    "status": "not_found"
                }
                self.cache[cache_key] = result
                return result
                
            elif response.status_code == 429:
                return {
                    "error": "VirusTotal API rate limit reached (Free tier 4 req/min). Using offline telemetry.",
                    "status": "rate_limited",
                    **self._generate_offline_mock(ioc, ioc_type)
                }
            else:
                return {"error": f"HTTP {response.status_code}: {response.text[:120]}", "status": "error"}

        except Exception as e:
            return {"error": str(e), "status": "exception", **self._generate_offline_mock(ioc, ioc_type)}

    def _generate_offline_mock(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """
        Realistic heuristic mock for demonstration or offline testing without API key.
        """
        ioc_low = ioc.lower()
        known_malicious_keywords = ["evil", "payload", "malware", "phish", "trojan", "stealer", "c2", "ransom"]
        known_benign = ["google.com", "microsoft.com", "cloudflare.com", "github.com", "8.8.8.8", "1.1.1.1"]

        if any(b in ioc_low for b in known_benign):
            malicious, suspicious, harmless = 0, 0, 85
            tags = ["safe", "cdn", "dns"]
            owner = "Cloudflare / Google Public Infrastructure"
        elif any(k in ioc_low for k in known_malicious_keywords) or "185.220." in ioc_low or "45.154." in ioc_low:
            malicious, suspicious, harmless = 54, 8, 2
            tags = ["c2", "tor-exit-node", "stealer", "cobalt-strike"]
            owner = "High-Risk Hosting / Bulletproof VPS"
        else:
            malicious, suspicious, harmless = 0, 1, 62
            tags = ["unclassified-traffic"]
            owner = "Commercial Internet Service Provider"

        return {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": 10,
            "reputation": -50 if malicious > 0 else 10,
            "tags": tags,
            "categories": {"threat": "malicious" if malicious > 5 else "benign"},
            "as_owner": owner,
            "country": "US",
            "source": "SOC-Sentinel Threat Engine (Heuristic Simulation)",
            "status": "simulated"
        }
