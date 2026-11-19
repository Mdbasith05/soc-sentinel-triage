import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, List, Set

# Regex Patterns for IOC Detection
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_REGEX = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")

# Whitelist common file extensions and noise words mistakenly caught as domains
IGNORED_DOMAINS = {
    "exe", "dll", "zip", "tar", "gz", "rar", "pdf", "docx", "xlsx", "png", "jpg", "txt", "log", "json"
}

def refang(text: str) -> str:
    """
    Converts defanged IOC strings back to standard routable formats.
    e.g. hxxps://evil[.]com/login -> https://evil.com/login
         192[.]168[.]1[.]1 -> 192.168.1.1
    """
    if not text:
        return ""
    cleaned = text
    # Protocols
    cleaned = re.sub(r"^hxxps?://", lambda m: "https://" if "hxxps" in m.group(0).lower() else "http://", cleaned, flags=re.IGNORECASE)
    # Brackets around dots or colons
    cleaned = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", cleaned)
    cleaned = re.sub(r"\[:\]|\(:\)|\{:\}", ":", cleaned)
    cleaned = re.sub(r"\[at\]|\(@\)|\{@\}", "@", cleaned, flags=re.IGNORECASE)
    return cleaned.strip()

def defang(text: str) -> str:
    """
    Defangs an active indicator to prevent accidental clicks in email / ticketing systems.
    e.g. https://evil.com -> hxxps://evil[.]com
         192.168.1.1 -> 192[.]168[.]1[.]1
    """
    if not text:
        return ""
    cleaned = text
    cleaned = re.sub(r"^https://", "hxxps://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^http://", "hxxp://", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.replace(".", "[.]")
    return cleaned

def is_valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def detect_ioc_type(ioc: str) -> str:
    """
    Identifies the precise category of a single indicator of compromise.
    """
    clean = refang(ioc.strip())
    
    if SHA256_REGEX.fullmatch(clean):
        return "sha256"
    if SHA1_REGEX.fullmatch(clean):
        return "sha1"
    if MD5_REGEX.fullmatch(clean):
        return "md5"
    if is_valid_ipv4(clean):
        return "ipv4"
    if clean.lower().startswith(("http://", "https://")):
        return "url"
    if DOMAIN_REGEX.fullmatch(clean):
        tld = clean.split(".")[-1].lower()
        if tld not in IGNORED_DOMAINS:
            return "domain"
            
    return "unknown"

def extract_all_iocs(raw_text: str) -> Dict[str, List[str]]:
    """
    Scans raw text/logs/alert dumps and extracts all distinct indicators grouped by type.
    """
    refanged_text = refang(raw_text)
    results: Dict[str, Set[str]] = {
        "sha256": set(),
        "sha1": set(),
        "md5": set(),
        "ipv4": set(),
        "domain": set(),
        "url": set()
    }

    # 1. Hashes
    for h in SHA256_REGEX.findall(refanged_text):
        results["sha256"].add(h.lower())
    for h in SHA1_REGEX.findall(refanged_text):
        results["sha1"].add(h.lower())
    for h in MD5_REGEX.findall(refanged_text):
        results["md5"].add(h.lower())

    # 2. URLs (extract first so domain regex doesn't fragment them)
    for u in URL_REGEX.findall(refanged_text):
        results["url"].add(u)

    # 3. IPv4
    for ip in IPV4_REGEX.findall(refanged_text):
        if is_valid_ipv4(ip):
            results["ipv4"].add(ip)

    # 4. Domains (avoid matching domains already part of URLs)
    for d in DOMAIN_REGEX.findall(refanged_text):
        tld = d.split(".")[-1].lower()
        if tld not in IGNORED_DOMAINS:
            # Don't capture IP addresses mistakenly
            if not is_valid_ipv4(d):
                results["domain"].add(d.lower())

    return {k: sorted(list(v)) for k, v in results.items()}
