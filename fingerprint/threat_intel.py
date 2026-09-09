"""
Threat Intelligence Integration for Netscan.

Checks public IPs against AbuseIPDB to identify known malicious actors
(spam, botnets, scanners, etc.) before/during network scans.

Usage:
    result = await check_ip("8.8.8.8")
    # result = {"is_malicious": False, "abuse_confidence": 0, "categories": [], ...}

Requires an AbuseIPDB API key set in netscan_config.yaml:
    threat_intel:
      abuseipdb_key: "YOUR_KEY_HERE"
"""
import asyncio
import aiohttp
import ipaddress
import logging
from functools import lru_cache
from utils.config import Config

logger = logging.getLogger("netscan.threat_intel")

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

# Human-readable category names from AbuseIPDB documentation
ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH Brute-Force", 23: "IoT Targeted"
}

# Simple in-memory cache to avoid re-querying within a scan session
_ip_cache: dict[str, dict] = {}


async def check_ip(ip: str) -> dict:
    """
    Check a single IP against AbuseIPDB.
    
    Returns a dict with keys:
        is_malicious (bool), abuse_confidence (int 0-100),
        total_reports (int), categories (list[str]),
        last_reported (str), country (str), isp (str)
    
    Returns quickly (with is_malicious=False) for private/loopback IPs.
    """
    default = {
        "is_malicious": False,
        "abuse_confidence": 0,
        "total_reports": 0,
        "categories": [],
        "last_reported": None,
        "country": "Unknown",
        "isp": "Unknown",
    }

    # Skip private / loopback addresses
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return {**default, "note": "Private/Local IP — skipped"}
    except ValueError:
        return {**default, "error": f"Invalid IP: {ip}"}

    # Cache hit
    if ip in _ip_cache:
        return _ip_cache[ip]

    api_key = getattr(Config, "ABUSEIPDB_KEY", None)
    if not api_key:
        logger.warning("[ThreatIntel] No AbuseIPDB API key configured. Skipping threat check.")
        return {**default, "note": "No API key configured"}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    try:
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(ABUSEIPDB_API_URL, headers=headers, params=params) as resp:
                if resp.status == 200:
                    data = (await resp.json()).get("data", {})
                    cat_ids = data.get("usageType", []) or []
                    # Map numeric category IDs to names
                    raw_cats = data.get("reports", [{}])
                    all_cat_ids = set()
                    for report in raw_cats:
                        all_cat_ids.update(report.get("categories", []))
                    categories = [ABUSE_CATEGORIES.get(c, f"Category {c}") for c in all_cat_ids]
                    
                    confidence = data.get("abuseConfidenceScore", 0)
                    result = {
                        "is_malicious": confidence >= 25,
                        "abuse_confidence": confidence,
                        "total_reports": data.get("totalReports", 0),
                        "categories": categories[:5],  # Top 5
                        "last_reported": data.get("lastReportedAt"),
                        "country": data.get("countryCode", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                    }
                    _ip_cache[ip] = result
                    return result
                else:
                    logger.warning(f"[ThreatIntel] AbuseIPDB returned HTTP {resp.status} for {ip}")
    except asyncio.TimeoutError:
        logger.debug(f"[ThreatIntel] Timeout checking {ip}")
    except Exception as e:
        logger.error(f"[ThreatIntel] Error checking {ip}: {e}")

    return default


async def check_ips_batch(ip_list: list[str], max_concurrency: int = 5) -> dict[str, dict]:
    """
    Batch-check multiple IPs concurrently with a semaphore to respect rate limits.
    
    Returns:
        dict mapping IP → threat intel result
    """
    semaphore = asyncio.Semaphore(max_concurrency)
    
    async def limited_check(ip):
        async with semaphore:
            return ip, await check_ip(ip)
    
    tasks = [limited_check(ip) for ip in ip_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    output = {}
    for item in results:
        if isinstance(item, Exception):
            continue
        ip, data = item
        output[ip] = data
    
    return output


def clear_cache():
    """Clear the in-memory threat intel cache (useful between scan sessions)."""
    _ip_cache.clear()
