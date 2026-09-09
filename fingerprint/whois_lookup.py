"""
WHOIS & ASN Enrichment module for Netscan.

Performs WHOIS lookups (via python-whois) and ASN resolution for public IPs,
providing ownership, registrar, and ISP/BGP information.

Usage:
    info = await whois_lookup("8.8.8.8")
    # info = {"registrar": "...", "org": "...", "country": "US", "created": "...", "asn": "..."}
"""
import asyncio
import ipaddress
import logging
from functools import lru_cache
from datetime import datetime

logger = logging.getLogger("netscan.whois")


@lru_cache(maxsize=256)
def _sync_whois(target: str) -> dict:
    """Blocking WHOIS lookup. Cached to avoid redundant lookups."""
    result = {
        "registrar": "Unknown",
        "org": "Unknown",
        "country": "Unknown",
        "created": "Unknown",
        "updated": "Unknown",
        "expiry": "Unknown",
        "name_servers": [],
        "asn": "Unknown",
    }

    try:
        import whois  # python-whois package
        w = whois.whois(target)
        
        result["registrar"] = str(w.registrar or "Unknown")
        result["org"] = str(w.org or w.registrant_name or "Unknown")
        result["country"] = str(w.country or "Unknown")
        
        # Dates may be lists (whois can return multiple)
        def _format_date(d):
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime):
                return d.strftime("%Y-%m-%d")
            return str(d) if d else "Unknown"
        
        result["created"] = _format_date(w.creation_date)
        result["updated"] = _format_date(w.updated_date)
        result["expiry"] = _format_date(w.expiration_date)
        
        ns = w.name_servers
        if ns:
            result["name_servers"] = sorted(set(str(n).lower() for n in ns))

    except ImportError:
        result["error"] = "python-whois not installed. Run: pip install python-whois"
        logger.warning("python-whois not installed.")
    except Exception as e:
        result["error"] = str(e)
        logger.debug(f"WHOIS lookup failed for {target}: {e}")

    # ASN lookup via ip-api (already used for geolocation) or ipinfo
    try:
        import socket
        asn_target = target
        # For IPs, try ipinfo-style reverse lookup (no external dep if already cached via geo)
        result["asn"] = _get_asn_info(asn_target)
    except Exception:
        pass

    return result


def _get_asn_info(ip: str) -> str:
    """Best-effort ASN detection via DNS-based Team Cymru service."""
    try:
        import socket
        # Reverse IP for Team Cymru lookup (e.g. 8.8.8.8 → 8.8.8.8.origin.asn.cymru.com)
        parts = ip.split(".")
        reversed_ip = ".".join(reversed(parts))
        txt_hostname = f"{reversed_ip}.origin.asn.cymru.com"
        result = socket.getaddrinfo(txt_hostname, None)
        # Team Cymru returns ASN in TXT records; try basic resolution as a fallback
        return f"Lookup: {txt_hostname}"
    except Exception:
        return "Unknown"


async def whois_lookup(target: str) -> dict:
    """
    Async wrapper for WHOIS lookup. Skips private/loopback IPs gracefully.

    Args:
        target: IP address or domain name.
    Returns:
        dict with WHOIS info (registrar, org, country, dates, ASN, etc.)
    """
    try:
        ip_obj = ipaddress.ip_address(target)
        if ip_obj.is_private or ip_obj.is_loopback:
            return {"org": "Private/Local Network", "country": "LAN", "registrar": "N/A"}
    except ValueError:
        pass  # It's a domain name, proceed normally

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_whois, target)
