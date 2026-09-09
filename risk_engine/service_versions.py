"""
Service Version Database — maps service banners to known software versions
and links them to CVE lookups.

Provides structured version extraction from raw banner strings for:
  - SSH (OpenSSH, Dropbear)
  - HTTP (Apache, Nginx, IIS, lighttpd)
  - FTP (vsftpd, ProFTPD, PureFTPD)
  - SMTP (Postfix, Exim, Sendmail)
  - Databases (MySQL, PostgreSQL, MongoDB)
  - Remote (RDP, VNC)

Usage:
    from risk_engine.service_versions import ServiceVersionDB
    info = ServiceVersionDB.parse_banner(80, "Apache/2.4.41 (Ubuntu)")
    # {"service": "Apache HTTP", "version": "2.4.41", "cve_search_key": "apache 2.4.41", "eol": True}
"""
import re
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("netscan.service_versions")


@dataclass
class ServiceInfo:
    service: str
    version: Optional[str]
    vendor: Optional[str]
    cve_search_key: str
    eol: bool = False           # End-of-life flag (known outdated)
    notes: Optional[str] = None


# ─── Pattern Registry ────────────────────────────────────────────────────────
# Each entry: (port_hint, regex_pattern, service_name, vendor)
# Port hint = None → match on any port

_BANNER_PATTERNS: list[tuple] = [
    # SSH
    (22,  r"SSH-\d+\.\d+-OpenSSH[_\s]([\d.]+\w*)",       "OpenSSH",          "OpenBSD"),
    (22,  r"SSH-\d+\.\d+-dropbear_([\d.]+)",               "Dropbear SSH",     "Dropbear"),
    (22,  r"SSH-\d+\.\d+-(\S+)",                           "SSH Server",       "Unknown"),

    # HTTP/Web
    (80,  r"Apache/([\d.]+)",                              "Apache HTTP",      "Apache"),
    (80,  r"nginx/([\d.]+)",                               "Nginx",            "Nginx"),
    (80,  r"Microsoft-IIS/([\d.]+)",                       "IIS",              "Microsoft"),
    (80,  r"lighttpd/([\d.]+)",                            "lighttpd",         "lighttpd"),
    (443, r"Apache/([\d.]+)",                              "Apache HTTPS",     "Apache"),
    (443, r"nginx/([\d.]+)",                               "Nginx HTTPS",      "Nginx"),
    (None, r"Express",                                     "Node.js Express",  "Node.js"),

    # FTP
    (21,  r"vsftpd ([\d.]+)",                              "vsftpd",           "vsftpd"),
    (21,  r"ProFTPD ([\d.]+)",                             "ProFTPD",          "ProFTPD"),
    (21,  r"Pure-FTPd",                                    "Pure-FTPd",        "Pure-FTPd"),
    (21,  r"FileZilla Server ([\d.]+)",                    "FileZilla FTP",    "FileZilla"),

    # SMTP
    (25,  r"Postfix",                                      "Postfix SMTP",     "Postfix"),
    (25,  r"Exim ([\d.]+)",                                "Exim SMTP",        "Exim"),
    (25,  r"Sendmail ([\d.]+)",                            "Sendmail",         "Sendmail"),

    # Databases
    (3306, r"([\d.]+)-.*MySQL",                            "MySQL",            "Oracle"),
    (3306, r"mysql_([\d.]+)",                              "MySQL",            "Oracle"),
    (5432, r"PostgreSQL ([\d.]+)",                         "PostgreSQL",       "PostgreSQL"),
    (27017, r"MongoDB",                                    "MongoDB",          "MongoDB"),
    (6379, r"\+PONG",                                      "Redis",            "Redis"),

    # Remote Desktop / VNC
    (3389, r"RDP",                                         "RDP",              "Microsoft"),
    (5900, r"RFB ([\d.]+)",                                "VNC",              "Various"),

    # Telnet
    (23,  r"(.+)",                                         "Telnet Service",   "Unknown"),
]

# EOL versions — these are known to be end-of-life or critically outdated
_EOL_SIGNATURES: list[tuple[str, str]] = [
    ("OpenSSH",     "7."),      # OpenSSH < 8.x → EOL
    ("Apache HTTP", "2.2."),    # Apache 2.2.x → EOL
    ("Apache HTTP", "2.4.1"),   # Apache 2.4.1-2.4.29 have known vulns
    ("Nginx",       "1.1"),     # Nginx < 1.14 → EOL
    ("vsftpd",      "2.3.4"),   # vsftpd 2.3.4 → Famous backdoor!
    ("MySQL",       "5.5."),    # MySQL 5.5 → EOL
    ("MySQL",       "5.6."),    # MySQL 5.6 → EOL
    ("PHP",         "5."),      # PHP 5.x → EOL
    ("PHP",         "7.0"),     # PHP 7.0 → EOL
    ("PHP",         "7.1"),     # PHP 7.1 → EOL
    ("IIS",         "6."),      # IIS 6 (Windows Server 2003) → EOL
    ("IIS",         "7."),      # IIS 7 (Windows Server 2008) → EOL
]


class ServiceVersionDB:
    """Banner parser and version database for known network services."""

    @classmethod
    def parse_banner(cls, port: int, banner: str) -> Optional[ServiceInfo]:
        """
        Parse a service banner and extract version information.

        Args:
            port:   The port number the banner was captured from.
            banner: Raw banner string from the service.

        Returns:
            ServiceInfo or None if banner is unrecognised.
        """
        if not banner or not banner.strip():
            return None

        banner_clean = banner.strip()

        for port_hint, pattern, service_name, vendor in _BANNER_PATTERNS:
            # Only match if port matches hint (or hint is None = wildcard)
            if port_hint is not None and port != port_hint:
                continue

            match = re.search(pattern, banner_clean, re.IGNORECASE)
            if match:
                version = None
                try:
                    version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                except IndexError:
                    pass

                eol = cls._is_eol(service_name, version)
                cve_key = f"{service_name.lower()} {version}" if version else service_name.lower()

                notes = None
                if version and "2.3.4" in version and "vsftpd" in service_name.lower():
                    notes = "⚠️ vsftpd 2.3.4 — BACKDOOR (CVE-2011-2523)"

                return ServiceInfo(
                    service=service_name,
                    version=version,
                    vendor=vendor,
                    cve_search_key=cve_key,
                    eol=eol,
                    notes=notes,
                )

        return None

    @classmethod
    def parse_banners(cls, ports: list[int], banners: list[str]) -> list[dict]:
        """
        Parse multiple banners (from a scan result) and return a list of dicts.

        Args:
            ports:   List of port numbers.
            banners: Corresponding list of banner strings.

        Returns:
            List of dicts with service version info (only non-None results).
        """
        results = []
        for port, banner in zip(ports, banners):
            info = cls.parse_banner(port, banner)
            if info:
                results.append({
                    "port": port,
                    "service": info.service,
                    "version": info.version,
                    "vendor": info.vendor,
                    "eol": info.eol,
                    "cve_search_key": info.cve_search_key,
                    "notes": info.notes,
                })
        return results

    @classmethod
    def _is_eol(cls, service_name: str, version: Optional[str]) -> bool:
        """Check if a service/version combination is known to be EOL."""
        if not version:
            return False
        for svc, ver_prefix in _EOL_SIGNATURES:
            if svc.lower() in service_name.lower() and version.startswith(ver_prefix):
                return True
        return False
