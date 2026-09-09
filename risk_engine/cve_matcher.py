import aiohttp
import re
import asyncio
from risk_engine.cve_database import cve_db
from utils.config import Config
from utils.logger import logger

class CVEMatcher:
    @staticmethod
    async def match_banner(banner):
        risks = []
        if not banner:
            return risks
            
        banner_lower = banner.lower()
        
        # 1. Fallback Heuristics
        if "vsftpd 2.3.4" in banner_lower:
            risks.append("CVE-2011-2523: vsftpd backdoor")
        if "openssh 4." in banner_lower or "openssh 5." in banner_lower:
            risks.append("Outdated OpenSSH version (High Risk)")
        if "apache/2.2" in banner_lower or "apache/2.0" in banner_lower:
            risks.append("Outdated Apache version (High Risk)")
            
        # Extract potential software/version
        match = re.search(r'([a-zA-Z\-]+)[/\s](\d+\.\d+(?:\.\d+)?)', banner)
        if not match:
            return risks
            
        software = match.group(1).lower()
        version = match.group(2)
        
        # 2. Local SQLite CVE DB Lookup
        local_cves = cve_db.search_cve(software, version)
        for item in local_cves:
            risks.append(f"{item['id']}: {item['summary']}")

        # 3. Async Public Vulnerability API Lookup (Fallback/Enhancement)
        # Try to enrich with CIRCL API, but timeout quickly to avoid slowing scan
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://cve.circl.lu/api/search/{software}/{version}"
                async with session.get(url, timeout=Config.TIMEOUT) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data and isinstance(data, list):
                            for item in data[:3]:  # Limit to top 3 from external
                                cve_id = item.get("id")
                                summary = item.get("summary", "")[:50] + "..."
                                if cve_id:
                                    risk_str = f"{cve_id}: {summary}"
                                    if risk_str not in risks:
                                        risks.append(risk_str)
        except asyncio.TimeoutError:
            logger.debug(f"CIRCL API timeout for {software}/{version}")
        except Exception as e:
            logger.debug(f"CIRCL API error for {software}/{version}: {e}")
            
        return list(set(risks))
