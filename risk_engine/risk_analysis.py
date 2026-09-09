from .cve_matcher import CVEMatcher
from .service_versions import ServiceVersionDB
from utils.logger import logger

class RiskAnalyzer:
    @staticmethod
    async def analyze(open_ports, banners, web_intel=None):
        """
        Comprehensive risk analysis with scoring.
        Returns: (risk_level, reasons, score, summary)
        Score: 0 (Safe) to 100 (Critical)
        """
        score = 0
        reasons = []

        # 1. Insecure Ports (High impact)
        insecure_ports = {
            21: ("FTP", 50),
            23: ("Telnet", 70),
            69: ("TFTP", 40),
            3389: ("RDP", 20),
            445: ("SMB", 40)
        }

        for port in open_ports:
            if port in insecure_ports:
                name, p_score = insecure_ports[port]
                score += p_score
                reasons.append(f"Critical service exposed: {name} (Port {port})")

        # 2. Banner/CVE Analysis
        for banner in banners:
            if not banner: continue
            try:
                cves = await CVEMatcher.match_banner(banner)
                if cves:
                    score += 50
                    reasons.extend(cves)
            except Exception as e:
                logger.error(f"Error matching banner '{banner}': {e}")
                reasons.append("Vulnerability analysis failed for a banner due to an internal error.")

        # 3. Service Version Analysis (EOL / Backdoor detection)
        if banners and open_ports:
            version_results = ServiceVersionDB.parse_banners(open_ports, banners)
            for v in version_results:
                if v.get("notes"):
                    # Critical backdoor or well-known exploit
                    score += 80
                    reasons.append(f"⚠️ CRITICAL: {v['notes']} on port {v['port']}")
                elif v.get("eol"):
                    score += 20
                    reasons.append(
                        f"End-of-life software: {v['service']} {v.get('version', '')} on port {v['port']}"
                    )

        # 4. Web Security Headers & TLS (If available)
        if web_intel:
            for port, data in web_intel.items():
                if "http" in data:
                    sec_headers = data["http"].get("security_headers", {})
                    missing = [h for h, v in sec_headers.items() if v == "Missing"]
                    if missing:
                        score += len(missing) * 5
                        reasons.append(f"Port {port} missing security headers: {', '.join(missing)}")

                if "tls" in data:
                    tls_data = data["tls"]
                    if "error" in tls_data:
                        score += 10
                        reasons.append(f"Port {port} TLS configuration issue: {tls_data['error']}")
                    elif tls_data.get("expired", False):
                        score += 20
                        reasons.append(f"Port {port} TLS certificate is EXPIRED.")

        # Final classification
        score = min(score, 100)
        if score >= 70:
            risk_level = "High"
        elif score >= 30:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        if not reasons and open_ports:
            reasons.append("Monitoring recommended for open ports.")

        summary = RiskAnalyzer.risk_summary(risk_level, score, len(reasons), len(open_ports))
        return risk_level, reasons, score, summary

    @staticmethod
    def risk_summary(risk_level, score, reason_count, open_ports_count):
        if risk_level == "High":
            return f"CRITICAL: {score}/100. Immediate attention required. {reason_count} vulnerabilities/risks identified across {open_ports_count} exposed ports."
        elif risk_level == "Medium":
            return f"WARNING: {score}/100. Moderate risk. {reason_count} issues found that could be exploited if left unattended."
        else:
            return f"SAFE: {score}/100. Low risk profile. Routine monitoring advised."
