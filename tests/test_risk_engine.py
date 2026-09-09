"""
Tests for RiskAnalyzer — covers scoring logic, CVE matching, and TLS/header analysis.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from risk_engine.risk_analysis import RiskAnalyzer


class TestRiskSummary:
    def test_high_risk_summary(self):
        summary = RiskAnalyzer.risk_summary("High", 85, 4, 6)
        assert "CRITICAL" in summary
        assert "85/100" in summary

    def test_medium_risk_summary(self):
        summary = RiskAnalyzer.risk_summary("Medium", 45, 2, 3)
        assert "WARNING" in summary
        assert "45/100" in summary

    def test_low_risk_summary(self):
        summary = RiskAnalyzer.risk_summary("Low", 5, 0, 1)
        assert "SAFE" in summary


@pytest.mark.asyncio
class TestRiskAnalyzer:
    async def test_no_ports_is_low_risk(self):
        level, reasons, score, summary = await RiskAnalyzer.analyze([], [])
        assert level == "Low"
        assert score == 0

    async def test_telnet_port_is_high_risk(self):
        """Port 23 (Telnet) should contribute 70 points → High risk."""
        level, reasons, score, summary = await RiskAnalyzer.analyze([23], [""])
        assert score >= 70
        assert level == "High"
        assert any("Telnet" in r for r in reasons)

    async def test_ftp_is_medium_or_high(self):
        """Port 21 (FTP) contributes 50 points → Medium or High."""
        level, reasons, score, summary = await RiskAnalyzer.analyze([21], [""])
        assert score >= 50
        assert level in ("Medium", "High")

    async def test_score_capped_at_100(self):
        """Multiple high-risk ports should not push score above 100."""
        ports = [21, 23, 3389, 445, 69]
        level, reasons, score, summary = await RiskAnalyzer.analyze(ports, [""] * 5)
        assert score <= 100
        assert level == "High"

    async def test_missing_security_headers_adds_score(self):
        web_intel = {
            80: {
                "http": {
                    "security_headers": {
                        "Strict-Transport-Security": "Missing",
                        "Content-Security-Policy": "Missing",
                        "X-Frame-Options": "Missing",
                    }
                }
            }
        }
        _, reasons, score, _ = await RiskAnalyzer.analyze([], [], web_intel=web_intel)
        assert score >= 15  # 3 headers × 5 pts
        assert any("security headers" in r for r in reasons)

    async def test_expired_tls_adds_score(self):
        web_intel = {
            443: {
                "tls": {"expired": True, "subject": "example.com"}
            }
        }
        _, reasons, score, _ = await RiskAnalyzer.analyze([], [], web_intel=web_intel)
        assert score >= 20
        assert any("EXPIRED" in r for r in reasons)

    async def test_tls_error_adds_score(self):
        web_intel = {
            443: {
                "tls": {"error": "CERTIFICATE_VERIFY_FAILED"}
            }
        }
        _, reasons, score, _ = await RiskAnalyzer.analyze([], [], web_intel=web_intel)
        assert score >= 10

    async def test_safe_device_monitoring_reason(self):
        """A device with only safe ports should still get a monitoring reminder."""
        level, reasons, score, _ = await RiskAnalyzer.analyze([80, 443], ["Apache", ""])
        if level == "Low":
            assert any("Monitoring" in r for r in reasons)

    async def test_banner_vsftpd_backdoor(self):
        """Known backdoor banner should be detected by CVEMatcher heuristics."""
        level, reasons, score, _ = await RiskAnalyzer.analyze(
            [21], ["220 (vsFTPd 2.3.4)"]
        )
        assert any("CVE-2011-2523" in r or "vsftpd" in r.lower() for r in reasons)
