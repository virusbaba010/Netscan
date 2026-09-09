"""
Tests for fingerprint modules — OS detection heuristics and TLS parsing.
"""
import pytest
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fingerprint.os_detection import native_tcp_fingerprint, get_os_from_ttl
from fingerprint.web_intelligence import get_tls_intelligence


class TestNativeTcpFingerprint:
    """Test TTL + window size heuristics without live network traffic."""

    def _make_mock_response(self, ttl, window):
        """Build a Scapy-like mock packet."""
        resp = MagicMock()
        resp.haslayer.side_effect = lambda layer: layer.__name__ in ("TCP", "IP")
        resp.__getitem__ = lambda self, layer: MagicMock(ttl=ttl, window=window)
        return resp

    @patch("fingerprint.os_detection.sr1")
    def test_linux_fingerprint(self, mock_sr1):
        mock_resp = MagicMock()
        mock_resp.haslayer.return_value = True
        mock_resp.__getitem__.side_effect = lambda cls: MagicMock(ttl=64, window=29200)
        mock_sr1.return_value = mock_resp

        result = native_tcp_fingerprint("192.168.1.1", port=80)
        assert result is not None
        assert "Linux" in result or "Unix" in result or "macOS" in result

    @patch("fingerprint.os_detection.sr1")
    def test_windows_fingerprint(self, mock_sr1):
        mock_resp = MagicMock()
        mock_resp.haslayer.return_value = True
        mock_resp.__getitem__.side_effect = lambda cls: MagicMock(ttl=128, window=64240)
        mock_sr1.return_value = mock_resp

        result = native_tcp_fingerprint("192.168.1.1", port=80)
        assert result is not None
        assert "Windows" in result

    @patch("fingerprint.os_detection.sr1")
    def test_no_response_returns_none(self, mock_sr1):
        mock_sr1.return_value = None
        result = native_tcp_fingerprint("192.168.1.1", port=80)
        assert result is None

    @patch("fingerprint.os_detection.sr1")
    def test_exception_returns_none(self, mock_sr1):
        mock_sr1.side_effect = PermissionError("Need root")
        result = native_tcp_fingerprint("192.168.1.1", port=80)
        assert result is None


class TestPingTTLFallback:
    @patch("fingerprint.os_detection.subprocess.check_output")
    def test_linux_ttl(self, mock_sub):
        mock_sub.return_value = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=64 time=5ms"
        result = get_os_from_ttl("1.1.1.1")
        assert "Linux" in result or "Unix" in result

    @patch("fingerprint.os_detection.subprocess.check_output")
    def test_windows_ttl(self, mock_sub):
        mock_sub.return_value = "Reply from 1.1.1.1: bytes=32 time=10ms TTL=128"
        result = get_os_from_ttl("1.1.1.1")
        assert "Windows" in result

    @patch("fingerprint.os_detection.subprocess.check_output")
    def test_exception_returns_unknown(self, mock_sub):
        mock_sub.side_effect = Exception("Ping failed")
        result = get_os_from_ttl("1.1.1.1")
        assert result == "Unknown OS"


class TestTLSIntelligence:
    @patch("fingerprint.web_intelligence.socket.create_connection")
    def test_tls_socket_error_returns_error_key(self, mock_conn):
        mock_conn.side_effect = ConnectionRefusedError("No TLS listener")
        # lru_cache can store results; use a unique IP per test
        result = get_tls_intelligence("10.255.255.255", 9999)
        assert "error" in result

    def test_tls_result_has_required_keys(self):
        """Validate that the TLS result dict always has all expected fields."""
        with patch("fingerprint.web_intelligence.socket.create_connection") as mock_conn:
            mock_conn.side_effect = OSError("Network error")
            result = get_tls_intelligence("10.255.255.254", 8443)
        required_keys = {"issuer", "subject", "expiry", "expired", "cipher", "version"}
        assert required_keys.issubset(result.keys())
