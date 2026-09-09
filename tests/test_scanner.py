"""
Tests for the NetworkScanner (Orchestrator) — mocks all I/O to test scanning logic.
"""
import pytest
import asyncio
import sys
import os
from unittest.mock import AsyncMock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.orchestrator import Orchestrator


SAMPLE_DEVICE_RESULT = {
    "ip": "192.168.1.1",
    "status": "Active",
    "mac": "AA:BB:CC:DD:EE:01",
    "vendor": "Cisco",
    "device_type": "Router",
    "risk_level": "High",
    "risk_score": 80,
    "open_ports": [22, 80],
    "os": "Linux",
    "is_iot": False,
    "risk_reasons": ["Monitoring recommended"],
}


class TestOrchestratorResolveTarget:
    @pytest.mark.asyncio
    async def test_single_ip_resolves_correctly(self):
        o = Orchestrator("192.168.1.1")
        ips = await o._resolve_target()
        assert ips == ["192.168.1.1"]

    @pytest.mark.asyncio
    async def test_cidr_resolves_to_ip_list(self):
        o = Orchestrator("192.168.1.0/30")
        ips = await o._resolve_target()
        # /30 has 2 usable hosts
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    @pytest.mark.asyncio
    async def test_invalid_target_raises_value_error(self):
        o = Orchestrator("not_a_valid_host_!!!!")
        with pytest.raises(ValueError):
            await o._resolve_target()


@pytest.mark.asyncio
class TestScanNetwork:
    """Integration-style tests with all I/O mocked."""

    @patch("core.orchestrator.DatabaseManager")
    @patch("core.orchestrator.ScanProxy.run_ping_sweep", new_callable=AsyncMock)
    @patch("core.orchestrator.ScanProxy.run_arp_scan", new_callable=AsyncMock)
    @patch("core.orchestrator.Orchestrator.analyze_device", new_callable=AsyncMock)
    async def test_scan_calls_ping_and_arp(self, mock_analyze, mock_arp, mock_ping, mock_db):
        mock_ping.return_value = ["192.168.1.1"]
        mock_arp.return_value = [{"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01"}]
        mock_analyze.return_value = SAMPLE_DEVICE_RESULT
        mock_db.return_value.save_scan = MagicMock(return_value="2024-01-01T00:00:00")

        o = Orchestrator("192.168.1.1")
        devices = await o.scan_network()

        mock_ping.assert_called_once()
        mock_arp.assert_called_once()
        mock_analyze.assert_called_once()
        assert len(devices) == 1
        assert devices[0]["ip"] == "192.168.1.1"

    @patch("core.orchestrator.DatabaseManager")
    @patch("core.orchestrator.ScanProxy.run_ping_sweep", new_callable=AsyncMock)
    @patch("core.orchestrator.ScanProxy.run_arp_scan", new_callable=AsyncMock)
    async def test_no_active_hosts_returns_inactive_devices(self, mock_arp, mock_ping, mock_db):
        mock_ping.return_value = []   # no live IPs
        mock_arp.return_value = []
        mock_db.return_value.save_scan = MagicMock()

        o = Orchestrator("192.168.1.1")
        devices = await o.scan_network()

        # Single explicit target is still forced into device list as fallback
        assert any(d["ip"] == "192.168.1.1" for d in devices)

    @patch("core.orchestrator.DatabaseManager")
    @patch("core.orchestrator.ScanProxy.run_ping_sweep", new_callable=AsyncMock)
    @patch("core.orchestrator.ScanProxy.run_arp_scan", new_callable=AsyncMock)
    @patch("core.orchestrator.Orchestrator.analyze_device", new_callable=AsyncMock)
    async def test_progress_callback_is_called(self, mock_analyze, mock_arp, mock_ping, mock_db):
        mock_ping.return_value = ["192.168.1.1"]
        mock_arp.return_value = [{"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01"}]
        mock_analyze.return_value = SAMPLE_DEVICE_RESULT
        mock_db.return_value.save_scan = MagicMock()

        progress_calls = []
        def cb(pct, msg):
            progress_calls.append((pct, msg))

        o = Orchestrator("192.168.1.1")
        await o.scan_network(progress_callback=cb)

        assert len(progress_calls) > 0
        pcts = [p for p, _ in progress_calls]
        assert pcts[-1] == 100  # Should end at 100%


class TestPruneData:
    def test_prune_removes_none_values(self):
        o = Orchestrator("192.168.1.1")
        raw = {"a": None, "b": "valid", "c": {}}
        result = o._prune_data(raw)
        assert "a" not in result
        assert "b" in result
        assert "c" not in result

    def test_prune_keeps_valid_nested(self):
        o = Orchestrator("192.168.1.1")
        raw = {"device": {"open_ports": [80], "os_guess": "Linux"}}
        result = o._prune_data(raw)
        assert result["device"]["open_ports"] == [80]

    def test_prune_removes_empty_lists(self):
        o = Orchestrator("192.168.1.1")
        raw = {"ports": [], "ip": "192.168.1.1"}
        result = o._prune_data(raw)
        assert "ports" not in result
        assert result["ip"] == "192.168.1.1"
