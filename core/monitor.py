"""
Continuous Monitoring Engine — periodically scans the network and emits
change events (new device, device gone, new high-risk port) via asyncio.

Usage:
    from core.monitor import NetworkMonitor
    monitor = NetworkMonitor("192.168.1.0/24", interval=300, callback=on_change)
    asyncio.create_task(monitor.start())
"""
import asyncio
import logging
from datetime import datetime
from core.orchestrator import Orchestrator

logger = logging.getLogger("netscan.monitor")


class NetworkMonitor:
    """Continuously scans a network and reports changes between scans."""

    def __init__(self, target: str, interval: int = 300, callback=None):
        """
        Args:
            target:    Network CIDR or IP to monitor (e.g. "192.168.1.0/24").
            interval:  Seconds between scans (default 5 minutes).
            callback:  Async or sync callable that receives (event_type, data).
                       event_type: "new_device" | "device_gone" | "new_risk_port" | "scan_complete"
        """
        self.target = target
        self.interval = interval
        self.callback = callback
        self._running = False
        self._known_devices: dict[str, dict] = {}  # ip → device dict

    async def start(self):
        """Main monitoring loop. Call asyncio.create_task(monitor.start()) to run it."""
        self._running = True
        logger.info(f"[Monitor] Starting continuous monitoring on {self.target} every {self.interval}s.")
        
        while self._running:
            try:
                await self._scan_and_diff()
            except Exception as e:
                logger.error(f"[Monitor] Scan error: {e}")
            await asyncio.sleep(self.interval)

    def stop(self):
        """Signal the monitoring loop to stop after the next sleep cycle."""
        self._running = False
        logger.info("[Monitor] Monitoring stopped.")

    async def _scan_and_diff(self):
        orchestrator = Orchestrator(self.target)
        devices = await orchestrator.scan_network()
        now = datetime.now().isoformat(timespec="seconds")

        active_devices = {d["ip"]: d for d in devices if d.get("status") == "Active"}

        # New devices
        for ip, dev in active_devices.items():
            if ip not in self._known_devices:
                logger.info(f"[Monitor] NEW DEVICE: {ip} ({dev.get('vendor', 'Unknown')})")
                await self._emit("new_device", {
                    "ip": ip,
                    "vendor": dev.get("vendor", "Unknown"),
                    "device_type": dev.get("device_type", "Unknown"),
                    "risk_level": dev.get("risk_level", "Low"),
                    "timestamp": now,
                })

        # Devices that disappeared
        for ip in list(self._known_devices.keys()):
            if ip not in active_devices:
                logger.info(f"[Monitor] DEVICE GONE: {ip}")
                await self._emit("device_gone", {
                    "ip": ip,
                    "last_seen": self._known_devices[ip].get("last_seen", "Unknown"),
                    "timestamp": now,
                })

        # Risk-level changes or new high-risk ports
        for ip, dev in active_devices.items():
            if ip in self._known_devices:
                old = self._known_devices[ip]
                old_ports = set(old.get("device", {}).get("open_ports", old.get("open_ports", [])))
                new_ports = set(dev.get("device", {}).get("open_ports", dev.get("open_ports", [])))
                new_open = new_ports - old_ports
                if new_open:
                    logger.info(f"[Monitor] NEW PORTS on {ip}: {new_open}")
                    await self._emit("new_risk_port", {
                        "ip": ip,
                        "new_ports": list(new_open),
                        "risk_level": dev.get("risk_level", "Low"),
                        "timestamp": now,
                    })

        # Update known state
        for ip, dev in active_devices.items():
            dev["last_seen"] = now
            self._known_devices[ip] = dev

        await self._emit("scan_complete", {
            "target": self.target,
            "active_count": len(active_devices),
            "timestamp": now,
        })

    async def _emit(self, event_type: str, data: dict):
        if not self.callback:
            return
        try:
            if asyncio.iscoroutinefunction(self.callback):
                await self.callback(event_type, data)
            else:
                self.callback(event_type, data)
        except Exception as e:
            logger.error(f"[Monitor] Callback error for {event_type}: {e}")
