"""
Privilege Separation Layer for Netscan.

Solves the fundamental security problem: Scapy/raw-socket operations require
root/Administrator privileges, but the entire PyQt6 GUI should NOT run as root.

Architecture:
  ┌─────────────────────┐        Unix Socket / subprocess pipe
  │  UI Process (unprivileged) │ ──────────────────────────────────►
  └─────────────────────┘                                           │
                                                                    ▼
                                                    ┌──────────────────────────┐
                                                    │  scan_worker.py (elevated) │
                                                    │  Runs: ARP, SYN scan       │
                                                    └──────────────────────────┘

The UI process calls ScanProxy, which:
  1. Detects whether it has raw socket privileges.
  2. If YES → runs scan inline (dev environment / already elevated).
  3. If NO  → spawns `core/scan_worker.py` via subprocess using `sudo -n`
              (or `pkexec` on Linux, `osascript` on macOS) and communicates
              via stdin/stdout JSON-lines protocol.

Usage (in orchestrator or UI):
    from core.privilege_proxy import ScanProxy
    proxy = ScanProxy()
    result = await proxy.run_arp_scan(ip_list)
"""
import asyncio
import json
import logging
import os
import sys
import socket

logger = logging.getLogger("netscan.privilege")


def _has_raw_socket_privilege() -> bool:
    """Return True if the process can open raw sockets (root / CAP_NET_RAW)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return True
    except PermissionError:
        return False
    except Exception:
        return False


class ScanProxy:
    """
    Transparent proxy for privileged network operations.

    Automatically delegates to an elevated subprocess when the current process
    lacks raw-socket privileges. Falls back to safe unprivileged methods
    (TCP connect scan, standard ICMP via subprocess ping) when elevation fails.
    """

    def __init__(self):
        self.is_privileged = _has_raw_socket_privilege()
        if self.is_privileged:
            logger.info("[ScanProxy] Running with raw-socket privileges (inline mode).")
        else:
            logger.warning(
                "[ScanProxy] No raw-socket privilege detected. "
                "ARP/SYN scans will delegate to elevated subprocess."
            )

    async def run_arp_scan(self, ip_list: list[str]) -> list[dict]:
        """
        Run ARP discovery on the given IP list.
        Returns: [{"ip": ..., "mac": ...}, ...]
        """
        if self.is_privileged:
            from scanner.arp_scan import arp_scan
            return await arp_scan(ip_list)
        else:
            return await self._delegate("arp_scan", {"ip_list": ip_list})

    async def run_ping_sweep(self, ip_list: list[str]) -> list[str]:
        """
        ICMP ping sweep. Falls back to subprocess ping when unprivileged.
        Returns: [active_ip, ...]
        """
        if self.is_privileged:
            from scanner.ping_sweep import ping_sweep
            return await ping_sweep(ip_list)
        else:
            # Unprivileged fallback: parallel subprocess pings
            return await self._unprivileged_ping_sweep(ip_list)

    async def run_port_scan(self, ip: str, ports: list[int]) -> list[int]:
        """
        TCP connect port scan. Does NOT need elevated privileges.
        Always runs inline.
        """
        from scanner.port_scan import port_scan
        return await port_scan(ip, ports)

    async def run_os_detect(self, ip: str, open_ports: list[int]) -> str:
        """
        OS Detection. Requires raw sockets for native TCP fingerprinting.
        Delegates if unprivileged.
        """
        if self.is_privileged:
            from fingerprint.os_detection import detect_os
            return await detect_os(ip, open_ports)
        else:
            result = await self._delegate("os_detect", {"ip": ip, "open_ports": open_ports})
            # _delegate returns parsed JSON, which for os_detect is a string or empty list on failure
            if isinstance(result, str):
                return result
            return "Unknown OS"

    # ─── Unprivileged fallbacks ───────────────────────────────────────────────

    async def _unprivileged_ping_sweep(self, ip_list: list[str], max_concurrency: int = 50) -> list[str]:
        """Ping each IP via subprocess (no raw socket needed)."""
        sem = asyncio.Semaphore(max_concurrency)
        active = []

        async def ping_one(ip):
            async with sem:
                try:
                    flag = "-c" if sys.platform != "win32" else "-n"
                    proc = await asyncio.create_subprocess_exec(
                        "ping", flag, "1", "-W", "1", ip,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await asyncio.wait_for(proc.wait(), timeout=3)
                    if proc.returncode == 0:
                        active.append(ip)
                except Exception:
                    pass

        await asyncio.gather(*[ping_one(ip) for ip in ip_list])
        return active

    # ─── Elevated subprocess delegation ──────────────────────────────────────

    async def _delegate(self, command: str, args: dict) -> list | str:
        """
        Spawn `core/scan_worker.py` as an elevated subprocess and communicate
        via temporary JSON files to bypass osascript piping limitations.
        """
        import tempfile
        import shutil

        worker_path = os.path.join(os.path.dirname(__file__), "scan_worker.py")
        payload = json.dumps({"command": command, "args": args})

        in_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w")
        in_file.write(payload)
        in_file.close()

        out_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        out_file.close()

        elevate_cmd = self._build_elevate_command(worker_path, in_file.name, out_file.name)
        if not elevate_cmd:
            logger.error("[ScanProxy] No elevation method available. Cannot run privileged scan.")
            os.unlink(in_file.name)
            os.unlink(out_file.name)
            return []

        try:
            proc = await asyncio.create_subprocess_exec(
                *elevate_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=120,
            )
            if proc.returncode != 0:
                logger.error(f"[ScanProxy] Worker exited with code {proc.returncode}: {stderr.decode()[:200]}")
                return []
            
            with open(out_file.name, "r") as f:
                result_raw = f.read().strip()
                if not result_raw:
                    return []
                result = json.loads(result_raw)
            return result
        except asyncio.TimeoutError:
            logger.error("[ScanProxy] Elevated worker timed out.")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"[ScanProxy] JSON parse error from worker: {e}")
            return []
        except Exception as e:
            logger.error(f"[ScanProxy] Delegate error: {e}")
            return []
        finally:
            if os.path.exists(in_file.name): os.unlink(in_file.name)
            if os.path.exists(out_file.name): os.unlink(out_file.name)

    def _build_elevate_command(self, worker_path: str, in_file: str, out_file: str) -> list[str] | None:
        """Build the OS-appropriate elevation command."""
        python = sys.executable
        worker_args = f"--input {in_file} --output {out_file}"

        if sys.platform == "darwin":
            # macOS: use osascript to prompt for password graphically
            script = f'do shell script "\\"{python}\\" \\"{worker_path}\\" {worker_args}" with administrator privileges'
            return ["osascript", "-e", script]

        elif sys.platform.startswith("linux"):
            # Linux: try pkexec first (GUI), then sudo -n (non-interactive)
            if self._cmd_exists("pkexec"):
                return ["pkexec", python, worker_path, "--input", in_file, "--output", out_file]
            elif self._cmd_exists("sudo"):
                return ["sudo", "-n", python, worker_path, "--input", in_file, "--output", out_file]

        elif sys.platform == "win32":
            # Windows: runas — limited support
            return ["runas", "/noprofile", "/user:Administrator", f"{python} {worker_path} {worker_args}"]

        return None

    @staticmethod
    def _cmd_exists(cmd: str) -> bool:
        import shutil
        return shutil.which(cmd) is not None
