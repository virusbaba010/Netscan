import asyncio
import subprocess
import platform
from scapy.all import IP, ICMP, sr

def scapy_ping_sweep(ip_list):
    try:
        # Batch send ICMP packets
        packets = [IP(dst=ip)/ICMP() for ip in ip_list]
        ans, _ = sr(packets, timeout=1.5, verbose=0)
        return [res[1].src for res in ans]
    except Exception:
        return None

async def ping_ip(ip):
    sys_name = platform.system().lower()
    if sys_name == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    elif sys_name == "darwin":
        cmd = ["ping", "-c", "1", "-W", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        await proc.wait()
        return ip if proc.returncode == 0 else None
    except Exception:
        return None

async def ping_sweep(ip_list, max_concurrency=20):
    loop = asyncio.get_running_loop()
    
    # 1. Try Scapy batch ping (Requires root, Extremely Fast)
    if ip_list:
        scapy_result = await loop.run_in_executor(None, scapy_ping_sweep, ip_list)
        if scapy_result is not None:
            return scapy_result

    # 2. Fallback to throttled subprocess ping (No root, Slower)
    sem = asyncio.Semaphore(max_concurrency)
    
    async def _throttled_ping(ip):
        async with sem:
            return await ping_ip(ip)
            
    tasks = [_throttled_ping(ip) for ip in ip_list]
    results = await asyncio.gather(*tasks)
    return [ip for ip in results if ip is not None]
