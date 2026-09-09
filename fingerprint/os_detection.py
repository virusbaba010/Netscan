import asyncio
import subprocess
import platform
import re
from scapy.all import IP, TCP, sr1

def native_tcp_fingerprint(ip, port=80):
    try:
        # Send TCP SYN packet
        pkt = IP(dst=ip)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1.5, verbose=0)
        
        if resp and resp.haslayer(TCP) and resp.haslayer(IP):
            ttl = resp[IP].ttl
            window = resp[TCP].window
            
            # Improved Fingerprinting Heuristics
            if ttl <= 64:
                if window in [65535, 4128]:
                    return "macOS/iOS (Native TCP)"
                elif window in [5840, 5720, 14600, 28960, 29200]:
                    return "Linux 2.4.x-6.x (Native TCP)"
                elif window in [8192]:
                    return "FreeBSD/OpenBSD (Native TCP)"
                return "Linux/Unix (Native TCP)"
            elif ttl <= 128:
                if window in [8192, 16384, 64240, 65535]:
                    return "Windows Server/10/11 (Native TCP)"
                elif window in [1024, 2048, 4096]:
                    return "Windows (Legacy) (Native TCP)"
                return "Windows (Native TCP)"
            elif ttl <= 255:
                if window in [4128, 8760, 16384]:
                    return "Cisco/Network Appliance (Native TCP)"
                return "Solaris/AIX/Network Appliance (Native TCP)"
    except Exception:
        pass
    return None

def get_os_from_ttl(ip):
    try:
        sys_name = platform.system().lower()
        if sys_name == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        elif sys_name == "darwin":
            cmd = ["ping", "-c", "1", "-W", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
            
        output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
        
        # Extract TTL
        match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:
                return "Linux/Unix/macOS (Ping TTL)"
            elif ttl <= 128:
                return "Windows (Ping TTL)"
            else:
                return "Network/Appliance (Ping TTL)"
    except Exception:
        pass
    return "Unknown OS"

def sync_os_detect(ip, open_ports=None):
    # 1. Try Native Active Probing (Fastest, requires root)
    if open_ports:
        for port in open_ports[:2]: # Try top 2 open ports
            os_guess = native_tcp_fingerprint(ip, port)
            if os_guess: return os_guess
            
    # 2. Try Nmap (Comprehensive but slow/external)
    try:
        import nmap
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-O -T4 --osscan-limit --max-os-tries 1")
        if ip in nm.all_hosts() and 'osmatch' in nm[ip] and nm[ip]['osmatch']:
            return nm[ip]['osmatch'][0]['name']
    except (subprocess.CalledProcessError, FileNotFoundError, ImportError):
        pass
    except Exception:
        pass
        
    # 3. Fallback to Ping TTL (Slowest, subprocess based)
    return get_os_from_ttl(ip)

async def detect_os(ip, open_ports=None):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, sync_os_detect, ip, open_ports)
