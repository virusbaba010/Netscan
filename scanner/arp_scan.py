import warnings
from scapy.all import ARP, Ether, srp
import asyncio

# Suppress Scapy warnings about MAC address resolution when hosts do not answer ARP
warnings.filterwarnings("ignore", message="Mac address to reach destination not found.*")

async def arp_scan(ip_range, timeout=2):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync_arp_scan, ip_range, timeout)

def _sync_arp_scan(ip_range, timeout):
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result, _ = srp(packet, timeout=timeout, verbose=0)
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        return devices
    except Exception as e:
        print(f"ARP scan error (try running as root?): {e}")
        return []
