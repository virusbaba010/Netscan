import asyncio
import ipaddress
import socket
from core.privilege_proxy import ScanProxy
from scanner.port_scan import port_scan
from fingerprint.mac_lookup import get_vendor
from fingerprint.service_detection import grab_banner
from fingerprint.geolocation import get_geolocation
from fingerprint.dns_intelligence import DNSIntelligence
from fingerprint.web_intelligence import run_web_intelligence
from iot_detection.iot_classifier import IoTClassifier
from risk_engine.risk_analysis import RiskAnalyzer
from utils.logger import logger
from utils.config import Config
from core.database import DatabaseManager

class Orchestrator:
    def __init__(self, target_network):
        self.target_network = target_network.strip()
        self.devices = []

    async def _resolve_domain(self, domain):
        cleaned = domain
        if '://' in cleaned:
            cleaned = cleaned.split('://', 1)[1]
        if '/' in cleaned:
            cleaned = cleaned.split('/', 1)[0]

        try:
            loop = asyncio.get_running_loop()
            info = await loop.getaddrinfo(cleaned, None, family=socket.AF_INET)
            return [info[0][4][0]]
        except (socket.gaierror, IndexError) as exc:
            raise ValueError(f"Invalid target format or unresolvable hostname: {self.target_network}") from exc

    async def _resolve_target(self):
        if not self.target_network or self.target_network.lower() in ['auto', 'lan']:
            auto_net = Config.get_local_network()
            if not auto_net:
                raise ValueError("Could not auto-detect local network.")
            self.target_network = auto_net

        if self.target_network.lower() == 'localhost':
            return ['127.0.0.1']

        try:
            net = ipaddress.ip_network(self.target_network, strict=False)
        except ValueError:
            try:
                ip = ipaddress.ip_address(self.target_network)
                return [str(ip)]
            except ValueError:
                return await self._resolve_domain(self.target_network)

        if net.num_addresses > Config.MAXIMUM_SCAN_HOSTS:
            raise ValueError(f"Network range too large to scan (max {Config.MAXIMUM_SCAN_HOSTS} hosts).")

        return [str(ip) for ip in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]

    async def scan_network(self, progress_callback=None):
        self.devices = []
        if progress_callback: progress_callback(5, "Resolving target...")
        ip_list = await self._resolve_target()

        if not ip_list:
            raise ValueError("No valid targets were resolved for scanning.")

        logger.info(f"Starting scan on {self.target_network} (Resolved {len(ip_list)} IPs)")
        if progress_callback: progress_callback(10, f"Running Discovery on {self.target_network}...")
        
        discovered_ips = {}
        
        # 1. Ping sweep first to find live IPs quickly
        if progress_callback: progress_callback(15, f"Running Ping Sweep on {len(ip_list)} IPs...")
        proxy = ScanProxy()
        active_ips = await proxy.run_ping_sweep(ip_list)
        
        if active_ips:
            if progress_callback: progress_callback(20, f"Running ARP Scan on {len(active_ips)} live IPs...")
            # 2. ARP scan ONLY the live IPs (broadcast only on live IP)
            basic_devices = await proxy.run_arp_scan(active_ips)
            for d in basic_devices:
                discovered_ips[d['ip']] = d['mac']
            
            # For any IP that replied to ping but not to ARP (e.g. routed)
            for ip in active_ips:
                if ip not in discovered_ips:
                    discovered_ips[ip] = "Unknown"

        # Override for single explicit targets (force port scan even if ping blocks)
        if len(ip_list) == 1 and ip_list[0] not in discovered_ips:
            discovered_ips[ip_list[0]] = "Unknown"
        
        devices_to_scan = [{'ip': ip, 'mac': mac} for ip, mac in discovered_ips.items()]
        
        # Identify if single domain was targeted
        is_single_domain = len(ip_list) == 1
        target_domain = self.target_network if is_single_domain else None
        
        # Populate active devices
        total = len(devices_to_scan)
        if total > 0:
            for i, dev in enumerate(devices_to_scan):
                if progress_callback: progress_callback(20 + int(80 * (i / total)), f"Analyzing {dev['ip']}...")
                dev_info = await self.analyze_device(dev, target_domain)
                dev_info["status"] = "Active"
                self.devices.append(dev_info)
        
        # Populate inactive/unreachable devices
        inactive_ips = [ip for ip in ip_list if ip not in discovered_ips]
        for ip in inactive_ips:
            self.devices.append({
                "ip": ip,
                "mac": "Unknown",
                "vendor": "Unknown",
                "open_ports": [],
                "banners": [],
                "os": "Unknown",
                "is_iot": False,
                "iot_reason": "",
                "risk_level": "None",
                "risk_reasons": [],
                "device_type": "Unreachable",
                "status": "Inactive"
            })
            
        if progress_callback: progress_callback(95, "Saving scan results...")
        try:
            db = DatabaseManager()
            db.save_scan(self.target_network, self.devices)
        except Exception as e:
            logger.error(f"Failed to save scan to database: {e}")
            
        if progress_callback: progress_callback(100, "Scan Complete")
        return self.devices

    def _prune_data(self, data):
        """Recursively removes null, empty lists/dicts, but keeps Unknown values"""
        if isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                pruned = self._prune_data(v)
                if pruned not in [None, "", {}, []]:
                    new_dict[k] = pruned
            return new_dict if new_dict else None
        elif isinstance(data, list):
            new_list = []
            for item in data:
                pruned = self._prune_data(item)
                if pruned not in [None, "", {}, []]:
                    new_list.append(pruned)
            return new_list if new_list else None
        else:
            if data in [None, ""]:
                return None
            return data

    async def analyze_device(self, dev, target_domain=None):
        ip = dev['ip']
        mac = dev['mac']
        
        vendor = await get_vendor(mac) if mac != "Unknown" else "Unknown"
        
        common_ports = list(set([21, 22, 23, 80, 443, 554, 1883, 3389, 8080] + Config.IOT_PORTS))
        open_ports = await port_scan(ip, common_ports)
        
        banners = []
        for p in open_ports:
            banner = await grab_banner(ip, p)
            banners.append(banner)
            
        proxy = ScanProxy()
        os_guess = await proxy.run_os_detect(ip, open_ports) if open_ports else "Unknown OS"
        
        is_iot, iot_reason = IoTClassifier.is_iot(vendor, open_ports, banners)
        
        # Run Web Intelligence for HTTP/TLS ports
        web_intel = {}
        web_tasks = [run_web_intelligence(ip, p) for p in open_ports if p in [80, 443, 8080, 8443]]
        if web_tasks:
            web_results = await asyncio.gather(*web_tasks)
            for p, result in zip([p for p in open_ports if p in [80, 443, 8080, 8443]], web_results):
                if result:
                    web_intel[p] = result
        
        risk_level, risk_reasons, risk_score, _risk_summary = await RiskAnalyzer.analyze(open_ports, banners, web_intel)
        
        dev_type = "IoT" if is_iot else "Standard"
        if risk_level == "High":
            dev_type += " (At-Risk)"
            
        geo_info = None
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private and not ip_obj.is_loopback:
                geo_info = await get_geolocation(ip)
        except:
            pass
            
        # Get DNS Intelligence (Domain if available, otherwise PTR for IP)
        dns_query_target = target_domain if target_domain else ip
        dns_info = await DNSIntelligence.get_dns_info(dns_query_target)
        
        # Build strict dynamic JSON schema
        raw_schema = {
            "ip": ip,
            "domain": dns_info.get("domain"),
            "status": "Active",
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_reasons": risk_reasons,
            "is_iot": is_iot,
            "iot_reason": iot_reason,
            "device_type": dev_type,
            "web_intelligence": web_intel,
            "network": {
                "isp": geo_info.get("isp") if geo_info else None,
                "asn": geo_info.get("as") if geo_info else None,
                "organization": geo_info.get("org") if geo_info else None,
                "ptr_record": dns_info.get("ptr_record")
            },
            "geo": {
                "country": geo_info.get("country") if geo_info else None,
                "region": geo_info.get("region") if geo_info else None,
                "city": geo_info.get("city") if geo_info else None,
                "lat": geo_info.get("lat") if geo_info else None,
                "lon": geo_info.get("lon") if geo_info else None
            },
            "dns": {
                "a_records": dns_info.get("a_records", []),
                "mx_records": dns_info.get("mx_records", []),
                "txt_records": dns_info.get("txt_records", []),
                "nameservers": dns_info.get("nameservers", [])
            },
            "device": {
                "open_ports": open_ports,
                "banners": banners,
                "os_guess": os_guess
            },
            "hardware": {
                "mac_address": mac,
                "vendor": vendor
            }
        }
        
        # Prune missing/unknown data entirely
        pruned_schema = self._prune_data(raw_schema)
        if not pruned_schema:
            pruned_schema = {"ip": ip, "status": "Active"}
            
        # Ensure 'status' is always top level for GUI dashboard stats logic
        pruned_schema["status"] = "Active"
        pruned_schema["ip"] = ip
        pruned_schema["risk_level"] = risk_level
        pruned_schema["risk_score"] = risk_score
        pruned_schema["is_iot"] = is_iot
            
        return pruned_schema
