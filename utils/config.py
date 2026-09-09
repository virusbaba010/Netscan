import os
import logging
import socket
import ipaddress
import yaml

class Config:
    # Defaults
    LOG_LEVEL = logging.INFO
    TIMEOUT = 2
    MAX_THREADS = 100
    MAXIMUM_SCAN_HOSTS = 65536
    RATE_LIMIT_PER_MINUTE = 45
    SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    EXCLUDE_IPS = []
    IOT_PORTS = [554, 1883, 8080, 80, 443, 37777, 8000, 34567, 81, 82]
    IOT_MAC_OUI = ["Espressif", "Raspberry Pi", "Tuya", "Sonoff", "Amazon", "Google", "Ring", "Dahua", "Hikvision", "Axis", "Panasonic", "Sony"]
    
    # Threat Intelligence
    ABUSEIPDB_KEY: str = ""
    
    # Port Scanning Profiles
    SCAN_PROFILES: dict = {
        "Top 20 (Default)": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443],
        "Web Only": [80, 443, 8080, 8443],
        "Databases Only": [1433, 1521, 3306, 5432, 5984, 6379, 27017, 27018, 27019],
        "SSH & Remote": [22, 23, 3389, 5900, 5901, 5902],
        "Top 100 Common": [21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 194, 443, 445, 465, 587, 631, 993, 995, 1080, 1194, 1433, 1521, 1723, 2082, 2083, 2181, 2483, 2484, 3000, 3306, 3389, 4848, 5000, 5432, 5900, 5984, 6379, 7001, 7002, 8080, 8181, 8443, 8888, 9000, 9042, 9092, 9200, 9300, 10000, 11211, 27017, 27018, 28017, 50000],
    }
    ACTIVE_SCAN_PROFILE: str = "Top 20 (Default)"
    
    # Continuous Monitoring
    MONITOR_INTERVAL: int = 300  # seconds
    WHOIS_ENABLED: bool = True

    @classmethod
    def load(cls):
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "netscan_config.yaml")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    data = yaml.safe_load(f)
                    if data:
                        core = data.get('core', {})
                        if 'log_level' in core:
                            level = core.get('log_level').upper()
                            cls.LOG_LEVEL = getattr(logging, level, logging.INFO)
                        if 'timeout' in core: cls.TIMEOUT = core.get('timeout')
                        if 'max_threads' in core: cls.MAX_THREADS = core.get('max_threads')
                        if 'maximum_scan_hosts' in core: cls.MAXIMUM_SCAN_HOSTS = core.get('maximum_scan_hosts')
                        if 'rate_limit_per_minute' in core: cls.RATE_LIMIT_PER_MINUTE = core.get('rate_limit_per_minute')
                        
                        scanner = data.get('scanner', {})
                        if 'ports' in scanner and scanner['ports']: cls.SCAN_PORTS = scanner.get('ports')
                        if 'exclude_ips' in scanner and scanner['exclude_ips']: cls.EXCLUDE_IPS = scanner.get('exclude_ips')
                        
                        # Custom scan profiles override
                        profiles = scanner.get('profiles', {})
                        if profiles:
                            cls.SCAN_PROFILES.update(profiles)
                        if 'active_profile' in scanner:
                            cls.ACTIVE_SCAN_PROFILE = scanner['active_profile']

                        iot = data.get('iot', {})
                        if 'ports' in iot and iot['ports']: cls.IOT_PORTS = iot.get('ports')
                        if 'mac_oui' in iot and iot['mac_oui']: cls.IOT_MAC_OUI = iot.get('mac_oui')
                        
                        # Threat Intelligence
                        threat = data.get('threat_intel', {})
                        if 'abuseipdb_key' in threat: cls.ABUSEIPDB_KEY = threat.get('abuseipdb_key', '')
                        
                        # Continuous Monitoring
                        monitor = data.get('monitoring', {})
                        if 'interval' in monitor: cls.MONITOR_INTERVAL = monitor.get('interval', 300)
                        
                        # WHOIS
                        enrichment = data.get('enrichment', {})
                        if 'whois_enabled' in enrichment: cls.WHOIS_ENABLED = enrichment.get('whois_enabled', True)
            except Exception as e:
                print(f"[!] Error loading config: {e}")

    @staticmethod
    def get_local_network():
        """Try to determine the active local IPv4 network and return it as a CIDR string."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            IP = s.getsockname()[0]
        except Exception:
            IP = None
        finally:
            s.close()

        if not IP or IP == '127.0.0.1':
            try:
                hostname = socket.gethostname()
                IP = socket.gethostbyname(hostname)
            except Exception:
                IP = None

        if IP and IP != '127.0.0.1':
            try:
                net = ipaddress.IPv4Network(f"{IP}/24", strict=False)
                return str(net)
            except Exception:
                return None

        return None

# Auto-load config on import
Config.load()
