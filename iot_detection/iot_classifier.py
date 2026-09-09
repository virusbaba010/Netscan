from utils.config import Config

class IoTClassifier:
    @staticmethod
    def is_iot(vendor, open_ports, banners):
        if vendor and any(v.lower() in vendor.lower() for v in Config.IOT_MAC_OUI):
            return True, "IoT Vendor Match"
        
        for port in open_ports:
            if port in [1883, 554]:
                return True, f"IoT Port {port} Open"
                
        for banner in banners:
            if banner and ("mqtt" in banner.lower() or "rtsp" in banner.lower() or "camera" in banner.lower()):
                return True, "IoT Protocol/Banner Detected"
                
        return False, "Not classified as IoT"
