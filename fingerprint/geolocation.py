import aiohttp
import asyncio
from datetime import datetime

_geo_cache = {}
_geo_semaphore = asyncio.Semaphore(10)
_last_request_time = datetime.min
_rate_limit_lock = asyncio.Lock()

async def get_geolocation(ip):
    # Private IPs or loopback
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip.startswith("127."):
        return None

    if ip in _geo_cache:
        return _geo_cache[ip]

    async with _geo_semaphore:
        # Rate limit to ~1.4 seconds between requests for ip-api.com (45/min limit)
        global _last_request_time
        async with _rate_limit_lock:
            now = datetime.now()
            time_since_last = (now - _last_request_time).total_seconds()
            if time_since_last < 1.4:
                await asyncio.sleep(1.4 - time_since_last)
            _last_request_time = datetime.now()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://ip-api.com/json/{ip}", timeout=3) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("status") == "success":
                            result = {
                                "city": data.get("city", "Unknown"),
                                "region": data.get("regionName", "Unknown"),
                                "country": data.get("country", "Unknown"),
                                "org": data.get("org", "Unknown"),
                                "lat": data.get("lat", 0.0),
                                "lon": data.get("lon", 0.0)
                            }
                            _geo_cache[ip] = result
                            return result
        except Exception:
            pass
            
    return None
