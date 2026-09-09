from mac_vendor_lookup import AsyncMacLookup

async def get_vendor(mac):
    try:
        lookup = AsyncMacLookup()
        return await lookup.lookup(mac)
    except Exception:
        return "Unknown"
