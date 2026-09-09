import asyncio

async def grab_banner(ip, port, timeout=2):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        
        if port in [80, 443, 8080]:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return data.decode('utf-8', errors='ignore').strip()
    except Exception:
        return ""
