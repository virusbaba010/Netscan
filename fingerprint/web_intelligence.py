import asyncio
import aiohttp
import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from functools import lru_cache

async def get_http_intelligence(ip, port):
    """Performs deep HTTP analysis to extract headers and server info."""
    url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}:{port}"
    timeout = aiohttp.ClientTimeout(total=5)
    
    headers_to_check = [
        "Server", "X-Powered-By", "Strict-Transport-Security", 
        "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"
    ]
    
    intel = {
        "server": "Unknown",
        "technologies": [],
        "security_headers": {},
        "is_https": port == 443
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Netscan/2.0"
    }
    
    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as session:
            async with session.get(url, headers=headers) as response:
                intel["server"] = response.headers.get("Server", "Unknown")
                tech = response.headers.get("X-Powered-By")
                if tech:
                    intel["technologies"].append(tech)
                
                for header in headers_to_check[2:]:
                    intel["security_headers"][header] = response.headers.get(header, "Missing")
    except Exception as e:
        intel["error"] = str(e)
        
    return intel

@lru_cache(maxsize=128)
def get_tls_intelligence(ip, port=443):
    """Extracts SSL/TLS certificate information using cryptography."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    tls_info = {
        "issuer": "Unknown",
        "subject": "Unknown",
        "expiry": "Unknown",
        "expired": False,
        "cipher": "Unknown",
        "version": "Unknown"
    }
    
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                tls_info["cipher"] = cipher[0] if cipher else "Unknown"
                tls_info["version"] = ssock.version()
                
                if der_cert:
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    # Extract common name from subject
                    subject_cn = next((attr.value for attr in cert.subject if attr.oid == x509.NameOID.COMMON_NAME), "Unknown")
                    issuer_cn = next((attr.value for attr in cert.issuer if attr.oid == x509.NameOID.COMMON_NAME), "Unknown")
                    
                    tls_info["subject"] = subject_cn
                    tls_info["issuer"] = issuer_cn
                    
                    not_valid_after = cert.not_valid_after_utc
                    tls_info["expiry"] = not_valid_after.isoformat()
                    tls_info["expired"] = datetime.now(timezone.utc) > not_valid_after
                    
                    tls_info["details"] = f"Subject: {subject_cn}, Issuer: {issuer_cn}, Protocol: {ssock.version()}"
    except Exception as e:
        tls_info["error"] = str(e)
        
    return tls_info

async def run_web_intelligence(ip, port):
    """Orchestrates both HTTP and TLS intelligence."""
    results = {}
    if port in [80, 443, 8080, 8443]:
        results["http"] = await get_http_intelligence(ip, port)
        if port in [443, 8443]:
            # Run TLS check in threadpool since ssl/socket is blocking
            loop = asyncio.get_event_loop()
            results["tls"] = await loop.run_in_executor(None, get_tls_intelligence, ip, port)
    return results
