import dns.resolver
import dns.reversename
import socket
import asyncio

class DNSIntelligence:
    @staticmethod
    async def get_dns_info(target):
        # Target could be IP or Domain
        info = {
            "a_records": [],
            "mx_records": [],
            "txt_records": [],
            "nameservers": [],
            "ptr_record": None,
            "domain": None
        }
        
        # Run blocking DNS resolutions in a thread to prevent freezing
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, DNSIntelligence._sync_get_dns_info, target, info)
        
    @staticmethod
    def _sync_get_dns_info(target, info):
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False
            
        try:
            if is_ip:
                try:
                    rev_name = dns.reversename.from_address(target)
                    ans = dns.resolver.resolve(rev_name, "PTR")
                    info["ptr_record"] = str(ans[0]).rstrip('.')
                except Exception: pass
            else:
                info["domain"] = target
                # Get A records
                try:
                    for r in dns.resolver.resolve(target, "A"):
                        info["a_records"].append(str(r))
                except Exception: pass
                
                # Get MX records
                try:
                    for r in dns.resolver.resolve(target, "MX"):
                        info["mx_records"].append(str(r.exchange).rstrip('.'))
                except Exception: pass
                
                # Get TXT records
                try:
                    for r in dns.resolver.resolve(target, "TXT"):
                        info["txt_records"].append(str(r).strip('"'))
                except Exception: pass
                
                # Get NS records
                try:
                    for r in dns.resolver.resolve(target, "NS"):
                        info["nameservers"].append(str(r).rstrip('.'))
                except Exception: pass
        except Exception:
            pass
            
        return info
