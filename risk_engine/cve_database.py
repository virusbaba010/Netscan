import sqlite3
import os
import re

class CVEDatabase:
    def __init__(self):
        self.db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cve_database.db")
        self._init_db()
        self._seed_data()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                software TEXT,
                version TEXT,
                summary TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def _seed_data(self):
        # A small initial seed of high-impact CVEs for common services
        seed = [
            ("CVE-2011-2523", "vsftpd", "2.3.4", "vsftpd 2.3.4 backdoor"),
            ("CVE-2021-41773", "apache", "2.4.49", "Path traversal and file disclosure vulnerability in Apache 2.4.49"),
            ("CVE-2021-42013", "apache", "2.4.50", "Path traversal and file disclosure vulnerability in Apache 2.4.50"),
            ("CVE-2017-7659", "apache", "2.4.24", "mod_http2 NULL pointer dereference"),
            ("CVE-2014-0160", "openssl", "1.0.1", "Heartbleed: Information disclosure vulnerability in OpenSSL"),
            ("CVE-2024-3094", "xz", "5.6.0", "Malicious code injected into xz/liblzma"),
            ("CVE-2024-3094-1", "xz", "5.6.1", "Malicious code injected into xz/liblzma"),
            ("CVE-2019-11043", "php", "7.3.10", "PHP-FPM under-flow leading to remote code execution"),
            ("CVE-2021-3156", "sudo", "1.9.5", "Sudo Baron Samedit vulnerability"),
            ("CVE-2020-14368", "proftpd", "1.3.7", "Out of bounds read in ProFTPD"),
            ("CVE-2015-3306", "proftpd", "1.3.5", "ProFTPD mod_copy RCE"),
            ("CVE-2019-14287", "sudo", "1.8.27", "Sudo privilege escalation"),
            ("CVE-2022-21907", "http.sys", "10", "Windows HTTP.sys Remote Code Execution Vulnerability"),
            ("CVE-2019-19781", "citrix", "13.0", "Citrix ADC and Gateway Directory Traversal RCE"),
            ("CVE-2021-26855", "exchange", "2013", "Microsoft Exchange Server SSRF Vulnerability"),
            ("CVE-2021-26855-1", "exchange", "2016", "Microsoft Exchange Server SSRF Vulnerability"),
            ("CVE-2021-26855-2", "exchange", "2019", "Microsoft Exchange Server SSRF Vulnerability")
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM cves")
        if cursor.fetchone()[0] == 0:
            cursor.executemany("INSERT INTO cves (id, software, version, summary) VALUES (?, ?, ?, ?)", seed)
            conn.commit()
            
        conn.close()

    def search_cve(self, software, version):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Exact version match first
        cursor.execute("SELECT id, summary FROM cves WHERE software = ? AND version = ?", (software, version))
        results = cursor.fetchall()
        
        # If no exact match, try a prefix match for minor versions (e.g., 2.4.x)
        if not results:
            if '.' in version:
                major_minor = version.rsplit('.', 1)[0]
                cursor.execute("SELECT id, summary FROM cves WHERE software = ? AND version LIKE ?", (software, f"{major_minor}%"))
                results = cursor.fetchall()
                
        conn.close()
        
        return [{"id": r[0], "summary": r[1]} for r in results]

# Singleton instance
cve_db = CVEDatabase()
