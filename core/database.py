import sqlite3
import json
from datetime import datetime
import threading

class DatabaseManager:
    def __init__(self, db_path="netscan_history.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            # Enable WAL mode for concurrency
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return self._local.conn


    def _create_schema(self, conn):
        """Idempotent schema initialization. Safe to call on any connection."""
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT,
                target_network TEXT,
                ip TEXT,
                status TEXT,
                mac TEXT,
                vendor TEXT,
                device_type TEXT,
                risk_level TEXT,
                risk_score INTEGER,
                open_ports TEXT,
                os_guess TEXT,
                full_json TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_time ON scan_history(scan_time)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_target_network ON scan_history(target_network)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON scan_history(ip)")
        conn.commit()

    def _init_db(self):
        """Initialize the database on the main thread connection."""
        self._create_schema(self._get_conn())

    def save_scan(self, target_network, devices):
        scan_time = datetime.now().isoformat()
        conn = self._get_conn()
        cursor = conn.cursor()
        for dev in devices:
            # Use raw dict keys if flattened, otherwise check nested dicts
            mac = dev.get("hardware", {}).get("mac_address", dev.get("mac", ""))
            vendor = dev.get("hardware", {}).get("vendor", dev.get("vendor", ""))
            open_ports = dev.get("device", {}).get("open_ports", dev.get("open_ports", []))
            os_guess = dev.get("device", {}).get("os_guess", dev.get("os", ""))
            
            cursor.execute("""
                INSERT INTO scan_history 
                (scan_time, target_network, ip, status, mac, vendor, device_type, risk_level, risk_score, open_ports, os_guess, full_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_time,
                target_network,
                dev.get("ip", ""),
                dev.get("status", ""),
                mac,
                vendor,
                dev.get("device_type", ""),
                dev.get("risk_level", ""),
                dev.get("risk_score", 0),
                json.dumps(open_ports),
                os_guess,
                json.dumps(dev)
            ))
        conn.commit()
        return scan_time

    def get_history(self, limit=50):
        """Retrieve unique scan instances."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT scan_time, target_network, COUNT(*) as device_count 
            FROM scan_history 
            GROUP BY scan_time, target_network
            ORDER BY scan_time DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_scan_by_time(self, scan_time):
        """Retrieve full details of a specific scan."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_history WHERE scan_time = ?", (scan_time,))
        return [dict(row) for row in cursor.fetchall()]

    def delete_scan(self, scan_time):
        """Delete a specific scan from history."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history WHERE scan_time = ?", (scan_time,))
        conn.commit()

    def get_diff(self, old_scan_time, new_scan_time):
        """Compare two scans and find new, missing, and changed devices."""
        old_devices = {d["ip"]: d for d in self.get_scan_by_time(old_scan_time)}
        new_devices = {d["ip"]: d for d in self.get_scan_by_time(new_scan_time)}
        
        added = [ip for ip in new_devices if ip not in old_devices]
        removed = [ip for ip in old_devices if ip not in new_devices]
        
        changed = []
        for ip in set(new_devices) & set(old_devices):
            if new_devices[ip]["open_ports"] != old_devices[ip]["open_ports"] or new_devices[ip]["risk_score"] != old_devices[ip]["risk_score"]:
                changed.append(ip)
                
        return {"added": added, "removed": removed, "changed": changed}
