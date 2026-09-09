"""
Tests for DatabaseManager — covers insertion, retrieval, history, diff, and WAL mode.
"""
import pytest
import json
import sqlite3
import threading
import tempfile
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.database import DatabaseManager


@pytest.fixture
def db(tmp_path):
    """Provide a fresh, isolated DatabaseManager for each test."""
    db_file = str(tmp_path / "test_netscan.db")
    return DatabaseManager(db_path=db_file)


SAMPLE_DEVICES = [
    {
        "ip": "192.168.1.1",
        "status": "Active",
        "mac": "AA:BB:CC:DD:EE:01",
        "vendor": "Cisco",
        "device_type": "Router",
        "risk_level": "High",
        "risk_score": 80,
        "open_ports": [22, 23, 80],
        "os": "IOS 15",
    },
    {
        "ip": "192.168.1.2",
        "status": "Active",
        "mac": "AA:BB:CC:DD:EE:02",
        "vendor": "Apple",
        "device_type": "Laptop",
        "risk_level": "Low",
        "risk_score": 5,
        "open_ports": [443],
        "os": "macOS",
    },
]

SAMPLE_DEVICES_V2 = [
    {
        "ip": "192.168.1.1",       # same IP, changed risk
        "status": "Active",
        "mac": "AA:BB:CC:DD:EE:01",
        "vendor": "Cisco",
        "device_type": "Router",
        "risk_level": "High",
        "risk_score": 90,           # changed score
        "open_ports": [22, 23, 80, 8443],  # new port added
        "os": "IOS 15",
    },
    {
        "ip": "192.168.1.5",       # new device
        "status": "Active",
        "mac": "AA:BB:CC:DD:EE:05",
        "vendor": "Samsung",
        "device_type": "Phone",
        "risk_level": "Low",
        "risk_score": 0,
        "open_ports": [],
        "os": "Android",
    },
]


class TestDatabaseManager:

    def test_wal_mode_enabled(self, db):
        """WAL journal mode should be set on every connection."""
        conn = db._get_conn()
        result = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert result.lower() == "wal"

    def test_table_exists(self, db):
        """scan_history table must be created on init."""
        conn = db._get_conn()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'"
        )
        assert cursor.fetchone() is not None

    def test_save_scan_returns_timestamp(self, db):
        scan_time = db.save_scan("192.168.1.0/24", SAMPLE_DEVICES)
        assert scan_time is not None
        assert "T" in scan_time  # ISO format check

    def test_save_and_retrieve_scan(self, db):
        scan_time = db.save_scan("192.168.1.0/24", SAMPLE_DEVICES)
        rows = db.get_scan_by_time(scan_time)
        assert len(rows) == len(SAMPLE_DEVICES)
        ips = [r["ip"] for r in rows]
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    def test_full_json_is_valid(self, db):
        scan_time = db.save_scan("192.168.1.0/24", SAMPLE_DEVICES)
        rows = db.get_scan_by_time(scan_time)
        for row in rows:
            parsed = json.loads(row["full_json"])
            assert "ip" in parsed

    def test_get_history_returns_summary(self, db):
        db.save_scan("192.168.1.0/24", SAMPLE_DEVICES)
        history = db.get_history()
        assert len(history) >= 1
        entry = history[0]
        assert "scan_time" in entry
        assert "target_network" in entry
        assert "device_count" in entry
        assert entry["device_count"] == len(SAMPLE_DEVICES)

    def test_delete_scan(self, db):
        scan_time = db.save_scan("192.168.1.0/24", SAMPLE_DEVICES)
        db.delete_scan(scan_time)
        rows = db.get_scan_by_time(scan_time)
        assert len(rows) == 0
        history = db.get_history()
        times = [h["scan_time"] for h in history]
        assert scan_time not in times

    def test_get_diff_added_removed_changed(self, db):
        old_time = db.save_scan("net", SAMPLE_DEVICES)
        new_time = db.save_scan("net", SAMPLE_DEVICES_V2)
        diff = db.get_diff(old_time, new_time)

        # 192.168.1.5 is new
        assert "192.168.1.5" in diff["added"]
        # 192.168.1.2 was removed
        assert "192.168.1.2" in diff["removed"]
        # 192.168.1.1 changed ports/score
        assert "192.168.1.1" in diff["changed"]

    def test_thread_safe_connections(self, db):
        """Each thread should get its own connection."""
        results = {}
        errors = []

        def worker(name):
            try:
                db.save_scan(f"thread-{name}", SAMPLE_DEVICES)
                results[name] = True
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert len(results) == 5

    def test_get_history_limit(self, db):
        for i in range(10):
            db.save_scan(f"net-{i}", SAMPLE_DEVICES[:1])
        history = db.get_history(limit=3)
        assert len(history) <= 3
