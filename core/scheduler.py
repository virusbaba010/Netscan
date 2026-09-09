"""
Scan Scheduler — periodic and one-shot scan scheduling for Netscan.

Supports:
  - One-shot scheduled scans (run at a future datetime)
  - Recurring scans (every N minutes/hours)
  - Persisting schedules to netscan_config.yaml (optional)
  - Qt signal emission for GUI integration

Usage:
    from core.scheduler import ScanScheduler
    scheduler = ScanScheduler()
    scheduler.add_recurring("192.168.1.0/24", interval_minutes=30, label="Home Network")
    scheduler.start()           # starts background asyncio loop
"""
import asyncio
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional

logger = logging.getLogger("netscan.scheduler")


@dataclass
class ScheduledScan:
    """Represents one scheduled scan job."""
    label: str
    target: str
    interval_minutes: int       # 0 = one-shot
    next_run: datetime
    enabled: bool = True
    last_run: Optional[datetime] = None
    run_count: int = 0


class ScanScheduler:
    """
    Background scan scheduler that runs scans on a configurable schedule.

    Thread-safe: schedules are accessed from both the UI thread (add/remove)
    and the background asyncio thread (running scans).
    """

    def __init__(self, scan_callback: Optional[Callable] = None):
        """
        Args:
            scan_callback: Async function called with (target: str, label: str)
                           when a scan is due. If None, scheduler is dry-run only.
        """
        self._jobs: list[ScheduledScan] = []
        self._lock = threading.Lock()
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self.scan_callback = scan_callback

    # ─── Public API ──────────────────────────────────────────────────────────

    def add_recurring(self, target: str, interval_minutes: int,
                      label: str = "", start_now: bool = False) -> ScheduledScan:
        """Add a recurring scan job."""
        first_run = datetime.now() if start_now else datetime.now() + timedelta(minutes=interval_minutes)
        job = ScheduledScan(
            label=label or target,
            target=target,
            interval_minutes=interval_minutes,
            next_run=first_run,
        )
        with self._lock:
            self._jobs.append(job)
        logger.info(f"[Scheduler] Added recurring job '{job.label}' every {interval_minutes}m, first run at {first_run.strftime('%H:%M:%S')}")
        return job

    def add_one_shot(self, target: str, run_at: datetime, label: str = "") -> ScheduledScan:
        """Schedule a single scan at a specific datetime."""
        job = ScheduledScan(
            label=label or target,
            target=target,
            interval_minutes=0,
            next_run=run_at,
        )
        with self._lock:
            self._jobs.append(job)
        logger.info(f"[Scheduler] Added one-shot job '{job.label}' at {run_at.strftime('%Y-%m-%d %H:%M:%S')}")
        return job

    def remove_job(self, label: str) -> bool:
        """Remove a job by label. Returns True if found and removed."""
        with self._lock:
            before = len(self._jobs)
            self._jobs = [j for j in self._jobs if j.label != label]
            return len(self._jobs) < before

    def list_jobs(self) -> list[dict]:
        """Return a snapshot of all scheduled jobs as dicts."""
        with self._lock:
            return [
                {
                    "label": j.label,
                    "target": j.target,
                    "interval_minutes": j.interval_minutes,
                    "next_run": j.next_run.strftime("%Y-%m-%d %H:%M:%S"),
                    "last_run": j.last_run.strftime("%Y-%m-%d %H:%M:%S") if j.last_run else None,
                    "run_count": j.run_count,
                    "enabled": j.enabled,
                }
                for j in self._jobs
            ]

    def enable_job(self, label: str, enabled: bool = True):
        with self._lock:
            for j in self._jobs:
                if j.label == label:
                    j.enabled = enabled
                    logger.info(f"[Scheduler] Job '{label}' {'enabled' if enabled else 'disabled'}.")

    # ─── Lifecycle ───────────────────────────────────────────────────────────

    def start(self):
        """Start the scheduler background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="netscan-scheduler")
        self._thread.start()
        logger.info("[Scheduler] Started.")

    def stop(self):
        """Stop the scheduler. Running scans are not interrupted."""
        self._running = False
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        logger.info("[Scheduler] Stopped.")

    # ─── Internal event loop ─────────────────────────────────────────────────

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._tick_loop())
        finally:
            self._loop.close()

    async def _tick_loop(self):
        """Main scheduling tick — checks jobs every 30 seconds."""
        while self._running:
            now = datetime.now()
            with self._lock:
                due_jobs = [j for j in self._jobs if j.enabled and j.next_run <= now]

            for job in due_jobs:
                logger.info(f"[Scheduler] Firing job '{job.label}' (target: {job.target})")
                asyncio.create_task(self._execute_job(job))

            await asyncio.sleep(30)  # Check every 30 seconds

    async def _execute_job(self, job: ScheduledScan):
        """Execute one scheduled scan job."""
        job.last_run = datetime.now()
        job.run_count += 1

        if self.scan_callback:
            try:
                await self.scan_callback(job.target, job.label)
            except Exception as e:
                logger.error(f"[Scheduler] Job '{job.label}' failed: {e}")

        # Reschedule recurring jobs; disable one-shots
        with self._lock:
            if job.interval_minutes > 0:
                job.next_run = datetime.now() + timedelta(minutes=job.interval_minutes)
                logger.info(f"[Scheduler] Job '{job.label}' rescheduled for {job.next_run.strftime('%H:%M:%S')}")
            else:
                job.enabled = False  # One-shot: disable after first run
