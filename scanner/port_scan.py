"""
Enhanced port scanner with bandwidth estimation.

Measures round-trip latency per connection attempt and extrapolates
approximate connection speed (useful for understanding network performance
and prioritising further scanning).
"""
import asyncio
import time


async def scan_port(ip, port, timeout=1):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port, True
    except:
        return port, False


async def scan_port_timed(ip, port, timeout=1) -> tuple[int, bool, float]:
    """
    Like scan_port but also returns the round-trip latency in milliseconds.
    Returns: (port, is_open, latency_ms)
    """
    t_start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        latency_ms = (time.monotonic() - t_start) * 1000
        writer.close()
        await writer.wait_closed()
        return port, True, round(latency_ms, 2)
    except:
        return port, False, -1.0


async def port_scan(ip, ports, timeout=0.5, max_concurrency=500):
    """
    High-performance async port scanner.
    Default concurrency increased to 500 for rapid subnet auditing.
    """
    sem = asyncio.Semaphore(max_concurrency)

    async def _scan(p):
        async with sem:
            return await scan_port(ip, p, timeout)

    tasks = [_scan(port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    open_ports = []
    for r in results:
        if isinstance(r, tuple) and r[1]:
            open_ports.append(r[0])

    return sorted(open_ports)


async def port_scan_with_bandwidth(ip: str, ports: list[int],
                                    timeout: float = 0.5,
                                    max_concurrency: int = 200) -> dict:
    """
    Enhanced port scan that measures per-connection latency and computes
    a bandwidth estimation score.

    Returns:
        {
          "open_ports": [80, 443, ...],
          "latencies_ms": {80: 12.3, 443: 9.1, ...},
          "avg_latency_ms": 10.7,
          "bandwidth_estimate": "High | Medium | Low | Unknown"
        }

    Bandwidth estimation heuristic (rough guideline):
      avg_latency < 5 ms  → High  (LAN / fast link)
      avg_latency < 20 ms → Medium
      avg_latency < 100ms → Low
      else                → Poor / WAN
    """
    sem = asyncio.Semaphore(max_concurrency)

    async def _scan_timed(p):
        async with sem:
            return await scan_port_timed(ip, p, timeout)

    tasks = [_scan_timed(p) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    open_ports = []
    latencies_ms = {}

    for r in results:
        if isinstance(r, tuple) and len(r) == 3:
            port, is_open, lat = r
            if is_open:
                open_ports.append(port)
                latencies_ms[port] = lat

    # Compute average latency over successful connections
    avg_latency = None
    if latencies_ms:
        valid = [v for v in latencies_ms.values() if v >= 0]
        avg_latency = round(sum(valid) / len(valid), 2) if valid else None

    if avg_latency is None:
        bw_estimate = "Unknown"
    elif avg_latency < 5:
        bw_estimate = "High (LAN)"
    elif avg_latency < 20:
        bw_estimate = "Medium"
    elif avg_latency < 100:
        bw_estimate = "Low"
    else:
        bw_estimate = "Poor (WAN/High Latency)"

    return {
        "open_ports": sorted(open_ports),
        "latencies_ms": latencies_ms,
        "avg_latency_ms": avg_latency,
        "bandwidth_estimate": bw_estimate,
    }
