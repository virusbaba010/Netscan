#!/usr/bin/env python3
"""
Elevated Scan Worker — spawned by ScanProxy when the main UI process lacks privileges.

Protocol: Reads one JSON-line from stdin, executes the requested scan operation,
and writes one JSON-line result to stdout.

Input:  {"command": "arp_scan", "args": {"ip_list": ["192.168.1.1", ...]}}
Output: [{"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01"}, ...]

Supported commands:
  - arp_scan:   ARP discovery → list[{ip, mac}]
  - ping_sweep: ICMP sweep   → list[str]  (active IPs)
"""
import asyncio
import json
import sys
import logging

logging.basicConfig(level=logging.WARNING)


async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", help="Path to input JSON file", default=None)
    parser.add_argument("--output", help="Path to output JSON file", default=None)
    args_cli = parser.parse_args()

    if args_cli.input:
        with open(args_cli.input, "r") as f:
            raw = f.read().strip()
    else:
        raw = sys.stdin.read().strip()

    if not raw:
        if args_cli.output:
            with open(args_cli.output, "w") as f: f.write("[]")
        else:
            sys.stdout.write(json.dumps([]))
        return

    try:
        req = json.loads(raw)
        command = req.get("command")
        args = req.get("args", {})
    except json.JSONDecodeError as e:
        sys.stderr.write(f"[scan_worker] JSON parse error: {e}\n")
        if args_cli.output:
            with open(args_cli.output, "w") as f: f.write("[]")
        else:
            sys.stdout.write(json.dumps([]))
        return

    result = []

    if command == "arp_scan":
        from scanner.arp_scan import arp_scan
        result = await arp_scan(args.get("ip_list", []))

    elif command == "ping_sweep":
        from scanner.ping_sweep import ping_sweep
        result = await ping_sweep(args.get("ip_list", []))

    elif command == "os_detect":
        from fingerprint.os_detection import detect_os
        result = await detect_os(args.get("ip", ""), args.get("open_ports", []))

    else:
        sys.stderr.write(f"[scan_worker] Unknown command: {command}\n")

    if args_cli.output:
        with open(args_cli.output, "w") as f:
            f.write(json.dumps(result))
    else:
        sys.stdout.write(json.dumps(result))


if __name__ == "__main__":
    # Ensure we can be run from the project root regardless of cwd
    import os
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, project_root)
    asyncio.run(main())
