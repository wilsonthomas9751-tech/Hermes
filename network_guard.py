#!/usr/bin/env python3
"""
network_guard.py — Detect unwanted computers on your local network.

Usage:
  python3 network_guard.py scan              # scan + report unknown hosts
  python3 network_guard.py scan --learn     # scan + add all found hosts to baseline
  python3 network_guard.py scan --ip 10.0.0.5  # scan a specific host
  python3 network_guard.py baseline         # show current known hosts
  python3 network_guard.py baseline --add 192.168.0.50  # trust a host
  python3 network_guard.py baseline --remove 192.168.0.50  # untrust
  python3 network_guard.py watch --interval 300  # daemon: scan every 5 min, alert on new

Stores baseline in ~/network_guard_baseline.json.
"""

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Config ──────────────────────────────────────────────────────────────
HOME = Path.home()
BASELINE_FILE = HOME / "network_guard_baseline.json"
SCAN_LOG = HOME / "network_guard_scan.log"
ALERT_LOG = HOME / "network_guard_alerts.log"
DEFAULT_INTERFACE = "eth0"
DEFAULT_INTERVAL = 300  # seconds
OUI_DB_URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUI_CACHE = HOME / "network_guard_oui.json"


# ── MAC vendor lookup (local OUI cache) ────────────────────────────────
def load_oui() -> dict:
    if OUI_CACHE.exists():
        try:
            return json.loads(OUI_CACHE.read_text())
        except Exception:
            pass
    return {}


def save_oui(oui: dict) -> None:
    OUI_CACHE.write_text(json.dumps(oui))


def mac_vendor(mac: str, oui: dict) -> str:
    """Look up manufacturer from MAC OUI (first 3 octets)."""
    mac_norm = mac.replace(":", "").replace("-", "").upper()[:6]
    return oui.get(mac_norm, "Unknown")


def download_oui() -> dict:
    """Download IEEE OUI list. Returns dict of OUI->vendor."""
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", "60", "--retry", "2", OUI_DB_URL],
            capture_output=True, text=True, timeout=90
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        oui = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("OUI") or line.startswith("company_id") or line.startswith("\t"):
                continue
            # Format: "28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd."
            # or:     "286FB9     (base 16)\t\tNokia Shanghai Bell Co., Ltd."
            m = re.match(r"^([0-9A-Fa-f]{2}[-:]){2}[0-9A-Fa-f]{2}\s+\(hex\)\s+(.+)$", line)
            if not m:
                m = re.match(r"^([0-9A-Fa-f]{6})\s+\(base\s+16\)\s+(.+)$", line)
            if m:
                oui_prefix = m.group(1).replace("-", "").replace(":", "").upper()[:6]
                vendor = m.group(2).strip()
                oui[oui_prefix] = vendor
        save_oui(oui)
        return oui
    except Exception as e:
        print(f"[!] Could not download OUI database: {e}", file=sys.stderr)
        return {}


# ── Network detection ──────────────────────────────────────────────────

def get_subnet() -> Optional[tuple]:
    """Detect local subnet from routing table. Returns (ip, prefix_len, interface) or None."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=10
        )
        m = re.search(r"dev\s+(\w+)\s+", result.stdout)
        iface = m.group(1) if m else DEFAULT_INTERFACE

        result2 = subprocess.run(
            ["ip", "addr", "show", iface],
            capture_output=True, text=True, timeout=10
        )
        ip_m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", result2.stdout)
        if ip_m:
            return (ip_m.group(1), int(ip_m.group(2)), iface)
    except Exception as e:
        print(f"[!] Error detecting subnet: {e}", file=sys.stderr)
    return None


def arp_table_hosts() -> dict:
    """Parse /proc/net/arp for known hosts. No root needed."""
    hosts = {}
    try:
        with open("/proc/net/arp") as f:
            header = f.readline()  # skip header
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] != "0.0.0.0":
                    ip = parts[0]
                    mac = parts[3]
                    if re.match(r"^[\da-fA-F:]{17}$", mac) and mac.lower() != "00:00:00:00:00:00":
                        hosts[ip] = {"mac": mac.lower(), "interface": parts[5] if len(parts) > 5 else "unknown"}
    except Exception as e:
        print(f"[!] Error reading /proc/net/arp: {e}", file=sys.stderr)
    return hosts


def ping_sweep(network_ip: str, prefix_len: int, iface: str = DEFAULT_INTERFACE) -> dict:
    """Ping-sweep the subnet. Returns dict of live hosts."""
    hosts = {}
    prefix_len = int(prefix_len)
    net_parts = [int(x) for x in network_ip.split(".")]

    if prefix_len >= 24:
        target_hosts = [f"{net_parts[0]}.{net_parts[1]}.{net_parts[2]}.{i}" for i in range(1, 255)]
    elif prefix_len >= 16:
        third_start = max(net_parts[2] + 1, 1)
        target_hosts = []
        for t in range(third_start, 256):
            for u in range(1, 255):
                target_hosts.append(f"{net_parts[0]}.{net_parts[1]}.{t}.{u}")
        target_hosts = target_hosts[:2000]  # safety cap
    else:
        print(f"[!] Subnet /{prefix_len} too large for sweep; skipping", file=sys.stderr)
        return hosts

    print(f"[*] Ping-sweep: {len(target_hosts)} hosts on {network_ip}/{prefix_len}...")

    # Try fping first (parallel, fast)
    use_fping = subprocess.run(["which", "fping"], capture_output=True).returncode == 0

    if use_fping:
        try:
            result = subprocess.run(
                ["fping", "-a", "-q", "-c", "1", "-t", "200"] + target_hosts,
                capture_output=True, text=True, timeout=300
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[1].rstrip(":")
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                        hosts[ip] = {"method": "fping", "rtt": parts[-1] if len(parts) > 2 else "unknown"}
        except subprocess.TimeoutExpired:
            print("[!] fping timed out; falling back to ping", file=sys.stderr)
            use_fping = False

    if not use_fping:
        def ping_one(ip_addr: str) -> Optional[str]:
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", "-I", iface, ip_addr],
                    capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    return ip_addr
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_one, ip): ip for ip in target_hosts}
            for future in concurrent.futures.as_completed(futures):
                alive_ip = future.result()
                if alive_ip:
                    hosts[alive_ip] = {"method": "ping"}

    return hosts


def scan_single_host(ip: str, iface: str = DEFAULT_INTERFACE) -> Optional[dict]:
    """Check if a specific host is alive."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", "-I", iface, ip],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return None
    except Exception:
        return None

    arp = arp_table_hosts()
    if ip in arp:
        return {"ip": ip, "mac": arp[ip]["mac"], "method": "ping+arp", "interface": arp[ip].get("interface", iface)}
    return {"ip": ip, "mac": "unknown", "method": "ping", "interface": iface}


# ── Baseline ────────────────────────────────────────────────────────────

def load_baseline() -> dict:
    if BASELINE_FILE.exists():
        try:
            return json.loads(BASELINE_FILE.read_text())
        except Exception:
            pass
    return {
        "known_hosts": {},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_updated": None,
        "notes": "",
        "version": 1
    }


def save_baseline(data: dict) -> None:
    BASELINE_FILE.write_text(json.dumps(data, indent=2))


def add_to_baseline(baseline: dict, ip: str, mac: str, note: str = "", oui: dict = None) -> None:
    baseline["known_hosts"][ip] = {
        "mac": mac.lower() if mac else "unknown",
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "note": note,
        "vendor": mac_vendor(mac, oui) if oui and mac and mac != "unknown" else "Unknown"
    }
    baseline["last_updated"] = datetime.now(timezone.utc).isoformat()


def remove_from_baseline(baseline: dict, ip: str) -> bool:
    if ip in baseline["known_hosts"]:
        del baseline["known_hosts"][ip]
        baseline["last_updated"] = datetime.now(timezone.utc).isoformat()
        return True
    return False


# ── Main scan ───────────────────────────────────────────────────────────

def scan(subnet_info: tuple, learn: bool = False, oui: dict = None, log: bool = True) -> dict:
    """Full scan: ARP table + ping sweep. Returns structured result."""
    ip, prefix, iface = subnet_info
    network_str = f"{ip}/{prefix}"
    print(f"[*] Scanning {network_str} on interface {iface}...")
    print(f"[*] {datetime.now(timezone.utc).isoformat()}")

    baseline = load_baseline()
    found = {}

    # Step 1: ARP table (instant, passive)
    print("[*] Reading ARP table...")
    arp_hosts = arp_table_hosts()
    for ip_addr, info in arp_hosts.items():
        found[ip_addr] = {"mac": info["mac"], "method": "arp", "interface": info.get("interface", iface)}

    # Step 2: Ping sweep (active — finds hosts not in ARP cache)
    print("[*] Ping sweep...")
    ping_hosts = ping_sweep(ip, prefix, iface)
    for ip_addr, info in ping_hosts.items():
        if ip_addr not in found:
            found[ip_addr] = info
        else:
            found[ip_addr]["method"] = found[ip_addr].get("method", "unknown") + "+ping"

    print(f"[*] Found {len(found)} live host(s)")

    # Categorize
    known = {}
    unknown = {}
    for ip_addr, info in found.items():
        mac = info.get("mac", "unknown")
        vendor = mac_vendor(mac, oui) if oui and mac != "unknown" else "Unknown"
        entry = {
            "ip": ip_addr,
            "mac": mac,
            "vendor": vendor,
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "detection_methods": list(set([info.get("method", "unknown")]))
        }

        if ip_addr in baseline["known_hosts"]:
            known[ip_addr] = entry
            baseline["known_hosts"][ip_addr]["last_seen"] = entry["last_seen"]
        else:
            unknown[ip_addr] = entry

    # Learn mode
    if learn and unknown:
        print(f"[*] Learning {len(unknown)} new host(s) into baseline...")
        for ip_addr, info in unknown.items():
            add_to_baseline(baseline, ip_addr, info["mac"], note="auto-learned", oui=oui)
        save_baseline(baseline)

    # Log
    if log:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subnet": network_str,
            "total_found": len(found),
            "known_count": len(known),
            "unknown_count": len(unknown),
            "unknown_hosts": [{"ip": h["ip"], "mac": h["mac"], "vendor": h["vendor"]} for h in unknown.values()],
            "known_hosts": list(known.keys())
        }
        with open(SCAN_LOG, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    return {
        "all_live": found,
        "known": known,
        "unknown": unknown,
        "baseline": baseline,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "subnet": network_str
    }


def print_report(result: dict) -> int:
    """Print scan results. Returns 1 if unknown hosts found (for scripting)."""
    print("\n" + "=" * 60)
    print("  NETWORK GUARD SCAN REPORT")
    print(f"  {result['timestamp']}")
    print("=" * 60)
    print(f"  Subnet:      {result['subnet']}")
    print(f"  Total live:  {len(result['all_live'])}")
    print(f"  Known:       {len(result['known'])}")
    print(f"  Unknown:     {len(result['unknown'])}")
    print("-" * 60)

    if result["known"]:
        print(f"\n  KNOWN HOSTS ({len(result['known'])}):")
        for ip in sorted(result["known"].keys()):
            info = result["known"][ip]
            print(f"    [{ip}] {info['mac']}  {info['vendor']}")

    if result["unknown"]:
        print(f"\n  WARNING — UNKNOWN HOSTS ({len(result['unknown'])}) — POSSIBLE INTRUDER:")
        for ip in sorted(result["unknown"].keys()):
            info = result["unknown"][ip]
            print(f"    [{ip}] {info['mac']}  {info['vendor']}")
        print("\n  Run: python3 network_guard.py baseline --add <IP>  to trust a host")
        print("  Run: python3 network_guard.py scan --learn       to trust all found")
    else:
        print("\n  OK — No unknown hosts detected.")

    print("=" * 60 + "\n")
    return 1 if result["unknown"] else 0


# ── Watch mode ──────────────────────────────────────────────────────────

def watch(interval: int, oui: dict = None) -> None:
    """Daemon mode: scan periodically, alert on new hosts."""
    print(f"[*] Network Guard watch mode — scanning every {interval}s")
    print("[*] Press Ctrl+C to stop.\n")

    subnet = get_subnet()
    if not subnet:
        print("[!] Could not detect subnet.", file=sys.stderr)
        sys.exit(1)

    baseline = load_baseline()
    print(f"[*] Baseline: {len(baseline['known_hosts'])} known host(s)")
    print(f"[*] Starting scans at {datetime.now(timezone.utc).isoformat()}\n")

    try:
        while True:
            result = scan(subnet, learn=False, oui=oui, log=True)

            if result["unknown"]:
                print(f"\n *** ALERT: {len(result['unknown'])} unknown host(s) detected! ***")
                for ip, info in result["unknown"].items():
                    print(f"  NEW: {ip}  {info['mac']}  {info['vendor']}")

                # Append to alert log
                alert_entry = {
                    "timestamp": result["timestamp"],
                    "new_hosts": [{"ip": h["ip"], "mac": h["mac"], "vendor": h["vendor"]} for h in result["unknown"].values()]
                }
                with open(ALERT_LOG, "a") as f:
                    f.write(json.dumps(alert_entry) + "\n")

            print(f"[*] Next scan in {interval}s... ({datetime.now(timezone.utc).isoformat()})\n")
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[*] Watch mode stopped.")


# ── CLI ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Network Guard — detect unwanted computers on your LAN",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 network_guard.py scan              # scan + report unknown hosts
  python3 network_guard.py scan --learn     # scan + trust all found
  python3 network_guard.py scan --ip 10.0.0.5  # check a single host
  python3 network_guard.py baseline         # list trusted hosts
  python3 network_guard.py baseline --add 192.168.0.50  # trust a host
  python3 network_guard.py baseline --remove 192.168.0.50  # untrust
  python3 network_guard.py watch --interval 300  # daemon: scan every 5 min
  python3 network_guard.py update-oui       # refresh MAC vendor database
        """
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_p = sub.add_parser("scan", help="Scan network and detect unknown hosts")
    scan_p.add_argument("--learn", action="store_true", help="Trust all found hosts")
    scan_p.add_argument("--ip", type=str, help="Scan a specific IP instead of whole subnet")
    scan_p.add_argument("--no-oui", action="store_true", help="Skip MAC vendor lookup")

    # baseline
    base_p = sub.add_parser("baseline", help="Manage trusted hosts baseline")
    base_p.add_argument("--add", type=str, metavar="IP", help="Add a host to baseline")
    base_p.add_argument("--remove", type=str, metavar="IP", help="Remove a host from baseline")
    base_p.add_argument("--note", type=str, default="", help="Note for added host")
    base_p.add_argument("--show-mac", action="store_true", help="Show MAC addresses")

    # watch
    watch_p = sub.add_parser("watch", help="Daemon: periodic scanning with alerts")
    watch_p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                         help=f"Scan interval in seconds (default: {DEFAULT_INTERVAL})")

    # update-oui
    sub.add_parser("update-oui", help="Download/update MAC vendor (OUI) database")

    args = parser.parse_args()

    # Load OUI
    oui = {}
    if args.command != "update-oui":
        if not getattr(args, "no_oui", False):
            oui = load_oui()
            if not oui:
                print("[*] OUI cache empty. Downloading vendor database...")
                oui = download_oui()

    if args.command == "scan":
        if args.ip:
            print(f"[*] Checking host {args.ip}...")
            host = scan_single_host(args.ip)
            if host:
                mac = host.get("mac", "unknown")
                vendor = mac_vendor(mac, oui) if oui else "Unknown"
                print(f"  Alive: {args.ip}  MAC: {mac}  Vendor: {vendor}")
                baseline = load_baseline()
                if args.ip in baseline["known_hosts"]:
                    print(f"  Status: KNOWN (in baseline)")
                else:
                    print(f"  Status: UNKNOWN (not in baseline)")
            else:
                print(f"  Host {args.ip} is not reachable.")
        else:
            subnet = get_subnet()
            if not subnet:
                print("[!] Could not detect subnet. Use --ip to scan a specific host.", file=sys.stderr)
                sys.exit(1)
            result = scan(subnet, learn=args.learn, oui=oui)
            rc = print_report(result)
            sys.exit(rc)

    elif args.command == "baseline":
        baseline = load_baseline()

        if args.add:
            ip = args.add
            arp = arp_table_hosts()
            mac = arp.get(ip, {}).get("mac", "unknown")
            if mac == "unknown":
                print(f"[!] {ip} not in ARP table; MAC set to 'unknown'. Host may be offline.")
            add_to_baseline(baseline, ip, mac, note=args.note, oui=oui)
            save_baseline(baseline)
            print(f"  Added {ip} to baseline (MAC: {mac})")

        elif args.remove:
            if remove_from_baseline(baseline, args.remove):
                save_baseline(baseline)
                print(f"  Removed {args.remove} from baseline")
            else:
                print(f"  {args.remove} not in baseline")

        else:
            print(f"\n  TRUSTED HOSTS ({len(baseline['known_hosts'])}):")
            print(f"  Created: {baseline.get('created_at', 'unknown')}")
            print(f"  Last updated: {baseline.get('last_updated', 'unknown')}")
            if baseline.get("notes"):
                print(f"  Notes: {baseline['notes']}")
            print("-" * 50)
            for ip in sorted(baseline["known_hosts"].keys()):
                info = baseline["known_hosts"][ip]
                extra = f"  {info['note']}" if info.get("note") else ""
                mac_str = f"  {info['mac']}" if args.show_mac else ""
                print(f"    [{ip}] {info['vendor']}{mac_str}{extra}")

    elif args.command == "watch":
        watch(args.interval, oui)

    elif args.command == "update-oui":
        print("[*] Downloading IEEE OUI database...")
        oui = download_oui()
        print(f"  Downloaded {len(oui)} OUI entries.")
        if oui:
            print(f"  Saved to {OUI_CACHE}")


if __name__ == "__main__":
    main()
