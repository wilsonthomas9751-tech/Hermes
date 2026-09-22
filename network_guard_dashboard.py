#!/usr/bin/env python3
"""
network_guard_dashboard.py — Web GUI for Network Guard.

Start:  python3 network_guard_dashboard.py
Access: http://<this-machine-ip>:9199

Login: root / Denmark1$

Features:
  - Login wall (HTTP Basic Auth)
  - Scan button (triggers network_guard.py scan)
  - Live host table (known + unknown)
  - Baseline editor (add/remove trusted hosts)
  - Scan history log
  - Auto-refresh option
"""

import base64
import json
import os
import re
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

# ── Config ──────────────────────────────────────────────────────────────
HOME = Path.home()
BASELINE_FILE = HOME / "network_guard_baseline.json"
SCAN_LOG = HOME / "network_guard_scan.log"
ALERT_LOG = HOME / "network_guard_alerts.log"
GUARD_SCRIPT = "/home/hermes/network_guard.py"
PORT = 9199
BIND = "0.0.0.0"

AUTH_USER = "root"
AUTH_PASS_HASH = "scrypt$16384$8$1$fmI/U/2AqcB0bnbB5fsg9g==$kcyo7czh0t3IZGAC+231l3JlFYamUUbRCxBAr/KR0ZQ="  # Denmark1$

# ── OUI loading ─────────────────────────────────────────────────────────
OUI_CACHE = HOME / "network_guard_oui.json"


def load_oui() -> dict:
    if OUI_CACHE.exists():
        try:
            return json.loads(OUI_CACHE.read_text())
        except Exception:
            pass
    return {}


def mac_vendor(mac: str, oui: dict) -> str:
    if not mac or mac == "unknown":
        return "Unknown"
    mac_norm = mac.replace(":", "").replace("-", "").upper()[:6]
    return oui.get(mac_norm, "Unknown")


# ── Baseline helpers ────────────────────────────────────────────────────

def load_baseline() -> dict:
    if BASELINE_FILE.exists():
        try:
            return json.loads(BASELINE_FILE.read_text())
        except Exception:
            pass
    return {"known_hosts": {}, "created_at": "", "last_updated": "", "notes": "", "version": 1}


def save_baseline(data: dict) -> None:
    BASELINE_FILE.write_text(json.dumps(data, indent=2))


# ── Scan runner ─────────────────────────────────────────────────────────

def run_scan() -> dict:
    """Run network_guard.py scan and parse output."""
    try:
        result = subprocess.run(
            ["python3", GUARD_SCRIPT, "scan"],
            capture_output=True, text=True, timeout=300,
            cwd=str(HOME)
        )
        output = result.stdout + result.stderr
        return parse_scan_output(output, result.returncode)
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out after 5 minutes", "timestamp": datetime.now(timezone.utc).isoformat()}
    except Exception as e:
        return {"error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()}


def parse_scan_output(text: str, exit_code: int) -> dict:
    """Parse network_guard.py scan output into structured data."""
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "exit_code": exit_code,
        "known": [],
        "unknown": [],
        "total_live": 0,
        "subnet": "unknown"
    }

    # Parse subnet
    m = re.search(r"Subnet:\s+(\S+)", text)
    if m:
        result["subnet"] = m.group(1)

    # Parse total
    m = re.search(r"Total live:\s+(\d+)", text)
    if m:
        result["total_live"] = int(m.group(1))

    # Parse host lines: [IP] MAC  Vendor
    host_pattern = re.compile(r"\[([\d.]+)\]\s+([\da-fA-F:]{17})\s+(.+)")
    in_unknown = False
    in_known = False

    for line in text.splitlines():
        if "WARNING" in line and "UNKNOWN HOSTS" in line:
            in_unknown = True
            in_known = False
            continue
        if "KNOWN HOSTS" in line:
            in_known = True
            in_unknown = False
            continue
        if "OK — No unknown" in line or "POSSIBLE INTRUDER" in line:
            continue

        m = host_pattern.search(line)
        if m:
            ip, mac, vendor = m.group(1), m.group(2).lower(), m.group(3).strip()
            entry = {"ip": ip, "mac": mac, "vendor": vendor}
            if in_unknown:
                result["unknown"].append(entry)
            elif in_known:
                result["known"].append(entry)

    # Parse scan log for history
    result["scan_log"] = load_scan_log()
    result["baseline"] = load_baseline()
    result["oui"] = load_oui()

    return result


def load_scan_log() -> list:
    """Load recent scan history."""
    if not SCAN_LOG.exists():
        return []
    try:
        entries = []
        with open(SCAN_LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        return entries[-20:]  # last 20
    except Exception:
        return []


def load_alerts() -> list:
    """Load alert history."""
    if not ALERT_LOG.exists():
        return []
    try:
        entries = []
        with open(ALERT_LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        return entries[-20:]
    except Exception:
        return []


# ── Baseline management ─────────────────────────────────────────────────

def add_baseline_host(ip: str, note: str = "") -> dict:
    baseline = load_baseline()
    arp = {}
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    arp[parts[0]] = parts[3].lower()
    except Exception:
        pass

    mac = arp.get(ip, "unknown")
    baseline["known_hosts"][ip] = {
        "mac": mac,
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "note": note,
        "vendor": mac_vendor(mac, load_oui())
    }
    baseline["last_updated"] = datetime.now(timezone.utc).isoformat()
    save_baseline(baseline)
    return {"success": True, "ip": ip, "mac": mac, "note": note}


def remove_baseline_host(ip: str) -> dict:
    baseline = load_baseline()
    if ip in baseline["known_hosts"]:
        del baseline["known_hosts"][ip]
        baseline["last_updated"] = datetime.now(timezone.utc).isoformat()
        save_baseline(baseline)
        return {"success": True, "ip": ip}
    return {"success": False, "error": f"{ip} not in baseline"}


# ── Auth ────────────────────────────────────────────────────────────────

def check_auth(header: Optional[str]) -> bool:
    if not header:
        return False
    if not header.startswith("Basic "):
        return False
    try:
        encoded = header.split(" ", 1)[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        user, password = decoded.split(":", 1)
        return user == AUTH_USER and verify_password(password, AUTH_PASS_HASH)
    except Exception:
        return False


def verify_password(password: str, hash_str: str) -> bool:
    """Verify password against scrypt hash."""
    try:
        import hashlib, hmac, base64
        parts = hash_str.split("$")
        if parts[0] != "scrypt":
            return False
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = base64.b64decode(parts[4])
        expected = base64.b64decode(parts[5])
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected), maxmem=0)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


# ── HTTP Handler ────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Guard — {TITLE}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #0d1117; color: #c9d1d9; min-height: 100vh; }}
  .header {{ background: #161b22; border-bottom: 1px solid #30363d;
             padding: 12px 24px; display: flex; align-items: center; gap: 16px;
             position: sticky; top: 0; z-index: 100; }}
  .header h1 {{ font-size: 18px; font-weight: 600; color: #58a6ff; }}
  .header .sub {{ color: #8b949e; font-size: 13px; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 20px; margin-bottom: 20px; }}
  .card h2 {{ font-size: 15px; color: #8b949e; text-transform: uppercase;
              letter-spacing: 0.5px; margin-bottom: 14px; font-weight: 500; }}
  .btn {{ display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px;
          border: 1px solid #30363d; background: #21262d; color: #c9d1d9;
          border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 500;
          transition: all 0.15s; }}
  .btn:hover {{ border-color: #58a6ff; color: #58a6ff; }}
  .btn.primary {{ background: #1f6feb; border-color: #1f6feb; color: #fff; }}
  .btn.primary:hover {{ background: #388bfd; border-color: #388bfd; }}
  .btn.danger {{ border-color: #da3633; color: #ff7b72; }}
  .btn.danger:hover {{ border-color: #ff7b72; color: #ff7b72; background: #da3633; }}
  .btn.green {{ border-color: #238636; color: #7ee787; }}
  .btn.green:hover {{ border-color: #7ee787; color: #7ee787; background: #238636; }}
  .btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px 12px; color: #8b949e; font-weight: 500;
        border-bottom: 1px solid #30363d; font-size: 11px; text-transform: uppercase;
        letter-spacing: 0.5px; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; }}
  tr:hover td {{ background: #1c2128; }}
  .badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px;
            font-size: 11px; font-weight: 500; }}
  .badge.ok {{ background: #23863622; color: #7ee787; border: 1px solid #23863655; }}
  .badge.warn {{ background: #d2992222; color: #d29922; border: 1px solid #d2992255; }}
  .badge.info {{ background: #1f6feb22; color: #58a6ff; border: 1px solid #1f6feb55; }}
  .stat {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }}
  .stat-box {{ flex: 1; min-width: 120px; background: #161b22; border: 1px solid #30363d;
               border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-box .num {{ font-size: 28px; font-weight: 700; }}
  .stat-box .label {{ font-size: 11px; color: #8b949e; text-transform: uppercase;
                      letter-spacing: 0.5px; margin-top: 4px; }}
  .stat-box.ok .num {{ color: #7ee787; }}
  .stat-box.warn .num {{ color: #d29922; }}
  .stat-box.info .num {{ color: #58a6ff; }}
  .form-row {{ display: flex; gap: 8px; margin-bottom: 12px; align-items: center; }}
  input[type="text"] {{ background: #0d1117; border: 1px solid #30363d; color: #c9d1d9;
                       padding: 6px 10px; border-radius: 6px; font-size: 13px;
                       outline: none; width: 200px; }}
  input[type="text"]:focus {{ border-color: #58a6ff; }}
  .empty {{ text-align: center; padding: 32px; color: #8b949e; }}
  .empty-icon {{ font-size: 32px; margin-bottom: 8px; opacity: 0.5; }}
  .toast {{ position: fixed; bottom: 24px; right: 24px; padding: 12px 20px;
            border-radius: 8px; font-size: 13px; z-index: 1000;
            animation: slideIn 0.3s ease; }}
  .toast.ok {{ background: #238636; color: #fff; }}
  .toast.err {{ background: #da3633; color: #fff; }}
  @keyframes slideIn {{ from {{ transform: translateY(20px); opacity: 0; }} to {{ transform: translateY(0); opacity: 1; }} }}
  .log-entry {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px;
                padding: 8px 12px; background: #0d1117; border-radius: 4px;
                margin-bottom: 4px; color: #8b949e; }}
  .log-entry .ts {{ color: #58a6ff; }}
  .log-entry .highlight {{ color: #ff7b72; }}
  .refresh-indicator {{ display: inline-block; width: 8px; height: 8px;
                        border-radius: 50%; background: #3fb950; margin-right: 6px;
                        vertical-align: middle; }}
  .refresh-indicator.busy {{ background: #d29922; animation: pulse 1s infinite; }}
  @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.4; }} }}
  .footer {{ text-align: center; padding: 24px; color: #484f58; font-size: 11px; }}
  .modal-overlay {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7);
                    z-index: 200; justify-content: center; align-items: center; }}
  .modal-overlay.active {{ display: flex; }}
  .modal {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 24px; min-width: 350px; max-width: 90vw; }}
  .modal h3 {{ font-size: 16px; margin-bottom: 16px; color: #c9d1d9; }}
  .modal .form-row {{ width: 100%; }}
  .modal input {{ width: 100%; }}
  .modal .btn {{ width: 100%; justify-content: center; margin-top: 8px; }}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>Network Guard</h1>
    <div class="sub">Local network monitoring — <span id="subnet">loading...</span></div>
  </div>
  <div style="margin-left:auto;display:flex;align-items:center;gap:12px;">
    <span id="refreshDot" class="refresh-indicator" title="Idle"></span>
    <button class="btn" onclick="toggleAutoRefresh()" id="refreshBtn">Auto-refresh: OFF</button>
    <button class="btn primary" onclick="runScan()" id="scanBtn">Scan Now</button>
    <span style="color:#484f58;font-size:12px;">user: {USER}</span>
  </div>
</div>

<div class="container">
  <div class="stat" id="stats">
    <div class="stat-box info">
      <div class="num" id="statTotal">-</div>
      <div class="label">Live Hosts</div>
    </div>
    <div class="stat-box ok">
      <div class="num" id="statKnown">-</div>
      <div class="label">Known</div>
    </div>
    <div class="stat-box warn">
      <div class="num" id="statUnknown">-</div>
      <div class="label">Unknown</div>
    </div>
  </div>

  <div class="card">
    <h2>Live Hosts</h2>
    {HOSTS_TABLE}
  </div>

  <div class="card">
    <h2>Baseline — Trusted Hosts</h2>
    {BASELINE_SECTION}
  </div>

  <div class="card">
    <h2>Scan History</h2>
    {HISTORY_SECTION}
  </div>

  <div class="card">
    <h2>Alerts</h2>
    {ALERTS_SECTION}
  </div>
</div>

<div class="footer">Network Guard Dashboard — {TIMESTAMP} UTC</div>

<div class="modal-overlay" id="addModal">
  <div class="modal">
    <h3>Add Host to Baseline</h3>
    <div class="form-row">
      <input type="text" id="addIp" placeholder="192.168.0.100" autocomplete="off">
    </div>
    <div class="form-row" style="flex-direction:column;align-items:stretch;">
      <input type="text" id="addNote" placeholder="Note (optional)" autocomplete="off">
    </div>
    <button class="btn primary" onclick="addHost()">Add Host</button>
    <button class="btn" onclick="closeModal()" style="margin-left:8px;">Cancel</button>
  </div>
</div>

<div id="toast" class="toast" style="display:none;"></div>

<script>
const USER = "{USER}";
let autoRefresh = false;
let refreshInterval = null;
const OUI = {OUI_JSON};

function macVendor(mac) {{
  if (!mac || mac === "unknown") return "Unknown";
  const prefix = mac.replace(/[:-]/g, "").toUpperCase().slice(0, 6);
  return OUI[prefix] || "Unknown";
}}

function showToast(msg, type) {{
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "toast " + (type || "ok");
  t.style.display = "block";
  setTimeout(() => {{ t.style.display = "none"; }}, 3000);
}}

function formatTime(iso) {{
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleString();
}}

function buildHostTable(hosts, emptyMsg) {{
  if (!hosts || hosts.length === 0) {{
    return `<div class="empty"><div class="empty-icon">○</div>${{emptyMsg}}</div>`;
  }}
  let html = `<table><thead><tr>
    <th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Status</th>
  </tr></thead><tbody>`;
  hosts.forEach(h => {{
    const status = h.mac === "unknown" ? '<span class="badge info">no ARP</span>'
                  : '<span class="badge ok">resolved</span>';
    html += `<tr>
      <td><strong>${{h.ip}}</strong></td>
      <td style="font-family:monospace;font-size:12px;">${{h.mac || "—"}}</td>
      <td>${{h.vendor}}</td>
      <td>${{status}}</td>
    </tr>`;
  }});
  html += "</tbody></table>";
  return html;
}}

function buildBaselineSection() {{
  const b = {BASELINE_JSON};
  const hosts = b && b.known_hosts ? Object.entries(b.known_hosts) : [];
  if (hosts.length === 0) {{
    return `<div class="empty"><div class="empty-icon">∅</div>
      No trusted hosts. Add one below, or run a scan and click "Learn".</div>`;
  }}
  let html = `<table><thead><tr>
    <th>IP</th><th>MAC</th><th>Vendor</th><th>Note</th><th>First Seen</th><th>Actions</th>
  </tr></thead><tbody>`;
  hosts.sort((a, b) => a[0].localeCompare(b[0])).forEach(([ip, info]) => {{
    html += `<tr>
      <td><strong>${{ip}}</strong></td>
      <td style="font-family:monospace;font-size:12px;">${{info.mac || "—"}}</td>
      <td>${{info.vendor || "Unknown"}}</td>
      <td style="color:#8b949e;">${{info.note || "—"}}</td>
      <td style="font-size:12px;color:#8b949e;">${{formatTime(info.first_seen)}}</td>
      <td>
        <button class="btn danger" onclick="removeHost('${{ip}}')"
          style="padding:4px 8px;font-size:11px;">Remove</button>
      </td>
    </tr>`;
  }});
  html += "</tbody></table>";
  html += `<div style="margin-top:16px;">
    <button class="btn green" onclick="openAddModal()">+ Add Host</button>
  </div>`;
  return html;
}}

function buildHistorySection() {{
  const entries = {HISTORY_JSON};
  if (!entries || entries.length === 0) {{
    return `<div class="empty"><div class="empty-icon">📋</div>No scan history yet. Run a scan.</div>`;
  }}
  let html = "";
  entries.slice().reverse().forEach(e => {{
    const ts = e.timestamp ? new Date(e.timestamp).toLocaleString() : "-";
    const unk = (e.unknown_count || 0);
    const cls = unk > 0 ? "highlight" : "";
    html += `<div class="log-entry">
      <span class="ts">${{ts}}</span> — ${{e.total_found!toLocaleString()}} hosts, ${{e.known_count!toLocaleString()}} known, <span class="${{cls!toLocaleString()}}">${{unk!toLocaleString()}} unknown</span>
      ${{e.subnet!toLocaleString() ? "· " + e.subnet!toLocaleString() : ""}}
    </div>`;
  }});
  return html;
}}

function buildAlertsSection() {{
  const entries = {ALERTS_JSON};
  if (!entries || entries.length === 0) {{
    return `<div class="empty"><div class="empty-icon">✓</div>No alerts. Network is clean.</div>`;
  }}
  let html = "";
  entries.slice().reverse().forEach(e => {{
    const ts = e.timestamp ? new Date(e.timestamp).toLocaleString() : "-";
    html += `<div class="log-entry" style="border-left:3px solid #d29922;">
      <span class="ts">${{ts}}</span> — <span class="highlight">ALERT: ${{e.new_hosts?.length||0}} new host(s)</span>
    </div>`;
    if (e.new_hosts) {{
      e.new_hosts.forEach(h => {{
        html += `<div class="log-entry" style="padding-left:24px;font-size:11px;">
          ${{h.ip}} · ${{h.mac ? h.mac.slice(0,17)+"…" : "?"}} · ${{h.vendor}}
        </div>`;
      }});
    }}
  }});
  return html;
}}

function updateUI(data) {{
  if (!data) return;
  document.getElementById("subnet").textContent = data.subnet || "unknown";
  document.getElementById("statTotal").textContent = data.total_live || 0;
  document.getElementById("statKnown").textContent = (data.known || []).length;
  document.getElementById("statUnknown").textContent = (data.unknown || []).length;

  document.getElementById("hosts_table").innerHTML = buildHostTable(data.unknown, "No unknown hosts — network is clean.");
  document.getElementById("baseline_section").innerHTML = buildBaselineSection();
  document.getElementById("history_section").innerHTML = buildHistorySection();
  document.getElementById("alerts_section").innerHTML = buildAlertsSection();
}}

async function runScan() {{
  const btn = document.getElementById("scanBtn");
  const dot = document.getElementById("refreshDot");
  btn.disabled = true;
  btn.textContent = "Scanning...";
  dot.className = "refresh-indicator busy";
  try {{
    const resp = await fetch("/api/scan");
    const data = await resp.json();
    updateUI(data);
    if (data.unknown && data.unknown.length > 0) {{
      showToast(`⚠ ${{data.unknown.length}} unknown host(s) detected!`, "err");
    }} else if (data.total_live > 0) {{
      showToast(`✓ Scan complete — ${{data.total_live}} hosts, all known.`, "ok");
    }}
  }} catch (e) {{
    showToast("Scan failed: " + e.message, "err");
  }}
  btn.disabled = false;
  btn.textContent = "Scan Now";
  dot.className = "refresh-indicator";
}}

function openAddModal() {{
  document.getElementById("addModal").classList.add("active");
  document.getElementById("addIp").focus();
}}

function closeModal() {{
  document.getElementById("addModal").classList.remove("active");
}}

async function addHost() {{
  const ip = document.getElementById("addIp").value.trim();
  const note = document.getElementById("addNote").value.trim();
  if (!ip || !/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(ip)) {{
    showToast("Enter a valid IP address", "err");
    return;
  }}
  try {{
    const resp = await fetch("/api/baseline/add", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{ ip, note }})
    }});
    const data = await resp.json();
    if (data.success) {{
      showToast(`Added ${{ip}} to baseline`, "ok");
      closeModal();
      document.getElementById("addIp").value = "";
      document.getElementById("addNote").value = "";
      updateUI(await (await fetch("/api/scan")).json());
    }} else {{
      showToast(data.error || "Failed", "err");
    }}
  }} catch (e) {{
    showToast("Error: " + e.message, "err");
  }}
}}

async function removeHost(ip) {{
  if (!confirm(`Remove ${{ip}} from baseline?`)) return;
  try {{
    const resp = await fetch("/api/baseline/remove", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{ ip }})
    }});
    const data = await resp.json();
    if (data.success) {{
      showToast(`Removed ${{ip}}`, "ok");
      updateUI(await (await fetch("/api/scan")).json());
    }} else {{
      showToast(data.error || "Failed", "err");
    }}
  }} catch (e) {{
    showToast("Error: " + e.message, "err");
  }}
}}

function toggleAutoRefresh() {{
  autoRefresh = !autoRefresh;
  const btn = document.getElementById("refreshBtn");
  const dot = document.getElementById("refreshDot");
  if (autoRefresh) {{
    btn.textContent = "Auto-refresh: ON (30s)";
    dot.className = "refresh-indicator busy";
    refreshInterval = setInterval(() => runScan(), 30000);
    runScan();
  }} else {{
    btn.textContent = "Auto-refresh: OFF";
    dot.className = "refresh-indicator";
    if (refreshInterval) {{ clearInterval(refreshInterval); refreshInterval = null; }}
  }}
}}

// Initial load
fetch("/api/scan").then(r => r.json()).then(updateUI);
</script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default logging

    def do_GET(self):
        if self.path.startswith("/api/"):
            self.handle_api()
        else:
            self.handle_page()

    def do_POST(self):
        self.handle_api()

    def handle_page(self):
        if not check_auth(self.headers.get("Authorization")):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Network Guard"')
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(login_page().encode())
            return

        data = current_data.get("last_scan")
        oui = load_oui()

        hosts_table = build_host_table_html(data)
        baseline_section = build_baseline_html()
        history_section = build_history_html()
        alerts_section = build_alerts_html()

        html = HTML_TEMPLATE
        html = html.replace("{TITLE}", "Dashboard")
        html = html.replace("{USER}", AUTH_USER)
        html = html.replace("{HOSTS_TABLE}", hosts_table)
        html = html.replace("{BASELINE_SECTION}", baseline_section)
        html = html.replace("{HISTORY_SECTION}", history_section)
        html = html.replace("{ALERTS_SECTION}", alerts_section)
        html = html.replace("{TIMESTAMP}", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"))
        html = html.replace("{OUI_JSON}", json.dumps(oui))
        html = html.replace("{BASELINE_JSON}", json.dumps(load_baseline().get("known_hosts", {})))
        html = html.replace("{HISTORY_JSON}", json.dumps(load_scan_log()))
        html = html.replace("{ALERTS_JSON}", json.dumps(load_alerts()))

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def handle_api(self):
        if not check_auth(self.headers.get("Authorization")):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Network Guard"')
            self.end_headers()
            return

        path = self.path

        if path == "/api/scan":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            result = run_scan()
            self.wfile.write(json.dumps(result).encode())
            current_data["last_scan"] = result
            return

        if path == "/api/baseline/add":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            try:
                data = json.loads(body)
                ip = data.get("ip", "")
                note = data.get("note", "")
                result = add_baseline_host(ip, note)
            except Exception as e:
                result = {"success": False, "error": str(e)}
            self.send_json(result)
            return

        if path == "/api/baseline/remove":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            try:
                data = json.loads(body)
                result = remove_baseline_host(data.get("ip", ""))
            except Exception as e:
                result = {"success": False, "error": str(e)}
            self.send_json(result)
            return

        if path == "/api/baseline":
            self.send_json(load_baseline())
            return

        if path == "/api/status":
            self.send_json({
                "running": True,
                "port": PORT,
                "uptime": datetime.now(timezone.utc).isoformat(),
                "baseline_count": len(load_baseline().get("known_hosts", {}))
            })
            return

        self.send_json({"error": "not found"})

    def send_json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())


def build_host_table_html(data):
    if not data:
        return '<div class="empty"><div class="empty-icon">⟳</div>Loading...</div>'

    unknown = data.get("unknown", [])
    if not unknown:
        return '<div class="empty"><div class="empty-icon">✓</div>No unknown hosts — network is clean.</div>'

    rows = ""
    for h in unknown:
        status = '<span class="badge info">no ARP</span>' if h.get("mac") == "unknown" else '<span class="badge ok">resolved</span>'
        rows += f"""<tr>
          <td><strong>{h['ip']}</strong></td>
          <td style="font-family:monospace;font-size:12px;">{h.get('mac', '—')}</td>
          <td>{h.get('vendor', 'Unknown')}</td>
          <td>{status}</td>
        </tr>"""

    return f"""<table><thead><tr>
      <th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Status</th>
    </tr></thead><tbody>{rows}</tbody></table>"""


def build_baseline_html():
    baseline = load_baseline()
    hosts = baseline.get("known_hosts", {})
    entries = list(hosts.items())

    if not entries:
        return '<div class="empty"><div class="empty-icon">∅</div>No trusted hosts. Add one below.</div>'

    rows = ""
    for ip, info in sorted(entries):
        rows += f"""<tr>
          <td><strong>{ip}</strong></td>
          <td style="font-family:monospace;font-size:12px;">{info.get('mac', '—')}</td>
          <td>{info.get('vendor', 'Unknown')}</td>
          <td style="color:#8b949e;">{info.get('note', '—') or '—'}</td>
          <td style="font-size:12px;color:#8b949e;">{format_time(info.get('first_seen'))}</td>
          <td>
            <button class="btn danger" onclick="removeHost('{ip}')"
              style="padding:4px 8px;font-size:11px;">Remove</button>
          </td>
        </tr>"""

    return f"""<table><thead><tr>
      <th>IP</th><th>MAC</th><th>Vendor</th><th>Note</th><th>First Seen</th><th>Actions</th>
    </tr></thead><tbody>{rows}</tbody></table>
    <div style="margin-top:16px;">
      <button class="btn green" onclick="openAddModal()">+ Add Host</button>
    </div>"""


def build_history_html():
    entries = load_scan_log()
    if not entries:
        return '<div class="empty"><div class="empty-icon">📋</div>No scan history yet. Run a scan.</div>'

    rows = ""
    for e in reversed(entries[-10:]):
        ts = e.get("timestamp", "-")
        unk = e.get("unknown_count", 0)
        cls = "highlight" if unk > 0 else ""
        rows += f"""<div class="log-entry">
          <span class="ts">{format_time(ts)}</span> — {e.get('total_found', 0)} hosts, {e.get('known_count', 0)} known, <span class="{cls}">{unk} unknown</span>
          {e.get('subnet', '') and '· ' + e['subnet'] or ''}
        </div>"""

    return rows


def build_alerts_html():
    entries = load_alerts()
    if not entries:
        return '<div class="empty"><div class="empty-icon">✓</div>No alerts. Network is clean.</div>'

    rows = ""
    for e in reversed(entries[-10:]):
        ts = e.get("timestamp", "-")
        rows += f"""<div class="log-entry" style="border-left:3px solid #d29922;">
          <span class="ts">{format_time(ts)}</span> — <span class="highlight">ALERT: {len(e.get('new_hosts', []))} new host(s)</span>
        </div>"""
        for h in e.get("new_hosts", []):
            rows += f"""<div class="log-entry" style="padding-left:24px;font-size:11px;">
              {h.get('ip')} · {h.get('mac', '?')[:17]}... · {h.get('vendor', '?')}
            </div>"""

    return rows


def format_time(iso):
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso


def login_page():
    return """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Network Guard — Login</title>
<style>
  body { background: #0d1117; color: #c9d1d9;
         font-family: -apple-system, BlinkMacSystemFont, sans-serif;
         display: flex; align-items: center; justify-content: center;
         min-height: 100vh; margin: 0; }
  .login-box { background: #161b22; border: 1px solid #30363d; border-radius: 12px;
               padding: 40px; width: 100%; max-width: 360px; text-align: center; }
  .login-box h1 { color: #58a6ff; font-size: 22px; margin-bottom: 8px; }
  .login-box .sub { color: #8b949e; font-size: 13px; margin-bottom: 28px; }
  .login-box form { display: flex; flex-direction: column; gap: 12px; }
  .login-box input { background: #0d1117; border: 1px solid #30363d;
                     color: #c9d1d9; padding: 10px 14px; border-radius: 6px;
                     font-size: 14px; outline: none; width: 100%; }
  .login-box input:focus { border-color: #58a6ff; }
  .login-box button { background: #1f6feb; border: none; color: #fff;
                      padding: 10px; border-radius: 6px; font-size: 14px;
                      font-weight: 500; cursor: pointer; margin-top: 8px; }
  .login-box button:hover { background: #388bfd; }
  .login-box .error { color: #ff7b72; font-size: 13px; margin-top: 12px;
                       display: none; }
</style></head><body>
<div class="login-box">
  <h1>Network Guard</h1>
  <div class="sub">Local network monitoring dashboard</div>
  <form onsubmit="submitLogin(event)">
    <input type="text" id="user" placeholder="Username" autocomplete="off">
    <input type="password" id="pass" placeholder="Password" autocomplete="off">
    <button type="submit">Sign in</button>
  </form>
  <div class="error" id="err">Invalid credentials</div>
</div>
<script>
function submitLogin(e) {{
  e.preventDefault();
  const u = document.getElementById("user").value;
  const p = document.getElementById("pass").value;
  const credentials = btoa(u + ":" + p);
  fetch("/api/status", {{
    headers: {{ "Authorization": "Basic " + credentials }}
  }}).then(r => {{
    if (r.ok) {{ window.location.href = "/"; }}
    else {{
      document.getElementById("err").style.display = "block";
      document.getElementById("pass").value = "";
    }}
  }}).catch(() => {{
    document.getElementById("err").style.display = "block";
  }});
}}
</script></body></html>"""


# ── Server ──────────────────────────────────────────────────────────────
current_data = {"last_scan": None}


def main():
    print(f"[*] Network Guard Dashboard starting on http://{BIND}:{PORT}")
    print(f"[*] Login: {AUTH_USER} / Denmark1$")
    print(f"[*] Press Ctrl+C to stop.\n")

    server = HTTPServer((BIND, PORT), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
