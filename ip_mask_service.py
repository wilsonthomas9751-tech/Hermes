"""
IP Mask Decoder — Windows Service
===================================
Run this script to install, start, stop, or remove the service.

Usage:
  python ip_mask_service.py install    # Install the service
  python ip_mask_service.py start      # Start the service
  python ip_mask_service.py stop       # Stop the service
  python ip_mask_service.py remove     # Remove the service
  python ip_mask_service.py run        # Run in console (debug mode, no service)

Prerequisites:
  - pywin32: pip install pywin32
  - The ip_mask_windows.py tool must be in the same directory or in PATH
  - Run the installer as Administrator

Service configuration (edit DEFAULT_CONFIG below or set env vars):
  PRIV_KEY_PATH  — path to private.pem
  HOST_IP        — IP to bind to (0.0.0.0 = all)
  ENC_MODE       — ec or rsa
  LOG_FILE       — optional log file path
"""

import os
import sys
import subprocess
import win32serviceutil
import win32service
import win32event
import servicemanager
import threading


# ============================================================================
# Default configuration (overridden by environment variables)
# ============================================================================
DEFAULT_CONFIG = {
    "PRIV_KEY_PATH": r"C:\ip-mask\keys\private.pem",
    "HOST_IP": "0.0.0.0",
    "ENC_MODE": "ec",
    "LOG_FILE": "",  # e.g. r"C:\ip-mask\decoder.log"
    "IFACE": "",     # e.g. "Ethernet" — leave blank for default
    "SCRIPT_PATH": "",  # path to ip_mask_windows.py, auto-detected if blank
}


def get_config():
    """Read config from env vars, falling back to defaults."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return {
        "PRIV_KEY_PATH": os.environ.get("PRIV_KEY_PATH", DEFAULT_CONFIG["PRIV_KEY_PATH"]),
        "HOST_IP": os.environ.get("HOST_IP", DEFAULT_CONFIG["HOST_IP"]),
        "ENC_MODE": os.environ.get("ENC_MODE", DEFAULT_CONFIG["ENC_MODE"]),
        "LOG_FILE": os.environ.get("LOG_FILE", DEFAULT_CONFIG["LOG_FILE"]),
        "IFACE": os.environ.get("IFACE", DEFAULT_CONFIG["IFACE"]),
        "SCRIPT_PATH": os.environ.get("SCRIPT_PATH", ""),
    }


class IPMaskDecoderService(win32serviceutil.ServiceFramework):
    """
    Windows Service that runs the IP Mask decoder in the background.
    Listens for incoming masked packets and decrypts the real IP.
    """

    _svc_name_ = "IPMaskDecoder"
    _svc_display_name_ = "IP Mask Decoder Service"
    _svc_description_ = (
        "Decrypts incoming IP-masked packets and logs the real source IPs. "
        "Requires Npcap + admin rights. Uses protocol 253 (experimental)."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.stop_requested = False
        self.thread = None
        self.process = None

    def SvcStop(self):
        """Called when the service is asked to stop."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_requested = True
        win32event.SetEvent(self.hWaitStop)
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

    def SvcDoRun(self):
        """Main service entry point."""
        import servicemanager
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, "Service starting..."))

        try:
            self._run_loop()
        except Exception as e:
            servicemanager.LogMsg(servicemanager.EVENTLOG_ERROR_TYPE,
                                  servicemanager.PYS_SERVICE_FAILURE,
                                  (self._svc_name_, f"Service failed: {e}"))
            raise

    def _run_loop(self):
        """Run the capture in a background thread."""
        config = get_config()

        # Resolve script path
        script_path = config["SCRIPT_PATH"] or \
                      os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "ip_mask_windows.py")
        if not os.path.isfile(script_path):
            raise FileNotFoundError(
                f"ip_mask_windows.py not found at {script_path}\n"
                f"Place it next to this service script or set SCRIPT_PATH env var."
            )

        if not os.path.isfile(config["PRIV_KEY_PATH"]):
            raise FileNotFoundError(
                f"Private key not found at {config['PRIV_KEY_PATH']}\n"
                f"Generate keys first: python ip_mask_windows.py generate-keys --type ec "
                f"--out <dir>"
            )

        cmd = [
            sys.executable, script_path, "capture",
            "--priv-key", config["PRIV_KEY_PATH"],
            "--ec" if config["ENC_MODE"] == "ec" else "",
            "--host", config["HOST_IP"],
        ]
        if config["IFACE"]:
            cmd += ["--iface", config["IFACE"]]
        if config["LOG_FILE"]:
            cmd += ["--log-file", config["LOG_FILE"]]

        # Remove empty strings from cmd
        cmd = [x for x in cmd if x]

        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, f"Starting capture: {' '.join(cmd)}"))

        # Run as background thread — the service framework needs the thread to be alive
        # while the service is running. We'll use a subprocess so we can kill it on stop.
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        # Periodic check: read output and log it, check for stop signal
        import select

        while not self.stop_requested:
            # Wait for stop event or output with timeout
            rc = win32event.WaitForSingleObject(self.hWaitStop, 1000)  # 1 second
            if rc == win32event.WAIT_OBJECT_0:
                break  # stop requested

            # Read available output
            try:
                line = self.process.stdout.readline()
                if line:
                    servicemanager.LogInfoMsg(f"[IPMaskDecoder] {line.rstrip()}")
            except Exception:
                pass

            # Check if process exited unexpectedly
            if self.process.poll() is not None:
                exit_code = self.process.returncode
                svc_status = "stopped" if exit_code == 0 else f"crashed (code {exit_code})"
                servicemanager.LogMsg(servicemanager.EVENTLOG_WARNING_TYPE,
                                      servicemanager.PYS_SERVICE_FAILURE,
                                      (self._svc_name_,
                                       f"Capture process {svc_status}"))
                # Restart after a delay (unless stopping)
                if not self.stop_requested:
                    servicemanager.LogInfoMsg("[IPMaskDecoder] Restarting in 5 seconds...")
                    win32event.WaitForSingleObject(self.hWaitStop, 5000)
                    if not self.stop_requested:
                        self.process = subprocess.Popen(
                            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        servicemanager.LogInfoMsg("[IPMaskDecoder] Restarted.")

        # Cleanup
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass


# ============================================================================
# Console mode (for debugging — no service)
# ============================================================================

def run_console():
    """Run the capture directly in the console (no service wrapper)."""
    config = get_config()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = config["SCRIPT_PATH"] or \
                  os.path.join(script_dir, "ip_mask_windows.py")

    if not os.path.isfile(script_path):
        print(f"ERROR: ip_mask_windows.py not found at {script_path}")
        sys.exit(1)

    if not os.path.isfile(config["PRIV_KEY_PATH"]):
        print(f"ERROR: Private key not found at {config['PRIV_KEY_PATH']}")
        print(f"Generate keys first:")
        print(f"  python ip_mask_windows.py generate-keys --type ec --out {os.path.dirname(config['PRIV_KEY_PATH'])}")
        sys.exit(1)

    cmd = [
        sys.executable, script_path, "capture",
        "--priv-key", config["PRIV_KEY_PATH"],
    ]
    if config["ENC_MODE"] == "ec":
        cmd.append("--ec")
    if config["HOST_IP"] and config["HOST_IP"] != "0.0.0.0":
        cmd += ["--host", config["HOST_IP"]]
    if config["IFACE"]:
        cmd += ["--iface", config["IFACE"]]
    if config["LOG_FILE"]:
        cmd += ["--log-file", config["LOG_FILE"]]

    print(f"Running in console mode (Ctrl-C to stop)...")
    print(f"  Command: {' '.join(cmd)}")
    print()
    os.execv(sys.executable, cmd)


# ============================================================================
# CLI for service management
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    action = sys.argv[1].lower()

    if action == "run":
        # Console mode — does NOT use service framework
        run_console()
    elif action in ("install", "start", "stop", "remove", "update",
                    "debug", "help"):
        # Pass through to win32serviceutil
        # Insert our service class and script name
        sys.argv = [sys.argv[0], action] + sys.argv[2:]
        win32serviceutil.HandleCommandLine(IPMaskDecoderService)
    else:
        print(f"Unknown action: {action}")
        print("Valid actions: install, start, stop, remove, run, debug, help")
        sys.exit(1)
