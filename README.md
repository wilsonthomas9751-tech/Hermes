# stigctl — DISA/STIG Compliance Automation

A bash wrapper around **OpenSCAP (`oscap`)** for scanning Linux systems against XCCDF security profiles (DISA STIGs, CIS, OSPP, etc.) and generating or applying remediation scripts.

## What it does

| Mode | Description |
|---|---|
| `scan` | Evaluate the system against a STIG profile → XCCDF results XML + optional HTML report |
| `plan` | Scan, then generate a **reviewable** remediation script from failed rules only (safe default) |
| `remediate` | Scan + apply fixes in one pass via `oscap --remediate` (destructive — requires `--yes`) |
| `generate` | Dump every remediation in a profile without scanning (for offline review or pipeline input) |
| `list-profiles` | List available XCCDF profiles in a data stream |
| `info` | Show data-stream metadata |
| `fetch` | Download the latest SCAP Security Guide data stream from GitHub, auto-detect the target OS, extract the matching data stream, and verify SHA-512 |

## Installation

### Prerequisites

| Command group | Required tools |
|---|---|
| `scan`, `plan`, `remediate`, `generate`, `list-profiles`, `info` | `openscap-scanner` (provides `oscap`) |
| `fetch` | `curl`, `jq`, `unzip`, `sha512sum` (from `coreutils`) |

### Install on Debian / Ubuntu

```bash
apt-get update
apt-get install -y openscap-scanner curl jq unzip coreutils
```

### Install on RHEL / CentOS / Fedora / Rocky / AlmaLinux

```bash
# RHEL/CentOS 8+
dnf install -y openscap-scanner scap-security-guide curl jq unzip

# Fedora
dnf install -y openscap-scanner scap-security-guide curl jq unzip

# Older RHEL/CentOS (yum)
yum install -y openscap-scanner scap-security-guide curl jq unzip
```

### Install the script

```bash
# Clone the repo (or copy stigctl from the release)
git clone git@github.com:wilsonthomas9751-tech/Hermes.git
cd Hermes

# Make executable
chmod +x stigctl

# Optional: install system-wide
sudo cp stigctl /usr/local/bin/stigctl
sudo chmod +x /usr/local/bin/stigctl
```

### Verify installation

```bash
stigctl --help
stigctl fetch --help
```

## Quick start

```bash
# 1. Fetch the latest STIG data stream for this system's OS
./stigctl fetch
# → writes to ./stig-data/ssg-<os>-ds.xml (e.g. ssg-debian13-ds.xml)

# 2. Find available profiles
./stigctl list-profiles --ds stig-data/ssg-debian13-ds.xml

# 3. Scan (safe)
sudo ./stigctl scan --ds stig-data/ssg-debian13-ds.xml --profile stig --report report.html

# 4. Generate a reviewable remediation script
./stigctl plan --ds stig-data/ssg-debian13-ds.xml --profile stig --fix-type bash
# → review stig-remediation.sh, then apply:
sudo bash stig-remediation.sh

# 5. Re-scan to confirm
sudo ./stigctl scan --ds stig-data/ssg-debian13-ds.xml --profile stig
```

## Fetch — always get the latest STIG content

`stigctl fetch` pulls the latest release from the [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) project (the upstream of `scap-security-guide`), extracts only the data stream for your OS, and verifies the SHA-512 checksum.

```bash
# Auto-detect OS, download, verify, extract → ./stig-data/ssg-<os>-ds.xml
./stigctl fetch

# Specify a target OS explicitly
./stigctl fetch --target-os rhel9
./stigctl fetch --target-os ubuntu2404
./stigctl fetch --target-os debian12

# Custom output directory
./stigctl fetch --target-os rhel9 --output-dir /opt/stig

# Skip SHA-512 verification (not recommended)
./stigctl fetch --no-verify
```

**What it does internally:**

1. Queries the GitHub API for the latest ComplianceAsCode/content release
2. Downloads the release ZIP + SHA-512 checksum file
3. Verifies the checksum (unless `--no-verify`)
4. Extracts only the requested `*-ds.xml` file
5. Writes it to `--output-dir` (default: `./stig-data`)
6. Cleans up the temporary download

**OS auto-detection:** reads `/etc/os-release` and maps to SSG data stream names. Supports `debian`, `ubuntu`, `rhel`, `centos`, `rocky`, `almalinux`, `ol`/`oraclelinux`, `fedora`, and derivatives via `ID_LIKE`. Use `--target-os` when auto-detection fails.

**Supported OS data streams** (from SSG releases): `ssg-rhel9-ds.xml`, `ssg-rhel10-ds.xml`, `ssg-ubuntu2404-ds.xml`, `ssg-debian12-ds.xml`, `ssg-debian13-ds.xml`, `ssg-centos8-ds.xml`, `ssg-ol9-ds.xml`, and many more. Use `fetch` with `--target-os` matching one of these names.

## Fix types

`bash` (default), `ansible`, `puppet`, `anaconda`, `ignition`, `kickstart`, `blueprint`

Not every rule has a remediation in every format — check generated output for gaps.

## Safety

- **Never apply remediation without reviewing it first.** STIG rules can disable services, restrict network access, change kernel parameters, enforce password policies, remove packages.
- **`remediate` requires `--yes`.** The script refuses without it.
- **Match the data stream to the target OS.** A RHEL 8 profile won't apply correctly to Ubuntu 22.04.
- **Not all rules are automatable.** Some STIG requirements need manual configuration.
- **Test on a non-production system first.**
- **Fetch verifies checksums by default.** The downloaded ZIP is SHA-512 verified against the official release checksum. Use `--no-verify` only when you must.

## Full command reference

```
stigctl <command> [options]

Commands:
  scan         Scan system against STIG profile. Outputs XCCDF results XML.
  plan         Scan, then generate a reviewable remediation script (safe).
  remediate    Scan and apply fixes in one pass (DANGEROUS — requires --yes).
  generate     Generate remediation script for ALL rules in profile (no scan).
  list-profiles List available XCCDF profiles in the data stream.
  info         Show data-stream metadata.
  fetch        Download latest SCAP Security Guide data stream from GitHub.

Options:
  --profile <id>        XCCDF profile name or ID (default: "stig")
  --ds <file>           Path to SCAP data stream XML
  --fix-type <type>     Remediation format: bash, ansible, puppet, anaconda,
                        ignition, kickstart, blueprint (default: bash)
  --output <file>       Output script filename (default: stig-remediation.sh)
  --results <file>      Results XML filename (default: stig-results.xml)
  --report <htmlfile>   Also produce an HTML report
  --extra "..."         Extra args forwarded to oscap xccdf eval
  --yes                 required for 'remediate' (acknowledge risk)
  --target-os <id>      OS ID for fetch (e.g. rhel9, ubuntu2404, debian12).
                        Auto-detected if omitted.
  --output-dir <dir>    Directory to write fetched data stream (default: ./stig-data)
  --no-verify           Skip SHA-512 checksum verification (not recommended)
  -h, --help            Show help
```

## Underlying oscap commands

```bash
# Scan
sudo oscap xccdf eval --profile <profile> --results results.xml [--report report.html] <data-stream.xml>

# Scan + live remediate
sudo oscap xccdf eval --profile <profile> --remediate <data-stream.xml>

# Generate fix from results (only failed rules)
oscap xccdf generate fix --result-id <result-id> --fix-type bash --output fix.sh results.xml

# Generate fix for ALL rules (no scan)
oscap xccdf generate fix --profile <profile> --fix-type bash --output fix.sh <data-stream.xml>
```

## Data stream locations

Pre-built data streams from `scap-security-guide`:

```
/usr/share/xml/scap/ssg/content/ssg-<os>-ds.xml
```

Or fetch fresh ones with `stigctl fetch`.

## Requirements summary

| Component | Purpose | Install |
|---|---|---|
| `openscap-scanner` | Provides `oscap` for scanning and remediation | `apt-get install openscap-scanner` / `dnf install openscap-scanner` |
| `scap-security-guide` | Pre-built data streams at `/usr/share/xml/scap/ssg/content/` | `dnf install scap-security-guide` (RHEL-family) |
| `curl` | HTTP downloads (fetch command) | `apt-get install curl` / `dnf install curl` |
| `jq` | JSON parsing of GitHub API response (fetch command) | `apt-get install jq` / `dnf install jq` |
| `unzip` | Extract SSG release ZIP (fetch command) | `apt-get install unzip` / `dnf install unzip` |
| `coreutils` | Provides `sha512sum` for checksum verification (fetch command) | Pre-installed on most distros |
| `sudo` / root access | Required for running oscap scans and applying remediations | Pre-installed |

## License

MIT
