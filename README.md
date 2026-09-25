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
apt-get install -y openscap-scanner ssg-base ssg-debian ssg-debderived \
  ssg-nondebian ssg-applications curl jq unzip coreutils
```

**Debian note:** The SSG content on Debian is split into multiple packages (`ssg-base`, `ssg-debian`, `ssg-debderived`, `ssg-nondebian`, `ssg-applications`). The `scap-security-guide` name is used on RHEL/Fedora. Also install `curl`, `jq`, `unzip` for the `fetch` command.

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

# Fix the CPE dictionary (Debian/Ubuntu only — run once, requires sudo)
stigctl fix-cpe
```

## Quick start

```bash
# 1. Fix the CPE dictionary (Debian/Ubuntu only — required before scanning)
sudo stigctl fix-cpe

# 2. Fetch the latest STIG data stream for this system's OS
./stigctl fetch
# → writes to ./stig-data/ssg-<os>-ds.xml (e.g. ssg-debian12-ds.xml)

# 3. Find available profiles
./stigctl list-profiles --ds stig-data/ssg-debian12-ds.xml

# 4. Scan (safe)
sudo ./stigctl scan --ds stig-data/ssg-debian12-ds.xml --profile stig --report report.html

# 5. Generate a reviewable remediation script
./stigctl plan --ds stig-data/ssg-debian12-ds.xml --profile stig --fix-type bash
# → review stig-remediation.sh, then apply:
sudo bash stig-remediation.sh

# 6. Re-scan to confirm
sudo ./stigctl scan --ds stig-data/ssg-debian12-ds.xml --profile stig
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

**Supported OS data streams** (from SSG releases): `ssg-rhel9-ds.xml`, `ssg-rhel10-ds.xml`, `ssg-ubuntu2404-ds.xml`, `ssg-debian12-ds.xml`, `ssg-centos8-ds.xml`, `ssg-ol9-ds.xml`, and many more. Use `fetch` with `--target-os` matching one of these names.

**Debian 13 (trixie):** The upstream ComplianceAsCode project does not yet ship SSG content for Debian 13. `stigctl` auto-detects Debian 13 and falls back to `debian12`. Use `--target-os debian12` explicitly if needed.

## CPE Dictionary Fix (Debian/Ubuntu)

The `openscap` package on Debian/Ubuntu has a known packaging bug: it deletes `/usr/share/openscap/cpe/` during build, so oscap cannot find `openscap-cpe-dict.xml` and fails with:

```
OpenSCAP Error: Unable to open file: /usr/share/openscap/cpe/openscap-cpe-dict.xml
```

stigctl has two protections against this:

1. **`stigctl fix-cpe`** — run once (requires sudo). Creates the missing directory and symlinks an SSG-provided CPE dictionary if SSG content is installed. If SSG is not installed, it prints the install commands.
2. **Auto-fix on scan/plan/remediate/generate** — every scanning command calls `fix_cpe` automatically. If it fails, the command continues with a warning (the scan may still work if the data stream bundles its own CPE content).

If `fix-cpe` cannot find an SSG CPE dictionary, you can manually download and place one:

```bash
sudo mkdir -p /usr/share/openscap/cpe
# Option A: symlink from SSG (if installed)
sudo ln -sf /usr/share/xml/scap/ssg/content/ssg-debian12-cpe-dictionary.xml \
            /usr/share/openscap/cpe/openscap-cpe-dict.xml
# Option B: use an SSG-provided CPE dict from any installed SSG platform package
```

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

## Windows STIG Automation (`stigctl.ps1`)

A companion PowerShell script for Windows Server and Windows Client STIG compliance,
built on **Microsoft PowerSTIG** (DSC-based STIG automation from the PowerShell Gallery).

### What it does

| Command | Description |
|---|---|
| `Install-PowerStig` | Install PowerSTIG + dependencies from PowerShell Gallery |
| `List-Stigs` | List all STIGs and versions available in the PowerSTIG module |
| `Generate-Config` | Generate a DSC configuration `.ps1` for a target STIG (OS version, role, STIG version, exceptions, skips) |
| `Compile-Config` | Dot-source and compile a generated `.ps1` to a `.mof` file |
| `Audit` | Run `Test-DscConfiguration` against a MOF — shows compliant and non-compliant settings |
| `Remediate` | Apply a MOF via `Start-DscConfiguration` (enforces STIG settings — reviewed first) |
| `Get-Status` | Show current DSC configuration status on the local machine |
| `Get-RuleHelp` | Show detailed help for a specific STIG rule ID (e.g. `V-73487`) |
| `Show-GpoRules` | List rules that are GPO-based (require manual Group Policy, not DSC) |
| `Fetch-DisaStig` | Print DISA STIG download URLs from `public.cyber.mil/stigs/downloads` |

### Architecture — Windows STIGs are not Linux STIGs

Windows STIGs are mostly **Group Policy (GPO)** and **registry settings**, not shell commands. There is no OpenSCAP equivalent for native Windows STIGs. The automation path is:

```
DISA STIG XCCDF → PowerSTIG parses XCCDF → DSC composite resources → Compile MOF
                                                              ↓
                                        Audit: Test-DscConfiguration
                                        Remediate: Start-DscConfiguration
```

PowerSTIG ships pre-processed STIG data (XML files in the module's `StigData/Processed` folder) that drives DSC resource generation. It handles rules that are automatable via DSC. Rules that are GPO-only or manual-observation-only are flagged by `Show-GpoRules` and `Generate-Config` so you know what needs manual application.

### Installation (PowerShell on Windows)

```powershell
# Run PowerShell as Administrator

# Install PowerSTIG from PowerShell Gallery
Install-Module -Name PowerSTIG -Scope CurrentUser -Force -AcceptLicense

# Or use stigctl.ps1:
.\stigctl.ps1 -Command Install-PowerStig
```

### Workflow

```powershell
# 1. Install PowerSTIG
.\stigctl.ps1 -Command Install-PowerStig

# 2. List available STIGs
.\stigctl.ps1 -Command List-Stigs

# 3. Generate a DSC config for Windows Server 2022 Member Server STIG v2.6
.\stigctl.ps1 -Command Generate-Config -CommandArgs @{
    Technology  = 'WindowsServer'
    OsVersion   = '2022'
    OsRole      = 'MS'          # MS = Member Server, DC = Domain Controller
    StigVersion = '2.6'
    OutputPath  = '.\WindowsServer-2022-MS-2.6.ps1'
}

# 4. Review the generated .ps1, then compile to MOF
.\stigctl.ps1 -Command Compile-Config -CommandArgs @{ ConfigPath = '.\WindowsServer-2022-MS-2.6.ps1' }

# 5. Audit the local system (run as Administrator)
.\stigctl.ps1 -Command Audit -CommandArgs @{ MofPath = '.\localhost.mof' }

# 6. If audit looks good, remediate (run as Administrator — CHANGES SETTINGS)
.\stigctl.ps1 -Command Remediate -CommandArgs @{ MofPath = '.\localhost.mof' }
```

### Handling GPO-only and manual rules

```powershell
# List rules that require manual Group Policy application
.\stigctl.ps1 -Command Show-GpoRules -CommandArgs @{
    Technology  = 'WindowsServer'
    OsVersion   = '2022'
    OsRole      = 'MS'
    StigVersion = '2.6'
}

# Apply GPO rules manually via:
#   • Group Policy Management Console (gpmc.msc) — domain-joined
#   • LGPO.exe — standalone / workgroup systems
#   • PowerShell: New-GPO -Name "STIG Baseline" | Set-GPPref...
```

### Exceptions and skips

```powershell
# Override a specific rule (e.g. V-1075 must be 1 instead of 0)
.\stigctl.ps1 -Command Generate-Config -CommandArgs @{
    Technology  = 'WindowsServer'
    OsVersion   = '2022'
    OsRole      = 'MS'
    StigVersion = '2.6'
    Exception   = @{ 'V-1075' = @{ ValueData = 1 } }
}

# Skip a specific rule
.\stigctl.ps1 -Command Generate-Config -CommandArgs @{
    Technology  = 'WindowsServer'
    OsVersion   = '2022'
    OsRole      = 'MS'
    StigVersion = '2.6'
    SkipRule    = 'V-253261'
}

# Skip an entire class of rules (e.g. AuditPolicyRule)
.\stigctl.ps1 -Command Generate-Config -CommandArgs @{
    Technology    = 'WindowsServer'
    OsVersion     = '2022'
    OsRole        = 'MS'
    StigVersion   = '2.6'
    SkipRuleType  = 'AuditPolicyRule'
}
```

### Rule help

```powershell
.\stigctl.ps1 -Command Get-RuleHelp -CommandArgs @{ RuleId = 'V-73487' }
```

### Getting the DISA STIG package (manual)

DISA's STIG downloads page (`public.cyber.mil/stigs/downloads/`) is a JavaScript SPA and cannot be scraped programmatically. Download manually:

```powershell
.\stigctl.ps1 -Command Fetch-DisaStig
```

This prints the current download URLs for all supported Windows STIGs. The ZIP packages contain:
- `*-Manual-xccdf.xml` — the XCCDF benchmark (for STIG Viewer / SCAP scanners)
- `*-OVAL.xml` — OVAL definitions
- Supporting files (PowerShell scripts for some rules, DoD EP XML, etc.)

These are used by STIG Viewer for compliance scoring. PowerSTIG's embedded STIG data is the primary automation path; DISA downloads supplement with manual GPO checklists and OVAL scanning.

### Supported STIGs in PowerSTIG

PowerSTIG covers (version-dependent, check `List-Stigs` for what's installed):

- `WindowsServer` — 2016, 2019, 2022, 2025 (MS and DC roles)
- `WindowsClient` — Windows 10, Windows 11
- `WindowsFirewall`
- `WindowsDnsServer`
- `WindowsDefender`
- `IisServer`, `IisSite`
- `SqlServer` — 2016, 2019, 2022
- `DotNetFramework`
- `Edge`, `Chrome`, `Firefox`, `InternetExplorer`
- `Microsoft Office` / `Office 365 ProPlus`
- And more (check `List-Stigs`)

### Safety

- **Review the generated .ps1 before compiling.** DSC remediation changes registry keys, GPO settings, service configurations, and more.
- **`Remediate` requires confirmation.** The script prompts before applying a MOF.
- **Run as Administrator** for audit and remediate operations.
- **Some changes require reboot.** The script warns about this.
- **GPO rules are not automatable via DSC.** Apply them via Group Policy Management or LGPO.exe.
- **Test on a non-production system first.**

### Requirements

| Component | Purpose | Install |
|---|---|---|
| `PowerSTIG` (PowerShell module) | DSC composite resources for STIG rules | `Install-Module -Name PowerSTIG -Scope CurrentUser` |
| `PSDscResources` | Built-in DSC resources (Registry, File, WindowsFeature, etc.) | Auto-installed as PowerSTIG dependency |
| `Windows PowerShell 5.1` or `PowerShell 7+` | DSC support | Pre-installed on Windows Server |
| Administrator rights | DSC audit/remediation | Run PowerShell as Administrator |
| WinRM (optional) | Remote DSC application | `Enable-PSRemoting -Force` |

### Differences from Linux `stigctl`

| Aspect | Linux `stigctl` | Windows `stigctl.ps1` |
|---|---|---|
| Scanning engine | OpenSCAP (`oscap`) | PowerSTIG DSC (`Test-DscConfiguration`) |
| Content source | SCAP Security Guide GitHub releases | PowerSTIG PSGallery + DISA STIG downloads |
| Remediation format | Bash script / Ansible playbook | DSC MOF + `Start-DscConfiguration` |
| Content fetch | `fetch` downloads SSG ZIP via GitHub API | `Install-PowerStig` from PSGallery; DISA downloads are manual |
| Rule coverage | Mostly automatable via bash | Mix of DSC-automatable, GPO-manual, and audit-only |
| Checksums | SHA-512 verification of downloads | PowerShell Gallery module signature verification |

## License

MIT
