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

## Quick start

```bash
# 1. Install OpenSCAP
#    Debian/Ubuntu:  apt-get install openscap-scanner
#    RHEL/CentOS:    dnf install openscap-scanner scap-security-guide

# 2. Find available profiles in your data stream
./stigctl list-profiles --ds /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml

# 3. Scan (safe)
sudo ./stigctl scan --ds ssg-rhel8-ds.xml --profile stig --report report.html

# 4. Generate a reviewable remediation script
./stigctl plan --ds ssg-rhel8-ds.xml --profile stig --fix-type bash
# → review stig-remediation.sh, then apply:
sudo bash stig-remediation.sh

# 5. Re-scan to confirm
sudo ./stigctl scan --ds ssg-rhel8-ds.xml --profile stig
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

Options:
  --profile <id>        XCCDF profile name or ID (default: "stig")
  --ds <file>           Path to SCAP data stream XML (required)
  --fix-type <type>     Remediation format: bash, ansible, puppet, anaconda,
                        ignition, kickstart, blueprint (default: bash)
  --output <file>       Output script filename (default: stig-remediation.sh)
  --results <file>      Results XML filename (default: stig-results.xml)
  --report <htmlfile>   Also produce an HTML report
  --extra "..."         Extra args forwarded to oscap xccdf eval
  --yes                 required for 'remediate' (acknowledge risk)
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

Examples: `ssg-rhel8-ds.xml`, `ssg-rhel9-ds.xml`, `ssg-ubuntu2204-ds.xml`, `ssg-debian11-ds.xml`.

## Requirements

- `openscap-scanner` (provides `oscap`)
- A SCAP data stream XML file (from `scap-security-guide` package or DISA STIG download)
- Root access for scanning (`sudo`)

## License

MIT
