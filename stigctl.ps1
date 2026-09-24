<#
.SYNOPSIS
    stigctl.ps1 — DISA STIG compliance helper for Windows Server and Windows Client.
.DESCRIPTION
    PowerShell wrapper around Microsoft PowerSTIG (DSC-based STIG automation) and
    DISA STIG content. Provides commands to install PowerSTIG, list available STIGs,
    generate DSC audit/remediation configurations, compile MOFs, audit a system,
    and apply remediations.

    Windows STIGs differ fundamentally from Linux STIGs: most rules are Group Policy
    (GPO) or registry settings, not shell commands. PowerSTIG uses PowerShell DSC
    composite resources to translate STIG rules into enforceable configuration.
    Many rules still require manual GPO application — the script documents both.

.PARAMETER Command
    The action to perform. Run `.\stigctl.ps1 -Command Help` for details.

.PARAMETER CommandArgs
    Arguments for the selected command, passed as a hashtable or array.

.EXAMPLE
    .\stigctl.ps1 -Command Install-PowerStig
    .\stigctl.ps1 -Command List-Stigs
    .\stigctl.ps1 -Command Generate-Config -CommandArgs @{Technology='WindowsServer'; OsVersion='2022'; OsRole='MS'; StigVersion='2.6'}
    .\stigctl.ps1 -Command Compile-Config -CommandArgs @{ConfigPath='.\WindowsServer-2022-MS-2.6.ps1'}
    .\stigctl.ps1 -Command Audit -CommandArgs @{MofPath='.\localhost.mof'}
    .\stigctl.ps1 -Command Remediate -CommandArgs @{MofPath='.\localhost.mof'}
    .\stigctl.ps1 -Command Get-Status
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Command,

    [Parameter(Position = 1)]
    [hashtable]$CommandArgs = @{}
)

#-------------------------------------------------------------------------------
# Global helpers
#-------------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Step)
    Write-Host "  >>> $Step" -ForegroundColor Yellow
}

function Write-Ok {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor DarkYellow
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "  [ERROR] $Message" -ForegroundColor Red
}

function ConvertTo-Bool {
    param([string]$Value)
    if ($null -eq $Value -or $Value -eq '') { return $false }
    return ($Value -eq $true -or $Value -eq 'true' -or $Value -eq '1' -or $Value -eq 'yes')
}

#-------------------------------------------------------------------------------
# Check requirements
#-------------------------------------------------------------------------------
function Test-PowerStigInstalled {
    if (-not (Get-Module -ListAvailable -Name PowerStig)) {
        return $false
    }
    $ver = (Get-Module -ListAvailable -Name PowerStig | Select-Object -First 1).Version
    Write-Info "PowerSTIG $ver found."
    return $true
}

function Test-PSModuleInstalled {
    param([string]$ModuleName)
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        return $false
    }
    return $true
}

function Install-PowerStigModule {
    Write-Step "Installing PowerSTIG from PowerShell Gallery..."
    try {
        if (-not (Test-PSModuleInstalled -ModuleName 'PowerStig')) {
            Write-Host "  Installing PowerSTIG (this may take a moment)..." -ForegroundColor Cyan
            Install-Module -Name PowerStig -Scope CurrentUser -Force -AcceptLicense -ErrorAction Stop
            Write-Ok "PowerSTIG installed."
        } else {
            Write-Ok "PowerSTIG already installed."
        }
    } catch {
        Write-ErrorMsg "Failed to install PowerSTIG: $_"
        Write-Host "  Try manually: Install-Module -Name PowerStig -Scope CurrentUser" -ForegroundColor Red
        return $false
    }
    return $true
}

#-------------------------------------------------------------------------------
# Command: Help
#-------------------------------------------------------------------------------
function Invoke-Help {
    Write-Header "stigctl.ps1 — Windows STIG Compliance Automation"
    Write-Host @'
 stigctl.ps1 wraps Microsoft PowerSTIG (DSC-based STIG automation) to help you
 download, audit, and remediate DISA STIGs on Windows Server and Windows Client.

 Windows STIGs are mostly Group Policy (GPO) and registry settings — not shell
 commands. PowerSTIG translates STIG rules into DSC composite resources that can
 audit and enforce settings via compiled MOF files. Many rules still require
 manual GPO application; the script flags both automated and manual rules.

 COMMANDS
 -------------------------------------------------------------------------------
 Install-PowerStig   Install PowerSTIG + dependencies from PowerShell Gallery.

 List-Stigs          List all STIGs and versions available in the installed
                     PowerSTIG module. Use this to find the right Technology/
                     OsVersion/OsRole/StigVersion for your target.

 Generate-Config     Generate a DSC configuration .ps1 file for a given STIG.
                     Review this file before compiling. Supports:
                       • Technology: WindowsServer | WindowsClient | WindowsFirewall
                         | WindowsDnsServer | WindowsDefender | ...
                       • OsVersion: 2016 | 2019 | 2022 | 2025 | 10 | 11 | ...
                       • OsRole: MS (Member Server) | DC (Domain Controller)
                       • StigVersion: e.g. 2.6 (find with List-Stigs)
                       • Exception: hashtable of rule overrides (e.g. V-1075)
                       • SkipRule: single rule ID to skip
                       • SkipRuleType: rule type to skip (e.g. AuditPolicyRule)
                       • OrgSettings: path to org settings XML file

 Compile-Config     Compile a generated .ps1 configuration to a .mof file.
                     Run as Administrator if the config references system settings.

 Audit              Run Test-DscConfiguration against a MOF to check compliance.
                     Output shows compliant and non-compliant settings.

 Remediate          Apply a MOF via Start-DscConfiguration (enforces STIG settings).
                     Run as Administrator. Review the MOF first.

 Get-Status         Show current DSC configuration status on the local machine.

 Get-RuleHelp       Show detailed help for a specific STIG rule ID (e.g. V-73487).

 Show-GpoRules      Show which rules in a STIG are GPO-based (require manual
                     Group Policy application, not DSC automation).

 Fetch-DisaStig     Print download URLs for DISA STIG packages from
                     public.cyber.mil/stigs/downloads. DISA's site is a JS SPA
                     and cannot be scraped programmatically from a script; this
                     prints the URLs so you can download manually or via your
                     enterprise download tool.

 OPTIONS (for Generate-Config)
 -------------------------------------------------------------------------------
 -Technology    WindowsServer | WindowsClient | WindowsFirewall | ...
 -OsVersion    2016 | 2019 | 2022 | 2025 | 10 | 11 (matches STIG naming)
 -OsRole       MS (Member Server) | DC (Domain Controller)
 -StigVersion  STIG release version, e.g. 2.6 (find with List-Stigs)
 -Exception    Hashtable of rule overrides: @{ 'V-1075' = @{ ValueData = 1 } }
 -SkipRule     Single rule ID to skip: 'V-1075'
 -SkipRuleType Skip a class of rules: 'AuditPolicyRule'
 -OrgSettings  Path to organizational settings XML file
 -OutputPath   Where to write the generated .ps1 (default: current directory)

 EXAMPLES
 -------------------------------------------------------------------------------
 # Install PowerSTIG
 .\stigctl.ps1 -Command Install-PowerStig

 # List available Windows Server STIGs
 .\stigctl.ps1 -Command List-Stigs

 # Generate a DSC config for Windows Server 2022 Member Server STIG v2.6
 .\stigctl.ps1 -Command Generate-Config -CommandArgs @{
     Technology = 'WindowsServer'
     OsVersion  = '2022'
     OsRole     = 'MS'
     StigVersion = '2.6'
     OutputPath = '.\WindowsServer-2022-MS-2.6.ps1'
 }

 # Compile the config to MOF
 .\stigctl.ps1 -Command Compile-Config -CommandArgs @{ ConfigPath = '.\WindowsServer-2022-MS-2.6.ps1' }

 # Audit the local system against the MOF (run as Administrator)
 .\stigctl.ps1 -Command Audit -CommandArgs @{ MofPath = '.\localhost.mof' }

 # Apply remediation (run as Administrator — this changes system settings!)
 .\stigctl.ps1 -Command Remediate -CommandArgs @{ MofPath = '.\localhost.mof' }

 SAFETY
 -------------------------------------------------------------------------------
 • Never apply a MOF without reviewing the generated .ps1 configuration first.
 • DSC remediation changes registry keys, GPO settings, service configs, etc.
 • Some STIG rules are GPO-only and cannot be applied via DSC — they require
   Group Policy Management Console (gpmc.msc) or LGPO.exe.
 • Test on a non-production system first.
 • Run as Administrator for audit/remediate operations.
'@
    Write-Host ""
}

#-------------------------------------------------------------------------------
# Command: Install-PowerStig
#-------------------------------------------------------------------------------
function Invoke-InstallPowerStig {
    Write-Header "Installing PowerSTIG"

    $missing = @()
    if (-not (Get-Module -ListAvailable -Name PowerStig)) { $missing += 'PowerStig' }

    if ($missing.Count -gt 0) {
        Write-Step "The following modules are missing: $($missing -join ', ')"
        $confirm = Read-Host "Install them from PowerShell Gallery? (y/n)"
        if ($confirm -ne 'y') {
            Write-Warn "Installation cancelled. Run manually: Install-Module -Name PowerStig -Scope CurrentUser"
            return
        }
        if (-not (Install-PowerStigModule)) {
            Write-ErrorMsg "Installation failed. See errors above."
            return
        }
    }

    Write-Step "Verifying installation..."
    $ver = (Get-Module -ListAvailable -Name PowerStig | Select-Object -First 1).Version
    Write-Ok "PowerSTIG $ver is installed."

    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Cyan
    Write-Host "    1. List available STIGs:  .\stigctl.ps1 -Command List-Stigs" -ForegroundColor White
    Write-Host "    2. Generate a config:      .\stigctl.ps1 -Command Generate-Config ..." -ForegroundColor White
    Write-Host "    3. Compile + audit + apply" -ForegroundColor White
    Write-Host ""
}

#-------------------------------------------------------------------------------
# Command: List-Stigs
#-------------------------------------------------------------------------------
function Invoke-ListStigs {
    Write-Header "Available STIGs in PowerSTIG"

    if (-not (Test-PowerStigInstalled)) {
        Write-ErrorMsg "PowerSTIG is not installed. Run: .\stigctl.ps1 -Command Install-PowerStig"
        return
    }

    Import-Module PowerStig -ErrorAction Stop

    Write-Step "Enumerating STIGs by Technology..."

    $stigs = Get-Stig -ListAvailable

    if ($stigs.Count -eq 0) {
        Write-Warn "No STIGs found in PowerSTIG data. The module may need to be reinstalled."
        return
    }

    # Group by technology
    $byTech = $stigs | Group-Object -Property Technology

    foreach ($tech in $byTech) {
        Write-Host ""
        Write-Host "  $($tech.Name)" -ForegroundColor Cyan
        Write-Host "  $(('-' * 60).Substring(0, [Math]::Min(60, $tech.Name.Length + 20)))" -ForegroundColor DarkGray

        $tech.Group | Sort-Object TechnologyVersion, TechnologyRole | ForEach-Object {
            $roleLabel = if ($_.TechnologyRole -eq 'MS') { 'Member Server' }
                         elseif ($_.TechnologyRole -eq 'DC') { 'Domain Controller' }
                         else { $_.TechnologyRole }
            Write-Host "    Version: $($_.TechnologyVersion)  Role: $($roleLabel.PadRight(20))  Rules: $($_.RuleList.Count)" -ForegroundColor White
        }
    }

    Write-Host ""
    Write-Host "  Tip: Use -StigVersion with Generate-Config. Example: 2.6" -ForegroundColor Yellow
    Write-Host ""
}

#-------------------------------------------------------------------------------
# Command: Generate-Config
#-------------------------------------------------------------------------------
function Invoke-GenerateConfig {
    Write-Header "Generating DSC Configuration"

    $tech    = $CommandArgs['Technology']
    $osVer   = $CommandArgs['OsVersion']
    $osRole  = $CommandArgs['OsRole']
    $stigVer = $CommandArgs['StigVersion']
    $exc     = $CommandArgs['Exception']
    $skip    = $CommandArgs['SkipRule']
    $skipType = $CommandArgs['SkipRuleType']
    $orgPath = $CommandArgs['OrgSettings']
    $outPath = $CommandArgs['OutputPath']

    if (-not $tech -or -not $osVer -or -not $osRole -or -not $stigVer) {
        Write-ErrorMsg "Missing required parameters: Technology, OsVersion, OsRole, StigVersion"
        Write-Host "  Run .\stigctl.ps1 -Command List-Stigs to find valid values." -ForegroundColor Red
        return
    }

    if (-not (Test-PowerStigInstalled)) {
        Write-ErrorMsg "PowerSTIG is not installed. Run: .\stigctl.ps1 -Command Install-PowerStig"
        return
    }

    Import-Module PowerStig -ErrorAction Stop

    # Validate the STIG exists
    $available = Get-Stig -Technology $tech | Where-Object {
        $_.TechnologyVersion -eq $osVer -and $_.TechnologyRole -eq $osRole
    }

    if ($available.Count -eq 0) {
        Write-ErrorMsg "No STIG found for Technology=$tech, OsVersion=$osVer, OsRole=$osRole"
        Write-Host "  Available combinations:" -ForegroundColor Yellow
        Get-Stig -Technology $tech | ForEach-Object {
            Write-Host "    OsVersion=$($_.TechnologyVersion)  OsRole=$($_.TechnologyRole)  Version=$($_.Version)" -ForegroundColor White
        }
        return
    }

    # Check that the requested StigVersion exists
    $validVersions = $available | ForEach-Object { $_.Version } | Select-Object -Unique
    if ($validVersions -notcontains $stigVer) {
        Write-Warn "StigVersion '$stigVer' not found for this combination. Available: $($validVersions -join ', ')"
        Write-Host "  Attempting to use '$stigVer' anyway — PowerSTIG may still find embedded data." -ForegroundColor Yellow
    }

    $outPath = if ($outPath) { $outPath } else { ".\${tech}_${osVer}_${osRole}_${stigVer}.ps1" }

    Write-Step "Building DSC configuration: $outPath"

    # Build the configuration script
    $configLines = @()
    $configLines += '<#'
    $configLines += '# Auto-generated by stigctl.ps1'
    $configLines += "# Technology: $tech | OsVersion: $osVer | OsRole: $osRole | StigVersion: $stigVer"
    $configLines += '# Review this file before compiling. Edit exceptions, skips, and org settings as needed.'
    $configLines += '<#'
    $configLines += ''
    $configLines += 'configuration STIGBaseline {'
    $configLines += '    param ('
    $configLines += '        [parameter()]'
    $configLines += '        [string] $NodeName = "localhost"'
    $configLines += '    )'
    $configLines += ''
    $configLines += '    Import-DscResource -ModuleName PowerStig'
    $configLines += ''
    $configLines += '    Node $NodeName {'

    # Build the composite resource parameters
    $params = @()
    $params += '        OsVersion      = "'$osVer'"'
    $params += '        OsRole         = "'$osRole'"'
    $params += '        StigVersion    = "'$stigVer'"'

    if ($orgPath) {
        $params += '        OrgSettings    = "' + $orgPath + '"'
    }

    if ($exc -and $exc.Count -gt 0) {
        $excJson = $exc | ConvertTo-Json -Depth 3
        $params += '        Exception      = @{' + ( $exc.GetEnumerator() | ForEach-Object {
            $v = $_.Value
            if ($v -is [hashtable]) {
                $valStr = ($v.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
                "'$($_.Key)' = @{ $valStr }"
            } else {
                "'$($_.Key)' = '$v'"
            }
        } | Join-String -Separator "`n" -Separator "        " ) + '}'
    }

    if ($skip) {
        $params += '        SkipRule       = "'$skip'"'
    }

    if ($skipType) {
        $params += '        SkipRuleType   = "'$skipType'"'
    }

    $params += '        DomainName     = ""   # Set to your domain if domain-joined'
    $params += '        ForestName     = ""   # Set to your forest if domain-joined'

    $configLines += '            ' + $tech + ' Baseline {'
    $configLines += '                ' + ($params -join "`n                ")
    $configLines += '            }'
    $configLines += '        }'
    $configLines += '    }'
    $configLines += '}'
    $configLines += ''
    $configLines += '# To compile:'
    $configLines += ". STIGBaseline -OutputPath `"$([System.IO.Path]::GetDirectoryName($outPath))`""
    $configLines += ''
    $configLines += '# To audit (run as Administrator):'
    $configLines += '# Test-DscConfiguration -Path "'$([System.IO.Path]::GetDirectoryName($outPath))'" -Verbose'
    $configLines += ''
    $configLines += '# To remediate (run as Administrator — CHANGES SYSTEM SETTINGS!):'
    $configLines += '# Start-DscConfiguration -Path "'$([System.IO.Path]::GetDirectoryName($outPath))'" -Wait -Verbose -Force'
    $configLines += ''

    $configContent = $configLines -join "`n"

    # Write the file
    $outDir = [System.IO.Path]::GetDirectoryName($outPath)
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    Set-Content -Path $outPath -Value $configContent -Encoding UTF8
    Write-Ok "Configuration written to: $outPath"
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Cyan
    Write-Host "    1. Review $outPath" -ForegroundColor White
    Write-Host "    2. Compile: .\stigctl.ps1 -Command Compile-Config -CommandArgs @{ ConfigPath = '$outPath' }" -ForegroundColor White
    Write-Host "    3. Audit:   .\stigctl.ps1 -Command Audit -CommandArgs @{ MofPath = '.\localhost.mof' }" -ForegroundColor White
    Write-Host "    4. Remediate (if audit looks good): .\stigctl.ps1 -Command Remediate -CommandArgs @{ MofPath = '.\localhost.moc' }" -ForegroundColor White
    Write-Host ""

    # Show what's automatable vs manual
    Write-Host "  Automatable vs Manual Rules" -ForegroundColor Cyan
    Write-Host "  --------------------------" -ForegroundColor DarkGray

    $stigObj = $available | Where-Object { $_.Version -eq $stigVer } | Select-Object -First 1
    if ($stigObj) {
        $stigObj.LoadRules() | Out-Null
        $total = $stigObj.RuleList.Count
        $auto = ($stigObj.RuleList | Where-Object { $_.RuleType -ne 'GpoRule' -and $_.RuleType -ne 'ManualRule' }).Count
        $gpo  = ($stigObj.RuleList | Where-Object { $_.RuleType -eq 'GpoRule' }).Count
        $manual = ($stigObj.RuleList | Where-Object { $_.RuleType -eq 'ManualRule' }).Count

        Write-Host "    Total rules:      $total" -ForegroundColor White
        Write-Host "    DSC-automatable:  $auto" -ForegroundColor Green
        Write-Host "    GPO (manual):     $gpo" -ForegroundColor Yellow
        Write-Host "    Manual (audit):   $manual" -ForegroundColor Red
        Write-Host ""
        Write-Warn "  GPO-based rules require manual Group Policy application (gpmc.msc or LGPO.exe)."
        Write-Warn "  Manual rules can only be audited, not remediated via DSC."
    }
    Write-Host ""
}

#-------------------------------------------------------------------------------
# Command: Compile-Config
#-------------------------------------------------------------------------------
function Invoke-CompileConfig {
    Write-Header "Compiling DSC Configuration to MOF"

    $configPath = $CommandArgs['ConfigPath']

    if (-not $configPath) {
        Write-ErrorMsg "ConfigPath is required. Example: -CommandArgs @{ ConfigPath = '.\WindowsServer-2022-MS-2.6.ps1' }"
        return
    }

    if (-not (Test-Path $configPath)) {
        Write-ErrorMsg "Configuration file not found: $configPath"
        return
    }

    Write-Step "Dot-sourcing and compiling: $configPath"

    $configName = [System.IO.Path]::GetFileNameWithoutExtension($configPath)
    $configDir  = [System.IO.Path]::GetDirectoryName($configPath)

    try {
        . "$configPath"
    } catch {
        Write-ErrorMsg "Failed to dot-source configuration: $_"
        Write-Host "  Ensure PowerSTIG is installed: .\stigctl.ps1 -Command Install-PowerStig" -ForegroundColor Red
        return
    }

    try {
        & $configName -OutputPath $configDir -ErrorAction Stop
        Write-Ok "MOF compiled to: $configDir"
    } catch {
        Write-ErrorMsg "Failed to compile MOF: $_"
        Write-Host "  Ensure you are running PowerShell as Administrator if the config references system resources." -ForegroundColor Red
        return
    }

    # List generated MOFs
    $mofs = Get-ChildItem -Path $configDir -Filter "*.mof" -ErrorAction SilentlyContinue
    if ($mofs) {
        Write-Host ""
        Write-Host "  Generated MOF files:" -ForegroundColor Cyan
        $mofs | ForEach-Object { Write-Host "    $($_.Name)" -ForegroundColor White }
    }
    Write-Host ""
}

#-------------------------------------------------------------------------------
# Command: Audit
#-------------------------------------------------------------------------------
function Invoke-Audit {
    Write-Header "Auditing System Against STIG MOF"

    $mofPath = $CommandArgs['MofPath']

    if (-not $mofPath) {
        Write-ErrorMsg "MofPath is required. Example: -CommandArgs @{ MofPath = '.\localhost.mof' }"
        return
    }

    if (-not (Test-Path $mofPath)) {
        # Try to find MOF in current directory
        $mofs = Get-ChildItem -Path . -Filter "*.mof" -ErrorAction SilentlyContinue
        if ($mofs) {
            Write-Warn "MOF not found at '$mofPath'. Found: $($mofs.Name -join ', ')"
            $mofPath = $mofs[0].FullName
            Write-Host "  Using: $mofPath" -ForegroundColor Yellow
        } else {
            Write-ErrorMsg "No MOF file found. Compile a config first: .\stigctl.ps1 -Command Compile-Config"
            return
        }
    }

    Write-Step "Running Test-DscConfiguration against: $mofPath"

    try {
        $audit = Test-DscConfiguration -Path (Split-Path $mofPath) -Verbose -ErrorAction Stop
    } catch {
        Write-ErrorMsg "Audit failed: $_"
        Write-Host "  Ensure you are running PowerShell as Administrator." -ForegroundColor Red
        Write-Host "  Ensure WinRM is enabled: Enable-PSRemoting -Force" -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "  Overall Compliance: $($audit.InDesiredState)" -ForegroundColor $(if ($audit.InDesiredState) { 'Green' } else { 'Red' })
    Write-Host ""

    if ($audit.ResourcesInDesiredState.Count -gt 0) {
        Write-Ok "$($audit.ResourcesInDesiredState.Count) settings are COMPLIANT:"
        $audit.ResourcesInDesiredState | ForEach-Object {
            Write-Host "    $($_.ResourceId)" -ForegroundColor Green
        }
    }

    if ($audit.ResourcesNotInDesiredState.Count -gt 0) {
        Write-Warn "$($audit.ResourcesNotInDesiredState.Count) settings are NON-COMPLIANT:"
        $audit.ResourcesNotInDesiredState | ForEach-Object {
            Write-Host "    $($_.ResourceId)" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  To see full details in a grid view, run in PowerShell:" -ForegroundColor Cyan
    Write-Host "    $audit | Select-Object -ExpandProperty ResourcesNotInDesiredState | Out-GridView" -ForegroundColor White
    Write-Host ""
}

#-------------------------------------------------------------------------------
# Command: Remediate
#-------------------------------------------------------------------------------
function Invoke-Remediate {
    Write-Header "Applying STIG Remediation (DSC)"

    $mofPath = $CommandArgs['MofPath']

    if (-not $mofPath -and -not $CommandArgs['ConfigPath']) {
        Write-ErrorMsg "MofPath or ConfigPath is required."
        return
    }

    if ($mofPath) {
        if (-not (Test-Path $mofPath)) {
            Write-ErrorMsg "MOF file not found: $mofPath"
            return
        }
    } else {
        # Compile from config path
        $configPath = $CommandArgs['ConfigPath']
        if (-not $configPath -or -not (Test-Path $configPath)) {
            Write-ErrorMsg "ConfigPath required and must exist."
            return
        }
        Write-Warn "ConfigPath provided — compiling MOF first..."
        $configName = [System.IO.Path]::GetFileNameWithoutExtension($configPath)
        . "$configPath"
        & $configName -OutputPath (Split-Path $configPath)
        $mofPath = (Get-ChildItem -Path (Split-Path $configPath) -Filter "*.mof" | Select-Object -First 1).FullName
    }

    Write-Warn "========================================================================"
    Write-Warn "  REMEDIATION WILL CHANGE SYSTEM SETTINGS."
    Write-Warn "  Review the generated .ps1 configuration before applying."
    Write-Warn "  Run as Administrator. Some changes may require a reboot."
    Write-Warn "========================================================================"
    Write-Host ""

    $confirm = Read-Host "Proceed with remediation? (y/n)"
    if ($confirm -ne 'y') {
        Write-Warn "Remediation cancelled."
        return
    }

    Write-Step "Applying MOF: $mofPath"

    try {
        Start-DscConfiguration -Path (Split-Path $mofPath) -Wait -Verbose -Force -ErrorAction Stop
        Write-Ok "Remediation completed."
    } catch {
        Write-ErrorMsg "Remediation failed: $_"
        Write-Host "  Ensure you are running PowerShell as Administrator." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Step "Verifying applied configuration..."
    try {
        $status = Get-DscConfigurationStatus -ErrorAction SilentlyContinue
        if ($status) {
            $status | Select-Object -Last 5 | Format-Table -AutoSize
        }
    } catch {
        Write-Warn "Could not retrieve DSC status: $_"
    }
    Write-Host ""
}

#-------------------------------------------------------------------------------
# Command: Get-Status
#-------------------------------------------------------------------------------
function Invoke-GetStatus {
    Write-Header "Current DSC Configuration Status"

    $status = Get-DscConfigurationStatus -ErrorAction SilentlyContinue

    if (-not $status) {
        Write-Warn "No DSC configuration status found. Either no MOF has been applied,"
        Write-Warn "or DSC is not configured on this system."
        return
    }

    $status | Select-Object -First 20 | Format-Table -AutoSize

    Write-Host ""
    $recent = $status | Sort-Object TimeCreated -Descending | Select-Object -First 5
    Write-Host "  Most recent runs:" -ForegroundColor Cyan
    $recent | ForEach-Object {
        $result = if ($_.Status -eq 'Success') { 'COMPLIANT' } else { $_.Status }
        Write-Host "    $($_.TimeCreated)  $result  $($_.ConfigurationName)" -ForegroundColor $(
            if ($_.Status -eq 'Success') { 'Green' } else { 'Red' })
    }
    Write-Host ""
}

#-------------------------------------------------------------------------------
# Command: Get-RuleHelp
#-------------------------------------------------------------------------------
function Invoke-GetRuleHelp {
    Write-Header "STIG Rule Help"

    $ruleId = $CommandArgs['RuleId']
    $tech   = $CommandArgs['Technology']
    $osVer  = $CommandArgs['OsVersion']
    $osRole = $CommandArgs['OsRole']

    if (-not $ruleId) {
        Write-ErrorMsg "RuleId is required. Example: -CommandArgs @{ RuleId = 'V-73487' }"
        return
    }

    if (-not (Test-PowerStigInstalled)) {
        Write-ErrorMsg "PowerSTIG is not installed. Run: .\stigctl.ps1 -Command Install-PowerStig"
        return
    }

    Import-Module PowerStig -ErrorAction Stop

    if ($tech) {
        $stigs = Get-Stig -Technology $tech | Where-Object {
            $_.TechnologyVersion -eq $osVer -and $_.TechnologyRole -eq $osRole
        }
    } else {
        $stigs = Get-Stig -ListAvailable
    }

    foreach ($stig in $stigs) {
        try {
            $stig.LoadRules() | Out-Null
            if ($stig.RuleList.Count -gt 0) {
                $help = $stig.GetExceptionHelp($ruleId)
                if ($help) {
                    Write-Host ""
                    Write-Host "  STIG: $($stig.Technology) $($stig.TechnologyVersion) $($stig.TechnologyRole) v$($stig.Version)" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host $help
                    Write-Host ""
                    return
                }
            }
        } catch {
            # Continue to next STIG
        }
    }

    Write-Warn "Rule ID '$ruleId' not found in any available STIG."
    Write-Host "  Run List-Stigs to see available STIGs, then try again with -Technology." -ForegroundColor Yellow
    Write-Host ""
}

#-------------------------------------------------------------------------------
# Command: Show-GpoRules
#-------------------------------------------------------------------------------
function Invoke-ShowGpoRules {
    Write-Header "GPO-Based Rules (Manual Application Required)"

    $tech    = $CommandArgs['Technology']
    $osVer   = $CommandArgs['OsVersion']
    $osRole  = $CommandArgs['OsRole']
    $stigVer = $CommandArgs['StigVersion']

    if (-not $tech -or -not $osVer -or -not $osRole) {
        Write-ErrorMsg "Technology, OsVersion, and OsRole are required."
        return
    }

    if (-not (Test-PowerStigInstalled)) {
        Write-ErrorMsg "PowerSTIG is not installed. Run: .\stigctl.ps1 -Command Install-PowerStig"
        return
    }

    Import-Module PowerStig -ErrorAction Stop

    $stigs = Get-Stig -Technology $tech | Where-Object {
        $_.TechnologyVersion -eq $osVer -and $_.TechnologyRole -eq $osRole
    }

    if ($stigVer) {
        $stigs = $stigs | Where-Object { $_.Version -eq $stigVer }
    }

    foreach ($stig in $stigs) {
        $stig.LoadRules() | Out-Null

        $gpoRules = $stig.RuleList | Where-Object { $_.RuleType -eq 'GpoRule' }
        $manualRules = $stig.RuleList | Where-Object { $_.RuleType -eq 'ManualRule' }

        Write-Host ""
        Write-Host "  STIG: $($stig.Technology) $($stig.TechnologyVersion) $($stig.TechnologyRole) v$($stig.Version)" -ForegroundColor Cyan
        Write-Host ""

        if ($gpoRules.Count -gt 0) {
            Write-Warn "  GPO Rules — apply via Group Policy Management (gpmc.msc) or LGPO.exe:"
            Write-Host ""
            $gpoRules | ForEach-Object {
                $desc = if ($_.Description) { $_.Description.Substring(0, [Math]::Min(120, $_.Description.Length)) } else { '(no description)' }
                Write-Host "    $($($_.RuleId)) — $desc" -ForegroundColor Yellow
            }
        }

        if ($manualRules.Count -gt 0) {
            Write-Warn "  Manual Rules — audit only, cannot be automatically enforced:"
            Write-Host ""
            $manualRules | ForEach-Object {
                $desc = if ($_.Description) { $_.Description.Substring(0, [Math]::Min(120, $_.Description.Length)) } else { '(no description)' }
                Write-Host "    $($($_.RuleId)) — $desc" -ForegroundColor Red
            }
        }

        if ($gpoRules.Count -eq 0 -and $manualRules.Count -eq 0) {
            Write-Ok "  All rules in this STIG are DSC-automatable."
        }

        Write-Host ""
    }
}

#-------------------------------------------------------------------------------
# Command: Fetch-DisaStig
#-------------------------------------------------------------------------------
function Invoke-FetchDisaStig {
    Write-Header "DISA STIG Download Information"

    Write-Host @'
 DISA STIG packages for Windows are published at:
   https://public.cyber.mil/stigs/downloads/
   https://cyber.mil/stigs/downloads/   (CAC-authenticated)

 The downloads page is a JavaScript single-page application (LWC Communities) and
 cannot be reliably scraped by a script. Download manually from the URLs below,
 or use your enterprise software distribution tool.

 WINDOWS SERVER STIG DOWNLOADS
 -------------------------------------------------------------------------------
| Product                                | STIG Version            | Typical Filename Prefix            |
|----------------------------------------|-------------------------|------------------------------------|
| Windows Server 2025                    | Latest quarterly        | U_MS_Windows_Server_2025          |
| Windows Server 2022                    | Latest quarterly        | U_MS_Windows_Server_2022          |
| Windows Server 2019                    | Latest quarterly        | U_MS_Windows_Server_2019          |
| Windows Server 2016                    | Latest quarterly        | U_MS_Windows_Server_2016          |
| Windows Server 2012 R2 (Retiring)     | Latest available        | U_MS_Windows_Server_2012_R2       |
| Windows DNS Server                     | Latest quarterly        | U_MS_Windows_DNS_Server           |
| Windows Defender Antivirus             | Latest quarterly        | U_MS_Windows_Defender_Antivirus   |

 Each STIG package ZIP typically contains:
   • *-Manual-xccdf.xml       — the XCCDF benchmark (for SCAP scanners / STIG Viewer)
   • *-OVAL.xml               — OVAL definitions (for automated scanning)
   • Supporting files (PowerShell scripts, DoD EP XML, etc.)
   • Supplemental Automation Content (PowerShell scripts for some rules)

 PowerShell Gallery: PowerSTIG (DSC automation, installable without DISA downloads)
   https://www.powershellgallery.com/packages/PowerSTIG
   Install-Module -Name PowerSTIG -Scope CurrentUser

 RECOMMENDED WORKFLOW
 -------------------------------------------------------------------------------
 1. Install PowerSTIG:  .\stigctl.ps1 -Command Install-PowerStig
 2. List STIGs:          .\stigctl.ps1 -Command List-Stigs
 3. Generate config:     .\stigctl.ps1 -Command Generate-Config ...
 4. Compile + audit:    .\stigctl.ps1 -Command Compile-Config
                         .\stigctl.ps1 -Command Audit
 5. For GPO rules:       Apply via Group Policy Management Console (gpmc.msc)
 6. Re-audit after GPO:  .\stigctl.ps1 -Command Audit

 Alternatively, DISA provides Supplemental Automation Content (PowerShell scripts)
 in the STIG download ZIP. These can be run directly for rules that have scripts.
'@

    Write-Host ""
}

#-------------------------------------------------------------------------------
# Main dispatch
#-------------------------------------------------------------------------------
$dispatch = @{
    'Help'             = { Invoke-Help }
    'Install-PowerStig'= { Invoke-InstallPowerStig }
    'List-Stigs'       = { Invoke-ListStigs }
    'Generate-Config'  = { Invoke-GenerateConfig }
    'Compile-Config'   = { Invoke-CompileConfig }
    'Audit'            = { Invoke-Audit }
    'Remediate'        = { Invoke-Remediate }
    'Get-Status'       = { Invoke-GetStatus }
    'Get-RuleHelp'     = { Invoke-GetRuleHelp }
    'Show-GpoRules'    = { Invoke-ShowGpoRules }
    'Fetch-DisaStig'   = { Invoke-FetchDisaStig }
}

if ($dispatch.ContainsKey($Command)) {
    & $dispatch[$Command]
} else {
    Write-Host ""
    Write-ErrorMsg "Unknown command: $Command"
    Write-Host "  Run .\stigctl.ps1 -Command Help for usage information." -ForegroundColor Yellow
    Write-Host ""
}
