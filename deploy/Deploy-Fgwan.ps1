<#
.SYNOPSIS
    Installs fgwan as a Windows service on a server with no development tools.

.DESCRIPTION
    Run this on the TARGET machine, from the folder it was copied into, in an
    elevated PowerShell session. It needs nothing that is not already part of
    Windows: no Go, no WiX, no .NET SDK, no browser, no installer framework.

    What it does, in order:
      1. Pre-flight checks (elevation, 64-bit, files present and unblocked).
      2. Copies fgwan.exe and the management script to Program Files.
      3. Runs setup on THIS machine: walks the FortiGate, selects interfaces,
         and stores the SNMPv3 credentials.
      4. Registers and starts the service, then verifies it is actually
         answering rather than merely running.

    Re-running it upgrades an existing install in place: the service is
    stopped, the binary replaced and the service restarted. The configuration
    and credentials are left alone.

.NOTES
    Setup runs on the target by design. Neither of the two things it produces
    can usefully be created elsewhere:

      credentials.dat is encrypted with DPAPI in machine scope, so a blob from
      the build host fails here with CryptUnprotectData failed. That is the
      protection working, not a defect.

      The interface selection depends on what this FortiGate actually reports,
      and the walk has to come from a host the device will answer.

.EXAMPLE
    .\Deploy-Fgwan.ps1
    .\Deploy-Fgwan.ps1 -Listen 0.0.0.0:8080 -OpenFirewall
    .\Deploy-Fgwan.ps1 -SetupMode Browser
    .\Deploy-Fgwan.ps1 -Upgrade
#>
[CmdletBinding()]
param(
    # Where the dashboard listens. Leave as loopback unless the dashboard is
    # meant to be reachable from other machines.
    [string]$Listen = '127.0.0.1:8080',

    # How to run first-time setup.
    #   Console - terminal prompts; works on Server Core and over plain RDP.
    #   Browser - the graphical wizard; needs a browser ON THIS SERVER.
    #   Skip    - a configuration already exists, or you will create one later.
    [ValidateSet('Console', 'Browser', 'Skip')]
    [string]$SetupMode = 'Console',

    # Add an inbound firewall rule for the listen port. Only meaningful with a
    # non-loopback -Listen.
    [switch]$OpenFirewall,

    # Skip setup entirely: just replace the binary and restart. Use when
    # rolling out a new build to a working install.
    [switch]$Upgrade,

    [string]$InstallDir  = "$env:ProgramFiles\fgwan",
    [string]$DataDir     = "$env:ProgramData\fgwan",
    [string]$ServiceName = 'fgwan'
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$configPath = Join-Path $DataDir 'config.json'
$credPath   = Join-Path $DataDir 'credentials.dat'
$logDir     = Join-Path $DataDir 'logs'
$exeTarget  = Join-Path $InstallDir 'fgwan.exe'
$mgmtTarget = Join-Path $InstallDir 'Manage-Fgwan.ps1'

function Write-Step($n, $text) {
    Write-Host ''
    Write-Host "[$n] $text" -ForegroundColor Cyan
}
function Write-Ok($text)   { Write-Host "    $text" -ForegroundColor Green }
function Write-Info($text) { Write-Host "    $text" -ForegroundColor DarkGray }
function Write-Warn($text) { Write-Host "    $text" -ForegroundColor Yellow }

# ---------------------------------------------------------------- 1. preflight
Write-Step 1 'Pre-flight checks'

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell session (Run as Administrator).'
}
Write-Ok 'Running elevated.'

if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'fgwan requires 64-bit Windows.'
}
Write-Ok "$([Environment]::OSVersion.VersionString), 64-bit."

$exeSource  = Join-Path $here 'fgwan.exe'
$mgmtSource = Join-Path $here 'Manage-Fgwan.ps1'
foreach ($f in @($exeSource, $mgmtSource)) {
    if (-not (Test-Path $f)) {
        throw "Missing $f. Copy the whole deployment folder, not just this script."
    }
}

# Files that arrived over a network share, a browser download or an extracted
# zip carry a Mark of the Web. PowerShell then refuses to run the script and
# SmartScreen warns on the binary, which looks like a broken package.
Get-ChildItem -Path $here -File | Unblock-File -ErrorAction SilentlyContinue
Write-Ok 'Deployment files unblocked (Mark of the Web cleared).'

$ver = & $exeSource -version 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "fgwan.exe will not run here: $ver"
}
Write-Ok "Binary runs: $ver"
Write-Info "SHA256 $((Get-FileHash $exeSource -Algorithm SHA256).Hash)"

# ------------------------------------------------------------- 2. copy files
Write-Step 2 'Installing files'

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Info 'Stopping the running service so the binary can be replaced...'
    Stop-Service -Name $ServiceName -Force
    (Get-Service -Name $ServiceName).WaitForStatus('Stopped', '00:00:30')
}

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir, $logDir | Out-Null
Copy-Item $exeSource  $exeTarget  -Force
Copy-Item $mgmtSource $mgmtTarget -Force
foreach ($doc in @('SERVICE.md', 'DEPLOY.md', 'README.md')) {
    $p = Join-Path $here $doc
    if (Test-Path $p) { Copy-Item $p $InstallDir -Force }
}
Write-Ok "Installed to $InstallDir"
Write-Ok "Data directory $DataDir"

# ----------------------------------------------------------------- 3. setup
if ($Upgrade) {
    Write-Step 3 'Upgrade mode: leaving configuration and credentials untouched'
    if (-not (Test-Path $configPath)) {
        throw "-Upgrade was given but there is no configuration at $configPath. Run without -Upgrade."
    }
    Write-Ok 'Existing configuration found.'
}
elseif (Test-Path $configPath) {
    Write-Step 3 'Configuration'
    Write-Ok "Using the existing configuration at $configPath"
    if (-not (Test-Path $credPath)) {
        Write-Warn 'No credential is stored on this machine yet.'
        & $exeTarget -set-credentials -credentials $credPath
        if (-not (Test-Path $credPath)) { throw 'Credentials were not stored.' }
        Write-Ok 'Credential stored and encrypted for this machine.'
    }
}
elseif ($SetupMode -eq 'Skip') {
    Write-Step 3 'Setup skipped'
    throw "No configuration at $configPath and -SetupMode Skip was given. " +
          "Run setup later with:  $exeTarget -setup-console -config `"$configPath`" -credentials `"$credPath`""
}
else {
    Write-Step 3 'First-time setup on this server'
    Write-Info 'This walks the FortiGate from THIS machine and stores the SNMPv3'
    Write-Info 'credentials encrypted for THIS machine. Neither step can be done'
    Write-Info 'on the build host and copied across.'
    Write-Host ''
    Write-Warn 'Before continuing, make sure the FortiGate trusts this server:'
    Write-Warn '    config system snmp user'
    Write-Warn '        edit "<snmp-user>"'
    Write-Warn '            set trusted-host <this-server-ip>/32'
    Write-Host ''

    if ($SetupMode -eq 'Browser') {
        Write-Info 'The graphical wizard needs a browser on this server, and the setup'
        Write-Info 'endpoints only answer to loopback, so it must be a browser running'
        Write-Info 'here - not on your workstation.'
        Write-Info "Open http://$Listen/setup.html, then press Ctrl+C in the wizard window."
        Write-Host ''
        Read-Host '    Press Enter to start the browser wizard'
        & $exeTarget -setup -config $configPath -credentials $credPath -listen $Listen
    }
    else {
        # The terminal wizard is the default because it works everywhere,
        # including Server Core, and needs nothing beyond this console.
        & $exeTarget -setup-console -config $configPath -credentials $credPath
    }

    if (-not (Test-Path $configPath)) {
        throw 'Setup exited without writing a configuration.'
    }
    Write-Ok 'Configuration written.'
    if (Test-Path $credPath) {
        Write-Ok 'Credential stored and encrypted for this machine.'
    } else {
        Write-Warn 'No credential was stored; the service will not be able to poll.'
        & $exeTarget -set-credentials -credentials $credPath
        if (-not (Test-Path $credPath)) { throw 'Credentials were not stored.' }
    }
}

# ------------------------------------------------------------ 4. the service
Write-Step 4 'Registering the service'

& $mgmtTarget -Action Install -Listen $Listen -ExePath $exeTarget -DataDir $DataDir -ServiceName $ServiceName

# --------------------------------------------------------------- 5. firewall
if ($OpenFirewall) {
    Write-Step 5 'Firewall'
    $port = ($Listen -split ':')[-1]
    if ($Listen -match '^(127\.0\.0\.1|localhost|\[::1\])') {
        Write-Warn "-Listen is loopback ($Listen); a firewall rule would have no effect. Skipped."
    }
    else {
        $ruleName = "fgwan dashboard (TCP $port)"
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $port -Profile Domain,Private | Out-Null
        Write-Ok "Inbound TCP $port allowed on domain and private profiles."
        Write-Warn 'fgwan has no authentication of its own. Put a reverse proxy in front'
        Write-Warn 'before exposing this beyond a trusted management network.'
    }
}

# ------------------------------------------------------------------ 6. verify
Write-Step 6 'Verifying'

Start-Sleep -Seconds 3
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Warn "Service state: $($svc.Status)"
    Write-Warn "Check the log:  & '$mgmtTarget' -Action Logs"
    throw 'The service did not reach Running.'
}
Write-Ok 'Service is running.'

# A service that is "Running" but cannot reach the firewall is the failure mode
# that matters, so check the health endpoint rather than stopping at the SCM.
$healthUrl = "http://$($Listen -replace '^0\.0\.0\.0', '127.0.0.1')/healthz"
$health = $null
foreach ($attempt in 1..10) {
    try { $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 3; break }
    catch { Start-Sleep -Seconds 2 }
}

if (-not $health) {
    Write-Warn "The service is running but $healthUrl did not answer."
    Write-Warn "Check the log:  & '$mgmtTarget' -Action Logs"
}
else {
    Write-Ok 'Dashboard is answering.'
    if ($health.last_error) {
        Write-Warn "Collector reports: $($health.last_error)"
        Write-Warn 'Most often this means the FortiGate trusted-host list does not yet'
        Write-Warn "include THIS server's address, or SNMP is not enabled on the"
        Write-Warn 'interface being reached. The service will keep retrying.'
    }
    elseif ($health.snmp_auth_fails -gt 0) {
        Write-Warn "SNMP authentication failures: $($health.snmp_auth_fails)"
        Write-Warn 'The passphrase or auth protocol does not match the FortiGate user.'
    }
    else {
        Write-Ok "Polling cleanly - $($health.samples) sample(s) collected."
    }
}

Write-Host ''
Write-Host '================================================================' -ForegroundColor Green
Write-Host ' fgwan is installed and will start automatically at boot.' -ForegroundColor Green
Write-Host '================================================================' -ForegroundColor Green
Write-Host ''
Write-Host "  Dashboard    http://$Listen/"
Write-Host "  Reconfigure  http://$Listen/setup.html   (no restart needed)"
Write-Host "  Log          $(Join-Path $logDir 'fgwan.log')"
Write-Host ''
Write-Host '  Management:' -ForegroundColor DarkGray
Write-Host "    & '$mgmtTarget' -Action Status"
Write-Host "    & '$mgmtTarget' -Action Logs -Tail 50"
Write-Host "    & '$mgmtTarget' -Action Restart"
Write-Host ''
