<#
.SYNOPSIS
    Installs, removes and inspects the fgwan Windows service.

.DESCRIPTION
    fgwan runs as a real Windows service under the LOCAL SERVICE account, so it
    starts at boot without anyone logging in and needs no console window.

    Changing which interfaces are monitored does NOT require any action here:
    open the dashboard and click Configure, which applies the new layout to the
    running service without restarting it.

    Earlier versions registered a scheduled task instead. Install detects and
    removes that task, so upgrading is a single step.

.EXAMPLE
    .\Manage-Fgwan.ps1 -Action Setup            # first run: walk the device
    .\Manage-Fgwan.ps1 -Action Install          # register and start the service
    .\Manage-Fgwan.ps1 -Action Status
    .\Manage-Fgwan.ps1 -Action Logs -Tail 50
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Install', 'Uninstall', 'Start', 'Stop', 'Restart',
                 'Status', 'Setup', 'Configure', 'Logs')]
    [string]$Action,

    [string]$Listen = '127.0.0.1:8080',

    [string]$ServiceName = 'fgwan',

    [string]$ExePath = "$env:ProgramFiles\fgwan\fgwan.exe",

    [string]$DataDir = "$env:ProgramData\fgwan",

    # Setup style: Console works everywhere including Server Core; Browser
    # needs a browser running ON THIS SERVER, because the setup endpoints only
    # answer to loopback.
    [ValidateSet('Console', 'Browser')]
    [string]$SetupMode = 'Console',

    [int]$Tail = 40
)

$ErrorActionPreference = 'Stop'

$configPath = Join-Path $DataDir 'config.json'
$credPath   = Join-Path $DataDir 'credentials.dat'
$logDir     = Join-Path $DataDir 'logs'
$logPath    = Join-Path $logDir 'fgwan.log'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This action requires an elevated PowerShell session.'
    }
}

function Get-Fgwan { Get-Service -Name $ServiceName -ErrorAction SilentlyContinue }

# Earlier releases used a scheduled task. Leaving it behind would mean two
# copies of the collector fighting over the same TCP port.
function Remove-LegacyTask {
    $task = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host 'Removing the scheduled task left over from an earlier version...' -ForegroundColor Yellow
        Stop-ScheduledTask  -TaskName $ServiceName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
    }
}

switch ($Action) {

    'Setup' {
        Assert-Admin
        $svc = Get-Fgwan
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Host 'The fgwan service is already running.' -ForegroundColor Yellow
            Write-Host 'You can change the monitored interfaces without stopping it:' -ForegroundColor Yellow
            Write-Host "  http://$Listen/setup.html" -ForegroundColor Cyan
            Write-Host ''
            $ans = Read-Host 'Run setup anyway? That needs the service stopped. [y/N]'
            if ($ans -notmatch '^[Yy]') { return }
            Stop-Service -Name $ServiceName
            (Get-Fgwan).WaitForStatus('Stopped', '00:00:20')
        }
        if ($SetupMode -eq 'Browser') {
            Write-Host 'The graphical wizard needs a browser ON THIS SERVER: the setup' -ForegroundColor DarkGray
            Write-Host 'endpoints only answer to loopback, because they accept passphrases.' -ForegroundColor DarkGray
            Write-Host "Open http://$Listen/setup.html, then press Ctrl+C here when done." -ForegroundColor DarkGray
            & $ExePath -setup -config $configPath -credentials $credPath -listen $Listen
        } else {
            & $ExePath -setup-console -config $configPath -credentials $credPath
        }
    }

    'Configure' {
        Start-Process "http://$Listen/setup.html"
    }

    'Install' {
        Assert-Admin

        if (-not (Test-Path $ExePath)) { throw "Not found: $ExePath" }
        if (-not (Test-Path $configPath)) {
            throw "No configuration at $configPath. Run: .\Manage-Fgwan.ps1 -Action Setup"
        }

        Remove-LegacyTask
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null

        if (Get-Fgwan) {
            Write-Host "Replacing the existing '$ServiceName' service..." -ForegroundColor Yellow
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            (Get-Fgwan).WaitForStatus('Stopped', '00:00:20')
            & sc.exe delete $ServiceName | Out-Null
            # The SCM removes the entry lazily; give it a moment.
            Start-Sleep -Seconds 2
        }

        # -service makes fgwan talk to the SCM. The log path is explicit so the
        # service writes somewhere predictable rather than to a console nobody
        # is watching.
        $binPath = '"{0}" -service -config "{1}" -credentials "{2}" -log "{3}" -listen {4}' -f `
            $ExePath, $configPath, $credPath, $logPath, $Listen

        New-Service -Name $ServiceName `
            -BinaryPathName $binPath `
            -DisplayName 'fgwan - FortiGate WAN Monitor' `
            -Description 'Polls FortiGate WAN and IPsec interfaces over SNMPv3 and serves a live bandwidth dashboard.' `
            -StartupType Automatic | Out-Null

        # LOCAL SERVICE is unprivileged and sufficient: fgwan makes one
        # outbound UDP/161 flow and binds one local TCP port (8080 needs no
        # privilege). Built-in accounts take no password, and trying to pass an
        # empty one through PowerShell to sc.exe is a well-known quoting trap.
        & sc.exe config $ServiceName obj= 'NT AUTHORITY\LocalService' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe could not set the service account (exit $LASTEXITCODE)"
        }

        # Delayed start: the network stack and routing are usually not ready at
        # the instant services first run, and an immediate SNMP timeout is a
        # noisy way to begin.
        & sc.exe config $ServiceName start= delayed-auto | Out-Null

        # Restart on failure: after 60 s, three times, with the counter reset
        # daily so a stable service does not stay flagged forever.
        & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

        # LOCAL SERVICE needs read access to the credential blob, and WRITE
        # access to the config: the reconfiguration wizard runs inside the
        # collector process and rewrites config.json in place.
        if (Test-Path $configPath) { & icacls.exe $configPath /grant '*S-1-5-19:(M)' | Out-Null }
        if (Test-Path $credPath)   { & icacls.exe $credPath   /grant '*S-1-5-19:(R)' | Out-Null }
        & icacls.exe $DataDir /grant '*S-1-5-19:(M)' | Out-Null
        & icacls.exe $logDir  /grant '*S-1-5-19:(M)' /T | Out-Null

        Start-Service -Name $ServiceName
        (Get-Fgwan).WaitForStatus('Running', '00:00:30')

        Write-Host ''
        Write-Host "Service '$ServiceName' installed and running." -ForegroundColor Green
        Write-Host "  Account      NT AUTHORITY\LocalService"
        Write-Host "  Startup      Automatic (delayed)"
        Write-Host "  Recovery     restart after 60s, 3 attempts"
        Write-Host "  Log          $logPath"
        Write-Host ''
        Write-Host "  Dashboard    http://$Listen/"
        Write-Host "  Reconfigure  http://$Listen/setup.html  (no restart needed)"
        Write-Host ''
        Write-Host 'It will now start automatically at boot. No console window required.' -ForegroundColor DarkGray
    }

    'Uninstall' {
        Assert-Admin
        Remove-LegacyTask
        if (Get-Fgwan) {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            & sc.exe delete $ServiceName | Out-Null
            Write-Host "Removed service '$ServiceName'" -ForegroundColor Green
        } else {
            Write-Host "Service '$ServiceName' is not installed."
        }
    }

    'Start' {
        Assert-Admin
        Start-Service -Name $ServiceName
        (Get-Fgwan).WaitForStatus('Running', '00:00:30')
        Write-Host "Started '$ServiceName'" -ForegroundColor Green
    }

    'Stop' {
        Assert-Admin
        Stop-Service -Name $ServiceName
        (Get-Fgwan).WaitForStatus('Stopped', '00:00:30')
        Write-Host "Stopped '$ServiceName'" -ForegroundColor Green
    }

    'Restart' {
        Assert-Admin
        Restart-Service -Name $ServiceName
        (Get-Fgwan).WaitForStatus('Running', '00:00:30')
        Write-Host "Restarted '$ServiceName'" -ForegroundColor Green
    }

    'Status' {
        $svc = Get-Fgwan
        if (-not $svc) {
            Write-Host "Service '$ServiceName' is not installed." -ForegroundColor Yellow
            if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) {
                Write-Host 'A legacy scheduled task exists. Run -Action Install to migrate.' -ForegroundColor Yellow
            }
            return
        }
        $wmi = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        [PSCustomObject]@{
            Service    = $ServiceName
            Status     = $svc.Status
            StartType  = $wmi.StartMode
            Account    = $wmi.StartName
            ProcessId  = $wmi.ProcessId
            ExitCode   = $wmi.ExitCode
            Credential = if (Test-Path $credPath) { 'stored' } else { 'MISSING - run -Action Setup' }
            LogFile    = if (Test-Path $logPath) { $logPath } else { '(not created yet)' }
        } | Format-List

        # The health endpoint is the real signal: a running process that cannot
        # reach the firewall still reports poll failures here. "generation"
        # counts how many configurations have been loaded since start.
        try {
            $h = Invoke-RestMethod -Uri "http://$Listen/healthz" -TimeoutSec 3
            Write-Host 'Health:' -ForegroundColor Cyan
            $h | Format-List
        } catch {
            Write-Host "Could not reach http://$Listen/healthz" -ForegroundColor Yellow
            if ($svc.Status -eq 'Running') {
                Write-Host 'The service is running but not answering. Check the log:' -ForegroundColor Yellow
                Write-Host '  .\Manage-Fgwan.ps1 -Action Logs' -ForegroundColor Cyan
            }
        }
    }

    'Logs' {
        if (-not (Test-Path $logPath)) {
            Write-Host "No log file at $logPath" -ForegroundColor Yellow
            Write-Host 'The service may not have started yet, or was installed without -log.'
            return
        }
        Get-Content -Path $logPath -Tail $Tail -Wait
    }
}
