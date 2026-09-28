<#
.SYNOPSIS
    Works out which Windows Application Control mechanism blocked fgwan.exe.

.DESCRIPTION
    "An Application Control policy has blocked this file" comes from one of
    three different subsystems, and they are fixed in completely different
    ways. This reports which one is active, and reads the CodeIntegrity event
    log for the actual block record, which names the file and the policy that
    rejected it.

    Run it from the deployment folder, elevated.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Diagnose-AppControl.ps1
#>
[CmdletBinding()]
param(
    [string]$Path = '.\fgwan.exe'
)

$ErrorActionPreference = 'Continue'

function Head($t) {
    Write-Host ''
    Write-Host "=== $t " -ForegroundColor Cyan -NoNewline
    Write-Host ('=' * [Math]::Max(0, 60 - $t.Length)) -ForegroundColor DarkGray
}

$verdict = @()

# --------------------------------------------------------------- 1. the file
Head 'The binary'

$full = (Resolve-Path $Path -ErrorAction SilentlyContinue).Path
if (-not $full) {
    Write-Host "  Not found: $Path" -ForegroundColor Yellow
} else {
    Write-Host "  $full"
    Write-Host "  SHA256 $((Get-FileHash $full -Algorithm SHA256).Hash)"
    $sig = Get-AuthenticodeSignature $full
    Write-Host "  Signature status : $($sig.Status)"
    if ($sig.SignerCertificate) {
        Write-Host "  Signed by        : $($sig.SignerCertificate.Subject)"
    } else {
        Write-Host '  Signed by        : (unsigned)' -ForegroundColor Yellow
        $verdict += 'The binary is unsigned, which is what every Application Control policy objects to.'
    }
    # A leftover Mark of the Web is a different problem, but worth ruling out.
    $zone = Get-Item $full -Stream Zone.Identifier -ErrorAction SilentlyContinue
    if ($zone) {
        Write-Host '  Mark of the Web  : STILL PRESENT' -ForegroundColor Yellow
        $verdict += "Run: Unblock-File '$full'"
    } else {
        Write-Host '  Mark of the Web  : cleared'
    }
}

# ------------------------------------------------------ 2. Smart App Control
Head 'Smart App Control (Windows 11 consumer)'

$sac = $null
try {
    $sac = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction Stop).VerifiedAndReputablePolicyState
} catch { }

switch ($sac) {
    0 { Write-Host '  State: OFF' -ForegroundColor Green }
    1 {
        Write-Host '  State: ON (enforcing)' -ForegroundColor Red
        $verdict += 'Smart App Control is ENFORCING. It blocks unsigned binaries outright.'
    }
    2 {
        Write-Host '  State: EVALUATION' -ForegroundColor Yellow
        $verdict += 'Smart App Control is in evaluation mode and may block unsigned binaries.'
    }
    default { Write-Host '  State: not present on this build' -ForegroundColor DarkGray }
}

# --------------------------------------------------------------- 3. WDAC
Head 'WDAC / Device Guard'

try {
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
                          -ClassName Win32_DeviceGuard -ErrorAction Stop
    $enf = $dg.CodeIntegrityPolicyEnforcementStatus
    $txt = @{ 0 = 'Off'; 1 = 'Audit mode'; 2 = 'ENFORCED' }[[int]$enf]
    Write-Host "  Policy enforcement        : $txt"
    if ($enf -eq 2) {
        $verdict += 'A WDAC policy is ENFORCED. It decides per-file whether code may run.'
    }
    $ums = $dg.UsermodeCodeIntegrityPolicyEnforcementStatus
    if ($null -ne $ums) {
        Write-Host "  User-mode CI enforcement  : $(@{0='Off';1='Audit mode';2='ENFORCED'}[[int]$ums])"
        if ($ums -eq 2) {
            $verdict += 'User-mode code integrity is ENFORCED, which is what blocks an .exe.'
        }
    }
} catch {
    Write-Host '  Device Guard WMI class not available' -ForegroundColor DarkGray
}

$active = 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active'
if (Test-Path $active) {
    $pols = Get-ChildItem $active -Filter *.cip -ErrorAction SilentlyContinue
    if ($pols) {
        Write-Host "  Active policy files ($($pols.Count)):"
        $pols | ForEach-Object { Write-Host "    $($_.Name)  $([math]::Round($_.Length/1KB,1)) KB" }
        $verdict += "WDAC policies are deployed in $active - these are managed centrally, not locally."
    } else {
        Write-Host '  No .cip policy files deployed' -ForegroundColor DarkGray
    }
}
if (Test-Path 'C:\Windows\System32\CodeIntegrity\SiPolicy.p7b') {
    Write-Host '  Legacy SiPolicy.p7b present' -ForegroundColor Yellow
}

# ---------------------------------------------- 4. the actual block record
Head 'CodeIntegrity block events (the authoritative answer)'

try {
    $ev = Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' `
                       -MaxEvents 60 -ErrorAction Stop |
          Where-Object { $_.Id -in 3076, 3077, 3033, 3034 }

    if (-not $ev) {
        Write-Host '  No recent block events.' -ForegroundColor DarkGray
    } else {
        $ev | Select-Object -First 6 | ForEach-Object {
            $kind = switch ($_.Id) {
                3077 { 'BLOCKED (enforced)' }
                3076 { 'would block (audit)' }
                3033 { 'BLOCKED (signature)' }
                3034 { 'would block (signature, audit)' }
            }
            Write-Host ''
            Write-Host "  [$($_.TimeCreated)] id=$($_.Id) $kind" -ForegroundColor Yellow
            # The message names the file and, usually, the deciding policy.
            ($_.Message -split "`n") |
                Where-Object { $_ -match 'File Name|Policy|Process Name' } |
                ForEach-Object { Write-Host "    $($_.Trim())" }
        }
        $verdict += 'The CodeIntegrity log above names the exact policy that rejected the file.'
    }
} catch {
    Write-Host '  Could not read the CodeIntegrity log (run elevated).' -ForegroundColor DarkGray
}

# ------------------------------------------------------------- 5. AppLocker
Head 'AppLocker'

try {
    $al = Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' `
                       -MaxEvents 20 -ErrorAction Stop |
          Where-Object { $_.Id -in 8004, 8003 }
    if ($al) {
        $al | Select-Object -First 4 | ForEach-Object {
            Write-Host "  [$($_.TimeCreated)] id=$($_.Id) $($_.Message.Split("`n")[0])" -ForegroundColor Yellow
        }
        $verdict += 'AppLocker is also logging blocks; it may be the mechanism rather than WDAC.'
    } else {
        Write-Host '  No AppLocker block events.' -ForegroundColor DarkGray
    }
} catch {
    Write-Host '  AppLocker log not present (feature not in use).' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- verdict
Head 'Summary'

if ($verdict) {
    $verdict | ForEach-Object { Write-Host "  - $_" }
} else {
    Write-Host '  Nothing conclusive found. Re-run immediately after reproducing the block.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '  Next steps depend on which mechanism it is:' -ForegroundColor Cyan
Write-Host '    Smart App Control ON  -> it must be turned off (one-way) or the binary'
Write-Host '                             needs a reputable commercial signature.'
Write-Host '    WDAC enforced         -> your security team adds a rule. Sign the binary'
Write-Host '                             first so the rule can be by publisher, not by'
Write-Host '                             hash (a hash rule breaks on every rebuild).'
Write-Host '    AppLocker             -> a publisher or path rule in Group Policy.'
Write-Host ''
