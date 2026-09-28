<#
.SYNOPSIS
    Builds fgwan and produces a self-contained deployment package.

.DESCRIPTION
    Run this on the BUILD machine. It produces a folder and a zip containing
    everything the target server needs and nothing it does not:

        fgwan.exe            the static binary (no runtime, no DLLs)
        Deploy-Fgwan.ps1     one-shot installer for the target
        Manage-Fgwan.ps1     day-to-day service management
        DEPLOY.md            the runbook
        SERVICE.md           service reference

    The target needs no Go, no WiX, no .NET SDK, no browser and no installer
    framework - only PowerShell and sc.exe, which are part of Windows.

.NOTES
    The package deliberately never contains credentials.dat. That blob is
    encrypted with machine-scoped DPAPI and is useless on any other machine;
    shipping it would only produce a confusing decryption error. Deploy-Fgwan
    prompts for the passphrases on the target instead.

.EXAMPLE
    .\deploy\Package-Fgwan.ps1
    .\deploy\Package-Fgwan.ps1 -Version 1.6.0 -IncludeConfig
#>
[CmdletBinding()]
param(
    [string]$Version = '1.8.0',

    [ValidateSet('amd64', 'arm64')]
    [string]$Arch = 'amd64',

    # Stage a configuration so the target does not have to walk the device.
    # Only useful when cloning an identical monitor; a new monitor does its own
    # walk. Safe either way: config.json holds no secrets.
    [switch]$IncludeConfig,

    [string]$ConfigPath = "$env:ProgramData\fgwan\config.json",

    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent $here
Set-Location $repo

if (-not $SkipBuild) {
    Write-Host 'Building...' -ForegroundColor Cyan
    & (Join-Path $repo 'build.ps1') -Arch $Arch -Version $Version
    if ($LASTEXITCODE -ne 0) { throw 'build.ps1 failed' }
}

$exe = Join-Path $repo "dist\$Arch\fgwan.exe"
if (-not (Test-Path $exe)) { throw "Missing $exe - run without -SkipBuild" }

$pkgName = "fgwan-$Version-$Arch-deploy"
$pkgDir  = Join-Path $repo "dist\$pkgName"
if (Test-Path $pkgDir) { Remove-Item $pkgDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $pkgDir | Out-Null

Copy-Item $exe $pkgDir -Force
Copy-Item (Join-Path $repo 'installer\Manage-Fgwan.ps1') $pkgDir -Force
Copy-Item (Join-Path $here 'Deploy-Fgwan.ps1')           $pkgDir -Force

foreach ($doc in @('DEPLOY.md', 'SERVICE.md', 'README.md')) {
    foreach ($candidate in @((Join-Path $here $doc), (Join-Path $repo $doc))) {
        if (Test-Path $candidate) { Copy-Item $candidate $pkgDir -Force; break }
    }
}

if ($IncludeConfig) {
    if (-not (Test-Path $ConfigPath)) {
        throw "-IncludeConfig was given but $ConfigPath does not exist."
    }
    Copy-Item $ConfigPath (Join-Path $pkgDir 'config.json') -Force
    Write-Host "Staged configuration from $ConfigPath" -ForegroundColor DarkGray
    Write-Host '  (contains no passphrases - only the device address, the' -ForegroundColor DarkGray
    Write-Host '   non-secret SNMPv3 parameters and the zone layout)' -ForegroundColor DarkGray
}

# A belt-and-braces check: if a credential blob ever ended up in the package,
# the target would fail with an opaque decryption error.
Get-ChildItem $pkgDir -Filter 'credentials*' -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item $_.FullName -Force
    Write-Host "Removed $($_.Name) from the package (machine-bound, not portable)" -ForegroundColor Yellow
}

$zip = Join-Path $repo "dist\$pkgName.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $pkgDir '*') -DestinationPath $zip

$hash = (Get-FileHash $zip -Algorithm SHA256).Hash
$size = [math]::Round((Get-Item $zip).Length / 1MB, 2)

Write-Host ''
Write-Host "  $zip" -ForegroundColor Green
Write-Host "  $size MB   SHA256 $hash" -ForegroundColor DarkGray
Write-Host ''
Write-Host '  Contents:' -ForegroundColor DarkGray
Get-ChildItem $pkgDir | ForEach-Object { Write-Host "    $($_.Name)" -ForegroundColor DarkGray }
Write-Host ''
Write-Host '  On the target server, in an ELEVATED PowerShell:' -ForegroundColor DarkGray
Write-Host "    Expand-Archive .\$pkgName.zip -DestinationPath C:\fgwan-deploy" -ForegroundColor DarkGray
Write-Host '    cd C:\fgwan-deploy' -ForegroundColor DarkGray
Write-Host '    powershell -ExecutionPolicy Bypass -File .\Deploy-Fgwan.ps1' -ForegroundColor DarkGray
