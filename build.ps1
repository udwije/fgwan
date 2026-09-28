<#
.SYNOPSIS
    Builds fgwan.exe for Windows.

.EXAMPLE
    .\build.ps1                      # amd64, stripped, with tests
    .\build.ps1 -Arch arm64          # for Windows on ARM
    .\build.ps1 -SkipTests           # faster iteration
#>
[CmdletBinding()]
param(
    [ValidateSet('amd64', 'arm64')]
    [string]$Arch = 'amd64',

    [string]$Version = '1.6.0',

    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw 'Go toolchain not found on PATH. Install from https://go.dev/dl/ and reopen the shell.'
}

Write-Host "go $(go version)" -ForegroundColor DarkGray

# The module has no third-party dependencies, so builds work fully offline.
$env:GOFLAGS = '-mod=mod'
$env:CGO_ENABLED = '0'

Write-Host 'gofmt...' -ForegroundColor Cyan
$unformatted = & gofmt -l .
if ($unformatted) {
    Write-Host 'Rewriting unformatted files:' -ForegroundColor Yellow
    $unformatted | ForEach-Object { Write-Host "  $_" }
    & gofmt -w .
}

if (-not $SkipTests) {
    Write-Host 'go vet + go test (host arch)...' -ForegroundColor Cyan
    & go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'go vet failed' }
    & go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'go test failed' }
}

$env:GOOS   = 'windows'
$env:GOARCH = $Arch

$outDir = Join-Path $PSScriptRoot "dist\$Arch"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$exe = Join-Path $outDir 'fgwan.exe'

Write-Host "building $exe ..." -ForegroundColor Cyan
& go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $exe .
if ($LASTEXITCODE -ne 0) { throw 'go build failed' }

foreach ($doc in @('README.md', 'SERVICE.md', 'DEPLOY.md')) {
    if (Test-Path (Join-Path $PSScriptRoot $doc)) {
        Copy-Item (Join-Path $PSScriptRoot $doc) (Join-Path $outDir $doc) -Force
    }
}

$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
$size = [math]::Round((Get-Item $exe).Length / 1MB, 2)

Write-Host ''
Write-Host "  $exe" -ForegroundColor Green
Write-Host "  $size MB   SHA256 $hash" -ForegroundColor DarkGray
Write-Host ''
Write-Host 'Try it with synthetic data (no SNMP traffic):' -ForegroundColor DarkGray
Write-Host "  $exe -sim" -ForegroundColor DarkGray
Write-Host 'Package it for a server with no dev tools:' -ForegroundColor DarkGray
Write-Host "  .\deploy\Package-Fgwan.ps1 -Version $Version" -ForegroundColor DarkGray
