<#
.SYNOPSIS
    Versions, commits, tags, and pushes an fgwan release from the local repository.
.EXAMPLE
    .\scripts\Release.ps1 -Version 1.8.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [string]$Remote = 'origin',
    [string]$Branch = 'main'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'Git is not available on PATH.'
}

if (-not (Test-Path '.git')) {
    throw 'Run this script from a cloned Git repository.'
}

$currentBranch = (git branch --show-current).Trim()
if ($currentBranch -ne $Branch) {
    throw "Release from '$Branch'. Current branch: '$currentBranch'."
}

$dirty = git status --porcelain
if ($dirty) {
    throw 'The working tree is not clean. Commit or stash changes before releasing.'
}

$tag = "v$Version"
if (git tag --list $tag) {
    throw "Tag $tag already exists locally."
}

git fetch $Remote --tags
if ($LASTEXITCODE -ne 0) { throw 'git fetch failed' }

if (git ls-remote --exit-code --tags $Remote "refs/tags/$tag" 2>$null) {
    throw "Tag $tag already exists on $Remote."
}

Set-Content -Path VERSION -Value $Version -Encoding ascii

$versionFiles = @('build.ps1', 'deploy\Package-Fgwan.ps1')
foreach ($file in $versionFiles) {
    $content = Get-Content $file -Raw
    $updated = [regex]::Replace(
        $content,
        "\[string\]\`$Version = '\d+\.\d+\.\d+'",
        "[string]`$Version = '$Version'",
        1
    )
    if ($updated -eq $content) {
        throw "Could not update the default version in $file."
    }
    Set-Content -Path $file -Value $updated -Encoding utf8
}

git add VERSION build.ps1 deploy/Package-Fgwan.ps1
git commit -m "chore: release $tag"
if ($LASTEXITCODE -ne 0) { throw 'git commit failed' }

git tag -a $tag -m "fgwan $tag"
if ($LASTEXITCODE -ne 0) { throw 'git tag failed' }

git push $Remote $Branch
if ($LASTEXITCODE -ne 0) { throw 'branch push failed; the local tag was not pushed' }

git push $Remote $tag
if ($LASTEXITCODE -ne 0) { throw 'tag push failed' }

Write-Host "Released $tag. GitHub Actions will build and publish the release." -ForegroundColor Green
