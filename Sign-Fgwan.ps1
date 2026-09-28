<#
.SYNOPSIS
    Code-signs fgwan.exe so an Application Control policy can allow it by
    publisher rather than by file hash.

.DESCRIPTION
    Run this on the BUILD machine, after building and before packaging.

    A hash rule pins one exact build, so it has to be re-issued for every
    rebuild. A publisher rule keeps working across versions, which is the
    difference between a one-off exception and something maintainable.

    With no arguments this mints a self-signed certificate. That is enough for
    WDAC and AppLocker publisher rules, provided your security team adds the
    certificate as a trusted signer in the policy. It is NOT enough for Smart
    App Control, which ignores locally trusted certificates - see the notes.

    If your organisation has an internal PKI that issues code-signing
    certificates, use that instead and pass -Thumbprint. It is the better
    answer: the trust chain already exists on every domain machine.

.PARAMETER Thumbprint
    Use an existing code-signing certificate from the current user's store
    instead of creating one.

.PARAMETER ExportCer
    Write the public certificate next to the binary, for the security team to
    import into the WDAC or AppLocker policy.

.EXAMPLE
    .\Sign-Fgwan.ps1 -Path .\dist\amd64\fgwan.exe
    .\Sign-Fgwan.ps1 -Path .\dist\amd64\fgwan.exe -Thumbprint A1B2C3...
#>
[CmdletBinding()]
param(
    [string]$Path = '.\dist\amd64\fgwan.exe',

    [string]$Thumbprint,

    [string]$Subject = 'CN=fgwan Internal Code Signing, O=Network and Information Security',

    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    [switch]$ExportCer
)

$ErrorActionPreference = 'Stop'

$exe = (Resolve-Path $Path).Path
Write-Host "Signing $exe" -ForegroundColor Cyan

# ------------------------------------------------------------- certificate
if ($Thumbprint) {
    $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
            Where-Object { $_.Thumbprint -eq $Thumbprint } |
            Select-Object -First 1
    if (-not $cert) { throw "No certificate with thumbprint $Thumbprint in the personal stores." }
    Write-Host "  Using existing certificate: $($cert.Subject)" -ForegroundColor Green
}
else {
    # Reuse a previously minted one rather than creating a new identity on
    # every run - a new cert would invalidate any policy rule already written
    # against the old one.
    $cert = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object {
                $_.Subject -eq $Subject -and
                $_.NotAfter -gt (Get-Date) -and
                $_.EnhancedKeyUsageList.FriendlyName -contains 'Code Signing'
            } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1

    if ($cert) {
        Write-Host "  Reusing self-signed certificate (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" -ForegroundColor Green
    }
    else {
        Write-Host '  Creating a self-signed code-signing certificate...' -ForegroundColor Yellow
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $Subject `
            -CertStoreLocation Cert:\CurrentUser\My `
            -KeyUsage DigitalSignature `
            -KeyExportPolicy Exportable `
            -KeyLength 3072 `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears(3)
        Write-Host "  Created. Thumbprint $($cert.Thumbprint)" -ForegroundColor Green
        Write-Host '  Keep this certificate. Re-creating it later produces a different' -ForegroundColor DarkGray
        Write-Host '  identity and invalidates any policy rule written against it.' -ForegroundColor DarkGray
    }
}

# ------------------------------------------------------------------- sign
# Timestamping matters: without it the signature stops validating the day the
# certificate expires, even on builds shipped years earlier.
$sig = Set-AuthenticodeSignature -FilePath $exe -Certificate $cert `
                                 -HashAlgorithm SHA256 `
                                 -TimestampServer $TimestampUrl

if ($sig.Status -ne 'Valid' -and $sig.Status -ne 'UnknownError') {
    Write-Host "  Signing reported: $($sig.Status) - $($sig.StatusMessage)" -ForegroundColor Yellow
}

$check = Get-AuthenticodeSignature $exe
Write-Host ''
Write-Host "  Status     : $($check.Status)" -ForegroundColor $(if ($check.Status -eq 'Valid') { 'Green' } else { 'Yellow' })
Write-Host "  Signer     : $($check.SignerCertificate.Subject)"
Write-Host "  Thumbprint : $($check.SignerCertificate.Thumbprint)"
if ($check.TimeStamperCertificate) {
    Write-Host "  Timestamped: yes"
} else {
    Write-Host '  Timestamped: NO - the signature will expire with the certificate' -ForegroundColor Yellow
}

# On the build machine the signer is not a trusted root, so Status will read
# UnknownError ("a certificate chain could not be built"). That is expected for
# a self-signed cert and does not mean the signature is malformed.
if ($check.Status -eq 'UnknownError') {
    Write-Host ''
    Write-Host '  Status UnknownError is normal for a self-signed certificate on a' -ForegroundColor DarkGray
    Write-Host '  machine that does not trust it. The signature itself is intact;' -ForegroundColor DarkGray
    Write-Host '  the chain simply does not resolve here.' -ForegroundColor DarkGray
}

# ----------------------------------------------------------------- export
if ($ExportCer -or -not $Thumbprint) {
    $cerPath = Join-Path (Split-Path $exe -Parent) 'fgwan-codesign.cer'
    Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
    Write-Host ''
    Write-Host "  Public certificate exported to:" -ForegroundColor Cyan
    Write-Host "    $cerPath"
    Write-Host '  Give this to whoever owns the Application Control policy. They can'
    Write-Host '  add it as a trusted signer, which then covers every future build.'
}

Write-Host ''
Write-Host '  Next: rebuild the deployment package so it carries the signed binary.' -ForegroundColor DarkGray
Write-Host '    .\deploy\Package-Fgwan.ps1 -SkipBuild' -ForegroundColor DarkGray
Write-Host ''
