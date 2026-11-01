#Requires -Version 5.1
# Test-only lifecycle. No production tool can reach this script.
[CmdletBinding()]
param([ValidateSet('Create','Remove','AssertAbsent','Sign')][string]$Action, [string]$Root)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repo 'tests/Disposable-Certificate.ps1')
. (Join-Path $repo 'scripts/Signing-Safety.ps1')
$manifest = Join-Path $Root 'certificate.json'
if ($Action -eq 'Create') {
    $certificate = $null; $handedOff = $false
    try {
        $certificate = New-DisposableSigningCertificate
        @{ Subject = $certificate.Subject; Thumbprint = $certificate.Thumbprint } | ConvertTo-Json | Set-Content -LiteralPath $manifest -Encoding UTF8
        $compiler = [IO.Path]::Combine([IO.Directory]::GetParent([Environment]::SystemDirectory).FullName, 'Microsoft.NET\Framework64\v4.0.30319\csc.exe')
        if (-not (Test-Path -LiteralPath $compiler)) { throw 'Windows .NET Framework compiler missing.' }
        $source = Join-Path $Root 'App.cs'
        'class App { static void Main() {} }' | Set-Content -LiteralPath $source
        & $compiler /nologo /target:exe ('/out:' + (Join-Path $Root 'build/First app.exe')) $source
        if ($LASTEXITCODE -ne 0) { throw 'Compilation failed.' }
        $handedOff = $true
    } finally { if (-not $handedOff) { Remove-DisposableSigningCertificate $certificate } }
    exit 0
}
$identity = Get-Content -Raw -LiteralPath $manifest | ConvertFrom-Json
if ($identity.Thumbprint -notmatch '^[A-F0-9]{40}$' -or
    $identity.Subject -cnotmatch '^CN=sign-my-app disposable test [a-f0-9]{32}$') { throw 'Disposable identity required.' }
if ($Action -eq 'Remove') { Remove-DisposableSigningCertificate $identity; exit 0 }
if ($Action -eq 'AssertAbsent') {
    foreach ($store in (Get-ChildItem -LiteralPath Cert:\CurrentUser)) {
        if (Test-Path -LiteralPath ('Cert:\CurrentUser\' + $store.Name + '\' + $identity.Thumbprint)) { throw 'Disposable certificate remains.' }
    }
    exit 0
}
if ($Action -eq 'Sign') {
    $certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $identity.Thumbprint)
    if ($certificate.Subject -cne $identity.Subject -or $certificate.Issuer -cne $certificate.Subject) { throw 'Disposable subject mismatch.' }
    $file = Join-Path $Root 'build/signed.exe'
    Copy-Item -LiteralPath (Join-Path $Root 'build/First app.exe') -Destination $file
    $tool = & (Join-Path $repo 'scripts/Find-SignTool.ps1')
    # TEST ONLY: exact new disposable publisher, offline. Never /a or a real key.
    Invoke-SigningNative $tool @('sign', '/fd', 'SHA256', '/sha1', $identity.Thumbprint, $file)
    if ((Get-AuthenticodeSignature -LiteralPath $file).SignerCertificate.Thumbprint -ne $identity.Thumbprint) { throw 'Wrong disposable signer.' }
    exit 0
}
