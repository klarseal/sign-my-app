#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$FilePath
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Signing-Safety.ps1"
$file = Resolve-LocalSigningFile $FilePath -BaseDirectory (Split-Path -Parent $PSScriptRoot)
if ($file.PSIsContainer) { throw 'Choose a file to verify.' }
$tool = & "$PSScriptRoot/Find-SignTool.ps1"
Invoke-SigningNative $tool @('verify', '/pa', '/v', $file.FullName)
$signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
if ($signature.SignerCertificate) {
    Write-Output "Publisher: $(ConvertTo-SigningDisplayText $signature.SignerCertificate.Subject)"
} else { Write-Output 'Publisher: no signing certificate found.' }
if ($signature.TimeStamperCertificate) {
    Write-Output "Timestamp signer: $(ConvertTo-SigningDisplayText $signature.TimeStamperCertificate.Subject)"
    Write-Output 'The timestamp certificate is present; inspect its date with Windows signature details.'
} else { Write-Output 'Timestamp: absent. Do not call this a timestamped release.' }
Write-Output "Authenticode status: $(ConvertTo-SigningDisplayText $signature.Status)"
Write-Output 'Verification passed: Windows accepted the publisher signature and file integrity under Authenticode policy on this machine.'
