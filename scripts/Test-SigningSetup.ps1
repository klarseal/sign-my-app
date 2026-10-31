#Requires -Version 5.1
[CmdletBinding()]
param([switch]$MachineStore)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Signing-Safety.ps1"
try {
    $tool = & "$PSScriptRoot/Find-SignTool.ps1"
    Write-Output "SignTool: $(ConvertTo-SigningDisplayText $tool)"
} catch {
    Write-Output (ConvertTo-SigningDisplayText $_.Exception.Message)
}

# Only public code signing subject and thumbprint metadata. Never enumerate other personal certificates.
$now = Get-Date
$store = if ($MachineStore) { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }
$certificates = @(Get-ChildItem -Path $store -CodeSigningCert | Where-Object {
    $_.NotBefore -le $now -and $_.NotAfter -gt $now -and $_.HasPrivateKey
})
if ($certificates.Count -eq 0) {
    Write-Output @'
This setup check did not find a certificate ready for signing.

If you already have one, check that it is installed for this Windows user. For cloud signing, sign in to the desktop app. For a USB token, check that it is connected. Then run this check again.

Need a certificate? A registered business, including a sole trader or micro company, can order Standard at Klarseal. EU and UK orders currently need a VAT number:
https://klarseal.com/code-signing/standard/?utm_source=github&utm_medium=readme&utm_campaign=sign-my-app
'@
} else {
    $certificates | ForEach-Object {
        [pscustomobject]@{
            Subject = ConvertTo-SigningDisplayText $_.Subject
            Thumbprint = ConvertTo-SigningDisplayText $_.Thumbprint
        }
    }
    Write-Output 'Visibility is not proof that the key is accessible or the certificate is publicly trusted.'
}
