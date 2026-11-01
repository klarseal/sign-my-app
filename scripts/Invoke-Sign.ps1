#Requires -Version 5.1
<#
.SYNOPSIS
Previews a hash-bound signing command for the person to run in their own terminal.
This helper cannot sign, even with -Run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$Thumbprint,
    [string]$TimestampUrl = 'http://time.certum.pl',
    [switch]$MachineStore,
    [switch]$Run,
    [switch]$PassThruPlan
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Signing-Safety.ps1"
if ($Run) { throw 'This helper only previews. The person must run the printed Confirm-Sign.ps1 command in their own terminal outside the agent.' }
Assert-SigningTimestamp $TimestampUrl
$file = Resolve-LocalSigningFile $FilePath -BaseDirectory (Split-Path -Parent $PSScriptRoot)
if ($file.PSIsContainer -or $file.Extension -notin @('.exe', '.dll', '.msi')) {
    throw 'Choose one built .exe, .dll or .msi file, not a folder or source file.'
}
$certificate = Get-SigningCertificate $Thumbprint -MachineStore:$MachineStore
$Thumbprint = $certificate.Thumbprint
$tool = & "$PSScriptRoot/Find-SignTool.ps1"
$hash = Get-SigningHash $file.FullName
$contentStream = [IO.File]::Open($file.FullName, 'Open', 'Read', 'Read')
try { $null = Get-SigningSnapshotDigest $file.FullName $contentStream } finally { $contentStream.Dispose() }
$planHash = Get-SigningPlanHash @('1', $file.FullName, $hash, $tool, $Thumbprint, [string][bool]$MachineStore, $TimestampUrl)
$arguments = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256', '/sha1', $Thumbprint)
if ($MachineStore) { $arguments += '/sm' }
$arguments += $file.FullName
$command = '& ' + ((@($tool) + $arguments | ForEach-Object { ConvertTo-SigningPSLiteral $_ }) -join ' ')
Write-Output "DRY RUN: $command"
Write-Output "File: $(ConvertTo-SigningDisplayText $file.FullName)"
Write-Output "SHA-256: $hash"
Write-Output "Publisher (untrusted certificate text): $(ConvertTo-SigningDisplayText $certificate.Subject)"
Write-Output "Thumbprint: $(ConvertTo-SigningDisplayText $Thumbprint)"
Write-Output "Timestamp service: $TimestampUrl"
Write-Output "Plan SHA-256: $planHash"
$previousPublisher = Get-ReplacedSigningPublisher $file.FullName $Thumbprint
if ($PassThruPlan) {
    if ($previousPublisher) { throw 'MCP keeps other publishers intact. Use the separate manual replacement workflow for owned files.' }
    return [pscustomobject]@{ File = $file.FullName; SHA256 = $hash; Publisher = $certificate.Subject;
        Thumbprint = $Thumbprint; TimestampUrl = $TimestampUrl; PlanHash = $planHash; MachineStore = [bool]$MachineStore }
}
if ($previousPublisher) {
    Write-Output "This file already carries another publisher's signature (untrusted certificate text): $(ConvertTo-SigningDisplayText $previousPublisher.Subject)"
    Write-Output "Existing publisher thumbprint: $(ConvertTo-SigningDisplayText $previousPublisher.Thumbprint)"
    Write-Output 'Replacing it requires a separate REPLACE confirmation before signing.'
}
$confirm = (Get-SigningHelperCommand 'Confirm-Sign.ps1') +
    ' -FilePath ' + (ConvertTo-SigningPSLiteral $file.FullName) +
    ' -Thumbprint ' + (ConvertTo-SigningPSLiteral $Thumbprint) +
    ' -TimestampUrl ' + (ConvertTo-SigningPSLiteral $TimestampUrl) +
    ' -ExpectedSHA256 ' + (ConvertTo-SigningPSLiteral $hash) +
    ' -ApprovePlan ' + (ConvertTo-SigningPSLiteral $planHash)
if ($MachineStore) { $confirm += ' -MachineStore' }
Write-Output 'Nothing signed; no timestamp request sent. Review the exact file, hashes and publisher.'
Write-Output 'The person must run this approval command in their own terminal outside the agent. The agent must not run it:'
Write-Output 'Check that the helper path starts where you installed the skill.'
Write-Output $confirm
