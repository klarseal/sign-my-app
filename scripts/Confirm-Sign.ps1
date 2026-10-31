#Requires -Version 5.1
# The person must run this command; agents must not run it or type confirmation.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$Thumbprint,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSHA256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ApprovePlan,
    [string]$TimestampUrl = 'http://time.certum.pl',
    [switch]$MachineStore
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Signing-Safety.ps1"
$FilePath = (Resolve-LocalSigningFile $FilePath -BaseDirectory (Split-Path -Parent $PSScriptRoot)).FullName
$PSBoundParameters['FilePath'] = $FilePath
Invoke-ApprovedSigning @PSBoundParameters
Write-Output 'Signing command succeeded. Check that the helper path starts where you installed the skill.'
Write-Output ((Get-SigningHelperCommand 'Test-Signature.ps1') + ' -FilePath ' + (ConvertTo-SigningPSLiteral $FilePath))
