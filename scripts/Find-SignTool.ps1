#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Signing-Safety.ps1"
# Machine installation directories: never PATH, environment, HKCU or project paths.
$view = if ([Environment]::Is64BitOperatingSystem) { [Microsoft.Win32.RegistryView]::Registry64 } else { [Microsoft.Win32.RegistryView]::Registry32 }
$machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
try {
    $key = $machine.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion')
    try {
        $roots = @('ProgramFilesDir (x86)', 'ProgramFilesDir') | ForEach-Object {
            $value = $key.GetValue($_, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($value -and $value -match '^[a-z]:\\' -and $value -notmatch '%') { Join-Path $value 'Windows Kits\10\bin' }
        }
    } finally { if ($key) { $key.Dispose() } }
} finally { $machine.Dispose() }
$architectures = if ([Environment]::Is64BitProcess) { @('x64', 'x86') } else { @('x86') }
foreach ($bin in ($roots | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $bin -PathType Container)) { continue }
    $versions = Get-ChildItem -LiteralPath $bin -Directory | Where-Object {
        $_.Name -match '^\d+\.\d+\.\d+\.\d+$'
    } | Sort-Object { [version]$_.Name } -Descending
    foreach ($folder in (@($versions.FullName) + @($bin))) {
        foreach ($arch in $architectures) {
            $candidate = Join-Path $folder "$arch\signtool.exe"
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
            $item = Resolve-LocalSigningFile $candidate
            $signature = Get-AuthenticodeSignature -LiteralPath $item.FullName
            if ($signature.Status -eq 'Valid' -and
                $signature.SignerCertificate.Subject -match '(?i)(?:^|,)\s*O=Microsoft Corporation(?:,|$)') {
                return $item.FullName
            }
        }
    }
}
throw 'SignTool was not found with a valid Microsoft signature in Windows Kits under Program Files. Install the Windows SDK and select Windows SDK Signing Tools for Desktop Apps: https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads . Then try again.'
