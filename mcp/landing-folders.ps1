#Requires -Version 5.1
# Read only: managed special folders do not create or verify directories.
# Downloads: https://learn.microsoft.com/troubleshoot/windows-client/shell-experience/change-personal-folder-location-fails
$ErrorActionPreference = 'Stop'
function Get-LandingFolder([Environment+SpecialFolder]$Name) {
    $value = [Environment]::GetFolderPath($Name, [Environment+SpecialFolderOption]::DoNotVerify)
    if (-not $value) { throw 'Windows folder lookup unavailable.' }
    return $value
}
$profile = Get-LandingFolder UserProfile
$documents = Get-LandingFolder CommonDocuments
function Expand-LandingPath([string]$Value) {
    $Value = $Value -ireplace '%USERPROFILE%', $profile.Replace('$', '$$')
    $Value = $Value -ireplace '%SystemDrive%', ([IO.Path]::GetPathRoot([Environment]::SystemDirectory).TrimEnd('\'))
    if ($public) { $Value = $Value -ireplace '%PUBLIC%', $public.Replace('$', '$$') }
    $Value = [Environment]::ExpandEnvironmentVariables($Value)
    if (-not $Value -or $Value -match '%' -or -not [IO.Path]::IsPathRooted($Value)) { throw 'Windows folder lookup unavailable.' }
    return $Value
}
$publicKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList')
try { $public = $publicKey.GetValue('Public') } finally { if ($publicKey) { $publicKey.Dispose() } }
if (-not $public) { throw 'Public folder lookup unavailable.' }
$public = Expand-LandingPath $public
$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
try {
    $downloads = if ($key) { $key.GetValue('{374DE290-123F-4565-9164-39C4925E467B}', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
} finally { if ($key) { $key.Dispose() } }
if (-not $downloads) { $downloads = Join-Path $profile 'Downloads' }
# The bridge deliberately strips inherited USERPROFILE. Expand from Windows' profile.
$downloads = Expand-LandingPath $downloads
$common = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
try {
    $publicDownloads = if ($common) { $common.GetValue('{3D644C9B-1FB8-4F30-9B45-F670235F79C0}', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
} finally { if ($common) { $common.Dispose() } }
if (-not $publicDownloads) { $publicDownloads = Join-Path $public 'Downloads' }
$publicDownloads = Expand-LandingPath $publicDownloads
$folders = @(
    $profile; $downloads; (Get-LandingFolder DesktopDirectory); (Get-LandingFolder MyDocuments)
    $public; $publicDownloads; (Get-LandingFolder CommonDesktopDirectory); $documents
    (Join-Path (Get-LandingFolder Windows) 'Temp')
    (Join-Path (Get-LandingFolder LocalApplicationData) 'Temp')
    [IO.Path]::GetTempPath()
)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::WriteLine((ConvertTo-Json -InputObject $folders -Compress))
