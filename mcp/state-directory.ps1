#Requires -Version 5.1
# Windows known-folder API, never a project path or environment override.
$ErrorActionPreference = 'Stop'
$folder = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Klarseal\SignMyApp'
$current = [IO.Path]::GetPathRoot($folder)
foreach ($part in $folder.Substring($current.Length).Split('\')) {
    $current = Join-Path $current $part
    if (Test-Path -LiteralPath $current) {
        if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked state directory refused.' }
    }
}
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
foreach ($identity in @($sid, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
$null = [IO.Directory]::CreateDirectory($folder, $acl)
Set-Acl -LiteralPath $folder -AclObject $acl
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::WriteLine($folder)
