#Requires -Version 5.1
# Discovery also removes our exact stale private stages. Never execute candidates.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ProjectFolder)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Signing-Safety.ps1"
$root = Resolve-LocalSigningFile $ProjectFolder
if (-not $root.PSIsContainer -or $root.FullName -eq [IO.Path]::GetPathRoot($root.FullName)) {
    throw 'Choose a build output folder, not a file or a whole drive.'
}
if (@($root.FullName.Split('\') | Where-Object { $_ -like 'sign-my-app-approved-*' }).Count) { return }
$pending = New-Object 'Collections.Generic.Stack[string]'
$pending.Push($root.FullName)
$clock = [Diagnostics.Stopwatch]::StartNew()
$visited = 0; $candidates = 0; $bytes = 0L
while ($pending.Count) {
    $directory = Resolve-LocalSigningFile $pending.Pop()
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($directory.FullName)) {
        $visited++
        if ($visited -gt 10000 -or $clock.Elapsed.TotalSeconds -gt 35) { throw 'Discovery limit reached. Choose a smaller build output folder.' }
        $item = Get-Item -LiteralPath $entry -Force
        # Do not follow links, read project instructions or enter private/configuration folders.
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        if ($item.PSIsContainer) {
            if ($item.Name -like 'sign-my-app-approved-*') {
                Remove-StaleSigningStage $item.FullName $directory.FullName
                continue
            }
            if ($item.Name -notin @('.git', 'node_modules', 'venv', '.venv', '.aws', '.codex', '.agents', '.claude', 'legal')) {
                $null = Resolve-LocalSigningFile $item.FullName
                $pending.Push($item.FullName)
            }
        } elseif ($item.Extension -in @('.exe', '.dll', '.msi')) {
            $candidates++; $bytes += $item.Length
            if ($candidates -gt 200 -or $item.Length -gt 1GB -or $bytes -gt 8GB) { throw 'Discovery size limit reached. Choose a smaller build output folder.' }
            $file = Resolve-LocalSigningFile $item.FullName
            [pscustomobject]@{
                Path = $file.FullName
                SHA256 = Get-SigningHash $file.FullName
                Bytes = $file.Length
                ModifiedUtc = $file.LastWriteTimeUtc.ToString('o')
            }
        }
    }
}
