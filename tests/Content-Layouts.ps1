# Layout-only PE fixtures: never executed, compiled or signed. No certificates.
[CmdletBinding()]
param([switch]$Measure, [string]$DigestScript)
$ErrorActionPreference = 'Stop'
if (-not $DigestScript) { $DigestScript = Join-Path $PSScriptRoot '../scripts/Authenticode-Content.ps1' }
. $DigestScript
$layoutRoot = Join-Path ([IO.Path]::GetTempPath()) ('sign-my-app-layouts-' + [guid]::NewGuid().ToString('N'))
function Get-LayoutDigest($Path) {
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try { Get-AuthenticodeContentDigest $Path $stream } finally { $stream.Dispose() }
}
try {
    $null = New-Item -ItemType Directory -Path $layoutRoot
    # Faithful content-comparison layouts, not functioning package builders:
    # PE stub + opaque archive/bundle + footer; signing appends an aligned table.
    $layouts = @(
        @{ Name = 'PyInstaller overlay'; Overlay = ('PYZ' + ('archive' * 37) + 'MEI' + [char]0x0c + [char]0x0b + [char]0x0a + [char]0x0b + [char]0x0e); Gap = 0 },
        @{ Name = 'NSIS overlay'; Overlay = ('NullsoftInst' + ('compressed-block' * 29)); Gap = 0 },
        @{ Name = 'Inno Setup overlay'; Overlay = ('Inno Setup Setup Data' + ('compressed-block' * 31)); Gap = 0 },
        @{ Name = 'Electron overlay (PE32+)'; Overlay = ('7zSfx' + ('app.asar' * 43)); Gap = 0; PE64 = 1 },
        @{ Name = '.NET single-file overlay (PE32+)'; Overlay = ('bundle-payload' * 41) + 'bundle-manifest'; Gap = 0; PE64 = 1 },
        @{ Name = 'Unaligned final section'; Overlay = ''; Gap = 0; Short = 1 },
        @{ Name = 'Unaligned .rsrc + gap'; Overlay = 'overlay'; Gap = 135; Short = 1 }
    )
    foreach ($layout in $layouts) {
        $unsigned = Join-Path $layoutRoot 'before.exe'; $signed = Join-Path $layoutRoot 'after.exe'
        $stream = New-Object IO.MemoryStream
        $writer = New-Object IO.BinaryWriter($stream)
        $optionalSize = if ($layout.PE64) { 240 } else { 224 }
        $securityOffset = if ($layout.PE64) { 296 } else { 280 }
        try {
            $stream.SetLength(2048 - $(if ($layout.Short -and -not $layout.Gap) { 135 } else { 0 }))
            $writer.Write([uint16]0x5a4d); $stream.Position = 0x3c; $writer.Write([uint32]128)
            $stream.Position = 128; $writer.Write([uint32]0x4550)
            $writer.Write([uint16]$(if ($layout.PE64) { 0x8664 } else { 0x14c })); $writer.Write([uint16]3)
            $stream.Position = 148; $writer.Write([uint16]$optionalSize)
            $stream.Position = 152; $writer.Write([uint16]$(if ($layout.PE64) { 0x20b } else { 0x10b }))
            $stream.Position = 188; $writer.Write([uint32]512) # FileAlignment
            $stream.Position = 212; $writer.Write([uint32]512) # SizeOfHeaders
            $stream.Position = $securityOffset - 36; $writer.Write([uint32]16) # NumberOfRvaAndSizes
            for ($i = 0; $i -lt 3; $i++) {
                $stream.Position = 152 + $optionalSize + 40 * $i + 16
                $size = if (($layout.Gap -and $i -eq 1) -or ($layout.Short -and -not $layout.Gap -and $i -eq 2)) { 377 } else { 512 }
                $writer.Write([uint32]$size); $writer.Write([uint32](512 + 512 * $i))
            }
            $stream.Position = $stream.Length
            $writer.Write([Text.Encoding]::ASCII.GetBytes($layout.Overlay))
            [IO.File]::WriteAllBytes($unsigned, $stream.ToArray())
            # Emulate only SignTool's excluded fields, zero alignment, and table.
            while ($stream.Length % 8) { $writer.Write([byte]0) }
            $certificateOffset = $stream.Length
            $writer.Write((New-Object byte[] 256))
            $stream.Position = 216; $writer.Write([uint32]12345) # checksum
            $stream.Position = $securityOffset; $writer.Write([uint32]$certificateOffset); $writer.Write([uint32]256)
            [IO.File]::WriteAllBytes($signed, $stream.ToArray())
        } finally { $writer.Dispose(); $stream.Dispose() }
        try {
            $before = Get-LayoutDigest $unsigned; $after = Get-LayoutDigest $signed
            $outcome = if ($before -eq 'content-comparison: not possible') { 'not possible' } elseif ($before -eq $after) { 'equal' } else { 'MISMATCH' }
        } catch { $outcome = 'refused: ' + $_.Exception.Message }
        if ($Measure) { [pscustomobject]@{ FileType = $layout.Name; Comparison = $outcome } }
        else {
            $expected = if ($layout.Gap) { 'not possible' } else { 'equal' }
            if ($outcome -ne $expected) { throw "$($layout.Name): $outcome (expected $expected)" }
            Write-Output "PASS: layout $($layout.Name): $outcome"
        }
    }
    # Real installed Git is read only. Do not check its signer or use its key.
    $git = (Get-Command git.exe).Source
    try { $digest = Get-LayoutDigest $git; $result = if ($digest -eq 'content-comparison: not possible') { 'not possible' } else { 'parsed' } }
    catch { $result = 'refused: ' + $_.Exception.Message }
    if ($Measure) { [pscustomobject]@{ FileType = 'Installed git.exe'; Comparison = $result } }
    elseif ($result -notin @('parsed','not possible')) { throw "Git comparison unexpectedly $result" }
    else { Write-Output "PASS: installed Git comparison: $result" }
} finally {
    $cleanup = [IO.Path]::GetFullPath($layoutRoot)
    if ([IO.Path]::GetDirectoryName($cleanup) -ne [IO.Path]::GetTempPath().TrimEnd('\') -or [IO.Path]::GetFileName($cleanup) -notmatch '^sign-my-app-layouts-[a-f0-9]{32}$') { throw 'Unsafe layout cleanup.' }
    if (Test-Path -LiteralPath $cleanup) { Remove-Item -LiteralPath $cleanup -Recurse -Force }
}
