# Managed PE content comparison. Windows verifies the signature separately.
# https://learn.microsoft.com/windows/win32/debug/pe-format#authenticode-pe-image-hash
# MSI SIP content hashing requires a native helper and is deliberately omitted.
function Get-AuthenticodeContentDigest([string]$Path, [IO.FileStream]$LockedFile) {
    if ([IO.Path]::GetExtension($Path) -eq '.msi') { return 'content-comparison: not possible' }
    $reader = New-Object IO.BinaryReader($LockedFile, [Text.Encoding]::UTF8, $true)
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $LockedFile.Position = 0
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Invalid PE image.' }
        $LockedFile.Position = 0x3c; $pe = $reader.ReadUInt32()
        if ($pe -lt 64 -or $pe -gt $LockedFile.Length - 24) { throw 'Invalid PE header.' }
        $LockedFile.Position = $pe
        if ($reader.ReadUInt32() -ne 0x4550) { throw 'Invalid PE signature.' }
        $LockedFile.Position = $pe + 6; $count = $reader.ReadUInt16()
        $LockedFile.Position = $pe + 20; $optionalSize = $reader.ReadUInt16()
        $optional = $pe + 24
        if ($optionalSize -lt 2 -or $optional + $optionalSize -gt $LockedFile.Length) { throw 'Invalid PE optional header size.' }
        $LockedFile.Position = $optional; $magic = $reader.ReadUInt16()
        $directory = switch ($magic) { 0x10b { $optional + 96 } 0x20b { $optional + 112 } default { throw 'Invalid PE optional header.' } }
        $checksum = $optional + 64; $security = $directory + 32
        if ($directory -gt $optional + $optionalSize) { throw 'Truncated PE optional header.' }
        $LockedFile.Position = $directory - 4; $directoryCount = $reader.ReadUInt32()
        if ([long]$directory + 8L * $directoryCount -gt $optional + $optionalSize) { throw 'Truncated PE data directories.' }
        $hasSecurity = $directoryCount -ge 5
        $LockedFile.Position = $optional + 60; $headers = $reader.ReadUInt32()
        $certificate = $certificateSize = 0
        if ($hasSecurity) { $LockedFile.Position = $security; $certificate = $reader.ReadUInt32(); $certificateSize = $reader.ReadUInt32() }
        if ($headers -gt $LockedFile.Length -or $optional + $optionalSize + 40 * $count -gt $headers) { throw 'Invalid PE header size.' }
        $sections = @()
        for ($i = 0; $i -lt $count; $i++) {
            $LockedFile.Position = $optional + $optionalSize + 40 * $i + 16
            $size = $reader.ReadUInt32(); $offset = $reader.ReadUInt32()
            if ($size) { $sections += [pscustomobject]@{ Offset = [long]$offset; Size = [long]$size } }
        }
        $ranges = @()
        if ($hasSecurity) { $ranges = @(@(0L, [long]$checksum), @([long]($checksum + 4), [long]($security - $checksum - 4)), @([long]($security + 8), [long]($headers - $security - 8))) }
        $end = [long]$headers; $comparable = $hasSecurity
        foreach ($section in ($sections | Sort-Object Offset)) {
            if ($section.Offset -gt $LockedFile.Length -or $section.Size -gt $LockedFile.Length - $section.Offset) { throw 'Invalid or truncated PE section. Nothing signed.' }
            if ($section.Offset -ne $end) { $comparable = $false }
            $ranges += ,@($section.Offset, $section.Size); $end = [Math]::Max($end, ($section.Offset + $section.Size))
        }
        $contentEnd = $LockedFile.Length
        if ($certificateSize) {
            if ($certificate -lt $end -or $certificateSize -lt 8 -or [long]$certificate + $certificateSize -gt $LockedFile.Length) { throw 'Invalid or truncated PE certificate table.' }
            if ([long]$certificate + $certificateSize -ne $LockedFile.Length) { $comparable = $false }
            $contentEnd = $certificate
        } elseif ($certificate) { throw 'Invalid PE certificate directory.' }
        # Unsupported layouts are distinct from malformed/truncated images.
        # Finish bounds validation before selecting Windows verification instead.
        if (-not $comparable) { return 'content-comparison: not possible' }
        if ($contentEnd -gt $end) { $ranges += ,@($end, ($contentEnd - $end)) }
        $buffer = New-Object byte[] 65536
        foreach ($range in $ranges) {
            $LockedFile.Position = $range[0]; $remaining = $range[1]
            while ($remaining -gt 0) {
                $read = $LockedFile.Read($buffer, 0, [int][Math]::Min($buffer.Length, $remaining))
                if ($read -le 0) { throw 'Unexpected end of PE image.' }
                $null = $hash.TransformBlock($buffer, 0, $read, $buffer, 0); $remaining -= $read
            }
        }
        # SignTool aligns the certificate table to eight bytes with zero padding.
        $padding = (8 - ($contentEnd % 8)) % 8
        if ($padding) { $zeros = New-Object byte[] $padding; $null = $hash.TransformBlock($zeros, 0, $zeros.Length, $zeros, 0) }
        $null = $hash.TransformFinalBlock((New-Object byte[] 0), 0, 0)
        return [BitConverter]::ToString($hash.Hash).Replace('-', '')
    } finally { $reader.Dispose(); $hash.Dispose() }
}
function Read-SigningDerNode([byte[]]$Bytes, [ref]$Offset, [int]$End, [int]$Tag) {
    $position = $Offset.Value
    if ($position -lt 0 -or $position + 2 -gt $End -or $Bytes[$position++] -ne $Tag) { throw 'Invalid signed digest encoding.' }
    $length = [int]$Bytes[$position++]
    if ($length -ge 128) {
        $count = $length -band 127; $length = 0
        if ($count -lt 1 -or $count -gt 4 -or $position + $count -gt $End) { throw 'Invalid signed digest length.' }
        for ($i = 0; $i -lt $count; $i++) { $length = ([long]$length * 256) + $Bytes[$position++] }
    }
    if ($length -gt $End - $position) { throw 'Truncated signed digest.' }
    $Offset.Value = [int]($position + $length)
    return @{ Start = $position; End = [int]($position + $length); Length = $length }
}
function Assert-PeSigningSignature([IO.FileStream]$File, [string]$Thumbprint, [string]$Digest) {
    Add-Type -AssemblyName System.Security
    $reader = New-Object IO.BinaryReader($File, [Text.Encoding]::UTF8, $true)
    try {
        $File.Position = 0x3c; $pe = $reader.ReadUInt32()
        $File.Position = $pe + 24; $magic = $reader.ReadUInt16()
        $File.Position = $pe + 24 + $(if ($magic -eq 0x10b) { 128 } else { 144 })
        $offset = $reader.ReadUInt32(); $size = $reader.ReadUInt32()
        if (-not $size) { throw 'Signed snapshot has no readable signature.' }
        if ($size -lt 8 -or $size -gt 16MB -or [long]$offset + $size -ne $File.Length) { throw 'Invalid snapshot signature size.' }
        $File.Position = $offset; $length = $reader.ReadUInt32()
        if ($length -lt 8 -or $length -gt $size -or $reader.ReadUInt16() -ne 0x200 -or $reader.ReadUInt16() -ne 2) { throw 'Invalid PE certificate record.' }
        $cms = New-Object Security.Cryptography.Pkcs.SignedCms
        $cms.Decode($reader.ReadBytes($length - 8))
        if ($cms.ContentInfo.ContentType.Value -ne '1.3.6.1.4.1.311.2.1.4' -or $cms.SignerInfos.Count -ne 1 -or $cms.SignerInfos[0].Certificate.Thumbprint -ne $Thumbprint) { throw 'Signed snapshot has an unexpected publisher or content type.' }
        $cms.CheckSignature($true)
        $content = $cms.ContentInfo.Content; $position = 0
        $outer = Read-SigningDerNode $content ([ref]$position) $content.Length 0x30
        if ($position -ne $content.Length) { throw 'Invalid signed content.' }
        $position = $outer.Start
        $null = Read-SigningDerNode $content ([ref]$position) $outer.End 0x30
        $info = Read-SigningDerNode $content ([ref]$position) $outer.End 0x30
        if ($position -ne $outer.End) { throw 'Invalid digest info.' }
        $position = $info.Start
        $algorithm = Read-SigningDerNode $content ([ref]$position) $info.End 0x30
        $value = Read-SigningDerNode $content ([ref]$position) $info.End 4
        if ($position -ne $info.End -or $value.Length -ne 32) { throw 'Expected a SHA-256 signature digest.' }
        $algorithmPosition = $algorithm.Start
        $oid = Read-SigningDerNode $content ([ref]$algorithmPosition) $algorithm.End 6
        $oidHex = [BitConverter]::ToString($content, $oid.Start, $oid.Length)
        if ($oidHex -ne '60-86-48-01-65-03-04-02-01') { throw 'Expected the SHA-256 algorithm.' }
        $signedDigest = [BitConverter]::ToString($content, $value.Start, $value.Length).Replace('-', '')
        if ($signedDigest -ne $Digest) { throw 'Signed snapshot Authenticode digest does not match its signature.' }
    } finally { $reader.Dispose() }
}
function Get-SigningSnapshotDigest([string]$Path, [IO.FileStream]$LockedFile, [string]$Thumbprint, [string]$ExpectedDigest) {
    $digest = Get-AuthenticodeContentDigest $Path $LockedFile
    $unavailable = 'content-comparison: not possible'
    if ($ExpectedDigest -and $ExpectedDigest -ne $unavailable -and $digest -ne $ExpectedDigest) {
        throw 'Signed snapshot Authenticode digest does not match the approved bytes. Original untouched.'
    }
    if ($Thumbprint -and ($digest -eq $unavailable -or $ExpectedDigest -eq $unavailable)) {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path
        if ($signature.SignerCertificate.Thumbprint -ne $Thumbprint -or $signature.Status -notin @('Valid','NotTrusted')) {
            throw 'Windows SIP integrity or signature verification failed. Original untouched.'
        }
    } elseif ($Thumbprint) {
        Assert-PeSigningSignature $LockedFile $Thumbprint $digest
    }
    if ($ExpectedDigest -eq $unavailable) { return $unavailable }
    return $digest
}
