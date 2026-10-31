#Requires -Version 5.1
# Shared validation. Data from projects and certificate subjects is never executable text.
function Test-SigningControlText([string]$Value) {
    for ($i = 0; $i -lt $Value.Length; $i++) {
        $category = [Globalization.CharUnicodeInfo]::GetUnicodeCategory($Value, $i)
        if ($category -in @('Control', 'Format', 'LineSeparator', 'ParagraphSeparator')) { return $true }
        if ([char]::IsHighSurrogate($Value[$i]) -and $i + 1 -lt $Value.Length -and [char]::IsLowSurrogate($Value[$i + 1])) { $i++ }
    }
    return $false
}
function Assert-SafeSigningText([string]$Value) {
    if ((Test-SigningControlText $Value) -or $Value -match '[''"\u2018-\u201f`$;&|<>]') {
        throw 'This name contains control characters, quotes or shell characters. Rename it before using a signing command.'
    }
}
function ConvertTo-SigningDisplayText([string]$Value) {
    # Escape before truncating: no raw terminal controls, bidi controls or line breaks.
    # Escape backslashes too, so literal escape-looking text stays distinguishable.
    $display = New-Object Text.StringBuilder
    for ($i = 0; $i -lt $Value.Length; $i++) {
        $width = 1
        if ([char]::IsHighSurrogate($Value[$i]) -and $i + 1 -lt $Value.Length -and [char]::IsLowSurrogate($Value[$i + 1])) { $width = 2 }
        if (Test-SigningControlText ($Value.Substring($i, $width))) {
            $escape = if ($width -eq 2) { '\U{0:X8}' -f [char]::ConvertToUtf32($Value, $i) } else { '\u{0:X4}' -f [int]$Value[$i] }
            $null = $display.Append($escape)
        } elseif ($Value[$i] -eq '\') { $null = $display.Append('\\') }
        else { $null = $display.Append($Value.Substring($i, $width)) }
        if ($display.Length -gt 512) { return $display.ToString(0, 509) + '...' }
        $i += $width - 1
    }
    return $display.ToString()
}
function Resolve-LocalSigningFile([string]$FilePath, [string]$BaseDirectory) {
    Assert-SafeSigningText $FilePath
    # Check before Get-Item, GetFullPath or Get-FileHash: no SMB/device access in preview.
    if (-not $FilePath -or $FilePath -match '^[\\/]{2}|^[\\/][?.]|^[a-z]:[^\\/]' -or
        ($FilePath -replace '^[a-z]:[\\/]', '') -match ':') {
        throw 'Use a local drive path. Network (UNC), device paths and alternate data streams are not allowed.'
    }
    if ($FilePath -notmatch '^[a-z]:[\\/]') {
        if ($FilePath -match '^[\\/]' -or $BaseDirectory -notmatch '^[a-z]:[\\/]') {
            throw 'Relative file paths require an explicit local drive base directory.'
        }
        Assert-SafeSigningText $BaseDirectory
        $FilePath = Join-Path $BaseDirectory $FilePath
    }
    $full = [IO.Path]::GetFullPath($FilePath)
    if ($full -notmatch '^[a-z]:\\') { throw 'Use a local drive path.' }
    $current = [IO.Path]::GetPathRoot($full)
    foreach ($part in $full.Substring($current.Length).Split('\')) {
        $current = Join-Path $current $part
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Use a local file directly, without symbolic links or directory junctions.'
        }
    }
    return Get-Item -LiteralPath $full
}
function Test-PublicSigningAddress([string]$Address) {
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip)) { return $false }
    $b = $ip.GetAddressBytes()
    if ($b.Length -eq 16) {
        return (($b[0] -band 0xe0) -eq 0x20 -and -not ($b[0] -eq 0x20 -and
            ($b[1] -eq 2 -or ($b[1] -eq 1 -and (($b[2] -eq 0) -or ($b[2] -eq 0x0d -and $b[3] -eq 0xb8))))))
    }
    return -not ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224 -or
        ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
        ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
        ($b[0] -eq 192 -and ($b[1] -eq 168 -or $b[1] -eq 0 -or ($b[1] -eq 88 -and $b[2] -eq 99))) -or
        ($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19 -or ($b[1] -eq 51 -and $b[2] -eq 100))) -or
        ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113))
}
function Assert-SigningTimestamp([string]$TimestampUrl, [switch]$ResolveHost) {
    $uri = $null
    if ((Test-SigningControlText $TimestampUrl) -or $TimestampUrl -match '[\s''"\u2018-\u201f`\\<>]' -or
        -not [uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -notin @('http','https') -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
        $uri.Host -notmatch '\.' -or $uri.Host -match '\.(localhost|local|internal|lan|home|test|invalid|example)\.?$|\.$') {
        throw 'Use an HTTP(S) timestamp URL with a public host, without spaces, quotes, credentials, query or fragment.'
    }
    $ip = $null
    if ([Net.IPAddress]::TryParse($uri.DnsSafeHost, [ref]$ip) -and -not (Test-PublicSigningAddress $uri.DnsSafeHost)) {
        throw 'The timestamp host must be public; local and private addresses are not allowed.'
    }
    if ($ResolveHost) {
        $addresses = @([Net.Dns]::GetHostAddresses($uri.DnsSafeHost))
        if ($addresses.Count -eq 0 -or @($addresses | Where-Object { -not (Test-PublicSigningAddress $_.ToString()) }).Count) {
            throw 'The timestamp host must resolve only to public addresses.'
        }
    }
}
function ConvertTo-SigningPSLiteral([string]$Value) {
    Assert-SafeSigningText $Value
    return "'" + $Value + "'"
}
function Get-SigningHash([string]$FilePath) {
    $file = Resolve-LocalSigningFile $FilePath
    if ($file.PSIsContainer) { throw 'Choose a built file, not a folder.' }
    return (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
}
function Get-SigningPlanHash([string[]]$Fields) {
    # Canonical length-prefixed UTF-8 fields: paths, file hash, tool, publisher thumbprint,
    # store and timestamp. Length prefixes prevent separator collisions.
    $text = ''
    foreach ($field in $Fields) { $text += $field.Length.ToString([Globalization.CultureInfo]::InvariantCulture) + ':' + $field }
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-', '') }
    finally { $algorithm.Dispose() }
}
function Get-SigningCertificate([string]$Thumbprint, [switch]$MachineStore) {
    if ($Thumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Choose a publisher with -Thumbprint from Test-SigningSetup.ps1.' }
    $store = 'CurrentUser'
    if ($MachineStore) { $store = 'LocalMachine' }
    $cert = Get-Item -LiteralPath ('Cert:\' + $store + '\My\' + $Thumbprint)
    if (-not @($cert.EnhancedKeyUsageList | Where-Object { [string]$_.ObjectId -eq '1.3.6.1.5.5.7.3.3' }).Count) { throw 'Choose a code signing certificate.' }
    if (-not $cert.HasPrivateKey -or $cert.NotBefore -gt (Get-Date) -or $cert.NotAfter -le (Get-Date)) {
        throw 'This certificate is not ready for signing. Check its dates and signing-app login.'
    }
    return $cert
}
function Invoke-SigningNative([string]$Tool, [string[]]$Arguments) {
    # ProcessStartInfo bypasses PS 5.1 native argument reserialization. Quote every Windows
    # argument; quotes are forbidden and trailing backslashes must be doubled before closing.
    $nativeArguments = foreach ($argument in $Arguments) {
        if ($argument.Contains('"') -or (Test-SigningControlText $argument)) { throw 'Unsafe native argument.' }
        '"' + ($argument -replace '(\\+)$', '$1$1') + '"'
    }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Tool
    $info.Arguments = $nativeArguments -join ' '
    $info.WorkingDirectory = Split-Path -Parent $Tool
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($info)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        if ($output) { Write-Host (ConvertTo-SigningDisplayText $output) }
        if ($process.ExitCode -ne 0) { throw "Signing failed or warned (exit $($process.ExitCode)). Inspect the file before retrying; do not release it." }
    } finally { $process.Dispose() }
}
function Assert-SigningApproval([string]$FilePath, [string]$ExpectedSHA256, [string]$ApprovePlan,
    [string]$Tool, [string]$Thumbprint, [bool]$MachineStore, [string]$TimestampUrl) {
    $file = Resolve-LocalSigningFile $FilePath
    $hash = Get-SigningHash $file.FullName
    $planHash = Get-SigningPlanHash @('1', $file.FullName, $hash, $Tool, $Thumbprint, [string]$MachineStore, $TimestampUrl)
    if ($hash -ne $ExpectedSHA256 -or $planHash -ne $ApprovePlan) {
        throw 'The file or signing plan changed after preview. Nothing signed. Preview it again.'
    }
}
function Initialize-AuthenticodeDigest {
    if (-not ('SignMyApp.AuthenticodeDigest' -as [type])) {
        Add-Type -AssemblyName System.Security
        Add-Type -Path (Join-Path $PSScriptRoot 'Authenticode-Digest.cs') -ReferencedAssemblies ([Security.Cryptography.Pkcs.SignedCms].Assembly.Location)
    }
}
function Get-AuthenticodeContentDigest([string]$Path, [IO.FileStream]$LockedFile) {
    Initialize-AuthenticodeDigest
    return [SignMyApp.AuthenticodeDigest]::Compute($Path, $LockedFile)
}
function Get-SigningSnapshotDigest([string]$Path, [IO.FileStream]$LockedFile,
    [string]$Thumbprint, [string]$ExpectedDigest) {
    $copyPath = $null
    $copyStream = $null
    try {
        $checkPath = $Path
        $checkStream = $LockedFile
        if ([IO.Path]::GetExtension($Path) -eq '.msi') {
            # The MSI SIP needs writable sharing and can rewrite compound storage
            # even when calculating a digest. Give it a disposable byte-for-byte
            # copy, while keeping the actual snapshot write/rename locked.
            $copyPath = Join-Path ([IO.Path]::GetDirectoryName($Path)) ('digest-' + [guid]::NewGuid().ToString('N') + '.msi')
            $writer = [IO.File]::Open($copyPath, 'CreateNew', 'Write', 'None')
            try { $LockedFile.Position = 0; $LockedFile.CopyTo($writer) } finally { $writer.Dispose() }
            $copyStream = [IO.File]::Open($copyPath, 'Open', 'Read', 'ReadWrite')
            $checkPath = $copyPath
            $checkStream = $copyStream
        }
        Initialize-AuthenticodeDigest
        # Verify the untouched signed copy before Compute can rewrite MSI metadata.
        if ($ExpectedDigest) {
            [SignMyApp.AuthenticodeDigest]::Verify($checkPath, $checkStream, $Thumbprint, $ExpectedDigest)
        }
        $digest = Get-AuthenticodeContentDigest $checkPath $checkStream
        if ($ExpectedDigest) {
            if ($digest -ne $ExpectedDigest) {
                throw 'Signed snapshot Authenticode digest does not match the approved bytes. Original untouched.'
            }
        }
        return $digest
    } finally {
        if ($copyStream) { $copyStream.Dispose() }
        if ($copyPath -and (Test-Path -LiteralPath $copyPath)) { Remove-Item -LiteralPath $copyPath -Force }
    }
}
function Get-SigningHelperCommand([string]$Name) {
    if ($Name -notin @('Find-SignTool.ps1', 'Test-SigningSetup.ps1', 'Invoke-Sign.ps1', 'Confirm-Sign.ps1', 'Test-Signature.ps1')) {
        throw 'Unknown signing helper.'
    }
    $path = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Name))
    Assert-SafeSigningText $path
    # SystemDirectory comes from Windows, never WINDIR, SystemRoot, PATH or CWD.
    $powershell = [IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\powershell.exe')
    Assert-SafeSigningText $powershell
    return '& "' + $powershell + '" -NoProfile -ExecutionPolicy Bypass -File "' + $path + '"'
}
function Get-ReplacedSigningPublisher([string]$Path, [string]$Thumbprint) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.SignerCertificate -and $signature.SignerCertificate.Thumbprint -ne $Thumbprint) {
        return $signature.SignerCertificate
    }
}
function Invoke-ApprovedSigning {
    [CmdletBinding()]
    param([string]$FilePath, [string]$ExpectedSHA256, [string]$ApprovePlan,
        [string]$Thumbprint, [string]$TimestampUrl = 'http://time.certum.pl', [switch]$MachineStore)
    # These checks belong to the operation itself, including when called directly.
    # They prevent mistakes; they cannot establish who controls this process.
    if ($ExpectedSHA256 -notmatch '^[A-Fa-f0-9]{64}$' -or $ApprovePlan -notmatch '^[A-Fa-f0-9]{64}$') {
        throw 'A previewed file hash and approval plan are required. Nothing signed.'
    }
    $original = Resolve-LocalSigningFile $FilePath -BaseDirectory (Split-Path -Parent $PSScriptRoot)
    if ($original.PSIsContainer -or $original.Extension -notin @('.exe', '.dll', '.msi')) { throw 'Choose one built .exe, .dll or .msi file.' }
    Assert-SigningTimestamp $TimestampUrl -ResolveHost
    $cert = Get-SigningCertificate $Thumbprint -MachineStore:$MachineStore
    $tool = & "$PSScriptRoot/Find-SignTool.ps1"
    Assert-SigningApproval $original.FullName $ExpectedSHA256 $ApprovePlan $tool $cert.Thumbprint ([bool]$MachineStore) $TimestampUrl
    Write-Host "File: $(ConvertTo-SigningDisplayText $original.FullName)"
    Write-Host "SHA-256: $ExpectedSHA256"
    Write-Host "Publisher (untrusted certificate text): $(ConvertTo-SigningDisplayText $cert.Subject)"
    Write-Host "Thumbprint: $(ConvertTo-SigningDisplayText $cert.Thumbprint)"
    Write-Host "Timestamp service: $TimestampUrl"
    Write-Host "Plan SHA-256: $ApprovePlan"
    $previousPublisher = Get-ReplacedSigningPublisher $original.FullName $cert.Thumbprint
    if ($previousPublisher) {
        Write-Host "This file already carries another publisher's signature (untrusted certificate text): $(ConvertTo-SigningDisplayText $previousPublisher.Subject)"
        Write-Host "Existing publisher thumbprint: $(ConvertTo-SigningDisplayText $previousPublisher.Thumbprint)"
        $replaceAnswer = Read-Host "Type REPLACE $(ConvertTo-SigningDisplayText $previousPublisher.Thumbprint) to allow replacing that signature"
        if ($replaceAnswer -cne "REPLACE $($previousPublisher.Thumbprint)") {
            throw 'Replacement confirmation did not match the existing publisher. Nothing signed.'
        }
    }
    $answer = Read-Host "Type SIGN $ApprovePlan to confirm this plan"
    if ($answer -cne "SIGN $ApprovePlan") { throw 'Typed confirmation did not match the plan hash. Nothing signed.' }
    # Resolve and bind the SDK tool again after the prompt, before any execution.
    $tool = & "$PSScriptRoot/Find-SignTool.ps1"
    Assert-SigningApproval $original.FullName $ExpectedSHA256 $ApprovePlan $tool $cert.Thumbprint ([bool]$MachineStore) $TimestampUrl
    $arguments = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256', '/sha1', $cert.Thumbprint)
    if ($MachineStore) { $arguments += '/sm' }
    $stageDir = $null
    $lockedSnapshot = $null
    $lockedOriginal = $null
    try {
        # A private, same-volume snapshot limits other identities' access. SignTool
        # must write it, so no write-denying handle can span signing. Same-account
        # code can still interfere; compare Authenticode content before committing.
        $stageRoot = $original.DirectoryName
        $stageDir = Join-Path $stageRoot ('sign-my-app-approved-' + [guid]::NewGuid().ToString('N'))
        $security = New-Object Security.AccessControl.DirectorySecurity
        $security.SetAccessRuleProtection($true, $false)
        $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $security.SetOwner($owner)
        foreach ($sid in @($owner, (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'))) {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $security.AddAccessRule($rule)
        }
        # Set the protected ACL at creation, rather than after exposing the directory.
        [IO.Directory]::CreateDirectory($stageDir, $security) | Out-Null
        $snapshot = Join-Path $stageDir ('approved' + $original.Extension)
        # Copy bytes through a newly created file so a broad source-file ACL is
        # never copied into the private directory (CopyFile can preserve it).
        $source = $destination = $null
        try {
            $source = [IO.File]::Open($original.FullName, 'Open', 'Read', 'Read')
            $destination = [IO.File]::Open($snapshot, 'CreateNew', 'Write', 'None')
            $source.CopyTo($destination)
        } finally {
            if ($destination) { $destination.Dispose() }
            if ($source) { $source.Dispose() }
        }
        $lockedSnapshot = [IO.File]::Open($snapshot, 'Open', 'Read', 'Read')
        if ((Get-SigningHash $snapshot) -ne $ExpectedSHA256) { throw 'The file changed after preview. Nothing signed. Preview it again.' }
        $approvedDigest = Get-SigningSnapshotDigest $snapshot $lockedSnapshot
        if ((Get-SigningHash $snapshot) -ne $ExpectedSHA256) { throw 'The snapshot changed during digest calculation. Original untouched.' }
        $lockedSnapshot.Dispose(); $lockedSnapshot = $null
        Invoke-SigningNative $tool ($arguments + @($snapshot))
        # Deny writes and renames throughout verification.
        $lockedSnapshot = [IO.File]::Open($snapshot, 'Open', 'Read', 'Read')
        $signedHash = Get-SigningHash $snapshot
        $null = Get-SigningSnapshotDigest $snapshot $lockedSnapshot $cert.Thumbprint $approvedDigest
        if ((Get-SigningHash $snapshot) -ne $signedHash) { throw 'The signed snapshot changed during verification. Original untouched.' }
        $null = Resolve-LocalSigningFile $original.FullName
        $lockedOriginal = [IO.File]::Open($original.FullName, 'Open', 'Read', 'Read')
        if ((Get-SigningHash $original.FullName) -ne $ExpectedSHA256) { throw 'The original file changed while signing. The signed snapshot was discarded. Preview again.' }
        # ReplaceFile requires conflicting access, so release verification handles.
        # The private ACL remains. Same-account tampering with this final handoff
        # is outside the protection model, as is modification of this script.
        $lockedOriginal.Dispose(); $lockedOriginal = $null
        $lockedSnapshot.Dispose(); $lockedSnapshot = $null
        # Same volume, atomic replacement; never copy partial signed bytes over the original.
        [SignMyApp.AuthenticodeDigest]::Replace($snapshot, $original.FullName)
    } finally {
        if ($lockedOriginal) { $lockedOriginal.Dispose() }
        if ($lockedSnapshot) { $lockedSnapshot.Dispose() }
        if ($stageDir) {
            $cleanup = [IO.Path]::GetFullPath($stageDir)
            if ([IO.Path]::GetDirectoryName($cleanup) -ne $original.DirectoryName -or
                [IO.Path]::GetFileName($cleanup) -notmatch '^sign-my-app-approved-[a-f0-9]{32}$') { throw 'Unsafe snapshot cleanup path.' }
            if (Test-Path -LiteralPath $cleanup) { Remove-Item -LiteralPath $cleanup -Recurse -Force }
        }
    }
}
