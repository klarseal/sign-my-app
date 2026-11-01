#Requires -Version 5.1
# Shared validation. Data from projects and certificate subjects is never executable text.
# Both runtimes use generated Unicode category/default-ignorable ranges, including
# supplementary planes. This avoids .NET Framework's older Unicode category table.
$script:SigningInvisibleRanges = (Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'Unicode-Safety.json') | ConvertFrom-Json).ranges
function Test-SigningControlText([string]$Value) {
    for ($i = 0; $i -lt $Value.Length; $i++) {
        $point = [int]$Value[$i]
        if ([char]::IsHighSurrogate($Value[$i]) -and $i + 1 -lt $Value.Length -and [char]::IsLowSurrogate($Value[$i + 1])) {
            $point = [char]::ConvertToUtf32($Value, $i); $i++
        }
        $low = 0; $high = $script:SigningInvisibleRanges.Count - 1
        while ($low -le $high) {
            $mid = ($low + $high) -shr 1
            $range = $script:SigningInvisibleRanges[$mid]
            if ($point -lt $range[0]) { $high = $mid - 1 }
            elseif ($point -gt $range[1]) { $low = $mid + 1 }
            else { return $true }
        }
    }
    return $false
}
function Assert-SafeSigningText([string]$Value) {
    if ((Test-SigningControlText $Value) -or $Value -match '[''"\u2018-\u201f`$;&|<>]') {
        throw 'This name contains control, invisible or private-use characters, quotes or shell characters. Rename it before using a signing command.'
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
function Get-SigningSessionFailure([string]$Output, [string[]]$KnownPaths = @()) {
    # Only classify a failed signing call, never verification or a successful call.
    # Exact allowlist; see references/session-errors.md for names and messages.
    $codes = '8009000D|80090013|80090016|80090017|80090019|8009001D|8009001E|80090022|8009002E|80090030|8010000C|80100017|8010001D|8010001E|8010002E|80100030|80100069|8010006E|8010006F'
    $match = [regex]::Match($Output, '(?i)\b0x(' + $codes + ')\b')
    if ($match.Success) { return '0x' + $match.Groups[1].Value.ToUpperInvariant() }
    # A reported non-session HRESULT wins over incidental provider-like words.
    if ($Output -match '(?i)\b0x[0-9a-f]{8}\b') { return }
    foreach ($knownPath in ($KnownPaths | Sort-Object Length -Descending)) {
        if ($knownPath) { $Output = [regex]::Replace($Output, [regex]::Escape($knownPath), '', 'IgnoreCase') }
    }
    $messages = @('Keyset does not exist', 'The keyset is not defined', 'Key does not exist',
        'Invalid provider specified', 'Provider type not defined',
        'Provider DLL failed to initialize correctly', 'Provider DLL could not be found',
        'No smart card inserted', 'The smart card has been removed',
        'The requested key container does not exist on the smart card',
        'No smart card readers are available',
        'The device that is required by this cryptographic provider is not ready for use',
        'This operation requires input from the user',
        'Provider could not perform the action since the context was acquired as silent',
        'The user has not authenticated to the smart card')
    foreach ($message in $messages) {
        if ($Output.IndexOf($message, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $message }
    }
    if ($Output -match '(?i)\btoken (?:is )?(?:not present|not logged in|expired)\b|\bsession (?:has )?expired\b') { return 'token/session unavailable' }
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
        # Provider UI is allowed, but must never hold the operation indefinitely.
        $waitMilliseconds = if ($Arguments[0] -eq 'sign') { 60000 } else { 45000 }
        if (-not $process.WaitForExit($waitMilliseconds)) {
            # Kill only this operation's process tree, not the signing app/session.
            $killInfo = New-Object Diagnostics.ProcessStartInfo
            $killInfo.FileName = [IO.Path]::Combine([Environment]::SystemDirectory, 'taskkill.exe')
            $killInfo.Arguments = '/PID ' + $process.Id + ' /T /F'
            $killInfo.UseShellExecute = $false; $killInfo.CreateNoWindow = $true
            $killInfo.RedirectStandardOutput = $true; $killInfo.RedirectStandardError = $true
            $killer = [Diagnostics.Process]::Start($killInfo)
            try { if (-not $killer.WaitForExit(5000)) { $killer.Kill() } } finally { $killer.Dispose() }
            if (-not $process.HasExited) { $process.Kill() }
            $null = $process.WaitForExit(5000)
            if ($Arguments[0] -eq 'sign') { throw 'KLARSEAL_SESSION_REQUIRED: provider-wait-timeout' }
            throw 'Verification time limit reached.'
        }
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) {
            if ($Arguments[0] -eq 'sign') { throw 'KLARSEAL_SESSION_REQUIRED: provider-output-timeout' }
            throw 'Verification output time limit reached.'
        }
        $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -and $Arguments[0] -eq 'sign') {
            $knownPaths = @($Tool, (Split-Path -Parent $Tool))
            foreach ($argument in $Arguments) {
                if ([IO.Path]::IsPathRooted($argument)) { $knownPaths += $argument; $knownPaths += Split-Path -Parent $argument }
            }
            $sessionFailure = Get-SigningSessionFailure $output $knownPaths
            # Do not display alarming provider diagnostics as the session result.
            if ($sessionFailure) { throw ('KLARSEAL_SESSION_REQUIRED: ' + $sessionFailure) }
        }
        if ($output) {
            if ($Arguments[0] -eq 'verify') {
                # Preserve bounded verbose chain/timestamp lines for verification.
                # Every native line is still untrusted data, escaped individually.
                if ($output.Length -gt 65536) { throw 'Verification output limit reached.' }
                foreach ($line in ($output -split '\r?\n')) { Write-Host (ConvertTo-SigningDisplayText $line) }
            } else { Write-Host (ConvertTo-SigningDisplayText $output) }
        }
        if ($process.ExitCode -ne 0) {
            throw "Signing failed or warned (exit $($process.ExitCode)). Inspect the file before retrying; do not release it."
        }
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
. (Join-Path $PSScriptRoot 'Authenticode-Content.ps1')
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
    Write-SigningNetworkNotice
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -eq 'HashMismatch') { throw 'Windows reports a corrupt signed file (HashMismatch). Nothing signed.' }
    if ($signature.SignerCertificate -and $signature.SignerCertificate.Thumbprint -ne $Thumbprint) {
        return $signature.SignerCertificate
    }
}
function Write-SigningNetworkNotice {
    # Information stream keeps the publisher return value separate from notices.
    Write-Host "Network notice: Windows may contact addresses in the file's certificate (AIA, CRL and OCSP), including local or private addresses, while checking signatures. Only check files you trust to trigger these requests."
}
function Remove-StaleSigningStage([string]$Path, [string]$Parent) {
    # Only an exact direct child, owned by us with our private ACL and contents.
    # Never recursively delete: links, subfolders and unexpected files preserve it.
    $cleanup = [IO.Path]::GetFullPath($Path)
    if ([IO.Path]::GetDirectoryName($cleanup) -ne [IO.Path]::GetFullPath($Parent) -or
        [IO.Path]::GetFileName($cleanup) -cnotmatch '^sign-my-app-approved-[a-f0-9]{32}$') { return }
    $lease = $null
    try {
        $stage = Resolve-LocalSigningFile $cleanup
        if (-not $stage.PSIsContainer) { return }
        $acl = Get-Acl -LiteralPath $cleanup
        $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner) { return }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.IdentityReference.Value -notin @($owner, 'S-1-5-18')) { return }
        }
        $children = @(Get-ChildItem -LiteralPath $cleanup -Force)
        foreach ($child in $children) {
            if ($child.PSIsContainer -or ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                $child.Name -cnotmatch '^(approved\.(exe|dll|msi)|stage\.lock)$') { return }
        }
        $lockPath = Join-Path $cleanup 'stage.lock'
        # Pre-lease versions need an age margin. New orphaned leases can be
        # collected at the next run immediately, without touching active stages.
        if (-not (Test-Path -LiteralPath $lockPath) -and $stage.LastWriteTimeUtc -gt [DateTime]::UtcNow.AddMinutes(-10)) { return }
        # Active operations hold this lease without sharing; taskkill releases it.
        $lease = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
        foreach ($child in $children) { if ($child.Name -ne 'stage.lock') { [IO.File]::Delete($child.FullName) } }
        $lease.Dispose(); $lease = $null
        [IO.File]::Delete($lockPath)
        [IO.Directory]::Delete($cleanup, $false)
    } catch {
        # Busy, changed or inaccessible directories stay excluded from discovery.
    } finally { if ($lease) { $lease.Dispose() } }
}
function Assert-SigningConsole {
    $message = 'Please run the confirmation command in your own Windows PowerShell window. Redirected input or a missing interactive console cannot confirm signing. Nothing signed.'
    try {
        if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected -or [Console]::IsOutputRedirected -or $Host.Name -ne 'ConsoleHost') { throw $message }
        foreach ($argument in [Environment]::GetCommandLineArgs()) {
            if ($argument -match '^[-/]NonI' -and 'NonInteractive'.StartsWith($argument.Substring(1), [StringComparison]::OrdinalIgnoreCase)) { throw $message }
        }
        # RawUI probes the actual console handle; no window visibility/class test.
        if (-not $Host.UI.RawUI -or $Host.UI.RawUI.BufferSize.Width -le 0) { throw $message }
        $null = $Host.UI.RawUI.KeyAvailable
        return
    } catch {}
    try { Write-Host $message -InformationAction Continue } catch {}
    throw $message
}
function Read-SigningConfirmation([string]$Prompt) {
    Assert-SigningConsole
    # ConsoleHost reads the terminal, not a caller-supplied Console.SetIn reader.
    $Host.UI.Write($Prompt + ': ')
    return $Host.UI.ReadLine()
}
function Invoke-ApprovedSigning {
    [CmdletBinding()]
    param([string]$FilePath, [string]$ExpectedSHA256, [string]$ApprovePlan,
        [string]$Thumbprint, [string]$TimestampUrl = 'http://time.certum.pl', [switch]$MachineStore,
        [scriptblock]$RequestApproval, [scriptblock]$OnSigningStarted)
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
    if (-not $RequestApproval) { Assert-SigningConsole }
    $contentStream = [IO.File]::Open($original.FullName, 'Open', 'Read', 'Read')
    try { $null = Get-SigningSnapshotDigest $original.FullName $contentStream } finally { $contentStream.Dispose() }
    Write-Host "File: $(ConvertTo-SigningDisplayText $original.FullName)"
    Write-Host "SHA-256: $ExpectedSHA256"
    Write-Host "Publisher (untrusted certificate text): $(ConvertTo-SigningDisplayText $cert.Subject)"
    Write-Host "Thumbprint: $(ConvertTo-SigningDisplayText $cert.Thumbprint)"
    Write-Host "Timestamp service: $TimestampUrl"
    Write-Host "Plan SHA-256: $ApprovePlan"
    $previousPublisher = Get-ReplacedSigningPublisher $original.FullName $cert.Thumbprint
    if ($previousPublisher) {
        if ($RequestApproval) { throw 'MCP refuses to replace another publisher. Nothing signed.' }
        Write-Host "This file already carries another publisher's signature (untrusted certificate text): $(ConvertTo-SigningDisplayText $previousPublisher.Subject)"
        Write-Host "Existing publisher thumbprint: $(ConvertTo-SigningDisplayText $previousPublisher.Thumbprint)"
        $replaceAnswer = Read-SigningConfirmation "Type REPLACE $(ConvertTo-SigningDisplayText $previousPublisher.Thumbprint) to allow replacing that signature"
        if ($replaceAnswer -cne "REPLACE $($previousPublisher.Thumbprint)") {
            throw 'Replacement confirmation did not match the existing publisher. Nothing signed.'
        }
    }
    $answer = if ($RequestApproval) { & $RequestApproval $ApprovePlan } else { Read-SigningConfirmation "Type SIGN $ApprovePlan to confirm this plan" }
    if ($answer -cne "SIGN $ApprovePlan") { throw 'Typed confirmation did not match the plan hash. Nothing signed.' }
    # Resolve and bind the SDK tool again after the prompt, before any execution.
    $tool = & "$PSScriptRoot/Find-SignTool.ps1"
    Assert-SigningApproval $original.FullName $ExpectedSHA256 $ApprovePlan $tool $cert.Thumbprint ([bool]$MachineStore) $TimestampUrl
    $arguments = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256', '/sha1', $cert.Thumbprint)
    if ($MachineStore) { $arguments += '/sm' }
    $stageDir = $null
    $lockedSnapshot = $null
    $lockedOriginal = $null
    $stageLease = $null
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
        $stageLease = [IO.File]::Open((Join-Path $stageDir 'stage.lock'), 'CreateNew', 'ReadWrite', 'None')
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
        $script:signingAttempted = $true
        if ($OnSigningStarted) { & $OnSigningStarted }
        Invoke-SigningNative $tool ($arguments + @($snapshot))
        # Deny writes and renames throughout verification.
        $lockedSnapshot = [IO.File]::Open($snapshot, 'Open', 'Read', 'Read')
        $signedHash = Get-SigningHash $snapshot
        $comparison = Get-SigningSnapshotDigest $snapshot $lockedSnapshot $cert.Thumbprint $approvedDigest
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
        [IO.File]::Replace($snapshot, $original.FullName, [NullString]::Value)
        if ($comparison -eq 'content-comparison: not possible') { Write-Host 'content-comparison: not possible; signing used SignTool and Windows verification with the exact publisher.' }
        [pscustomobject]@{ ContentComparison = $(if ($comparison -eq 'content-comparison: not possible') { 'not possible' } else { 'matched' }) }
    } finally {
        if ($lockedOriginal) { $lockedOriginal.Dispose() }
        if ($lockedSnapshot) { $lockedSnapshot.Dispose() }
        if ($stageLease) { $stageLease.Dispose() }
        if ($stageDir) {
            $cleanup = [IO.Path]::GetFullPath($stageDir)
            if ([IO.Path]::GetDirectoryName($cleanup) -ne $original.DirectoryName -or
                [IO.Path]::GetFileName($cleanup) -notmatch '^sign-my-app-approved-[a-f0-9]{32}$') { throw 'Unsafe snapshot cleanup path.' }
            if (Test-Path -LiteralPath $cleanup) { Remove-Item -LiteralPath $cleanup -Recurse -Force }
        }
    }
}
