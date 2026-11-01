# Dot-sourced by the suite. Only layout bytes and its disposable publisher.
$r3Root = Join-Path $testRoot 'round3'
$null = New-Item -ItemType Directory -Path $r3Root
& {
    . $fixtureSafetyPath
    $fallbackApp = Join-Path $r3Root 'installer-overlay.exe'
    Copy-Item -LiteralPath $attackApp -Destination $fallbackApp
    $bytes = [IO.File]::ReadAllBytes($fallbackApp)
    $pe = [BitConverter]::ToUInt32($bytes, 0x3c)
    # An optional header may legally omit the security directory. Comparison
    # is unavailable before signing; SignTool supplies the directory afterward.
    [BitConverter]::GetBytes([uint32]4).CopyTo($bytes, ($pe + 24 + 92))
    [IO.File]::WriteAllBytes($fallbackApp, $bytes)
    [IO.File]::AppendAllText($fallbackApp, 'opaque installer overlay')
    Set-TestPlan $fallbackApp
    # As with MSI on this PC, the disposable untrusted publisher does not yield
    # a usable managed Windows status. Preserve this refusal, never trust a root.
    Assert-Throws { Invoke-TestApproval $fallbackApp } 'round 3: uncertain real Windows fallback refuses replacement' 'Windows SIP integrity'
    Assert-True ((Get-SigningHash $fallbackApp) -eq $currentHash) 'round 3: uncertain Windows fallback preserves original'
    & {
        # Explicit Windows-status seam only in this test scope. Native signing
        # becomes a recorder; no synthetic positive result can use a real key.
        function Invoke-SigningNative {}
        $r3Status = 'Valid'; $r3Publisher = $thumb
        function Get-AuthenticodeSignature {
            param($LiteralPath)
            if ($LiteralPath -notlike '*sign-my-app-approved-*') { return [pscustomobject]@{ Status = 'NotSigned' } }
            [pscustomobject]@{ Status = $r3Status; SignerCertificate = [pscustomobject]@{ Thumbprint = $r3Publisher } }
        }
        $result = @(Invoke-TestApproval $fallbackApp)
        Assert-True (@($result | Where-Object { $_.ContentComparison -eq 'not possible' }).Count -eq 1) 'round 3: synthetic valid Windows result permits unsupported layout and reports fallback'
        # Exercise the same verification branch without signing or replacing.
        $stage = Join-Path $r3Root ('sign-my-app-approved-' + ('9' * 32))
        $null = New-Item -ItemType Directory -Path $stage
        $sample = Join-Path $stage 'approved.exe'; Copy-Item -LiteralPath $fallbackApp -Destination $sample
        $stream = [IO.File]::Open($sample, 'Open', 'Read', 'Read')
        try {
            foreach ($r3Status in @('HashMismatch','UnknownError','NotSigned')) {
                Assert-Throws { Get-SigningSnapshotDigest $sample $stream $thumb 'content-comparison: not possible' } ('round 3: fallback refuses Windows ' + $r3Status) 'integrity or signature verification failed'
            }
            $r3Status = 'Valid'; $r3Publisher = 'A' * 40
            Assert-Throws { Get-SigningSnapshotDigest $sample $stream $thumb 'content-comparison: not possible' } 'round 3: fallback refuses another publisher even with Valid status' 'integrity or signature verification failed'
        } finally { $stream.Dispose() }
        function Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'HashMismatch' } }
        Assert-Throws { Get-ReplacedSigningPublisher $fallbackApp $thumb } 'round 3: known corrupt signature refused before approval' 'HashMismatch'
    }
}
& {
    . "$scripts/Signing-Safety.ps1"
    $hostileFolder = Join-Path $r3Root 'session expired'
    $hostileFile = Join-Path $hostileFolder 'token expired.exe'
    $null = New-Item -ItemType Directory -Path $hostileFolder
    Assert-True (-not (Get-SigningSessionFailure ("SignTool Error: cannot write " + $hostileFile) @($hostileFile, $hostileFolder))) 'round 3: hostile file/folder words do not classify a session failure'
    Assert-True (-not (Get-SigningSessionFailure '0x80096010: session expired')) 'round 3: non-session HRESULT wins over session words'
    Assert-True ((Get-SigningSessionFailure ('0x80090016: ' + $hostileFile) @($hostileFile, $hostileFolder)) -eq '0x80090016') 'round 3: exact session HRESULT retains priority'
    Assert-True ([bool](Get-SigningSessionFailure ('session expired: ' + $hostileFile) @($hostileFile, $hostileFolder))) 'round 3: real session words outside known paths still classify'
    [IO.File]::WriteAllText((Join-Path $sessionFixture 'mode.txt'), ('cannot write ' + $hostileFile))
    Assert-Throws { Invoke-SigningNative $sessionTool @('sign', $hostileFile) } 'round 3: real failed subprocess in hostile folder stays a non-session failure' 'Signing failed or warned'

    $bad = Join-Path $r3Root 'truncated.exe'
    $bytes = [IO.File]::ReadAllBytes($app); [IO.File]::WriteAllBytes($bad, $bytes[0..100])
    $preflightFixture = Join-Path $r3Root 'preflight'
    $null = New-Item -ItemType Directory -Path $preflightFixture
    Copy-Item -Path (Join-Path $scripts '*') -Destination $preflightFixture
    ('param(); return ' + (ConvertTo-SigningPSLiteral $fakeTool)) | Set-Content -LiteralPath (Join-Path $preflightFixture 'Find-SignTool.ps1')
    @'
function Assert-SigningTimestamp {}
function Assert-SigningConsole { throw 'APPROVAL REACHED' }
function Invoke-SigningNative { throw 'NATIVE REACHED' }
'@ | Add-Content -LiteralPath (Join-Path $preflightFixture 'Signing-Safety.ps1')
    . "$preflightFixture/Signing-Safety.ps1"
    $badHash = Get-SigningHash $bad
    $badPlan = Get-SigningPlanHash @('1', $bad, $badHash, $fakeTool, $thumb, 'False', 'http://time.certum.pl')
    Assert-Throws { Invoke-ApprovedSigning -FilePath $bad -ExpectedSHA256 $badHash -ApprovePlan $badPlan -Thumbprint $thumb -RequestApproval { throw 'APPROVAL REACHED' } } 'round 3: truncated image rejected before approval or native tool' 'Invalid PE header'
    Assert-Throws { & "$preflightFixture/Invoke-Sign.ps1" -FilePath $bad -Thumbprint $thumb -PassThruPlan } 'round 3: corrupt image rejected before MCP plan approval' 'Invalid PE header'
}
& {
    . "$scripts/Signing-Safety.ps1"
    # Construct production-private stages, plus close-looking unrelated folders.
    function New-R3Stage($Name) {
        $target = Join-Path $r3Root $Name
        $security = New-Object Security.AccessControl.DirectorySecurity
        $security.SetAccessRuleProtection($true, $false)
        $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $security.SetOwner($owner)
        foreach ($sid in @($owner, (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'))) {
            $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        $null = [IO.Directory]::CreateDirectory($target, $security)
        [IO.File]::WriteAllText((Join-Path $target 'approved.exe'), 'stale snapshot')
        return $target
    }
    $stale = New-R3Stage ('sign-my-app-approved-' + ('a' * 32))
    $busy = New-R3Stage ('sign-my-app-approved-' + ('b' * 32))
    $extra = New-R3Stage ('sign-my-app-approved-' + ('c' * 32))
    $nested = New-R3Stage ('sign-my-app-approved-' + ('d' * 32))
    $recent = New-R3Stage ('sign-my-app-approved-' + ('e' * 32))
    $orphan = New-R3Stage ('sign-my-app-approved-' + ('1' * 32))
    [IO.File]::WriteAllText((Join-Path $orphan 'stage.lock'), '')
    $broad = Join-Path $r3Root ('sign-my-app-approved-' + ('f' * 32))
    $null = New-Item -ItemType Directory -Path $broad
    [IO.File]::WriteAllText((Join-Path $broad 'approved.exe'), 'not private')
    $near = New-R3Stage 'sign-my-app-approved-not-a-guid'
    [IO.File]::WriteAllText((Join-Path $extra 'user.txt'), 'keep')
    $null = New-Item -ItemType Directory -Path (Join-Path $nested 'nested')
    $lease = [IO.File]::Open((Join-Path $busy 'stage.lock'), 'CreateNew', 'ReadWrite', 'None')
    try {
        foreach ($target in @($stale,$busy,$extra,$nested,$near,$broad)) { [IO.Directory]::SetLastWriteTimeUtc($target, [DateTime]::UtcNow.AddHours(-1)) }
        $found = @(& "$scripts/Find-BuiltFiles.ps1" -ProjectFolder $r3Root)
        Assert-True (@($found | Where-Object { $_.Path -like '*sign-my-app-approved-*' }).Count -eq 0) 'round 3: all staging prefixes excluded from built files'
        Assert-True (-not (Test-Path -LiteralPath $stale)) 'round 3: exact stale private stage from interrupted signing removed'
        Assert-True (-not (Test-Path -LiteralPath $orphan)) 'round 3: new orphaned lease collected immediately at the next discovery'
        foreach ($target in @($busy,$extra,$nested,$near,$recent,$broad)) {
            Assert-True (Test-Path -LiteralPath $target) ('round 3: preserves busy, unexpected, recent or nonexact stage: ' + [IO.Path]::GetFileName($target))
        }
        Assert-True (@(& "$scripts/Find-BuiltFiles.ps1" -ProjectFolder $near).Count -eq 0) 'round 3: explicit staging root excluded too'
        Remove-StaleSigningStage $extra (Join-Path $r3Root 'wrong-parent')
        Assert-True (Test-Path -LiteralPath $extra) 'round 3: cleanup refuses a mismatched parent'
    } finally { $lease.Dispose() }
}
