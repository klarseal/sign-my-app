# Dot-sourced by Run-Tests.ps1, with its throwaway certificate and isolated files.
# Test substitutions exist only in the copied fixture, never production helpers.
$renamedCmd = Join-Path $testRoot 'signtool.exe'
Copy-Item -LiteralPath ([IO.Path]::Combine([Environment]::SystemDirectory, 'cmd.exe')) -Destination $renamedCmd
$cmdSignature = Get-AuthenticodeSignature -LiteralPath $renamedCmd
Assert-True ($cmdSignature.Status -eq 'Valid' -and $cmdSignature.SignerCertificate.Subject -match 'O=Microsoft Corporation') 'R2: renamed cmd.exe satisfies the old name/signature rule'
$copyDir = Join-Path $testRoot 'copied-sdk'
New-Item -ItemType Directory -Path $copyDir | Out-Null
$copiedTool = Join-Path $copyDir 'signtool.exe'
Copy-Item -LiteralPath $tool -Destination $copiedTool
[IO.File]::WriteAllText((Join-Path $copyDir 'mssign32.dll'), 'junk DLL beside a genuine copied SignTool')
$env:ProgramFiles = $testRoot
${env:ProgramFiles(x86)} = $testRoot
$env:PATH = $copyDir + ';' + $testRoot
try {
    Assert-True ((& "$scripts/Find-SignTool.ps1") -eq $tool) 'R2: poisoned PATH and ProgramFiles cannot select renamed cmd or copied SDK with adjacent DLL'
} finally {
    $env:ProgramFiles = $oldProgramFiles
    ${env:ProgramFiles(x86)} = $oldProgramFilesX86
    $env:PATH = $oldPath
}
Assert-True ($tool -match '\\Windows Kits\\10\\bin\\(?:\d+\.\d+\.\d+\.\d+\\)?(?:x86|x64)\\signtool\.exe$' -and
    (Get-AuthenticodeSignature -LiteralPath $tool).Status -eq 'Valid') 'R2: selected tool is Microsoft-signed in machine SDK location'

$fixtureSafetyPath = Join-Path $fixture 'Signing-Safety.ps1'
$fixtureSafety = (Get-Content -Raw -LiteralPath $fixtureSafetyPath).
    Replace('function Invoke-SigningNative(', 'function Invoke-TestNative(').
    Replace('Assert-SigningTimestamp $TimestampUrl -ResolveHost', 'Assert-SigningTimestamp $TimestampUrl')
$fixtureSafety += @'

# TEST FIXTURE ONLY: scripted answers and offline signing with the test publisher.
function Assert-SigningConsole {}
function Read-SigningConfirmation([string]$Prompt) {
    $config = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'test-config.json') | ConvertFrom-Json
    if ($Prompt -like 'Type REPLACE *') { return $config.ReplaceAnswer }
    return $config.Answer
}
function Invoke-SigningNative([string]$Tool, [string[]]$Arguments) {
    if ($Arguments[0] -eq 'verify') { Invoke-TestNative $Tool $Arguments; return }
    $config = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'test-config.json') | ConvertFrom-Json
    $snapshot = $Arguments[-1]
    foreach ($target in @((Split-Path $snapshot -Parent), $snapshot)) {
        $acl = Get-Acl -LiteralPath $target
        if (@($acl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @(
            [Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18') }).Count) {
            throw 'Test: snapshot directory or file is not private.'
        }
    }
    if ($config.Mode -eq 'swap') {
        [IO.File]::WriteAllText($config.Signal, $snapshot)
        $deadline = (Get-Date).AddSeconds(15)
        while (-not (Test-Path -LiteralPath $config.Ack)) {
            if ((Get-Date) -gt $deadline) { throw 'Test: swap watcher timed out.' }
            Start-Sleep -Milliseconds 10
        }
        if ([IO.File]::ReadAllText($config.Ack) -ne 'swapped') { throw 'Test: watcher did not swap bytes.' }
    }
    if ($config.Mode -eq 'change-original') { [IO.File]::AppendAllText($config.Original, 'concurrent build') }
    if ($config.Mode -eq 'record') { Invoke-TestNative $Tool $Arguments; return }
    if ($config.Mode -eq 'fail') { throw 'Test: tool failed.' }
    # TEST ONLY: remove timestamp options. Production always requests a timestamp.
    $offline = @()
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        if ($Arguments[$i] -in @('/tr', '/td')) { $i++; continue }
        $offline += $Arguments[$i]
    }
    if ($offline -contains '/a' -or $offline[([Array]::IndexOf($offline, '/sha1') + 1)] -ne $config.Thumbprint) {
        throw 'Test: signing must select only the disposable thumbprint.'
    }
    Invoke-TestNative $Tool $offline
    if ($config.Mode -eq 'bad-signature') {
        # The RSA signature is at the end of this untimestamped test signature;
        # this offset is before the final alignment padding, inside signature data.
        $bytes = [IO.File]::ReadAllBytes($snapshot)
        $bytes[$bytes.Length - 16] = $bytes[$bytes.Length - 16] -bxor 1
        [IO.File]::WriteAllBytes($snapshot, $bytes)
    }
}
'@
[IO.File]::WriteAllText($fixtureSafetyPath, $fixtureSafety)
. $fixtureSafetyPath
$configPath = Join-Path $fixture 'test-config.json'
function Set-TestPlan([string]$Target, [string]$Mode = 'offline', [string]$SelectedTool = $tool) {
    ('param(); return ' + (ConvertTo-SigningPSLiteral $SelectedTool)) | Set-Content -LiteralPath (Join-Path $fixture 'Find-SignTool.ps1') -Encoding UTF8
    $script:currentHash = Get-SigningHash $Target
    $script:currentPlan = Get-SigningPlanHash @('1', $Target, $currentHash, $SelectedTool, $thumb, 'False', 'http://time.certum.pl')
    $script:config = @{
        Answer = "SIGN $currentPlan"; Mode = $Mode; Thumbprint = $thumb; Original = $Target
        Signal = (Join-Path $testRoot 'swap-signal.txt'); Ack = (Join-Path $testRoot 'swap-ack.txt')
    }
    $config | ConvertTo-Json | Set-Content -LiteralPath $configPath
}
function Invoke-TestApproval([string]$Target) {
    Invoke-ApprovedSigning -FilePath $Target -ExpectedSHA256 $currentHash -ApprovePlan $currentPlan -Thumbprint $thumb
}
Set-TestPlan $app 'record' $fakeTool
$config.Answer = 'SIGN'
$config | ConvertTo-Json | Set-Content -LiteralPath $configPath
Assert-Throws { Invoke-TestApproval $app } 'R3: direct call refuses confirmation without plan hash' 'Typed confirmation'
$config.Answer = 'SIGN ' + ('A' * 64)
$config | ConvertTo-Json | Set-Content -LiteralPath $configPath
Assert-Throws { Invoke-TestApproval $app } 'R3: direct call refuses confirmation for a different plan' 'Typed confirmation'
Assert-Throws { Invoke-ApprovedSigning -FilePath $app -ExpectedSHA256 $currentHash -ApprovePlan ('A'*64) -Thumbprint $thumb } 'R3: direct call refuses changed approval plan' 'changed after preview'
Assert-True (-not (Test-Path -LiteralPath $env:SIGN_MY_APP_TEST_LOG)) 'R3: missing or wrong approval never starts SignTool'

# A new classic console with production guards and CONIN$ input. The other
# snapshot tests retain scripted answers; strip those overrides from this copy.
Set-TestPlan $app 'record' $fakeTool
$consoleFixture = Join-Path $testRoot 'native-console-fixture'
New-Item -ItemType Directory -Path $consoleFixture | Out-Null
Copy-Item -Path (Join-Path $fixture '*') -Destination $consoleFixture
$consoleSafety = Get-Content -Raw -LiteralPath $fixtureSafetyPath
$consoleTokens = $null; $consoleErrors = $null
$consoleAst = [Management.Automation.Language.Parser]::ParseInput($consoleSafety, [ref]$consoleTokens, [ref]$consoleErrors)
$consoleOverrides = @($consoleAst.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Assert-SigningConsole','Read-SigningConfirmation')
}, $false) | Group-Object Name | ForEach-Object { $_.Group | Select-Object -Skip 1 })
if ($consoleErrors.Count -or $consoleOverrides.Count -ne 2) { throw 'Expected exactly two console fixture overrides.' }
foreach ($override in ($consoleOverrides | Sort-Object { $_.Extent.StartOffset } -Descending)) {
    $consoleSafety = $consoleSafety.Remove($override.Extent.StartOffset, $override.Extent.EndOffset - $override.Extent.StartOffset)
}
[IO.File]::WriteAllText((Join-Path $consoleFixture 'Signing-Safety.ps1'), $consoleSafety)
$ps = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
if (-not $NonDesktop) {
    . (Join-Path $repo 'mcp/tests/Desktop-Lock.ps1')
    $desktopMutex = Enter-DesktopTestLock 'Commands'
    try {
$consoleResult = Join-Path $testRoot 'console-result.txt'
$consoleScript = Join-Path $testRoot 'console-test.ps1'
$consoleSource = @'
param($Fixture, $App, $Hash, $Plan, $Thumbprint, $Result)
$ErrorActionPreference = 'Stop'
try {
    if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { throw 'Test requires a normal console.' }
    . (Join-Path $Fixture 'Signing-Safety.ps1')
    Add-Type -Path __CONSOLE_TEST_SOURCE__
    [Console]::Title = 'TEST ONLY - nothing will be signed'
    Write-Host 'TEST ONLY - nothing will be signed'
    [SigningConsoleTest]::Show()
    Assert-SigningConsole
    [SigningConsoleTest]::QueueText("SIGN $Plan")
    # These labels must have no bearing on console usability or approval.
    $env:AI_AGENT = 'regression-test'
    $env:CLAUDECODE = 'regression-test'
    try { & (Join-Path $Fixture 'Confirm-Sign.ps1') -FilePath $App -ExpectedSHA256 $Hash -ApprovePlan $Plan -Thumbprint $Thumbprint }
    catch { if ($_.Exception.Message -notmatch 'no readable signature') { throw } }
    if (-not (Test-Path -LiteralPath $env:SIGN_MY_APP_TEST_LOG)) { throw 'Stub not reached.' }
    [IO.File]::WriteAllText($Result, 'normal console reached stubbed SignTool')
} catch { [IO.File]::WriteAllText($Result, $_.ToString()); exit 1 }
'@
$consoleSource = $consoleSource.Replace('[SigningConsoleTest]::Show()', ('. ' + (ConvertTo-SigningPSLiteral (Join-Path $repo 'mcp/tests/Desktop-Lock.ps1')) + '; $windowMutex = Enter-DesktopTestLock; [SigningConsoleTest]::Show()'))
$consoleSource = $consoleSource.Replace('__CONSOLE_TEST_SOURCE__', (ConvertTo-SigningPSLiteral (Join-Path $PSScriptRoot 'Console-Input.cs')))
[IO.File]::WriteAllText($consoleScript, $consoleSource)
$ps = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$consoleArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $consoleScript, $consoleFixture, $app, $currentHash, $currentPlan, $thumb, $consoleResult)
$quotedConsoleArgs = ($consoleArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '
$console = Start-Process -FilePath ([IO.Path]::Combine([Environment]::SystemDirectory, 'conhost.exe')) -ArgumentList ('"' + $ps + '" ' + $quotedConsoleArgs) -WorkingDirectory ([Environment]::SystemDirectory) -WindowStyle Hidden -PassThru
try {
    if (-not $console.WaitForExit(30000)) { $console.Kill(); throw 'Normal console test timed out.' }
    $consoleText = [IO.File]::ReadAllText($consoleResult)
    if ($console.ExitCode -ne 0) { throw "Normal console failed: $consoleText" }
    Assert-True ($consoleText -eq 'normal console reached stubbed SignTool') 'R1: classic console reaches stubbed SignTool through production guard and native CONIN$'
} finally { $console.Dispose() }
Remove-Item -LiteralPath $env:SIGN_MY_APP_TEST_LOG

    } finally { Exit-DesktopTestLock $desktopMutex }
} else { Write-Output 'SKIP: visible classic console regression (NonDesktop)' }

Set-TestPlan $app 'fail'
Assert-Throws { Invoke-TestApproval $app } 'R4: signing failure leaves original untouched' 'tool failed'
Assert-True ((Get-SigningHash $app) -eq $currentHash) 'R4: original hash unchanged after tool failure'
Set-TestPlan $app 'bad-signature'
Assert-Throws { Invoke-TestApproval $app } 'R4: corrupted signature refused even when content digest matches' 'signature|hash'
Assert-True ((Get-SigningHash $app) -eq $currentHash) 'R4: corrupted signature leaves original untouched'

# Deterministically reproduce the review race: a separate same-account process
# replaces the snapshot after hashing, just before SignTool opens it.
$attackApp = Join-Path $testRoot 'other-build.exe'
Copy-Item -LiteralPath $app -Destination $attackApp
$bytes = [IO.File]::ReadAllBytes($attackApp); $bytes[0x200] = $bytes[0x200] -bxor 1; [IO.File]::WriteAllBytes($attackApp, $bytes)
$watcherScript = Join-Path $testRoot 'swap-watcher.ps1'
[IO.File]::WriteAllText($watcherScript, @'
param($Signal, $Ack, $Attack)
$ErrorActionPreference = 'Stop'
try {
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path -LiteralPath $Signal)) {
        if ((Get-Date) -gt $deadline) { throw 'No snapshot signal.' }
        Start-Sleep -Milliseconds 10
    }
    $snapshot = [IO.File]::ReadAllText($Signal)
    [IO.File]::Copy($Attack, $snapshot, $true)
    [IO.File]::WriteAllText($Ack, 'swapped')
} catch { [IO.File]::WriteAllText($Ack, $_.ToString()); exit 1 }
'@)
Set-TestPlan $app 'swap'
$watcherArgs = (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $watcherScript, $config.Signal, $config.Ack, $attackApp) | ForEach-Object { '"' + $_ + '"' }) -join ' '
$watcher = Start-Process -FilePath $ps -ArgumentList $watcherArgs -WindowStyle Hidden -PassThru
try {
    Assert-Throws { Invoke-TestApproval $app } 'R4: reproduced swap attack refused by Authenticode digest comparison' 'Authenticode digest does not match'
    if (-not $watcher.WaitForExit(30000)) { $watcher.Kill(); throw 'Swap watcher timed out.' }
    Assert-True ($watcher.ExitCode -eq 0 -and [IO.File]::ReadAllText($config.Ack) -eq 'swapped') 'R4: separate watcher actually replaced snapshot bytes before real signing'
    Assert-True ((Get-SigningHash $app) -eq $currentHash) 'R4: swap attack leaves original byte-for-byte untouched'
} finally { if (-not $watcher.HasExited) { $watcher.Kill() }; $watcher.Dispose() }

Set-TestPlan $app 'change-original'
Assert-Throws { Invoke-TestApproval $app } 'R4: concurrent build refuses replacement of changed original' 'original file changed'
Assert-True ((Get-SigningHash $app) -ne $currentHash) 'R4: concurrent build bytes preserved'
Set-TestPlan $app
Invoke-TestApproval $app
Assert-True ($true) 'R4: real SignTool signs approved snapshot offline and atomically replaces original'
Assert-True (@(Get-ChildItem -LiteralPath $testRoot -Directory -Filter 'sign-my-app-approved-*').Count -eq 0) 'R4: all private snapshot directories cleaned up'

# Exercise the other supported formats through the same approval and SIP checks.
$testDll = Join-Path $testRoot 'payload.dll'
& $compiler /nologo /target:library "/out:$testDll" $appSource
if ($LASTEXITCODE -ne 0) { throw 'Test DLL compilation failed.' }
Set-TestPlan $testDll
Invoke-TestApproval $testDll
Assert-True ((Get-AuthenticodeSignature -LiteralPath $testDll).SignerCertificate.Thumbprint -eq $thumb) 'R4: DLL content digest and exact throwaway signer verified'

$testMsi = Join-Path $testRoot 'test-installer.msi'
$installer = $database = $summary = $view = $null
try {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($testMsi, 3)
    $view = $database.OpenView('CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) LOCALIZABLE PRIMARY KEY `Property`)')
    $view.Execute(); $view.Close()
    $summary = $database.GetType().InvokeMember('SummaryInformation', 'GetProperty', $null, $database, @(10))
    foreach ($entry in @(@(1, 1252), @(2, 'Disposable signing test'), @(7, 'Intel;1033'), @(9, ('{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}')), @(14, 200), @(15, 0))) {
        $summary.GetType().InvokeMember('Property', 'SetProperty', $null, $summary, $entry) | Out-Null
    }
    $summary.Persist()
    $database.Commit()
} finally {
    foreach ($com in @($view, $summary, $database, $installer)) {
        if ($com) { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($com) | Out-Null }
    }
}
Set-TestPlan $testMsi
# This minimal MSI reproduces a Windows SIP metadata failure even with plain
# SignTool. A matching embedded signer/digest must never be called verification.
Assert-Throws { Invoke-TestApproval $testMsi } 'L6: MSI rejected when Windows SIP rejects its signed metadata' 'Windows SIP integrity'
Assert-True ((Get-SigningHash $testMsi) -eq $currentHash) 'L6: rejected MSI leaves original byte-for-byte untouched'
$rawMsi = Join-Path $testRoot 'plain-signtool.msi'
Copy-Item -LiteralPath $testMsi -Destination $rawMsi
Invoke-TestNative $tool @('sign', '/fd', 'SHA256', '/sha1', $thumb, $rawMsi)
$msiSignature = Get-AuthenticodeSignature -LiteralPath $rawMsi
Assert-True ($msiSignature.SignerCertificate.Thumbprint -eq $thumb -and $msiSignature.Status -eq 'HashMismatch') 'L6: plain SignTool reproduces MSI HashMismatch before helper digest verification'
Assert-Throws { & "$scripts/Test-Signature.ps1" -FilePath $rawMsi 2>&1 } 'L6: public verification rejects the reproduced MSI HashMismatch' 'failed|warned|WinVerifyTrust'

# The same logical entries in 512-byte compound storage pass Windows integrity.
Add-Type -Path (Join-Path $PSScriptRoot 'Test-Storage.cs')
$msi512 = Join-Path $testRoot '512-byte-installer.msi'
[TestStorage]::Convert512($testMsi, $msi512)
Assert-True ([IO.File]::ReadAllBytes($testMsi)[30] -eq 12 -and [IO.File]::ReadAllBytes($msi512)[30] -eq 9) 'L6: MSI control uses 4096-byte and 512-byte sector fixtures'
Set-TestPlan $msi512
$stream = [IO.File]::Open($msi512, 'Open', 'Read', 'Read')
try { $msiApprovedDigest = Get-SigningSnapshotDigest $msi512 $stream } finally { $stream.Dispose() }
Invoke-TestApproval $msi512
$msiSignature = Get-AuthenticodeSignature -LiteralPath $msi512
Assert-True ($msiSignature.SignerCertificate.Thumbprint -eq $thumb -and $msiSignature.Status -ne 'HashMismatch') 'L6: 512-byte MSI passes Windows SIP integrity and exact disposable signer checks'
$savedErrorPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $trustOutput = @(& $tool verify /pa /debug $msi512 2>&1)
    $trustExit = $LASTEXITCODE
} finally { $ErrorActionPreference = $savedErrorPreference }
Assert-True ($trustExit -eq 1 -and ($trustOutput -join ' ') -match 'terminated in a root' -and
    ($trustOutput -join ' ') -match 'not trusted' -and ($trustOutput -join ' ') -notmatch '0x80096010') 'L6: signed 512-byte MSI Windows verification fails only on untrusted root'

$badMetadataMsi = Join-Path $testRoot 'bad-metadata.msi'
Copy-Item -LiteralPath $msi512 -Destination $badMetadataMsi
[TestStorage]::CorruptExtendedMetadata($badMetadataMsi)
Assert-True ((Get-AuthenticodeSignature -LiteralPath $badMetadataMsi).Status -eq 'HashMismatch') 'L6: changing MSI extended metadata reproduces Windows HashMismatch'
$stream = [IO.File]::Open($badMetadataMsi, 'Open', 'Read', 'Read')
try {
    Assert-Throws { Get-SigningSnapshotDigest $badMetadataMsi $stream $thumb $msiApprovedDigest } 'L6: MSI metadata is verified before digest calculation can rewrite it' 'Windows SIP integrity'
} finally { $stream.Dispose() }
