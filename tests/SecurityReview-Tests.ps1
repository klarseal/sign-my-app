# Dot-sourced before the signing fixtures replace production functions.
foreach ($point in @(0x00a0, 0x2003, 0x3000, 0x2800, 0xe000, 0xf0000, 0x100000)) {
    $character = [char]::ConvertFromUtf32($point)
    Assert-Throws { Assert-SafeSigningText ('First' + $character + 'app.exe') } ('S3: U+{0:X} refused' -f $point) 'Rename'
    Assert-True (-not (ConvertTo-SigningDisplayText $character).Contains($character)) ('S3: U+{0:X} visibly escaped' -f $point)
}

# No certificate lookup, key access, timestamp request or native signing is possible.
$pipeScript = Join-Path $testRoot 'redirected-confirmation.ps1'
$pipeSource = @'
param($Safety, $App)
$ErrorActionPreference = 'Stop'
. $Safety
function Get-SigningCertificate { [pscustomobject]@{ Thumbprint = ('A' * 40); Subject = 'synthetic publisher' } }
function Assert-SigningTimestamp {}
function Assert-SigningApproval {}
function Get-ReplacedSigningPublisher {}
function Get-SigningSnapshotDigest { throw 'PIPE REACHED SIGNING STAGE' }
function Invoke-SigningNative { throw 'Native invocation forbidden in this test.' }
try {
    Invoke-ApprovedSigning -FilePath $App -ExpectedSHA256 (Get-SigningHash $App) -ApprovePlan ('B' * 64) -Thumbprint ('A' * 40)
    exit 2
} catch { exit 1 } # The production guard must display its own kind message.
'@
[IO.File]::WriteAllText($pipeScript, $pipeSource)
$pipeInfo = New-Object Diagnostics.ProcessStartInfo
$pipeInfo.FileName = [IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\powershell.exe')
$pipeInfo.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $pipeScript + '" "' + (Join-Path $scripts 'Signing-Safety.ps1') + '" "' + $app + '"'
$pipeInfo.WorkingDirectory = [Environment]::SystemDirectory
$pipeInfo.UseShellExecute = $false
$pipeInfo.CreateNoWindow = $true
$pipeInfo.RedirectStandardInput = $true
$pipeInfo.RedirectStandardOutput = $true
$pipeInfo.RedirectStandardError = $true
$pipeChild = [Diagnostics.Process]::Start($pipeInfo)
try {
    $pipeOut = $pipeChild.StandardOutput.ReadToEndAsync()
    $pipeErr = $pipeChild.StandardError.ReadToEndAsync()
    $pipeChild.StandardInput.WriteLine('SIGN ' + ('B' * 64))
    $pipeChild.StandardInput.Close()
    if (-not $pipeChild.WaitForExit(15000)) { $pipeChild.Kill(); throw 'Piped confirmation timed out.' }
    $pipeText = $pipeOut.GetAwaiter().GetResult() + $pipeErr.GetAwaiter().GetResult()
    $pipeMessage = 'Please run the confirmation command in your own Windows PowerShell window. Redirected input or a missing interactive console cannot confirm signing. Nothing signed.'
    Assert-True ($pipeChild.ExitCode -eq 1 -and $pipeText.Trim() -ceq $pipeMessage) ('S2: piped SIGN refused before signing: ' + $pipeText.Trim())
} finally { $pipeChild.Dispose() }

if (-not $NonDesktop) {
    . (Join-Path $repo 'mcp/tests/Desktop-Lock.ps1')
    $desktopMutex = Enter-DesktopTestLock 'Commands'
    try {
$consoleProbeScript = Join-Path $testRoot 'console-input-probe.ps1'
$consoleProbeResult = Join-Path $testRoot 'console-input-result.txt'
@'
param($Safety, $Source, $Result)
$ErrorActionPreference = 'Stop'
try {
    . $Safety
    Add-Type -Path $Source
    [Console]::Title = 'TEST ONLY - nothing will be signed'
    Write-Host 'TEST ONLY - nothing will be signed'
    [SigningConsoleTest]::Show()
    [SigningConsoleTest]::QueueSampleText()
    if ((Read-SigningConfirmation 'Console regression') -cne 'console regression answer') { throw 'Console answer changed.' }
    if (-not [SigningConsoleTest]::FreeConsole()) { throw 'Could not detach test console.' }
    $refusal = $null
    try { Assert-SigningConsole } catch { $refusal = $_.Exception.Message }
    if ($refusal -notlike 'Please run the confirmation command in your own Windows PowerShell window.*') { throw 'Detached console was accepted.' }
    [IO.File]::WriteAllText($Result, 'normal input accepted; detached console refused')
} catch { [IO.File]::WriteAllText($Result, $_.ToString()); exit 1 }
'@ | ForEach-Object { $_.Replace('[SigningConsoleTest]::Show()', ('. ' + (ConvertTo-SigningPSLiteral (Join-Path $repo 'mcp/tests/Desktop-Lock.ps1')) + '; $windowMutex = Enter-DesktopTestLock; [SigningConsoleTest]::Show()')) } | Set-Content -LiteralPath $consoleProbeScript
$consoleProbeArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $consoleProbeScript,
    (Join-Path $scripts 'Signing-Safety.ps1'), (Join-Path $PSScriptRoot 'Console-Input.cs'), $consoleProbeResult)
$consoleProbe = Start-Process -FilePath ([IO.Path]::Combine([Environment]::SystemDirectory, 'conhost.exe')) -ArgumentList ((@($pipeInfo.FileName) + $consoleProbeArgs | ForEach-Object { '"' + $_ + '"' }) -join ' ') -WorkingDirectory ([Environment]::SystemDirectory) -WindowStyle Hidden -PassThru
try {
    if (-not $consoleProbe.WaitForExit(15000)) { $consoleProbe.Kill(); throw 'Console input probe timed out.' }
    $consoleProbeText = [IO.File]::ReadAllText($consoleProbeResult)
    Assert-True ($consoleProbe.ExitCode -eq 0 -and $consoleProbeText -ceq 'normal input accepted; detached console refused') ('S2: real Windows PowerShell console input and detached refusal: ' + $consoleProbeText)
} finally { $consoleProbe.Dispose() }

    } finally { Exit-DesktopTestLock $desktopMutex }
} else { Write-Output 'SKIP: visible classic console regression (NonDesktop)' }

# Verify warning order before either Windows chain-checking entry point.
$networkFixture = Join-Path $testRoot 'network-warning-fixture'
New-Item -ItemType Directory -Path $networkFixture | Out-Null
Copy-Item -LiteralPath (Join-Path $scripts 'Test-Signature.ps1') -Destination $networkFixture
Copy-Item -LiteralPath (Join-Path $scripts 'Signing-Safety.ps1') -Destination $networkFixture
Copy-Item -LiteralPath (Join-Path $scripts 'Authenticode-Content.ps1') -Destination $networkFixture
Copy-Item -LiteralPath (Join-Path $scripts 'Unicode-Safety.json') -Destination $networkFixture
('param(); return ' + (ConvertTo-SigningPSLiteral $fakeTool)) | Set-Content -LiteralPath (Join-Path $networkFixture 'Find-SignTool.ps1')
@'

function Get-AuthenticodeSignature { param($LiteralPath); Write-Host 'AUTHENTICODE CHECK'; [pscustomobject]@{ Status = 'NotSigned' } }
function Invoke-SigningNative { param($Tool, $Arguments); Write-Output 'SIGNTOOL CHECK' }
'@ | Add-Content -LiteralPath (Join-Path $networkFixture 'Signing-Safety.ps1')
$networkOutput = @(& "$networkFixture/Test-Signature.ps1" -FilePath $app 6>&1 | ForEach-Object { [string]$_ })
Assert-True ($networkOutput[0] -ceq "Network notice: Windows may contact addresses in the file's certificate (AIA, CRL and OCSP), including local or private addresses, while checking signatures. Only check files you trust to trigger these requests.") 'S4: network notice precedes both chain checks'
Assert-True ($networkOutput -contains 'AUTHENTICODE CHECK' -and $networkOutput -contains 'SIGNTOOL CHECK') 'S4: normal chain checks remain enabled'

# Observe real Windows URL retrieval using only a new software certificate, an
# uninstalled ephemeral issuer and a loopback HTTP listener. Never trust the CA.
Add-Type -Path (Join-Path $PSScriptRoot 'Network-Probe.cs')
$probe = $null
$probeCertificate = $null
try {
    $probe = New-Object SigningNetworkProbe
    $probeCertificate = $probe.Certificate
    $probeStore = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
    try { $probeStore.Open('ReadWrite'); $probeStore.Add($probeCertificate) } finally { $probeStore.Close() }
    $probeApp = Join-Path $testRoot 'network-probe.exe'
    Copy-Item -LiteralPath $app -Destination $probeApp
    Invoke-SigningNative $tool @('sign', '/fd', 'SHA256', '/sha1', $probeCertificate.Thumbprint, $probeApp)
    Write-Output ('S4: signing preparation loopback requests: ' + ($probe.Requests -join ', '))
    $probe.Clear()
    $probeNoticeBeforeRequest = $false
    $null = Get-ReplacedSigningPublisher $probeApp $thumb 6>&1 | ForEach-Object {
        if ([string]$_ -like 'Network notice:*') { $probeNoticeBeforeRequest = $probe.Requests.Count -eq 0 }
    }
    Assert-True $probeNoticeBeforeRequest 'round 2: notice delivered before real planted-file AIA retrieval'
    $authRequests = @($probe.Requests)
    $probe.Clear()
    try { Invoke-SigningNative $tool @('verify', '/pa', '/v', $probeApp) } catch {
        if ($_.Exception.Message -notmatch 'failed or warned') { throw }
    }
    $toolRequests = @($probe.Requests)
    Write-Output ('S4: Authenticode loopback requests: ' + ($authRequests -join ', '))
    Write-Output ('S4: SignTool loopback requests: ' + ($toolRequests -join ', '))
    Assert-True (($authRequests.Count + $toolRequests.Count) -gt 0) 'S4: real signature verification follows a planted certificate URL'
} finally {
    try { if ($probeCertificate) { Remove-DisposableSigningCertificate $probeCertificate } }
    finally { if ($probe) { $probe.Dispose() } }
}
