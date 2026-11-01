# Standalone console regressions; no certificate store, real key or signing tool.
# Also dot-sourced by Run-Tests.ps1 before any approval fixture overrides input.
$ptyScripts = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts'
$ptyRoot = Join-Path ([IO.Path]::GetTempPath()) ('sign-my-app-conpty-' + [guid]::NewGuid().ToString('N'))
$ptyPassed = 0
function Assert-ConPTY([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw "FAIL: ConPTY: $Name" }
    $script:ptyPassed++
    Write-Output "PASS: ConPTY: $Name"
}
try {
    New-Item -ItemType Directory -Path $ptyRoot | Out-Null
    . "$ptyScripts/Signing-Safety.ps1"
    Add-Type -Path (Join-Path $PSScriptRoot 'PseudoConsole.cs')
    Copy-Item -Path (Join-Path $ptyScripts '*') -Destination $ptyRoot
    $ptyApp = Join-Path $ptyRoot 'synthetic.exe'
    [IO.File]::WriteAllText($ptyApp, 'harmless non-executable fixture')
    $ptyTool = Join-Path $ptyRoot 'never-executed.exe'
    ('param(); return ' + (ConvertTo-SigningPSLiteral $ptyTool)) | Set-Content -LiteralPath (Join-Path $ptyRoot 'Find-SignTool.ps1')
    @'

# TEST ONLY: all certificate and signing work is synthetic. Keep console checks,
# managed ConsoleHost input, plan/hash checks and typed-answer validation unchanged.
function Get-SigningCertificate { [pscustomobject]@{ Thumbprint = ('A' * 40); Subject = 'synthetic console test' } }
function Assert-SigningTimestamp {}
function Get-ReplacedSigningPublisher {}
function Get-SigningSnapshotDigest { return 'synthetic digest' }
function Invoke-SigningNative { throw 'CONPTY SIGNING STUB REACHED' }
'@ | Add-Content -LiteralPath (Join-Path $ptyRoot 'Signing-Safety.ps1')
    $ptyHash = Get-SigningHash $ptyApp
    $ptyPlan = Get-SigningPlanHash @('1', $ptyApp, $ptyHash, $ptyTool, ('A' * 40), 'False', 'http://time.certum.pl')
    $ptyPS = [IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\powershell.exe')
    $ptyConfirmArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File', (Join-Path $ptyRoot 'Confirm-Sign.ps1'),
        '-FilePath',$ptyApp,'-Thumbprint',('A' * 40),'-ExpectedSHA256',$ptyHash,'-ApprovePlan',$ptyPlan)
    $ptyCommand = ($ptyConfirmArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $ptyPrompt = "Type SIGN $ptyPlan to confirm this plan:"
    $ptyProbe = Join-Path $ptyRoot 'probe.ps1'
    @'
param($Confirm, $App, $Hash, $Plan, $ConsoleSource)
Add-Type -Path $ConsoleSource
Write-Host ('CONSOLE STATE: ' + [SigningConsoleTest]::Describe())
try { & $Confirm -FilePath $App -ExpectedSHA256 $Hash -ApprovePlan $Plan -Thumbprint ('A' * 40) }
catch {
    if ($_.Exception.Message -cne 'CONPTY SIGNING STUB REACHED') { throw }
    Write-Host 'CONPTY SIGNING STUB SUCCEEDED'
    exit 0
}
throw 'Signing stub was not reached.'
'@ | Set-Content -LiteralPath $ptyProbe
    $ptyProbeArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$ptyProbe,(Join-Path $ptyRoot 'Confirm-Sign.ps1'),$ptyApp,$ptyHash,$ptyPlan,(Join-Path $PSScriptRoot 'Console-Input.cs'))
    $ptyProbeCommand = ($ptyProbeArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '
    # The probe treats only the signing-stub sentinel as success. All console
    # checks and prompt reads run unchanged in the actual Confirm-Sign entrypoint.
    $ptyResult = [SigningPseudoConsoleTest]::Run($ptyPS, $ptyProbeCommand, $ptyPrompt, "SIGN $ptyPlan")
    Assert-ConPTY ($ptyResult.Output.Contains('CONSOLE STATE: True|False|PseudoConsoleWindow|False')) 'real hidden PseudoConsoleWindow has non-redirected input'
    Assert-ConPTY $ptyResult.PromptSeen 'real CreatePseudoConsole displays production confirmation prompt'
    if (-not $ptyResult.Output.Contains('CONPTY SIGNING STUB SUCCEEDED')) { throw $ptyResult.Output }
    Assert-ConPTY ($ptyResult.ExitCode -eq 0 -and $ptyResult.Output.Contains('CONPTY SIGNING STUB SUCCEEDED')) 'correct managed terminal answer passes plan validation and signing stub exits zero'
    $ptyWrong = [SigningPseudoConsoleTest]::Run($ptyPS, $ptyCommand, $ptyPrompt, 'SIGN wrong-plan')
    Assert-ConPTY ($ptyWrong.PromptSeen -and $ptyWrong.ExitCode -eq 1 -and $ptyWrong.Output.Contains('Typed confirmation did not match') -and -not $ptyWrong.Output.Contains('CONPTY SIGNING STUB REACHED')) 'wrong answer refuses visibly before signing stub'
    # A real terminal output stream with redirected stdin must still refuse.
    $ptyCmd = [IO.Path]::Combine([Environment]::SystemDirectory, 'cmd.exe')
    $ptyRedirected = [SigningPseudoConsoleTest]::Run($ptyCmd, ('/d /c ""' + $ptyPS + '" ' + $ptyCommand + ' < NUL"'), $null, $null)
    Assert-ConPTY ($ptyRedirected.ExitCode -eq 1 -and $ptyRedirected.Output.Contains('Please run the confirmation command in your own Windows PowerShell window.') -and $ptyRedirected.Output.Contains('Nothing signed.') -and -not $ptyRedirected.Output.Contains('CONPTY SIGNING STUB REACHED')) 'redirected refusal is visible on real terminal output'
    $ptySuppressed = [SigningPseudoConsoleTest]::Run($ptyCmd, ('/d /c ""' + $ptyPS + '" ' + $ptyCommand + ' < NUL 2>NUL"'), $null, $null)
    Assert-ConPTY ($ptySuppressed.ExitCode -eq 1 -and $ptySuppressed.Output.Contains('Please run the confirmation command in your own Windows PowerShell window.') -and $ptySuppressed.Output.Contains('Nothing signed.')) 'kind refusal remains visible when stderr is suppressed'
    $ptyNonInteractive = [SigningPseudoConsoleTest]::Run($ptyPS, ('-NonInteractive ' + $ptyCommand), $null, $null)
    Assert-ConPTY ($ptyNonInteractive.ExitCode -eq 1 -and -not $ptyNonInteractive.Output.Contains('CONPTY SIGNING STUB REACHED') -and $ptyNonInteractive.Output.Contains('Nothing signed.')) '-NonInteractive refuses even with a real pseudo console'
    $ptyAbbreviated = [SigningPseudoConsoleTest]::Run($ptyPS, ('-NonI ' + $ptyCommand), $null, $null)
    Assert-ConPTY ($ptyAbbreviated.ExitCode -eq 1 -and $ptyAbbreviated.Output.Contains('Nothing signed.')) 'abbreviated -NonI also refuses'
    $ptyPiped = [SigningPseudoConsoleTest]::Run($ptyCmd, ('/d /c "echo SIGN ' + $ptyPlan + ' | "' + $ptyPS + '" ' + $ptyCommand + '"'), $null, $null)
    Assert-ConPTY ($ptyPiped.ExitCode -eq 1 -and $ptyPiped.Output.Contains('Nothing signed.') -and -not $ptyPiped.Output.Contains('CONPTY SIGNING STUB REACHED')) 'piped correct answer refuses on real terminal output'
    $ptyOutputFile = Join-Path $ptyRoot 'redirected-output.txt'
    $ptyOutputRedirected = [SigningPseudoConsoleTest]::Run($ptyCmd, ('/d /c ""' + $ptyPS + '" ' + $ptyCommand + ' > "' + $ptyOutputFile + '""'), $null, $null)
    Assert-ConPTY ($ptyOutputRedirected.ExitCode -eq 1 -and (Get-Content -Raw -LiteralPath $ptyOutputFile).Contains('Nothing signed.')) 'redirected output refuses even with console input'
} finally {
    $ptyCleanup = [IO.Path]::GetFullPath($ptyRoot)
    if ([IO.Path]::GetDirectoryName($ptyCleanup) -ne [IO.Path]::GetTempPath().TrimEnd('\') -or [IO.Path]::GetFileName($ptyCleanup) -notmatch '^sign-my-app-conpty-[a-f0-9]{32}$') { throw 'Unsafe ConPTY cleanup.' }
    if (Test-Path -LiteralPath $ptyCleanup) { Remove-Item -LiteralPath $ptyCleanup -Recurse -Force }
}
Write-Output "CONPTY RESULT: $ptyPassed checks passed."
