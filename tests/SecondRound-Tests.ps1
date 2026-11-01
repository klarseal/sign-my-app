# Standalone regressions; no certificate store or signing operation is used.
[CmdletBinding()]
param([ValidateSet('All','Unicode','Console','Disclosure','NonDesktop')][string]$Only = 'All')
$ErrorActionPreference = 'Stop'
$srRepo = Split-Path $PSScriptRoot -Parent
$srScripts = Join-Path $srRepo 'scripts'
$srRoot = Join-Path ([IO.Path]::GetTempPath()) ('sign-my-app-round2-' + [guid]::NewGuid().ToString('N'))
$srFailures = 0; $srPassed = 0
function Assert-SecondRound([bool]$Condition, [string]$Name) {
    if ($Condition) { $script:srPassed++; Write-Output "PASS: round 2: $Name" }
    else { $script:srFailures++; Write-Output "FAIL: round 2: $Name" }
}
try {
    New-Item -ItemType Directory -Path $srRoot | Out-Null
    . "$srScripts/Signing-Safety.ps1"
    if ($Only -in @('All','Unicode','NonDesktop')) {
        # Exercise every generated range at both ends and every gap in PS 5.1.
        # Node checks the complete scalar space against the Unicode properties.
        $srRanges = (Get-Content -Raw -LiteralPath (Join-Path $srScripts 'Unicode-Safety.json') | ConvertFrom-Json).ranges
        $srRangesOK = $true
        foreach ($srRange in $srRanges) {
            foreach ($srPoint in @($srRange[0], $srRange[1])) {
                $srChar = if ($srPoint -ge 0xd800 -and $srPoint -le 0xdfff) { [string][char]$srPoint } else { [char]::ConvertFromUtf32($srPoint) }
                if (-not (Test-SigningControlText $srChar) -or (ConvertTo-SigningDisplayText $srChar).Contains($srChar)) { $srRangesOK = $false }
            }
        }
        for ($srIndex = 1; $srIndex -lt $srRanges.Count; $srIndex++) {
            $srGap = [char]::ConvertFromUtf32($srRanges[$srIndex - 1][1] + 1)
            if (Test-SigningControlText $srGap) { $srRangesOK = $false }
        }
        Assert-SecondRound $srRangesOK 'every generated invisible range and gap follows the shared policy'
        foreach ($srPoint in @(0x3164, 0x115f, 0xfe0f, 0xe0100)) {
            $srChar = [char]::ConvertFromUtf32($srPoint)
            $srRefused = $false
            try { Assert-SafeSigningText ('App' + $srChar + 'Setup.exe') } catch { $srRefused = $_.Exception.Message -match 'Rename' }
            Assert-SecondRound $srRefused ('U+{0:X} refused' -f $srPoint)
            Assert-SecondRound (-not (ConvertTo-SigningDisplayText $srChar).Contains($srChar)) ('U+{0:X} escaped' -f $srPoint)
        }
    }
    if ($Only -in @('All','Console')) {
        . (Join-Path $srRepo 'mcp/tests/Desktop-Lock.ps1')
        $desktopMutex = Enter-DesktopTestLock 'Commands'
        try {
        $srProbe = Join-Path $srRoot 'console.ps1'; $srResult = Join-Path $srRoot 'result.json'
        @'
param($Safety, $Source, $Result)
$ErrorActionPreference = 'Stop'
try {
    . $Safety
    Add-Type -Path $Source
    $hiddenState = [SigningConsoleTest]::Describe()
    [Console]::SetIn((New-Object IO.StringReader("forged answer`n")))
    $hiddenAccepted = $true
    try { Assert-SigningConsole } catch { $hiddenAccepted = $false }
    [Console]::Title = 'TEST ONLY - nothing will be signed'
    Write-Host 'TEST ONLY - nothing will be signed'
    [SigningConsoleTest]::Show()
    [Console]::SetIn((New-Object IO.StringReader("forged answer`n")))
    $deviceRead = $true
    for ($sample = 0; $sample -lt 5; $sample++) {
        [SigningConsoleTest]::QueueSampleText()
        if ((Read-SigningConfirmation 'Device probe') -cne 'console regression answer') { $deviceRead = $false }
    }
    [SigningConsoleTest]::FreeConsole() | Out-Null
    $detachedRefused = $false
    try { Assert-SigningConsole } catch { $detachedRefused = $_.Exception.Message -like 'Please run*' }
    @{ hidden = $hiddenAccepted; state = $hiddenState; device = $deviceRead; detached = $detachedRefused } | ConvertTo-Json | Set-Content -LiteralPath $Result
} catch { [IO.File]::WriteAllText($Result, $_.ToString()); exit 1 }
'@ | ForEach-Object { $_.Replace('[SigningConsoleTest]::Show()', ('. ' + (ConvertTo-SigningPSLiteral (Join-Path $srRepo 'mcp/tests/Desktop-Lock.ps1')) + '; $windowMutex = Enter-DesktopTestLock; [SigningConsoleTest]::Show()')) } | Set-Content -LiteralPath $srProbe
        $srPS = [IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\powershell.exe')
        $srArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$srProbe,(Join-Path $srScripts 'Signing-Safety.ps1'),(Join-Path $PSScriptRoot 'Console-Input.cs'),$srResult)
        # Explicit conhost exercises the hidden classic console; ConPTY-Tests
        # separately covers modern terminals without showing their hidden HWND.
        $srChild = Start-Process -FilePath ([IO.Path]::Combine([Environment]::SystemDirectory, 'conhost.exe')) -ArgumentList ((@($srPS) + $srArgs | ForEach-Object { '"' + $_ + '"' }) -join ' ') -WorkingDirectory ([Environment]::SystemDirectory) -WindowStyle Hidden -PassThru
        try {
            if (-not $srChild.WaitForExit(15000)) { $srChild.Kill(); throw 'Round 2 console test timed out.' }
            $srText = Get-Content -Raw -LiteralPath $srResult
            if ($srChild.ExitCode -ne 0) { throw $srText }
            try { $srConsole = $srText | ConvertFrom-Json }
            catch { throw "Round 2 console probe failed: $srText" }
            Assert-SecondRound $srConsole.hidden 'managed guard cannot reject a hidden classic console'
            Assert-SecondRound ($srConsole.state -ceq 'True|False|ConsoleWindowClass|False') 'hidden classic console has non-redirected input; visibility is no longer checked'
            Assert-SecondRound $srConsole.device 'visible console ignores SetIn and reads ConsoleHost terminal'
            Assert-SecondRound $srConsole.detached 'detached console refused'
        } finally { $srChild.Dispose() }
        } finally { Exit-DesktopTestLock $desktopMutex }
    }
    if ($Only -in @('All','Disclosure','NonDesktop')) {
        $srFixture = Join-Path $srRoot 'fixture'; New-Item -ItemType Directory -Path $srFixture | Out-Null
        Copy-Item -Path (Join-Path $srScripts '*') -Destination $srFixture
        $srApp = Join-Path $srRoot 'fixture.exe'; [IO.File]::WriteAllText($srApp, 'not executable')
        'param(); return ''C:\synthetic\signtool.exe''' | Set-Content -LiteralPath (Join-Path $srFixture 'Find-SignTool.ps1')
        @'

function Get-SigningCertificate { param($Thumbprint, [switch]$MachineStore); [pscustomobject]@{ Thumbprint = ('A' * 40); Subject = 'synthetic publisher' } }
function Assert-SigningTimestamp {}
function Assert-SigningApproval {}
function Get-SigningSnapshotDigest {}
function Assert-SigningConsole {}
function Read-SigningConfirmation { throw 'ROUND2 PROMPT STOP' }
function Get-AuthenticodeSignature { param($LiteralPath); Write-Host 'ROUND2 CHAIN CHECK'; [pscustomobject]@{ Status = 'NotSigned' } }
function Invoke-SigningNative { throw 'Native invocation forbidden.' }
'@ | Add-Content -LiteralPath (Join-Path $srFixture 'Signing-Safety.ps1')
        foreach ($srMode in @('Preview','Approval','Publisher')) {
            $srOutput = @(& {
                try {
                    if ($srMode -eq 'Preview') { & "$srFixture/Invoke-Sign.ps1" -FilePath $srApp -Thumbprint ('A' * 40) 6>&1 }
                    else {
                        . "$srFixture/Signing-Safety.ps1"
                        if ($srMode -eq 'Publisher') { Get-ReplacedSigningPublisher $srApp ('A' * 40) 6>&1 }
                        else { Invoke-ApprovedSigning -FilePath $srApp -ExpectedSHA256 ('B' * 64) -ApprovePlan ('C' * 64) -Thumbprint ('A' * 40) 6>&1 }
                    }
                } catch { if ($_.Exception.Message -ne 'ROUND2 PROMPT STOP') { throw } }
            } | ForEach-Object { [string]$_ })
            $srJoined = $srOutput -join "`n"
            Assert-SecondRound ($srJoined.IndexOf('Network notice:') -ge 0 -and $srJoined.IndexOf('Network notice:') -lt $srJoined.IndexOf('ROUND2 CHAIN CHECK')) "$srMode notice precedes file chain check"
        }
    }
} finally {
    $srCleanup = [IO.Path]::GetFullPath($srRoot)
    if ([IO.Path]::GetDirectoryName($srCleanup) -ne [IO.Path]::GetTempPath().TrimEnd('\') -or [IO.Path]::GetFileName($srCleanup) -notmatch '^sign-my-app-round2-[a-f0-9]{32}$') { throw 'Unsafe round 2 cleanup.' }
    if (Test-Path -LiteralPath $srCleanup) { Remove-Item -LiteralPath $srCleanup -Recurse -Force }
}
if ($srFailures) { throw "Round 2: $srFailures failed, $srPassed passed." }
Write-Output "ROUND2 RESULT: $srPassed checks passed."
