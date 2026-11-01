# Synthetic UI only. No signing code, certificate access or production test flag.
param([string]$Source, [string]$Decision = 'Sign once', [int]$At = 3000,
    [int]$Limit = 6000, [switch]$Small, [switch]$Background, [switch]$Manual,
    [switch]$SlowClose, [switch]$SameTick, [switch]$NativeInput)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Desktop-Lock.ps1')
$desktopMutex = Enter-DesktopTestLock
try {
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[Windows.Forms.Application]::SetUnhandledExceptionMode([Windows.Forms.UnhandledExceptionMode]::ThrowException)
$global:decisionProbeResult = @{ samples = @(); events = @(); decision = $null }
$global:decisionInputScript = Join-Path $PSScriptRoot 'Click-Approval.ps1'
$global:decisionInputDriver = $null
$sourceText = [IO.File]::ReadAllText($Source)
if (-not $sourceText.Contains("`$form.Text = 'Sign my app'")) { throw 'Missing production title' }
$sourceText = $sourceText.Replace("`$form.Text = 'Sign my app'", "`$form.Text = 'TEST ONLY - nothing will be signed'")
if ($Small) {
    $sourceText = $sourceText.Replace('[Windows.Forms.Screen]::FromControl($form).WorkingArea', '(New-Object Drawing.Rectangle(0, 0, 800, 450))')
}
if ($Background) {
    . (Join-Path $PSScriptRoot 'Foreground-Fixture.ps1') -Embedded
    $sourceText = $sourceText.Replace('$presentation.visible = & $isPresented', @'
        $foregroundFixture.form.Show()
        $foregroundFixture.form.Activate()
        [Windows.Forms.Application]::DoEvents()
        $presentation.visible = & $isPresented
'@)
}
$sourceText = $sourceText.Replace('$form.Add_Shown({', '$foregroundFixture = if ($Background) { New-ForegroundFixture } else { $null }; $form.Add_Shown({')
$instrument = @'
        if ($Small) {
            $form.AutoScaleMode = 'None'
            $form.Scale((New-Object Drawing.SizeF(1.5, 1.5)))
        }
        if ($SlowClose) { $form.Add_FormClosing({ Start-Sleep -Milliseconds 350 }) }
        $driver = New-Object Windows.Forms.Timer
        $driver.Interval = 10
        $driveState = @{ early = $false; ready = $false; clicked = $false }
        $inputDriver = $null
        if ($NativeInput) {
            $inputStart = New-Object Diagnostics.ProcessStartInfo
            $inputStart.FileName = [IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\powershell.exe')
            $inputScript = $global:decisionInputScript
            $inputStart.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $inputScript +
                '" -TargetProcess ' + $PID + ' -Handle ' + $form.Handle.ToInt64() + ' -Started ' + $inputStarted +
                ' -At ' + $At + ' -Decision "' + $Decision + '"'
            $inputStart.UseShellExecute = $false; $inputStart.CreateNoWindow = $true
            $inputStart.RedirectStandardOutput = $true; $inputStart.RedirectStandardError = $true
            $inputDriver = [Diagnostics.Process]::Start($inputStart)
            $global:decisionInputDriver = $inputDriver
        }
        $recordClick = { $global:decisionProbeResult.clickedAt = $decisionState.clickedAt }.GetNewClosure()
        $sign.Add_Click($recordClick); $always.Add_Click($recordClick)
        $initialText = $text.Text
        $driver.Add_Tick({
            $elapsed = $watch.ElapsedMilliseconds
            if ($Background -and -not $driveState.clicked -and $elapsed -ge 500 -and $elapsed -lt 2200) {
                if ([Windows.Forms.Form]::ActiveForm -ne $foregroundFixture.form) { throw 'Typing target lost foreground' }
                [Windows.Forms.SendKeys]::SendWait('x')
            }
            if (-not $driveState.early -and $elapsed -ge 1800) {
                $driveState.early = $true
                $global:decisionProbeResult.samples += @{ at = $elapsed; enabled = $sign.Enabled; stage = 'early' }
            }
            if (-not $driveState.ready -and $elapsed -ge 2250) {
                $driveState.ready = $true
                $buttonsVisible = $true
                foreach ($button in @($cancel, $sign, $always)) {
                    $rectangle = $form.RectangleToClient($button.RectangleToScreen($button.ClientRectangle))
                    $buttonsVisible = $buttonsVisible -and $form.ClientRectangle.Contains($rectangle)
                }
                $global:decisionProbeResult.samples += @{
                    at = $elapsed; enabled = $sign.Enabled; stage = 'ready'
                    active = ([Windows.Forms.Form]::ActiveForm -eq $form)
                    visible = $form.Visible; topmost = $form.TopMost; taskbar = $form.ShowInTaskbar
                    onScreen = (& $isPresented); buttonsVisible = $buttonsVisible
                    width = $form.Width; height = $form.Height; textHeight = $text.Height
                    typedInTarget = if ($Background) { $foregroundFixture.text.Text.Contains('xxxx') } else { $false }
                    approvalUnchanged = $text.Text -eq $initialText
                }
            }
            if (-not $NativeInput -and -not $Manual -and -not $SameTick -and -not $driveState.clicked -and $elapsed -ge $At) {
                $driveState.clicked = $true
                $form.Activate()
                if ($Decision -eq 'Sign once') { $sign.PerformClick() } else { $always.PerformClick() }
                $global:decisionProbeResult.clickedAt = $decisionState.clickedAt
            }
        }.GetNewClosure())
        $form.Add_FormClosed({
            $driver.Stop(); $driver.Dispose()
            if ($foregroundFixture) { $foregroundFixture.form.Dispose() }
        }.GetNewClosure())
        $driver.Start()
'@
if ($SameTick) {
    $sourceText = $sourceText.Replace('if (-not $decisionState.approved -and $watch.ElapsedMilliseconds -ge $RemainingMilliseconds)', @'
if (-not $driveState.clicked -and $watch.ElapsedMilliseconds -ge ($RemainingMilliseconds - 120)) {
            $driveState.clicked = $true
            $sign.PerformClick()
            $global:decisionProbeResult.clickedAt = $decisionState.clickedAt
            Start-Sleep -Milliseconds 250
        }
        if (-not $decisionState.approved -and $watch.ElapsedMilliseconds -ge $RemainingMilliseconds)
'@)
}
$sourceText = $sourceText.Replace('$watch = [Diagnostics.Stopwatch]::StartNew()', '$inputStarted = [Diagnostics.Stopwatch]::GetTimestamp(); $watch = [Diagnostics.Stopwatch]::StartNew()')
. ([scriptblock]::Create($sourceText.Replace('$timer.Add_Tick({', ($instrument + "`n    `$timer.Add_Tick({"))))
$watchTotal = [Diagnostics.Stopwatch]::StartNew()
$global:decisionProbeResult.decision = Request-NativeSigningApproval "TEST ONLY - nothing will be signed`r`nSynthetic decision test. No signing code is loaded." $Limit {
    param($eventData)
    $global:decisionProbeResult.events += $eventData
}
$global:decisionProbeResult.elapsed = $watchTotal.ElapsedMilliseconds
if ($global:decisionInputDriver) {
    try {
        if (-not $global:decisionInputDriver.WaitForExit(5000)) { $global:decisionInputDriver.Kill(); throw 'Native input driver hung' }
        $global:decisionProbeResult.inputExit = $global:decisionInputDriver.ExitCode
        $global:decisionProbeResult.inputError = $global:decisionInputDriver.StandardError.ReadToEnd()
    } finally { $global:decisionInputDriver.Dispose() }
}
$global:decisionProbeResult | ConvertTo-Json -Depth 8 -Compress
} finally {
    if ($global:decisionInputDriver) {
        try { if (-not $global:decisionInputDriver.HasExited) { $global:decisionInputDriver.Kill() } } catch {}
    }
    Exit-DesktopTestLock $desktopMutex
}
