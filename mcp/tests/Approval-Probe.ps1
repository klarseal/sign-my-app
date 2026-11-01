# Test-only rendering of the real function with synthetic text. Never approves.
function Invoke-ApprovalProbe($Request) {
    . (Join-Path $PSScriptRoot 'Desktop-Lock.ps1')
    $desktopMutex = Enter-DesktopTestLock
    try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::SetUnhandledExceptionMode([Windows.Forms.UnhandledExceptionMode]::ThrowException)
    $script:probeRequest = $Request
    $global:approvalProbeState = @{ result = $null }
    $global:approvalProbeRequest = $Request
    $source = [IO.File]::ReadAllText($Request.source)
    if (-not $source.Contains("`$form.Text = 'Sign my app'")) { throw 'Missing production title' }
    $source = $source.Replace("`$form.Text = 'Sign my app'", "`$form.Text = 'TEST ONLY - nothing will be signed'")
    $Request.message = "TEST ONLY - nothing will be signed`r`n" + $Request.message
    if ($Request.small) {
        $source = $source.Replace('[Windows.Forms.Screen]::FromControl($form).WorkingArea', '(New-Object Drawing.Rectangle(0, 0, 800, 450))')
    }
    # Instrument only a private test copy; production has no testing/approval flag.
    $instrument = @'
        # This synthetic rendering fixture cannot approve, even if unrelated
        # shared-desktop input clicks an enabled button during measurement.
        # Enabled/review behavior is still measured; only Cancel can close it.
        $sign.Add_Click({ $decisionState.approved = $null; $form.DialogResult = 'None' }.GetNewClosure())
        $always.Add_Click({ $decisionState.approved = $null; $form.DialogResult = 'None' }.GetNewClosure())
        if ($script:probeRequest.scale -ne 1) {
            $form.AutoScaleMode = 'None'
            $form.Font = New-Object Drawing.Font($form.Font.FontFamily, ($form.Font.Size * $script:probeRequest.scale))
            $form.Scale((New-Object Drawing.SizeF($script:probeRequest.scale, $script:probeRequest.scale)))
        }
        $probeTimer = New-Object Windows.Forms.Timer
        $probeTimer.Interval = 200
        $reviewProbe = @{ phase = -1; line = 0; snapshots = @{}; foreground = $false; foregroundHandle = 0 }
        # Measure initial presentation in Shown, before later desktop activity can
        # take focus away while the separate scrolling checks run.
        $form.Add_Shown({
            $reviewProbe.foreground = [Windows.Forms.Form]::ActiveForm -eq $form
        }.GetNewClosure())
        $probeTimer.Add_Tick({
            if ($global:approvalProbeRequest.review -and $reviewProbe.phase -eq 0) {
                if ($watch.ElapsedMilliseconds -lt 2300) { return }
                $reviewProbe.snapshots.top = @{ enabled = $sign.Enabled; seen = $seen.Count; total = ($text.GetLineFromCharIndex($text.TextLength) + 1) }
                $text.SelectionStart = $text.TextLength; $text.ScrollToCaret()
                $reviewProbe.phase = 1
                return
            }
            if ($global:approvalProbeRequest.review -and $reviewProbe.phase -gt 0) {
                $total = ($text.GetLineFromCharIndex($text.TextLength) + 1)
                $snapshot = @{ enabled = $sign.Enabled; seen = $seen.Count; total = $total }
                if ($reviewProbe.phase -eq 1) {
                    $reviewProbe.snapshots.bottom = $snapshot
                    $text.SelectionStart = 0; $text.ScrollToCaret()
                    $reviewProbe.phase = 2
                } elseif ($reviewProbe.line -lt $total) {
                    $text.SelectionStart = $text.GetFirstCharIndexFromLine($reviewProbe.line)
                    $text.ScrollToCaret()
                    $reviewProbe.line += 5
                } else {
                    $reviewProbe.snapshots.finished = $snapshot
                    $global:approvalProbeState.result.review = $reviewProbe.snapshots
                    $probeTimer.Stop(); $probeTimer.Dispose()
                    # Close only with Cancel. This probe never chooses Sign.
                    $global:approvalProbeState.result.cancelClicked = $true
                    $cancel.PerformClick()
                }
                return
            }
            if ($watch.ElapsedMilliseconds -lt 500) { return }
            if (-not $global:approvalProbeRequest.review) { $probeTimer.Stop() }
            $allVisible = $true
            for ($i = 0; $i -lt $text.Text.Length; $i++) {
                if ($text.Text[$i] -in @([char]13, [char]10)) { continue }
                $point = $text.GetPositionFromCharIndex($i)
                if ($point.X -lt 0 -or $point.X -ge $text.ClientSize.Width -or $point.Y -lt 0 -or $point.Y + $text.Font.Height -gt $text.ClientSize.Height) { $allVisible = $false }
            }
            $working = [Windows.Forms.Screen]::FromControl($form).WorkingArea
            $global:approvalProbeState.result = @{
                visible = $form.Visible
                foreground = $reviewProbe.foreground
                foregroundHandle = $reviewProbe.foregroundHandle
                formHandle = $form.Handle.ToInt64()
                topMost = $form.TopMost
                stdioRedirected = ([Console]::IsInputRedirected -and [Console]::IsOutputRedirected)
                allTextVisible = $allVisible; wrap = $text.WordWrap
                crlf = $text.Text.Contains("`r`n")
                width = $text.ClientSize.Width; height = $text.ClientSize.Height
                onScreen = $working.Contains($form.Bounds)
                buttonsVisible = (@($cancel, $sign, $always) | Where-Object { -not $form.ClientRectangle.Contains($form.RectangleToClient($_.RectangleToScreen($_.ClientRectangle))) }).Count -eq 0
                scale = $global:approvalProbeRequest.scale
                text = $text.Text
            }
            if ($global:approvalProbeRequest.review) {
                $reviewProbe.phase = 0
            }
            if ($global:approvalProbeRequest.report) {
                [IO.File]::WriteAllText($global:approvalProbeRequest.report, ($global:approvalProbeState.result | ConvertTo-Json -Compress))
                # Capture actual desktop pixels, not an off-screen render.
                $bitmap = New-Object Drawing.Bitmap($form.Width, $form.Height)
                $graphics = [Drawing.Graphics]::FromImage($bitmap)
                try {
                    $graphics.CopyFromScreen($form.Location, [Drawing.Point]::Empty, $form.Size)
                    $bitmap.Save([IO.Path]::ChangeExtension($global:approvalProbeRequest.report, '.png'), [Drawing.Imaging.ImageFormat]::Png)
                } finally { $graphics.Dispose(); $bitmap.Dispose() }
            }
        }.GetNewClosure())
        $probeTimer.Start()
        $timer.Start()
'@
    . ([scriptblock]::Create($source.Replace('$sign.Add_Click($acceptDecision); $always.Add_Click($acceptDecision)', '# render-only: no approval handlers').Replace('$timer.Start()', $instrument)))
    $approved = (Request-NativeSigningApproval $Request.message $Request.hold) -in @('Sign once','Always for this project')
    $global:approvalProbeState.result.approved = $approved
    if ($Request.report) { [IO.File]::WriteAllText($Request.report, ($global:approvalProbeState.result | ConvertTo-Json -Depth 8 -Compress)) }
    return @{ failed = $false; output = @($global:approvalProbeState.result) }
    } finally { Exit-DesktopTestLock $desktopMutex }
}
