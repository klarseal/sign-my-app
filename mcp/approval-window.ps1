#Requires -Version 5.1
# Standard Windows controls only. Invoked by the installed bridge, never a tool.
function Request-NativeSigningApproval([string]$Message, [int]$RemainingMilliseconds, [scriptblock]$OnEvent) {
    if ($RemainingMilliseconds -le 0) { throw 'Approval expired.' }
    Add-Type -AssemblyName System.Windows.Forms
    $presentation = @{ visible = $false }
    $form = New-Object Windows.Forms.Form
    $form.Text = 'Sign my app'
    $form.AutoSize = $true
    $form.AutoSizeMode = 'GrowAndShrink'
    $form.StartPosition = 'CenterScreen'
    $form.ShowInTaskbar = $true
    $reportState = {
        param($Stage)
        if ($OnEvent) { & $OnEvent @{
            event = 'window_state'; stage = $Stage; visible = $form.Visible
            active = ([Windows.Forms.Form]::ActiveForm -eq $form); minimized = ($form.WindowState -eq 'Minimized')
            bounds = @{ x = $form.Left; y = $form.Top; width = $form.Width; height = $form.Height }
            monitor = [Windows.Forms.Screen]::FromControl($form).DeviceName
            onScreen = [Windows.Forms.Screen]::FromControl($form).WorkingArea.Contains($form.Bounds)
            topMost = $form.TopMost; taskbar = $form.ShowInTaskbar
        } }
    }.GetNewClosure()
    # Readable, topmost text counts even when Windows leaves another app active.
    # Activation is required only when accepting a decision.
    $isPresented = {
        $form.Visible -and $form.TopMost -and
            $form.WindowState -eq 'Normal' -and $form.Width -gt 0 -and $form.Height -gt 0 -and
            [Windows.Forms.Screen]::FromControl($form).WorkingArea.Contains($form.Bounds)
    }.GetNewClosure()
    $panel = New-Object Windows.Forms.FlowLayoutPanel
    $panel.FlowDirection = 'TopDown'
    $panel.WrapContents = $false
    $panel.AutoSize = $true
    $text = New-Object Windows.Forms.TextBox
    $text.Multiline = $true; $text.ReadOnly = $true; $text.ScrollBars = 'Vertical'
    $text.WordWrap = $true; $text.Width = 680; $text.Height = 300
    # Win32 EDIT needs CRLF. LF alone leaves subsequent text off to the right.
    $text.Text = ($Message -replace "`r?`n", "`r`n")
    $cancel = New-Object Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.DialogResult = 'Cancel'
    $sign = New-Object Windows.Forms.Button
    $sign.Text = 'Sign once'; $sign.AutoSize = $true; $sign.Enabled = $false; $sign.DialogResult = 'OK'
    $always = New-Object Windows.Forms.Button
    $always.Text = 'Always for this project'; $always.AutoSize = $true; $always.Enabled = $false; $always.DialogResult = 'Yes'
    $panel.Controls.AddRange(@($text, $cancel, $sign, $always)); $form.Controls.Add($panel)
    $restoreOnScreen = {
        $working = [Windows.Forms.Screen]::FromControl($form).WorkingArea
        # Preserve the controls and their order; only the scrolling text viewport
        # gives up space on small screens (including after DPI scaling).
        $form.MaximumSize = $working.Size
        $overflowWidth = [Math]::Max(0, $panel.PreferredSize.Width + ($form.Width - $form.ClientSize.Width) - $working.Width)
        $overflowHeight = [Math]::Max(0, $panel.PreferredSize.Height + ($form.Height - $form.ClientSize.Height) - $working.Height)
        if ($overflowWidth -gt 0 -or $overflowHeight -gt 0) {
            $text.Size = New-Object Drawing.Size([Math]::Max(1, $text.Width - $overflowWidth), [Math]::Max(1, $text.Height - $overflowHeight))
            $panel.PerformLayout(); $form.PerformLayout()
        }
        if ($form.WindowState -eq 'Normal' -and -not $working.Contains($form.Bounds)) {
            $form.Location = New-Object Drawing.Point(
                ($working.Left + [Math]::Max(0, [int](($working.Width - $form.Width) / 2))),
                ($working.Top + [Math]::Max(0, [int](($working.Height - $form.Height) / 2))))
            & $reportState 'restored on screen'
        }
    }.GetNewClosure()
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $decisionState = @{ approved = $null; clickedAt = $null; source = 'close' }
    # Capture eligibility in the click handler. Closing/disposing the dialog can
    # take us past the deadline; that must not revoke an already accepted click.
    $acceptDecision = {
        param($sender, $eventArgs)
        $clickedAt = $watch.ElapsedMilliseconds
        if ($sender.Enabled -and (& $isPresented) -and [Windows.Forms.Form]::ActiveForm -eq $form -and
            $clickedAt -ge 2000 -and $clickedAt -lt $RemainingMilliseconds) {
            $decisionState.approved = $sender.Text; $decisionState.clickedAt = $clickedAt
            $decisionState.source = 'click'
            $form.DialogResult = if ($sender -eq $sign) { 'OK' } else { 'Yes' }
            $form.Close()
        }
    }.GetNewClosure()
    $sign.DialogResult = 'None'; $always.DialogResult = 'None'
    $sign.Add_Click($acceptDecision); $always.Add_Click($acceptDecision)
    $cancel.Add_Click({ $decisionState.source = 'cancel' }.GetNewClosure())
    $form.AcceptButton = $cancel; $form.CancelButton = $cancel
    $form.Add_Shown({
        # Re-show after the startup hide flag. Separate-process desktop probes
        # verify that this restore finishes Normal with nonzero on-screen bounds.
        $form.WindowState = 'Minimized'
        $form.WindowState = 'Normal'
        $form.TopMost = $true
        & $restoreOnScreen
        $form.BringToFront()
        $form.Activate()
        [Windows.Forms.Application]::DoEvents()
        $presentation.visible = & $isPresented
        & $reportState 'shown'
        if (-not $presentation.visible) { $form.Close(); return }
        $text.SelectionStart = 0; $text.SelectionLength = 0; $text.ScrollToCaret()
        $cancel.Select()
    }.GetNewClosure())
    $timer = New-Object Windows.Forms.Timer
    $timer.Interval = 100
    $sampled = @{ one = $false; five = $false }
    $seen = New-Object 'Collections.Generic.HashSet[int]'
    $reviewLayout = @{ width = 0; fontHeight = 0 }
    $timer.Add_Tick({
        & $restoreOnScreen
        if (-not $sampled.one -and $watch.ElapsedMilliseconds -ge 1000) { $sampled.one = $true; & $reportState 'after 1 s' }
        if (-not $sampled.five -and $watch.ElapsedMilliseconds -ge 5000) { $sampled.five = $true; & $reportState 'after 5 s' }
        # Wrapped line numbers change when the viewport or DPI changes.
        if ($reviewLayout.width -ne $text.ClientSize.Width -or $reviewLayout.fontHeight -ne $text.Font.Height) {
            $seen.Clear(); $reviewLayout.width = $text.ClientSize.Width; $reviewLayout.fontHeight = $text.Font.Height
        }
        $presented = & $isPresented
        $reviewed = $false
        if ($presented) {
            $firstIndex = $text.GetCharIndexFromPosition((New-Object Drawing.Point(0, 0)))
            $first = $text.GetLineFromCharIndex($firstIndex)
            $total = $text.GetLineFromCharIndex($text.TextLength) + 1
            for ($line = $first; $line -lt $total; $line++) {
                $index = $text.GetFirstCharIndexFromLine($line)
                if ($index -lt 0) { break }
                $point = $text.GetPositionFromCharIndex($index)
                if ($point.Y + $text.Font.Height -gt $text.ClientSize.Height) { break }
                if ($point.Y -ge 0) { $null = $seen.Add($line) }
            }
            $reviewed = $seen.Count -eq $total
        }
        $sign.Enabled = $reviewed -and $watch.ElapsedMilliseconds -ge 2000
        $always.Enabled = $sign.Enabled
        if (-not $decisionState.approved -and $watch.ElapsedMilliseconds -ge $RemainingMilliseconds) { $decisionState.source = 'timeout'; $form.DialogResult = 'Cancel'; $form.Close() }
    }.GetNewClosure())
    try {
        $timer.Start()
        $answer = $form.ShowDialog()
        if (-not $presentation.visible) { throw 'Approval window could not be shown.' }
        if ($decisionState.approved) {
            if ($OnEvent) { & $OnEvent @{
                event = 'window_result'; source = 'click'; decision = $decisionState.approved
                elapsedMilliseconds = $decisionState.clickedAt; remainingMilliseconds = $RemainingMilliseconds
            } }
            return $decisionState.approved
        }
        if ($OnEvent) { & $OnEvent @{ event = 'window_result'; source = $decisionState.source } }
        if ($decisionState.source -eq 'timeout') { return 'Timeout' }
        return 'Cancel'
    } finally { $timer.Dispose(); $form.Dispose(); $watch.Stop() }
}
