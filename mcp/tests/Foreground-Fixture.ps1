# Synthetic typing target. Dot-source with -Embedded to join one locked test.
param([string]$Report, [switch]$Embedded)
function New-ForegroundFixture {
    Add-Type -AssemblyName System.Windows.Forms
    $form = New-Object Windows.Forms.Form
    $form.Text = 'TEST ONLY - nothing will be signed - typing target'
    $form.Location = New-Object Drawing.Point(20, 20)
    $form.StartPosition = 'Manual'
    $form.Size = New-Object Drawing.Size(500, 180)
    $text = New-Object Windows.Forms.TextBox
    $text.Multiline = $true; $text.Dock = 'Fill'
    $text.Text = "TEST ONLY - nothing will be signed`r`n"
    $form.Controls.Add($text)
    $form.Add_Shown({ $text.Select(); $text.SelectionStart = $text.TextLength }.GetNewClosure())
    return @{ form = $form; text = $text }
}
if (-not $Embedded) {
    . (Join-Path $PSScriptRoot 'Desktop-Lock.ps1')
    Invoke-WithDesktopTestLock {
        $fixture = New-ForegroundFixture
        try { $null = $fixture.form.ShowDialog() }
        finally {
            if ($Report) { [IO.File]::WriteAllText($Report, $fixture.text.Text) }
            $fixture.form.Dispose()
        }
    }
}
