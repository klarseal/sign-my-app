#Requires -Version 5.1
# Managed relay: Node's startup SW_HIDE ends here, before the WinForms process.
# Fixed installed bridge only; no request data or project path becomes source.
$ErrorActionPreference = 'Stop'
$start = New-Object Diagnostics.ProcessStartInfo
$start.FileName = [IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\powershell.exe')
$start.Arguments = '-NoLogo -NoProfile -STA -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot 'bridge.ps1') + '"'
$start.WorkingDirectory = [Environment]::SystemDirectory
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.WindowStyle = 'Normal'
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$child = [Diagnostics.Process]::Start($start)
# Dedicated managed runspaces avoid a synchronous pipe read blocking the other
# direction. Every frame is flushed; approval remains on private anonymous pipes.
$relay = {
    param($Source, $Target, $CloseTarget)
    try {
        $buffer = New-Object byte[] 4096
        while (($count = $Source.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $Target.Write($buffer, 0, $count)
            $Target.Flush()
        }
    } catch [IO.IOException] { } catch [ObjectDisposedException] { }
    finally { if ($CloseTarget) { $Target.Close() } }
}
function Start-PrivateRelay($Source, $Target, $CloseTarget) {
    $pipeline = [PowerShell]::Create()
    $null = $pipeline.AddScript($relay.ToString()).AddArgument($Source).AddArgument($Target).AddArgument($CloseTarget)
    return @{ pipeline = $pipeline; task = $pipeline.BeginInvoke() }
}
$inputRelay = Start-PrivateRelay ([Console]::OpenStandardInput()) $child.StandardInput.BaseStream $true
$outputRelay = Start-PrivateRelay $child.StandardOutput.BaseStream ([Console]::OpenStandardOutput()) $false
$errorRelay = Start-PrivateRelay $child.StandardError.BaseStream ([Console]::OpenStandardError()) $false
$child.WaitForExit()
foreach ($forward in @($outputRelay, $errorRelay)) {
    $null = $forward.pipeline.EndInvoke($forward.task)
    if ($forward.pipeline.HadErrors) { [Environment]::Exit(1) }
    $forward.pipeline.Dispose()
}
# stdin may still be waiting for the parent on a Cancel/timeout. Exit the relay
# process without waiting on that read. The bridge has finished its own cleanup.
[Environment]::Exit($child.ExitCode)
