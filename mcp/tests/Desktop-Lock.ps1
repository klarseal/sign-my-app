# Test-only session-wide locks, shared across worktrees and direct invocations.
# Managed WaitOne/abandonment recovery never creates a window.
param([switch]$Lease)
function Enter-DesktopTestLock([string]$Kind = 'Windows') {
    $mutex = New-Object Threading.Mutex($false, ('Local\Klarseal.ApprovalTests.' + $Kind))
    try { try { $null = $mutex.WaitOne() } catch [Threading.AbandonedMutexException] {} }
    catch { $mutex.Dispose(); throw }
    return $mutex
}
function Exit-DesktopTestLock($Mutex) {
    try { $Mutex.ReleaseMutex() } finally { $Mutex.Dispose() }
}
function Invoke-WithDesktopTestLock([scriptblock]$Action) {
    $mutex = Enter-DesktopTestLock
    try { & $Action } finally { Exit-DesktopTestLock $mutex }
}
if ($Lease) {
    $mutex = Enter-DesktopTestLock 'Commands'
    try {
        [Console]::Out.WriteLine('LOCKED'); [Console]::Out.Flush()
        $null = [Console]::In.ReadLine()
    } finally { Exit-DesktopTestLock $mutex }
}
