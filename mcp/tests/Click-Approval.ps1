# Independent UI Automation input driver. No forms, certificates or signing.
param([int]$TargetProcess, [long]$Handle, [long]$Started, [int]$At, [string]$Decision)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
if ($Decision -notin @('Sign once', 'Always for this project')) { throw 'Invalid test decision' }
$window = [Windows.Automation.AutomationElement]::FromHandle([IntPtr]$Handle)
if ($window.Current.ProcessId -ne $TargetProcess -or $window.Current.Name -cne 'TEST ONLY - nothing will be signed') {
    throw 'Refusing to interact with anything except the exact test window'
}
while (([Diagnostics.Stopwatch]::GetTimestamp() - $Started) * 1000 / [Diagnostics.Stopwatch]::Frequency -lt $At) {
    Start-Sleep -Milliseconds 5
}
$condition = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::NameProperty, $Decision)
$button = $window.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
if (-not $button) { throw 'Missing test button' }
# Native UIA provider delivery in another process exercises the actual button,
# including enabled/focus behavior, without altering the function's return value.
$button.SetFocus()
$invoke = $button.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)
$invoke.Invoke()
