#Requires -Version 5.1
# Fixed dispatch only. Data arrives as JSON on stdin, never as PowerShell source.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$expectedPowerShell = [IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\powershell.exe')
if ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName -ine $expectedPowerShell) { exit 1 }
$repo = Split-Path -Parent $PSScriptRoot
$scripts = Join-Path $repo 'scripts'
. (Join-Path $scripts 'Signing-Safety.ps1')
$lines = New-Object 'Collections.Generic.List[object]'
$size = 0
$failed = $false
$sessionRequired = $false
$sessionReason = $null
$approvalUnavailable = $false
$approvalTimedOut = $false
$script:signingAttempted = $false
try {
    # One bounded JSON line. Signing keeps stdin open for the approval relay.
    $inputText = [Console]::In.ReadLine()
    if ($inputText.Length -gt 65536) { throw 'Input limit.' }
    $request = $inputText | ConvertFrom-Json
    $arguments = @{}
    if ($request.arguments.machine_store -eq $true) { $arguments.MachineStore = $true }
    & {
        switch -CaseSensitive ($request.name) {
            'check_signing_setup' { & (Join-Path $scripts 'Test-SigningSetup.ps1') @arguments }
            'find_built_files' { & (Join-Path $scripts 'Find-BuiltFiles.ps1') -ProjectFolder $request.arguments.project_folder }
            'prepare_signing' {
                if ($request.arguments.timestamp_url) { $arguments.TimestampUrl = $request.arguments.timestamp_url }
                foreach ($file in $request.arguments.files) {
                    & (Join-Path $scripts 'Invoke-Sign.ps1') -FilePath $file -Thumbprint $request.arguments.thumbprint @arguments
                }
            }
            'sign_files' {
                . (Join-Path $PSScriptRoot 'sign-operation.ps1')
                Invoke-McpSigning $request
            }
            'verify_signature' { & (Join-Path $scripts 'Test-Signature.ps1') -FilePath $request.arguments.file }
            default { throw 'Unknown operation.' }
        }
    } 6>&1 | ForEach-Object {
        $entry = if ($_ -is [Management.Automation.InformationRecord]) { [string]$_.MessageData } else { $_ }
        $size += ($entry | ConvertTo-Json -Compress -Depth 6).Length
        if ($size -gt 196608) { throw 'Output limit.' }
        $lines.Add($entry)
    }
} catch {
    # Never serialize exceptions: they can echo supplied paths, URLs or process details.
    $failed = $true
    if ($request.name -eq 'sign_files') {
        # Classify known failures into fixed text; never echo an exception that
        # could contain untrusted input or provider details.
        $reason = switch -Regex ($_.Exception.Message) {
            '^KLARSEAL_APPROVAL_TIMEOUT$' { $approvalTimedOut = $true; 'The Sign window got no answer, so nothing was signed. Ask me to try again when you''re ready.'; break }
            '^KLARSEAL_SESSION_REQUIRED: (.+)$' { $sessionRequired = $true; $sessionReason = $Matches[1]; 'The certificate session looks closed. Please log in to SimplySign Desktop, then ask to sign again.'; break }
            'file or signing plan changed|file changed after preview|original file changed' { 'The file or signing plan changed. Review it and approve a fresh plan.'; break }
            'KLARSEAL_APPROVAL_UNAVAILABLE' { $approvalUnavailable = $true; "I couldn't show you the approval here."; break }
            'Approval expired|Approval unavailable' { 'Approval expired or was unavailable. Signing refused.'; break }
            'Signing declined|Native approval declined' { 'Signing was declined or cancelled.'; break }
            'Another signing operation' { 'Another signing operation is active. Wait for it to finish.'; break }
            'another publisher|other publishers' { 'This file has another publisher. MCP will not replace that signature.'; break }
            default { 'Signing checks or verification could not complete.' }
        }
        $lines.Add($reason)
        if ($approvalTimedOut) {
            # No signing step ran. A missed window is not a person's refusal.
        } elseif ($approvalUnavailable) {
            $lines.Add('Tell the person that approval could not be shown. Ask them to open an interactive Windows desktop and request signing again there. Do not retry automatically.')
        } elseif ($sessionRequired) {
            $lines.Add('Tell the person the certificate session looks closed: log in to SimplySign Desktop privately, then ask to sign again. The current file was left unchanged. Do not retry automatically.')
        } elseif ($script:signingAttempted) {
            $lines.Add('Signing or verification refused. No automatic retry. Inspect the file before retrying. If SimplySign has expired, please sign in privately in SimplySign Desktop and tell the assistant when you are back. Keep your code private.')
        }
    }
}
@{ failed = $failed; sessionRequired = $sessionRequired; sessionReason = $sessionReason; approvalUnavailable = $approvalUnavailable; approvalTimedOut = $approvalTimedOut; signingAttempted = $script:signingAttempted; output = @($lines.ToArray()) } | ConvertTo-Json -Compress -Depth 8
