# Runs inside the bridge. Approval is read only from its private parent pipe.
# There is no public approve/skip parameter and no saved approval file.
function Invoke-McpSigning($Request) {
    $mutex = New-Object Threading.Mutex($false, 'Local\Klarseal.SignMyApp.Signing')
    $held = $false
    try {
        try { $held = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw 'Another signing operation is active.' }
        $plans = @()
        $settings = @{}
        if ($Request.arguments.machine_store -eq $true) { $settings.MachineStore = $true }
        if ($Request.arguments.timestamp_url) { $settings.TimestampUrl = $Request.arguments.timestamp_url }
        foreach ($file in $Request.arguments.files) {
            $preview = @(& (Join-Path $scripts 'Invoke-Sign.ps1') -FilePath $file -Thumbprint $Request.arguments.thumbprint -PassThruPlan @settings 6>&1)
            $plan = @($preview | Where-Object { $_ -is [pscustomobject] -and $_.PlanHash })
            if ($plan.Count -ne 1) { throw 'Could not prepare signing plan.' }
            $plans += $plan[0]
        }
        [Console]::Out.WriteLine((@{ event = 'approval'; plans = $plans } | ConvertTo-Json -Depth 8 -Compress))
        $reply = [Console]::In.ReadLine() | ConvertFrom-Json
        if ($reply.timedOut -eq $true) { throw 'KLARSEAL_APPROVAL_TIMEOUT' }
        if (-not $reply -or $reply.path -notin @('elicitation','window') -or $reply.remaining -le 0 -or $reply.remaining -gt 300000) { throw 'Approval unavailable.' }
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $nativeApproved = $false
        if ($reply.path -eq 'window') {
            . (Join-Path $PSScriptRoot 'approval-window.ps1')
            $reportWindow = { param($event) [Console]::Out.WriteLine(($event | ConvertTo-Json -Depth 5 -Compress)) }
            try { $decision = Request-NativeSigningApproval $reply.message $reply.remaining $reportWindow }
            catch { throw 'KLARSEAL_APPROVAL_UNAVAILABLE' }
            if ($decision -eq 'Timeout') { throw 'KLARSEAL_APPROVAL_TIMEOUT' }
            if ($decision -notin @('Sign once','Always for this project')) { throw 'Native approval declined.' }
            [Console]::Out.WriteLine((@{ event = 'window_approved'; decision = $decision } | ConvertTo-Json -Compress))
            $recorded = [Console]::In.ReadLine() | ConvertFrom-Json
            if ($recorded.recorded -ne $true) { throw 'Approval unavailable.' }
            # The form captured an eligible pre-deadline click and the private
            # parent recorded it. Closing/relay latency cannot revoke that answer.
            $nativeApproved = $true
        } elseif ($reply.sign -cne 'Sign') { throw 'Signing declined.' }
        # Batch approval is consumed once per exact plan. Never request a second answer.
        $remainingPlans = New-Object 'Collections.Generic.HashSet[string]'
        foreach ($plan in $plans) { if (-not $remainingPlans.Add($plan.PlanHash)) { throw 'Repeated signing plan.' } }
        $approval = {
            param($hash)
            if ((-not $nativeApproved -and $watch.ElapsedMilliseconds -ge $reply.remaining) -or -not $remainingPlans.Remove($hash)) { throw 'Approval expired or already consumed.' }
            return "SIGN $hash"
        }.GetNewClosure()
        foreach ($plan in $plans) {
            $tool = & (Join-Path $scripts 'Find-SignTool.ps1')
            Assert-SigningApproval $plan.File $plan.SHA256 $plan.PlanHash $tool $plan.Thumbprint ([bool]$plan.MachineStore) $plan.TimestampUrl
            $reportSigning = { [Console]::Out.WriteLine('{"event":"signing_started"}') }
            $comparison = Invoke-ApprovedSigning -FilePath $plan.File -ExpectedSHA256 $plan.SHA256 -ApprovePlan $plan.PlanHash -Thumbprint $plan.Thumbprint -TimestampUrl $plan.TimestampUrl -MachineStore:$plan.MachineStore -RequestApproval $approval -OnSigningStarted $reportSigning
            [Console]::Out.WriteLine((@{ event = 'signed'; plan = $plan; contentComparison = $comparison.ContentComparison } | ConvertTo-Json -Depth 8 -Compress))
            & (Join-Path $scripts 'Test-Signature.ps1') -FilePath $plan.File -RequireTimestamp
            $signature = Get-AuthenticodeSignature -LiteralPath $plan.File
            if (-not $signature.TimeStamperCertificate) { throw 'Timestamp missing. Do not release.' }
            [pscustomobject]@{ File = $plan.File; Publisher = $signature.SignerCertificate.Subject;
                SHA256 = (Get-FileHash -LiteralPath $plan.File -Algorithm SHA256).Hash; ApprovedSHA256 = $plan.SHA256; TimestampUrl = $plan.TimestampUrl;
                Thumbprint = $signature.SignerCertificate.Thumbprint; TimestampSigner = $signature.TimeStamperCertificate.Subject;
                Verification = [string]$signature.Status; ContentComparison = $comparison.ContentComparison; TimestampEvidence = 'See verbose SignTool timestamp date above.' }
        }
    } finally { if ($held) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
}
