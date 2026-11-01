# Dot-sourced with this suite's exact disposable certificate. No real provider.
$sessionFixture = Join-Path $testRoot 'session-fixture'
New-Item -ItemType Directory -Path $sessionFixture | Out-Null
Copy-Item -Path (Join-Path $scripts '*') -Destination $sessionFixture
$sessionTool = Join-Path $sessionFixture 'FakeProvider.exe'
$sessionSource = Join-Path $sessionFixture 'FakeProvider.cs'
@'
using System;
using System.IO;
using System.Threading;
class FakeProvider {
    static int Main(string[] args) {
        string mode = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "mode.txt"));
        File.WriteAllText(args[args.Length - 1], "partial snapshot write");
        if (mode == "wait") { Thread.Sleep(120000); return 0; }
        Console.Error.WriteLine("SignTool Error: " + mode);
        return 1;
    }
}
'@ | Set-Content -LiteralPath $sessionSource
& $compiler /nologo /target:exe ('/out:' + $sessionTool) $sessionSource
if ($LASTEXITCODE -ne 0) { throw 'Fake provider compilation failed.' }
('param(); return ' + (ConvertTo-SigningPSLiteral $sessionTool)) | Set-Content -LiteralPath (Join-Path $sessionFixture 'Find-SignTool.ps1')
& {
    . (Join-Path $sessionFixture 'Signing-Safety.ps1')
    # All classifier cases, and an actual failed process for each. The only key
    # lookup is the exact disposable identity selected by Run-Tests.ps1.
    $codes = @('8009000D','80090013','80090016','80090017','80090019','8009001D','8009001E','80090022','8009002E','80090030',
        '8010000C','80100017','8010001D','8010001E','8010002E','80100030','80100069','8010006E','8010006F')
    $sessionHash = Get-SigningHash $app
    $sessionPlan = Get-SigningPlanHash @('1', $app, $sessionHash, $sessionTool, $thumb, 'False', 'http://time.certum.pl')
    # Synthetic person answer is confined to this fake provider fixture. It
    # cannot reach real SignTool. Production console checks are tested separately.
    $approval = { param($hash); "SIGN $hash" }
    function Assert-SigningTimestamp {}
    foreach ($code in $codes) {
        [IO.File]::WriteAllText((Join-Path $sessionFixture 'mode.txt'), ('0x' + $code))
        Assert-Throws { Invoke-ApprovedSigning -FilePath $app -ExpectedSHA256 $sessionHash -ApprovePlan $sessionPlan -Thumbprint $thumb -RequestApproval $approval } ('session code 0x' + $code) ('KLARSEAL_SESSION_REQUIRED: 0x' + $code)
        Assert-True ((Get-SigningHash $app) -eq $sessionHash -and @(Get-ChildItem -LiteralPath $testRoot -Filter 'sign-my-app-approved-*').Count -eq 0) ('session code 0x' + $code + ' preserves original and discards partial snapshot')
    }
    foreach ($message in @('Keyset does not exist', 'The keyset is not defined', 'Key does not exist',
        'Invalid provider specified', 'Provider type not defined', 'Provider DLL failed to initialize correctly',
        'Provider DLL could not be found', 'No smart card inserted', 'The smart card has been removed',
        'The requested key container does not exist on the smart card', 'No smart card readers are available',
        'The device that is required by this cryptographic provider is not ready for use',
        'This operation requires input from the user', 'Provider could not perform the action since the context was acquired as silent',
        'The user has not authenticated to the smart card', 'token not present', 'token is not logged in', 'token expired', 'session has expired')) {
        Assert-True ([bool](Get-SigningSessionFailure $message)) ('session message: ' + $message)
    }
    foreach ($message in @('0x80096010', '0x800B0109', '0x800900160', 'No certificates were found that met all the given criteria', 'The timestamp server could not be reached', 'session settings saved')) {
        Assert-True (-not (Get-SigningSessionFailure $message)) ('unrelated failure remains distinct: ' + $message)
    }
    [IO.File]::WriteAllText((Join-Path $sessionFixture 'mode.txt'), 'wait')
    $sessionWatch = [Diagnostics.Stopwatch]::StartNew()
    Assert-Throws { Invoke-ApprovedSigning -FilePath $app -ExpectedSHA256 $sessionHash -ApprovePlan $sessionPlan -Thumbprint $thumb -RequestApproval $approval } 'provider wait returns session-required at the production deadline' 'KLARSEAL_SESSION_REQUIRED: provider-wait-timeout'
    Assert-True ($sessionWatch.Elapsed.TotalSeconds -ge 60 -and $sessionWatch.Elapsed.TotalSeconds -lt 75) 'production provider wait is bounded at 60 seconds plus process cleanup'
    Assert-True ((Get-SigningHash $app) -eq $sessionHash -and @(Get-ChildItem -LiteralPath $testRoot -Filter 'sign-my-app-approved-*').Count -eq 0) 'provider timeout preserves original and discards partial snapshot'
    Assert-True (@(Get-Process -Name FakeProvider -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $sessionTool }).Count -eq 0) 'timed-out fake provider has exited'
}
