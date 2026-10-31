# Dot-sourced after Discovery-Signing-Tests.ps1; all prompt answers and discovery are fixtures.
foreach ($codepoint in @(0x0085, 0x009b)) {
    Assert-Throws { Assert-SafeSigningText ('control' + [char]$codepoint + '.exe') } ('L6: U+{0:X4} filename refused with rename advice' -f $codepoint) 'Rename'
}
$project = Join-Path $testRoot 'hostile-project'
New-Item -ItemType Directory -Path (Join-Path $project 'scripts') | Out-Null
$sentinel = Join-Path $project 'repo-helper-ran.txt'
('$null = New-Item -ItemType File -Path ' + (ConvertTo-SigningPSLiteral $sentinel)) |
    Set-Content -LiteralPath (Join-Path $project 'scripts/Invoke-Sign.ps1')
$previewCommand = (Get-SigningHelperCommand 'Invoke-Sign.ps1') + ' -FilePath ' +
    (ConvertTo-SigningPSLiteral $app) + ' -Thumbprint ' + (ConvertTo-SigningPSLiteral $thumb)
$expectedPrefix = '& "' + $ps + '" -NoProfile -ExecutionPolicy Bypass -File "' + $fixture + '\'
Assert-True ($previewCommand.StartsWith($expectedPrefix)) 'L1: helper command uses its own absolute installation path and per-run bypass'
$oldNativeDirectory = [Environment]::CurrentDirectory
Push-Location $project
try {
    [Environment]::CurrentDirectory = $project
    Assert-True ((Resolve-LocalSigningFile ([IO.Path]::GetFileName($app)) -BaseDirectory $testRoot).FullName -eq $app) 'L1: relative file resolves against explicit base despite hostile current directories'
    Assert-Throws { Resolve-LocalSigningFile ([IO.Path]::GetFileName($app)) } 'L1: relative file without explicit base is refused' 'explicit local drive base'
    $absolutePreview = @(Invoke-Expression $previewCommand)
    Assert-True ($LASTEXITCODE -eq 0 -and -not (Test-Path -LiteralPath $sentinel)) 'L1: hostile repository helper never runs from project current directory'
    $approvalCommand = @($absolutePreview | Where-Object { $_ -like '& *powershell.exe*Confirm-Sign.ps1*' })
    Assert-True ($approvalCommand.Count -eq 1 -and $approvalCommand[0].StartsWith($expectedPrefix) -and
        $absolutePreview -contains 'Check that the helper path starts where you installed the skill.') 'L1: printed approval uses absolute installed path and tells person to check it'
    $relativePreview = @(& "$fixture/Invoke-Sign.ps1" -FilePath ([IO.Path]::GetFileName($app)) -Thumbprint $thumb)
    Assert-True ($relativePreview -contains "File: $(ConvertTo-SigningDisplayText $app)") 'L1: preview resolves relative app path against skill directory'
} finally { [Environment]::CurrentDirectory = $oldNativeDirectory; Pop-Location }

# Existing foreign signature disclosure and a separate consent before native work.
$foreignFile = Join-Path $testRoot 'foreign-publisher.exe'
Copy-Item -LiteralPath $renamedCmd -Destination $foreignFile
$foreignSigner = (Get-AuthenticodeSignature -LiteralPath $foreignFile).SignerCertificate
Set-TestPlan $foreignFile 'record' $fakeTool
$foreignPreview = @(& "$fixture/Invoke-Sign.ps1" -FilePath $foreignFile -Thumbprint $thumb)
Assert-True (($foreignPreview -join "`n").Contains("another publisher's signature") -and
    ($foreignPreview -join "`n").Contains($foreignSigner.Thumbprint)) 'L6: preview discloses existing foreign publisher and thumbprint'
Assert-Throws { Invoke-TestApproval $foreignFile } 'L6: foreign signature replacement refused without separate consent' 'Replacement confirmation'
Assert-True (-not (Test-Path -LiteralPath $env:SIGN_MY_APP_TEST_LOG)) 'L6: missing replacement consent never reaches native tool'
$config.ReplaceAnswer = 'REPLACE ' + $foreignSigner.Thumbprint
$config | ConvertTo-Json | Set-Content -LiteralPath $configPath
Assert-Throws { Invoke-TestApproval $foreignFile } 'L6: replacement consent reaches recorder then rejects unchanged foreign signature' 'no readable signature|unexpected publisher'
Assert-True ((Test-Path -LiteralPath $env:SIGN_MY_APP_TEST_LOG) -and (Get-SigningHash $foreignFile) -eq $currentHash) 'L6: explicit replacement consent checked before native work; foreign original preserved'
Remove-Item -LiteralPath $env:SIGN_MY_APP_TEST_LOG
Set-TestPlan $app
Assert-True ($null -eq (Get-ReplacedSigningPublisher $app $thumb)) 'L6: same publisher does not require replacement consent'

# Start from Undefined in every scope, then exercise -File with per-run Bypass.
# Setup enumeration stays isolated to the new test certificate in the child too.
$setupPath = Join-Path $fixture 'Test-SigningSetup.ps1'
$setupSource = Get-Content -Raw -LiteralPath $setupPath
$setupSource = $setupSource.Replace('Get-ChildItem -Path $store -CodeSigningCert',
    ('Get-Item -LiteralPath ' + (ConvertTo-SigningPSLiteral ('Cert:\CurrentUser\My\' + $thumb))))
[IO.File]::WriteAllText($setupPath, $setupSource)
$policySource = @'
$ErrorActionPreference = 'Continue'
# -ExecutionPolicy Undefined alone retains an inherited process preference.
Remove-Item Env:\PSExecutionPolicyPreference -ErrorAction SilentlyContinue
if (@(Get-ExecutionPolicy -List | Where-Object { $_.ExecutionPolicy -ne 'Undefined' }).Count) { throw 'Policy fixture requires every scope Undefined.' }
if ((Get-ExecutionPolicy) -ne 'Restricted') { throw 'Expected default Windows client policy Restricted.' }
$fixture = __FIXTURE__
$app = __APP__
$thumb = __THUMB__
$hash = __HASH__
$plan = __PLAN__
$blocked = @(& ([IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\powershell.exe')) -NoProfile -File (Join-Path $fixture 'Find-SignTool.ps1') 2>&1)
if ($LASTEXITCODE -ne 1 -or ($blocked -join ' ') -notmatch 'PSSecurityException|UnauthorizedAccess') { throw 'Default policy did not block unsigned helper.' }
Write-Output 'POLICY BASELINE: every scope Undefined; effective Restricted blocks unsigned helper'
foreach ($name in @('Find-SignTool.ps1', 'Test-SigningSetup.ps1', 'Invoke-Sign.ps1', 'Confirm-Sign.ps1', 'Test-Signature.ps1')) {
    $extra = @()
    $expectedExit = 0
    if ($name -eq 'Invoke-Sign.ps1') { $extra = @('-FilePath', $app, '-Thumbprint', $thumb) }
    if ($name -eq 'Confirm-Sign.ps1') {
        $extra = @('-FilePath', $app, '-Thumbprint', $thumb, '-ExpectedSHA256', ('0' * 64), '-ApprovePlan', $plan)
        $expectedExit = 1
    }
    if ($name -eq 'Test-Signature.ps1') { $extra = @('-FilePath', $app); $expectedExit = 1 }
    $output = @(& ([IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\powershell.exe')) -NoProfile -ExecutionPolicy Bypass -File (Join-Path $fixture $name) @extra 2>&1)
    if ($LASTEXITCODE -ne $expectedExit) { throw ('Wrong helper exit for ' + $name + ': ' + ($output -join ' ')) }
    if ($name -eq 'Confirm-Sign.ps1' -and ($output -join ' ') -notmatch 'changed after preview') { throw 'Human helper blocked before plan validation.' }
    if ($name -eq 'Test-Signature.ps1' -and ($output -join ' ') -notmatch 'failed or warned') { throw 'Verification blocked before running.' }
    Write-Output ('POLICY PASS: ' + $name)
}
exit 0
'@
$policySource = $policySource.Replace('__FIXTURE__', (ConvertTo-SigningPSLiteral $fixture)).
    Replace('__APP__', (ConvertTo-SigningPSLiteral $app)).Replace('__THUMB__', (ConvertTo-SigningPSLiteral $thumb)).
    Replace('__HASH__', (ConvertTo-SigningPSLiteral $currentHash)).Replace('__PLAN__', (ConvertTo-SigningPSLiteral $currentPlan))
$policyOutput = @(& $ps -NoProfile -ExecutionPolicy Undefined -Command $policySource)
Assert-True ($LASTEXITCODE -eq 0 -and @($policyOutput | Where-Object { $_ -like 'POLICY PASS: *' }).Count -eq 5 -and
    $policyOutput -contains 'POLICY BASELINE: every scope Undefined; effective Restricted blocks unsigned helper') 'L3: all five absolute helpers run with per-run Bypass from every policy scope Undefined'

# Run the suite's real failure/finally path in a child, then inspect only its thumbprint.
$savedErrorPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $failureOutput = @(& $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Run-Tests.ps1') -FailAfterCertificateCopy 2>&1)
    $failureExit = $LASTEXITCODE
} finally { $ErrorActionPreference = $savedErrorPreference }
$failureText = $failureOutput -join "`n"
Assert-True ($failureExit -eq 1 -and $failureText -match 'Injected\s+failure\s+after\s+disposable\s+CA\s+copy') 'L2: injected failure exits nonzero and executes certificate cleanup'
if ($failureText -notmatch 'TEST CERTIFICATE: ([A-F0-9]{40}) Subject=(CN=sign-my-app disposable test [a-f0-9]{32})') { throw 'Missing failed child certificate identity.' }
$failedThumb = $Matches[1]
$remainingCopies = @(Get-ChildItem -LiteralPath Cert:\CurrentUser | Where-Object {
    Test-Path -LiteralPath ('Cert:\CurrentUser\' + $_.Name + '\' + $failedThumb)
})
Assert-True ($remainingCopies.Count -eq 0 -and $failureText -match 'removed from every user store') 'L2: failure removes exact disposable certificate from My, CA, Root and every other user store'
