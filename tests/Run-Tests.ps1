#Requires -Version 5.1
[CmdletBinding()]
param([switch]$FailAfterCertificateCopy, [switch]$NonDesktop)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$scripts = Join-Path $repo 'scripts'
. "$scripts/Signing-Safety.ps1"
. "$PSScriptRoot/Disposable-Certificate.ps1"
$testRoot = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ('sign-my-app-' + [guid]::NewGuid().ToString('N'))))
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$certificate = $null
$oldLog = $env:SIGN_MY_APP_TEST_LOG
$oldProgramFiles = $env:ProgramFiles
$oldProgramFilesX86 = ${env:ProgramFiles(x86)}
$oldPath = $env:PATH
$passed = 0
$suiteExitCode = 0
function Assert-True([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw "FAIL: $Name" }
    $script:passed++
    Write-Output "PASS: $Name"
}
function Assert-Throws([scriptblock]$Action, [string]$Name, [string]$Message = '.') {
    $caught = $null
    try { & $Action | Out-Null } catch { $caught = $_.Exception.Message }
    Assert-True ($null -ne $caught -and $caught -match $Message) "$Name$(if ($null -eq $caught -or $caught -notmatch $Message) { ": $caught" })"
}
try {
    if (-not $testRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test directory.' }
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $parseErrors = @()
    foreach ($scriptFile in (Get-ChildItem -LiteralPath $scripts -Filter '*.ps1')) {
        $tokens = $null; $errorsForFile = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptFile.FullName, [ref]$tokens, [ref]$errorsForFile) | Out-Null
        $parseErrors += $errorsForFile
    }
    Assert-True ($parseErrors.Count -eq 0) 'all helper scripts parse in Windows PowerShell 5.1'
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
    if (-not (Test-Path -LiteralPath $compiler)) { throw 'Tests need the Windows .NET Framework C# compiler.' }
    $stubSource = Join-Path $testRoot 'FakeTool.cs'
    $fakeTool = Join-Path $testRoot 'Fake SignTool.exe'
    'using System; using System.IO; class FakeTool { static int Main(string[] args) { File.WriteAllLines(Environment.GetEnvironmentVariable("SIGN_MY_APP_TEST_LOG"), args); return 0; } }' | Set-Content -LiteralPath $stubSource -Encoding UTF8
    & $compiler /nologo /target:exe "/out:$fakeTool" $stubSource
    if ($LASTEXITCODE -ne 0) { throw 'Argument recorder compilation failed.' }
    $env:SIGN_MY_APP_TEST_LOG = Join-Path $testRoot 'arguments.txt'
    $appSource = Join-Path $testRoot 'App.cs'
    $app = Join-Path $testRoot 'First app demo.exe'
    'class App { static void Main() { } }' | Set-Content -LiteralPath $appSource -Encoding UTF8
    & $compiler /nologo /target:exe "/out:$app" $appSource
    if ($LASTEXITCODE -ne 0) { throw 'Test executable compilation failed.' }
    $certificate = New-DisposableSigningCertificate
    $subject = $certificate.Subject
    $thumb = $certificate.Thumbprint
    Write-Output "TEST CERTIFICATE: $thumb Subject=$subject"
    # Reproduce chain building's cached CA copy without trusting the certificate.
    $caStore = New-Object Security.Cryptography.X509Certificates.X509Store('CA', 'CurrentUser')
    try { $caStore.Open('ReadWrite'); $caStore.Add($certificate) } finally { $caStore.Close() }
    if ($FailAfterCertificateCopy) { throw 'Injected failure after disposable CA copy.' }
    Assert-True ($thumb -match '^[A-F0-9]{40}$') 'throwaway certificate created; every signing test selects its thumbprint'
    # Mock only discovery in an isolated fixture, never add a production test bypass.
    $fixture = Join-Path $testRoot 'fixture'
    New-Item -ItemType Directory -Path $fixture | Out-Null
    Copy-Item -Path (Join-Path $scripts '*.ps1') -Destination $fixture
    Copy-Item -LiteralPath (Join-Path $scripts 'Unicode-Safety.json') -Destination $fixture
    ('param(); return ' + (ConvertTo-SigningPSLiteral $fakeTool)) | Set-Content -LiteralPath (Join-Path $fixture 'Find-SignTool.ps1') -Encoding UTF8
    $hashBefore = Get-SigningHash $app
    $preview = & "$fixture/Invoke-Sign.ps1" -FilePath $app -Thumbprint $thumb
    Assert-True (($preview -join "`n") -match '^DRY RUN:') 'preview leaves signing to the human'
    Assert-True (-not (Test-Path -LiteralPath $env:SIGN_MY_APP_TEST_LOG)) 'preview never starts even the harmless tool'
    Assert-True ((Get-SigningHash $app) -eq $hashBefore) 'preview leaves exact bytes unchanged'
    foreach ($url in @('http://t/a\" /f C:/evil.pfx /d \"b', 'https://time.certum.pl/a b', 'https://time.certum.pl/a"b', 'file:///time', 'http://localhost/', 'http://127.0.0.1/', 'http://169.254.169.254/', 'http://10.0.0.1/', 'http://private.local/', 'https://user:secret@time.certum.pl/')) {
        Assert-Throws { & "$fixture/Invoke-Sign.ps1" -FilePath $app -Thumbprint $thumb -TimestampUrl $url } 'H4: unsafe timestamp URL rejected' 'timestamp|HTTP|public'
    }
    $nativeArgs = @('sign', '/fd', 'SHA256', '/tr', 'https://time.certum.pl/rfc3161', '/td', 'SHA256', '/sha1', $thumb, $app)
    Invoke-SigningNative $fakeTool $nativeArgs
    $actual = @(Get-Content -LiteralPath $env:SIGN_MY_APP_TEST_LOG)
    Assert-True (($actual -join "`n") -ceq ($nativeArgs -join "`n")) 'H4: PS 5.1 marshalling preserves exact arguments and path with spaces'
    Remove-Item -LiteralPath $env:SIGN_MY_APP_TEST_LOG
    Assert-Throws { & "$scripts/Invoke-Sign.ps1" -FilePath $app -Thumbprint $thumb -Run } 'H5: -Run cannot sign under an agent' 'only previews'
    Assert-True (($preview -join "`n").Contains("'/sha1' '$thumb'")) 'H5: certificate always pinned; no automatic publisher selection'
    Assert-True (($preview -join "`n").Contains($subject)) 'H5: preview shows selected publisher'
    Assert-Throws { & "$fixture/Invoke-Sign.ps1" -FilePath $app } 'H5: missing publisher thumbprint refused' 'Thumbprint'
    $fields = @('1', $app, $hashBefore, $fakeTool, $thumb, 'False', 'http://time.certum.pl')
    $planHash = Get-SigningPlanHash $fields
    Assert-True (($preview -join "`n").Contains("Plan SHA-256: $planHash")) 'H6: preview hash binds exact bytes and signing options'
    [IO.File]::AppendAllText($app, 'changed')
    Assert-True ((Get-SigningHash $app) -ne $hashBefore) 'H6: changed bytes invalidate preview hash'
    $changedPreview = & "$fixture/Invoke-Sign.ps1" -FilePath $app -Thumbprint $thumb
    Assert-True (-not ($changedPreview -join "`n").Contains("Plan SHA-256: $planHash")) 'H6: changed file needs a different approval plan'
    $fields[6] = 'https://time.certum.pl'
    Assert-True ((Get-SigningPlanHash $fields) -ne $planHash) 'H6: timestamp change invalidates approval'
    Assert-Throws { Assert-SigningApproval $app $hashBefore $planHash $fakeTool $thumb $false 'http://time.certum.pl' } 'H6: execution refuses bytes changed after preview' 'changed after preview'
    Assert-Throws { Invoke-ApprovedSigning -FilePath $app -ExpectedSHA256 $hashBefore } 'R3: direct call without plan refused before native execution' 'approval plan'
    Assert-True (-not (Test-Path -LiteralPath $env:SIGN_MY_APP_TEST_LOG)) 'H6: unapproved bytes never reach the tool'
    foreach ($candidateName in @('$(HARMLESS).exe', ('x' + [char]0x2019 + ';Write-Output HARMLESS;' + [char]0x2019 + '.exe'), "line`n.exe", 'a&b.exe', ('rtl' + [char]0x202e + '.exe'), ('isolate' + [char]0x2067 + '.exe'), ('next-line' + [char]0x0085 + '.exe'), ('csi' + [char]0x009b + '.exe'))) {
        Assert-Throws { & "$fixture/Invoke-Sign.ps1" -FilePath (Join-Path $testRoot $candidateName) -Thumbprint $thumb } 'H7: shell/control filename refused with rename advice' 'Rename'
    }
    $command = $preview | Where-Object { $_ -like '& *powershell.exe*Confirm-Sign.ps1*' } | Select-Object -Last 1
    $tokens = $null; $errorsForCommand = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($command, [ref]$tokens, [ref]$errorsForCommand)
    Assert-True ($errorsForCommand.Count -eq 0 -and $ast.EndBlock.Statements.Count -eq 1) 'H7: printed command parses as exactly one PowerShell statement'
    $readme = Get-Content -Raw -LiteralPath "$repo/README.md"
    $installGuide = Get-Content -Raw -LiteralPath "$repo/mcp/INSTALL-FOR-AGENTS.md"
    Assert-True ($readme.Contains('mcp/INSTALL-FOR-AGENTS.md') -and $installGuide.Contains('.claude\skills\sign-my-app') -and $installGuide.Contains('.agents\skills\sign-my-app')) 'H8: user-level installations for Claude and Codex'
    $releaseVersion = (Get-Content -Raw -LiteralPath (Join-Path $repo 'VERSION')).Trim()
    Assert-True ($installGuide.Contains("--branch '$releaseVersion' --depth 1") -and $installGuide.Contains('verify it is inside that') -and $installGuide.Contains('remove only that `.git` directory')) 'H8: tag-pinned clone and copied git metadata removed'
    foreach ($path in @('\\nonexistent.invalid\share\app.exe', '//nonexistent.invalid/share/app.exe', '\\?\C:\app.exe', '\\.\C:\app.exe', 'C:\app.exe:stream')) {
        Assert-Throws { & "$fixture/Invoke-Sign.ps1" -FilePath $path -Thumbprint $thumb } 'H9: UNC/device/stream refused before access' 'local drive|UNC'
    }
    function Get-ChildItem {
        param([string]$Path, [switch]$CodeSigningCert)
        if ($Path -in @('Cert:\CurrentUser\My','Cert:\LocalMachine\My') -and $CodeSigningCert) { return $certificate }
        throw 'Setup must request only code signing certificates.'
    }
    try {
        $setup = @(& "$fixture/Test-SigningSetup.ps1")
        $machineSetup = @(& "$fixture/Test-SigningSetup.ps1" -MachineStore)
    }
    finally { Remove-Item Function:\Get-ChildItem }
    $metadata = @($setup | Where-Object { $_ -isnot [string] })
    Assert-True ($metadata.Count -eq 1 -and ($metadata[0].PSObject.Properties.Name -join ',') -eq 'Subject,Thumbprint') 'M11: setup returns code signing subject and thumbprint only'
    $machineMetadata = @($machineSetup | Where-Object { $_ -isnot [string] })
    Assert-True ($machineMetadata.Count -eq 1 -and ($machineMetadata[0].PSObject.Properties.Name -join ',') -eq 'Subject,Thumbprint') 'M11: machine-store setup also filters code signing metadata'
    Assert-True (-not (Get-Content -Raw "$scripts/Test-SigningSetup.ps1").Contains('certutil')) 'M11: no unfiltered Personal-store dump'
    foreach ($doc in @('references/workflow.md','SKILL.md','AGENTS.md')) {
        $text = Get-Content -Raw -LiteralPath (Join-Path $repo $doc)
        Assert-True ($text -match 'untrusted data' -and $text -match 'never instructions') "M12: $doc treats project/certificate text as data"
    }
    Assert-Throws { & "$scripts/Find-SignTool.ps1" -Path $fakeTool } 'R2: explicit discovery path removed' 'parameter'
    Assert-Throws { & "$scripts/Invoke-Sign.ps1" -FilePath $app -Thumbprint $thumb -SignToolPath $fakeTool } 'R2: preview tool override removed' 'parameter'
    Assert-Throws { & "$scripts/Confirm-Sign.ps1" -FilePath $app -Thumbprint $thumb -ExpectedSHA256 $hashBefore -ApprovePlan $planHash -SignToolPath $fakeTool } 'R2: confirmation tool override removed' 'parameter'
    $tool = & "$scripts/Find-SignTool.ps1"
    Assert-True ([IO.Path]::IsPathRooted($tool)) 'real Microsoft-signed SDK SignTool found'
    if ($NonDesktop) {
        Write-Output 'SKIP: SecondRound visible Console section (4 checks; NonDesktop)'
        . "$PSScriptRoot/SecondRound-Tests.ps1" -Only NonDesktop
    }
    else { . "$PSScriptRoot/SecondRound-Tests.ps1" }
    $passed += $srPassed
    . "$PSScriptRoot/ConPTY-Tests.ps1"
    $passed += $ptyPassed
    . "$PSScriptRoot/Session-Tests.ps1"
    . "$PSScriptRoot/SecurityReview-Tests.ps1"
    . "$PSScriptRoot/ReReview-Tests.ps1"
    . "$PSScriptRoot/LastReview-Tests.ps1"
    . "$PSScriptRoot/FinalFour-Tests.ps1"
    $layoutChecks = @(& "$PSScriptRoot/Content-Layouts.ps1")
    $layoutChecks | Write-Output
    $passed += $layoutChecks.Count
    . "$PSScriptRoot/ThirdRound-Tests.ps1"
    $signature = Get-AuthenticodeSignature -LiteralPath $app
    Assert-True ($signature.SignerCertificate.Thumbprint -eq $thumb) 'embedded signer is exactly throwaway certificate'
    Assert-True ($null -eq $signature.TimeStamperCertificate) 'offline test has no timestamp as expected'
    Assert-Throws { & "$scripts/Test-Signature.ps1" -FilePath $app 2>&1 } 'verification rejects untrusted disposable publisher' 'failed|warned|root|trust'
    $bytes = [IO.File]::ReadAllBytes($app); $bytes[0x200] = $bytes[0x200] -bxor 1; [IO.File]::WriteAllBytes($app, $bytes)
    Assert-True ((Get-AuthenticodeSignature -LiteralPath $app).Status -eq 'HashMismatch') 'changing signed bytes detected as HashMismatch'
} catch {
    $suiteExitCode = 1
    Write-Output $_.ScriptStackTrace
    Write-Error $_ -ErrorAction Continue
} finally {
    try { Remove-DisposableSigningCertificate $certificate }
    catch { $suiteExitCode = 1; Write-Error $_ -ErrorAction Continue }
    $env:SIGN_MY_APP_TEST_LOG = $oldLog
    $env:ProgramFiles = $oldProgramFiles
    ${env:ProgramFiles(x86)} = $oldProgramFilesX86
    $env:PATH = $oldPath
    $cleanupPath = [IO.Path]::GetFullPath($testRoot)
    if (-not $cleanupPath.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($cleanupPath) -notmatch '^sign-my-app-[a-f0-9]{32}$') { throw 'Unsafe cleanup path.' }
    if (Test-Path -LiteralPath $cleanupPath) { Remove-Item -LiteralPath $cleanupPath -Recurse -Force }
    Write-Output 'CLEANUP: temporary files removed.'
}
# Native negative tests deliberately leave LASTEXITCODE=1. Own the suite's result.
if ($suiteExitCode -eq 0) { Write-Output "RESULT: $passed checks passed. No real company certificate used; no timestamp service contacted." }
exit $suiteExitCode
