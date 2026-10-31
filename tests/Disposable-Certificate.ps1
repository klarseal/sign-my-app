# Test-only cleanup: exact newly created thumbprint and subject, in every user store.
function Remove-DisposableSigningCertificate($Certificate) {
    if (-not $Certificate) { return }
    if ($Certificate.Subject -cnotmatch '^CN=sign-my-app disposable test [a-f0-9]{32}$') {
        throw 'Refusing cleanup of a certificate outside the disposable test subject.'
    }
    $failures = @()
    foreach ($store in (Get-ChildItem -LiteralPath Cert:\CurrentUser)) {
        $path = 'Cert:\CurrentUser\' + $store.Name + '\' + $Certificate.Thumbprint
        try {
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $copy = Get-Item -LiteralPath $path
            if ($copy.Subject -cne $Certificate.Subject) { throw 'Certificate subject changed; cleanup stopped for this store.' }
            if ($store.Name -eq 'My') { Remove-Item -LiteralPath $path -DeleteKey -ErrorAction Stop }
            else { Remove-Item -LiteralPath $path -ErrorAction Stop }
            if (Test-Path -LiteralPath $path) { throw 'Disposable certificate remains.' }
        } catch { $failures += $_ }
    }
    if ($failures.Count) { throw ($failures -join "`n") }
    Write-Output "CLEANUP: disposable certificate $($Certificate.Thumbprint) removed from every user store, including its private key."
}
