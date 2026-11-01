# Test-only software key. Avoid certificate enrollment's CIM service and any
# installed token/provider discovery. Never request or export a real key.
function New-DisposableSigningCertificate {
    $subject = 'CN=sign-my-app disposable test ' + [guid]::NewGuid().ToString('N')
    $parameters = New-Object Security.Cryptography.CngKeyCreationParameters
    $parameters.Provider = New-Object Security.Cryptography.CngProvider('Microsoft Software Key Storage Provider')
    $parameters.KeyUsage = [Security.Cryptography.CngKeyUsages]::Signing
    $parameters.ExportPolicy = [Security.Cryptography.CngExportPolicies]::None
    $key = $null; $rsa = $null; $certificate = $null; $added = $false
    try {
        $key = [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa,
            ('sign-my-app-test-' + [guid]::NewGuid().ToString('N')), $parameters)
        $rsa = New-Object Security.Cryptography.RSACng($key)
        $request = New-Object Security.Cryptography.X509Certificates.CertificateRequest(
            $subject, $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $usages = New-Object Security.Cryptography.OidCollection
        $null = $usages.Add((New-Object Security.Cryptography.Oid('1.3.6.1.5.5.7.3.3')))
        $request.CertificateExtensions.Add((New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($usages, $false)))
        $request.CertificateExtensions.Add((New-Object Security.Cryptography.X509Certificates.X509KeyUsageExtension([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true)))
        $certificate = $request.CreateSelfSigned([DateTimeOffset]::Now.AddMinutes(-5), [DateTimeOffset]::Now.AddDays(1))
        $store = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
        try { $store.Open('ReadWrite'); $store.Add($certificate); $added = $true } finally { $store.Close() }
        return $certificate
    } finally {
        if ($rsa) { $rsa.Dispose() }
        if (-not $added -and $key) { $key.Delete() }
        if ($key) { $key.Dispose() }
    }
}

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
            if ($copy.Issuer -cne $copy.Subject -and $copy.Issuer -cnotmatch '^CN=sign-my-app disposable issuer [a-f0-9]{32}$') {
                throw 'Refusing cleanup of a certificate not issued by itself or the disposable test issuer.'
            }
            if ($store.Name -eq 'My') { Remove-Item -LiteralPath $path -DeleteKey -ErrorAction Stop }
            else { Remove-Item -LiteralPath $path -ErrorAction Stop }
            if (Test-Path -LiteralPath $path) { throw 'Disposable certificate remains.' }
        } catch { $failures += $_ }
    }
    if ($failures.Count) { throw ($failures -join "`n") }
    Write-Output "CLEANUP: disposable certificate $($Certificate.Thumbprint) removed from every user store, including its private key."
}
