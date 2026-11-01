// TEST ONLY. Disposable software identity and a loopback HTTP recorder.
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

public sealed class SigningNetworkProbe : IDisposable {
    readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
    readonly ConcurrentQueue<string> requests = new ConcurrentQueue<string>();
    readonly Task worker;
    CngKey key;
    public X509Certificate2 Certificate { get; private set; }
    public string[] Requests { get { return requests.ToArray(); } }
    public void Clear() { string value; while (requests.TryDequeue(out value)) {} }
    static byte[] Der(byte tag, params byte[][] values) {
        using (var bytes = new MemoryStream()) {
            foreach (var value in values) bytes.Write(value, 0, value.Length);
            var body = bytes.ToArray();
            if (body.Length > 127) throw new Exception("Test DER too long.");
            using (var result = new MemoryStream()) {
                result.WriteByte(tag); result.WriteByte((byte)body.Length);
                result.Write(body, 0, body.Length); return result.ToArray();
            }
        }
    }
    public SigningNetworkProbe() {
        listener.Start();
        worker = Task.Run(async () => {
            try {
                while (true) {
                    using (var client = await listener.AcceptTcpClientAsync())
                    using (var stream = client.GetStream()) {
                        client.ReceiveTimeout = 5000;
                        var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true);
                        var line = reader.ReadLine(); requests.Enqueue(line ?? "empty request");
                        while (!String.IsNullOrEmpty(reader.ReadLine())) {}
                        var reply = Encoding.ASCII.GetBytes("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        stream.Write(reply, 0, reply.Length);
                    }
                }
            } catch (SocketException) {} catch (ObjectDisposedException) {}
        });
        try {
            var parameters = new CngKeyCreationParameters {
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                KeyUsage = CngKeyUsages.Signing, ExportPolicy = CngExportPolicies.None
            };
            key = CngKey.Create(CngAlgorithm.Rsa, "sign-my-app-test-" + Guid.NewGuid().ToString("N"), parameters);
            using (var rsa = new RSACng(key))
            using (var issuerKey = RSA.Create()) {
                var issuerRequest = new CertificateRequest("CN=sign-my-app disposable issuer " + Guid.NewGuid().ToString("N"), issuerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
                using (var issuer = issuerRequest.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(2))) {
                    var request = new CertificateRequest("CN=sign-my-app disposable test " + Guid.NewGuid().ToString("N"), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    var usages = new OidCollection(); usages.Add(new Oid("1.3.6.1.5.5.7.3.3"));
                    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, false));
                    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
                    string url = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port + "/" + Guid.NewGuid().ToString("N");
                    // id-ad-caIssuers and a CRL distribution point, both test-only loopback URLs.
                    request.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.1", Der(0x30, Der(0x30,
                        new byte[] { 6, 8, 43, 6, 1, 5, 5, 7, 48, 2 }, Der(0x86, Encoding.ASCII.GetBytes(url + "/issuer")))), false));
                    request.CertificateExtensions.Add(new X509Extension("2.5.29.31", Der(0x30, Der(0x30, Der(0xa0, Der(0xa0,
                        Der(0x86, Encoding.ASCII.GetBytes(url + "/crl")))))), false));
                    using (var leaf = request.Create(issuer, DateTimeOffset.Now.AddMinutes(-5), DateTimeOffset.Now.AddDays(1), Guid.NewGuid().ToByteArray())) {
                        Certificate = leaf.CopyWithPrivateKey(rsa);
                    }
                }
            }
        } catch { Dispose(); throw; }
    }
    public void Dispose() {
        listener.Stop();
        if (Certificate != null) Certificate.Dispose();
        if (key != null) {
            // The exact-certificate cleanup normally already deleted this key.
            if (CngKey.Exists(key.KeyName, key.Provider)) key.Delete();
            key.Dispose(); key = null;
        }
        try { worker.Wait(6000); } catch (AggregateException) {}
    }
}
