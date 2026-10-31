// Windows SIPs calculate SHA-256 Authenticode content digests for PE and MSI.
// This excludes the fields legitimately changed by signing.
// https://learn.microsoft.com/en-us/windows/win32/api/mssip/nf-mssip-cryptsipcreateindirectdata
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace SignMyApp {
    public static class AuthenticodeDigest {
        // Windows PowerShell 5.1 coerces a null string argument to "" at a direct
        // File.Replace call. Keep the optional backup path genuinely null in C#.
        public static void Replace(string snapshot, string original) {
            File.Replace(snapshot, original, null);
        }
        [StructLayout(LayoutKind.Sequential)]
        struct Blob { public uint Size; public IntPtr Data; }
        [StructLayout(LayoutKind.Sequential)]
        struct Algorithm { public IntPtr Oid; public Blob Parameters; }
        [StructLayout(LayoutKind.Sequential)]
        struct Attribute { public IntPtr Oid; public Blob Value; }
        [StructLayout(LayoutKind.Sequential)]
        struct IndirectData { public Attribute Data; public Algorithm Algorithm; public Blob Digest; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct Subject {
            public uint Size;
            public IntPtr Type, File;
            [MarshalAs(UnmanagedType.LPWStr)] public string Name;
            public IntPtr DisplayName;
            public uint Reserved1, Version;
            public IntPtr Provider;
            public Algorithm Algorithm;
            public uint Flags, Encoding, Reserved2, CapiSettings, SecuritySettings, Index, UnionChoice;
            public IntPtr AdditionalInfo, ClientData;
        }
        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CryptSIPRetrieveSubjectGuid(string name, IntPtr file, out Guid type);
        [DllImport("crypt32.dll", SetLastError = true)]
        static extern bool CryptSIPCreateIndirectData(ref Subject subject, ref uint size, IntPtr data);
        [DllImport("crypt32.dll", SetLastError = true)]
        static extern bool CryptSIPVerifyIndirectData(ref Subject subject, IntPtr data);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CryptAcquireContext(out IntPtr provider, string container, string name, uint type, uint flags);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptReleaseContext(IntPtr provider, uint flags);
        [DllImport("crypt32.dll", SetLastError = true)]
        static extern bool CryptSIPGetSignedDataMsg(ref Subject subject, out uint encoding, uint index, ref uint size, byte[] data);
        [DllImport("crypt32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern bool CryptDecodeObjectEx(uint encoding, string type, byte[] encoded, uint length,
            uint flags, IntPtr parameters, IntPtr decoded, ref uint size);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DuplicateHandle(IntPtr sourceProcess, Microsoft.Win32.SafeHandles.SafeFileHandle source,
            IntPtr targetProcess, out IntPtr duplicate, uint access, bool inherit, uint options);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);

        static IntPtr DuplicateForSip(FileStream lockedFile) {
            IntPtr duplicate;
            IntPtr process = GetCurrentProcess();
            if (!DuplicateHandle(process, lockedFile.SafeFileHandle, process, out duplicate, 0, false, 2))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            // MSI's SIP consumes hFile and sets it to zero on completion. Keep the
            // original verification lock alive, and close only unconsumed duplicates.
            return duplicate;
        }

        static string ReadDigest(IntPtr buffer) {
            IndirectData data = (IndirectData)Marshal.PtrToStructure(buffer, typeof(IndirectData));
            if (data.Digest.Size != 32 || Marshal.PtrToStringAnsi(data.Algorithm.Oid) != "2.16.840.1.101.3.4.2.1")
                throw new IOException("Expected a SHA-256 Authenticode digest (size=" + data.Digest.Size + "; oid=" + Marshal.PtrToStringAnsi(data.Algorithm.Oid) + "; error=" + Marshal.GetLastWin32Error() + ").");
            byte[] digest = new byte[32];
            Marshal.Copy(data.Digest.Data, digest, 0, digest.Length);
            return BitConverter.ToString(digest).Replace("-", "");
        }

        // Verify signature mathematics and the signed digest, independently of root
        // trust. Test-Signature.ps1 separately checks public trust and timestamp.
        public static void Verify(string path, FileStream lockedFile, string thumbprint, string expectedDigest) {
            Guid type;
            lockedFile.Position = 0;
            if (!CryptSIPRetrieveSubjectGuid(path, lockedFile.SafeFileHandle.DangerousGetHandle(), out type))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot identify signed snapshot.");
            IntPtr guid = Marshal.AllocHGlobal(16);
            IntPtr buffer = IntPtr.Zero;
            IntPtr provider = IntPtr.Zero;
            Subject subject = new Subject();
            try {
                Marshal.StructureToPtr(type, guid, false);
                subject.Size = (uint)Marshal.SizeOf(typeof(Subject));
                subject.Type = guid;
                subject.Name = path;
                subject.File = DuplicateForSip(lockedFile);
                uint encoding, size = 0;
                if (!CryptSIPGetSignedDataMsg(ref subject, out encoding, 0, ref size, null))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Signed snapshot has no readable signature.");
                if (size == 0 || size > 16 * 1024 * 1024) throw new IOException("Invalid snapshot signature size.");
                byte[] message = new byte[size];
                if (!CryptSIPGetSignedDataMsg(ref subject, out encoding, 0, ref size, message))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read snapshot signature.");
                SignedCms cms = new SignedCms();
                cms.Decode(message);
                if (cms.ContentInfo.ContentType.Value != "1.3.6.1.4.1.311.2.1.4" || cms.SignerInfos.Count != 1 ||
                    cms.SignerInfos[0].Certificate == null ||
                    !String.Equals(cms.SignerInfos[0].Certificate.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
                    throw new CryptographicException("Signed snapshot has an unexpected publisher or content type. Original untouched.");
                try { cms.CheckSignature(true); }
                catch (CryptographicException error) {
                    throw new CryptographicException("Signed snapshot has an invalid cryptographic signature. Original untouched.", error);
                }
                byte[] content = cms.ContentInfo.Content;
                size = 0;
                if (!CryptDecodeObjectEx(0x10001, "1.3.6.1.4.1.311.2.1.4", content, (uint)content.Length, 0, IntPtr.Zero, IntPtr.Zero, ref size))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot size signed Authenticode digest.");
                if (size == 0 || size > 1024 * 1024) throw new IOException("Invalid signed digest size.");
                buffer = Marshal.AllocHGlobal((int)size);
                if (!CryptDecodeObjectEx(0x10001, "1.3.6.1.4.1.311.2.1.4", content, (uint)content.Length, 0, IntPtr.Zero, buffer, ref size))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot decode signed Authenticode digest.");
                if (ReadDigest(buffer) != expectedDigest)
                    throw new CryptographicException("Signature Authenticode digest does not match the approved bytes. Original untouched.");
                // Digest equality and CMS mathematics do not validate format-specific
                // signed metadata (including MSI's MsiDigitalSignatureEx stream).
                if (!CryptAcquireContext(out provider, null, "Microsoft Enhanced RSA and AES Cryptographic Provider", 24, 0xf0000000))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                subject.Provider = provider;
                subject.Encoding = 0x10001;
                subject.Algorithm = ((IndirectData)Marshal.PtrToStructure(buffer, typeof(IndirectData))).Algorithm;
                if (!CryptSIPVerifyIndirectData(ref subject, buffer))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows SIP integrity verification failed. Original untouched.");
            } finally {
                if (subject.File != IntPtr.Zero && subject.File != new IntPtr(-1)) CloseHandle(subject.File);
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                if (provider != IntPtr.Zero) CryptReleaseContext(provider, 0);
                Marshal.FreeHGlobal(guid);
            }
        }

        // Caller retains its verification handle. PE denies writes; MSI requires
        // writable sharing for structured storage. SIP gets a separate duplicate.
        public static string Compute(string path, FileStream lockedFile) {
            Guid type;
            lockedFile.Position = 0;
            if (!CryptSIPRetrieveSubjectGuid(path, lockedFile.SafeFileHandle.DangerousGetHandle(), out type))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot identify Authenticode file type.");
            IntPtr guid = Marshal.AllocHGlobal(16);
            IntPtr oid = Marshal.StringToHGlobalAnsi("2.16.840.1.101.3.4.2.1");
            IntPtr buffer = IntPtr.Zero;
            IntPtr provider = IntPtr.Zero;
            Subject subject = new Subject();
            try {
                // MSI's SIP needs an explicit SHA-256-capable provider. VERIFYCONTEXT
                // creates no key container and never accesses a signing private key.
                if (!CryptAcquireContext(out provider, null, "Microsoft Enhanced RSA and AES Cryptographic Provider", 24, 0xf0000000))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                Marshal.StructureToPtr(type, guid, false);
                subject.Size = (uint)Marshal.SizeOf(typeof(Subject));
                subject.Type = guid;
                subject.Name = path;
                subject.File = DuplicateForSip(lockedFile);
                subject.Algorithm.Oid = oid;
                subject.Provider = provider;
                subject.Encoding = 0x10001;
                uint size = 0;
                if (!CryptSIPCreateIndirectData(ref subject, ref size, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (size == 0 || size > 1024 * 1024) throw new IOException("Invalid Authenticode digest size.");
                buffer = Marshal.AllocHGlobal((int)size);
                if (!CryptSIPCreateIndirectData(ref subject, ref size, buffer))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot calculate Authenticode digest.");
                return ReadDigest(buffer);
            } finally {
                if (subject.File != IntPtr.Zero && subject.File != new IntPtr(-1)) CloseHandle(subject.File);
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                Marshal.FreeHGlobal(oid);
                Marshal.FreeHGlobal(guid);
                if (provider != IntPtr.Zero) CryptReleaseContext(provider, 0);
            }
        }
    }
}
