# Security regression tests

Run on Windows PowerShell 5.1, replacing the example installation prefix with the
absolute path of your reviewed skill copy:

Change the drive in the PowerShell path if Windows is installed elsewhere.

```powershell
& "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\Users\YOUR-USER\.agents\skills\sign-my-app\tests\Run-Tests.ps1"
```

The bypass affects only this run. No Pester or downloads are needed. The tests
compile a harmless argument recorder, EXE and DLL with the Windows .NET Framework
compiler and create a temporary Windows Installer database. They never install or
execute a test payload.

Each run creates a non-exportable, one-day certificate with the exact subject
`CN=sign-my-app disposable test <32 lowercase hex GUID characters>` in
`Cert:\CurrentUser\My`. Every offline signing call pins that new certificate's
exact `/sha1` thumbprint. Real publisher certificates are never selected. Setup
enumeration is mocked to return only the new certificate, including in child
processes. The tests add a disposable CA copy to reproduce Windows chain caching;
Windows signature queries can also cache copies there. Trust stores are therefore
not claimed to be untouched.

Cleanup enumerates CurrentUser **store names**, then looks up only the run's exact
thumbprint in every store, checks its complete subject and removes that copy.
It deletes the private key from My. It never adds a trusted root or changes another
certificate. A child deliberately throws immediately after creating its CA copy;
the parent confirms nonzero exit and absence of that exact thumbprint in My, CA,
Root and every other user store. Cleanup runs in `finally`, including on test
failure. The GUID-named temporary directory is also removed. A certificate-store
prompt must be left unanswered: stop and report it.

Production helpers have no test switches. Copied fixtures substitute discovery,
scripted prompt answers and timestamp handling. Signing is offline and selects
only the disposable certificate. File hashing, plan checking, snapshot creation,
content digest comparison, CMS verification, Windows SIP integrity verification
and atomic replacement use the production implementation.

| Coverage | Regression |
| --- | --- |
| Installed helper identity | Put a fake helper in an app repository, change both PowerShell and process current directories, then execute the generated absolute preview command. The fake helper never runs. Check the printed absolute approval command and installation-path reminder. |
| Relative app paths | Resolve against an explicit base despite hostile current directories; reject a relative path without a base. The preview uses its installed skill directory as its base. |
| Default execution policy | Start a child with every policy scope Undefined. All five absolute helpers run with per-run Bypass. Confirmation uses an invalid plan so it reaches validation without signing; signature verification reaches its expected untrusted-publisher failure. No saved policy is changed. |
| Certificate cleanup | Exercise the runner's actual injected-failure/finally path and inspect only its exact disposable thumbprint in every CurrentUser store. The normal run uses the same cleanup. |
| Filename controls | Reject every BMP Unicode control, format, line separator and paragraph separator by category, plus supplementary format text. Explicitly test U+009D and U+2028 before file access, URL handling and native execution. |
| PowerShell launcher | Poison WINDIR, SystemRoot and PATH; execute the generated launcher in default cmd from a project containing powershell.cmd. Only the Windows system-directory executable runs. Check every documented launcher and drive guidance. |
| Metadata display | Synthetic foreign and selected subjects contain newlines, ESC, spoofed thumbprint/agent-note lines and overlong text. Preview, confirmation, setup, verification and native output escape controls into one line and cap metadata at 512 characters. No foreign certificate or private key is created. |
| Release version | README install tag equals VERSION. |
| Existing publisher | Preview discloses a different publisher and thumbprint. Missing separate REPLACE consent prevents native work. Matching consent reaches only a harmless recorder, then the unchanged foreign signature is rejected and the original preserved. |
| SDK discovery | Reject overrides, renamed cmd.exe, poisoned PATH/ProgramFiles and copied SignTool beside junk DLL data. Use the Microsoft-signed machine SDK installation. Untrusted copies are never executed. |
| Approval and console | Refuse absent/changed plans and incorrect SIGN answers. A hidden normal console reaches a harmless recorder with fixture answers. Agent labels and process ancestry are not approval checks. |
| Snapshot integrity | A separate watcher swaps the snapshot before real offline signing. Digest comparison rejects it. Also reject a corrupt signature and preserve a concurrent build. Verify private ACLs and snapshot cleanup. |
| EXE and DLL | Compare approved and signed SHA-256 Authenticode digests, validate CMS mathematics, exact publisher and Windows SIP integrity, then atomically replace the original. Public trust remains separate. |
| MSI | Reject the generated 4096-byte-sector MSI when Windows SIP integrity fails. Plain SignTool reproduces HashMismatch before any helper digest call; the public verification helper rejects it too. Copy the logical entries into 512-byte compound storage and verify successful SIP integrity, the exact signer and only the expected untrusted-root failure from Windows policy verification. |

The old MSI assertion checked only `SignerCertificate.Thumbprint`. The generated
MSI already fails Windows verification immediately after plain offline SignTool
signing (`0x80096010`, HashMismatch). SHA-1 and x86 SignTool controls reproduced it
as well. The failure is isolated to the generated database's version-4 compound
storage with 4096-byte sectors on this PC: copying the same logical entries into
version-3 storage with 512-byte sectors passes Windows SIP integrity and fails
SignTool policy verification only for the untrusted root. The tests retain both
cases. This does not claim that every 4096-byte MSI fails on every Windows version.
CMS mathematics and content digest equality alone missed Windows' rejection of
the format's signed metadata. The helper now also requires the format-specific
`CryptSIPVerifyIndirectData` call on the untouched signed copy, **before** a digest
call can rewrite MSI metadata. No publicly trusted MSI release is claimed.
The MSI SIP still receives a disposable writable-sharing copy because
digest calculation can rewrite compound storage while the actual snapshot stays
locked. Snapshot hashes before/after verification remain pinned.

The suite also covers unsafe timestamp URLs, exact native argument boundaries,
preview-only behavior, publisher pinning, changed bytes/options, one-statement
commands, tag-pinned user-level installation, UNC/device/stream rejection,
restricted setup metadata, untrusted project text, untrusted publisher rejection
and HashMismatch after signed-byte tampering.

The runner explicitly exits **0 on pass, 1 on failure**, including cleanup failure.
Previously the intentional failing native SignTool verification left
`$LASTEXITCODE = 1` even after assertions passed. PowerShell retains a native
program's exit code until another native command or explicit script exit replaces
it; the runner now owns its result. No saved execution policy is changed.

No real issued certificate, SimplySign login, purchase, identity flow, token, live
timestamp service or public-trust success is exercised. Windows certificate
queries may contact certificate services. Scripted test answers do not prove
human presence: same-account scripts can pipe SIGN and REPLACE answers. Only
key-provider approval closes that gap. Agents must not run the final command or
type its confirmation for real signing. Keep SimplySign sessions open only while
signing and close them afterwards.

Authenticode excludes signature storage and some format fields. A second PE
WIN_CERTIFICATE, a PE checksum change or an MSI trailer after signing can pass
the content check. Same-account code can also modify helpers and interfere with
the final handoff. Private ACLs and locks are not a same-account boundary.

Validation on 2026-10-31 used Windows PowerShell 5.1. The full run exited 0;
the injected-failure child exited 1. Selected exact output:

```text
PASS: L1: hostile repository helper never runs from project current directory
PASS: L1: printed approval uses absolute installed path and tells person to check it
PASS: L2: injected failure exits nonzero and executes certificate cleanup
PASS: L2: failure removes exact disposable certificate from My, CA, Root and every other user store
PASS: L3: all five absolute helpers run with per-run Bypass from every policy scope Undefined
PASS: L6: U+0085 filename refused with rename advice
PASS: L6: U+009B filename refused with rename advice
PASS: L6: foreign signature replacement refused without separate consent
PASS: L6: MSI rejected when Windows SIP rejects its signed metadata
PASS: L6: 512-byte MSI passes Windows SIP integrity and exact disposable signer checks
PASS: L6: signed 512-byte MSI Windows verification fails only on untrusted root
PASS: L6: MSI metadata is verified before digest calculation can rewrite it
PASS: F1: default cmd in project cannot run planted powershell.cmd
PASS: F4: every BMP control/format/line/paragraph separator and supplementary format is refused and escaped
PASS: F4: U+009D refused before filesystem access
PASS: F4: U+2028 refused before filesystem access
PASS: F2: preview sanitises selected and foreign publisher without spoofed lines
PASS: F2: confirmation sanitises selected and foreign publisher before prompt; no signing reached
PASS: F2: native metadata output is escaped as one bounded line
PASS: F3: README install tag matches VERSION used by the release command
RESULT: 126 checks passed. No real company certificate used; no timestamp service contacted.
```
