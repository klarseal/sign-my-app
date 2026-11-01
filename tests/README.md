# Security regression tests

Run on Windows PowerShell 5.1, replacing the example installation prefix with the
absolute path of your reviewed copy:

Change the drive in the PowerShell path if Windows is installed elsewhere.

```powershell
& "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\Users\YOUR-USER\.agents\skills\sign-my-app\tests\Run-Tests.ps1" -NonDesktop
```

`-NonDesktop` shows no window. It skips the few checks that briefly show a
classic console window (in `SecondRound-Tests.ps1`, `SecurityReview-Tests.ps1`
and `ReReview-Tests.ps1`); leave it off to include them, on a desktop you aren't
using. Hidden console and ConPTY checks always run.

The bypass affects only this run. No Pester or downloads are needed. The tests
compile a harmless argument recorder, EXE and DLL with the Windows .NET Framework
compiler and create a temporary Windows Installer database. They never install or
execute a test payload. Shipped helpers compile nothing; only the tests do.

Each run creates a non-exportable, one-day, self-signed certificate with the exact
subject `CN=sign-my-app disposable test <32 lowercase hex GUID characters>` in
`Cert:\CurrentUser\My`, using .NET's CertificateRequest and the Microsoft Software
Key Storage Provider (.NET Framework 4.7.2 or later). Every offline signing call
pins that new certificate's exact `/sha1` thumbprint. Real publisher certificates
are never selected. Setup enumeration is mocked to return only the new
certificate, including in child processes. The tests add a disposable CA copy to
reproduce Windows chain caching; Windows signature queries can also cache copies
there. Trust stores are therefore not claimed to be untouched.

Cleanup enumerates CurrentUser **store names**, then looks up only the run's exact
thumbprint in every store, checks its complete subject and that it was issued by
itself or the suite's disposable test issuer, and removes that copy. It deletes the private key from My. It never adds a trusted
root or changes another certificate. A child deliberately throws immediately after
creating its CA copy; the parent confirms nonzero exit and absence of that exact
thumbprint in My, CA, Root and every other user store. Cleanup runs in `finally`,
including on test failure. The GUID-named temporary directory is also removed.
A certificate-store prompt must be left unanswered: stop and report it.

Production helpers have no test switches. Copied fixtures substitute discovery,
scripted prompt answers and timestamp handling. Signing is offline and selects
only the disposable certificate. File hashing, plan checking, snapshot creation,
content digest comparison, CMS verification and atomic replacement use the
production implementation. Parsed PE snapshots are checked with managed hashing
and CMS mathematics before replacement; this is not Windows SIP verification.
MSI and unsupported PE layouts use Windows Authenticode verification with the
exact publisher before replacement. Final SignTool policy verification follows.

| Coverage | Regression |
| --- | --- |
| Installed helper identity | Put a fake helper in an app repository, change both PowerShell and process current directories, then execute the generated absolute preview command. The fake helper never runs. Check the printed absolute approval command and installation-path reminder. |
| Relative app paths | Resolve against an explicit base despite hostile current directories; reject a relative path without a base. The preview uses its installed skill directory as its base. |
| Default execution policy | Start a child with every policy scope Undefined. All five absolute helpers run with per-run Bypass. Confirmation uses an invalid plan so it reaches validation without signing; signature verification reaches its expected untrusted-publisher failure. No saved policy is changed. |
| Certificate cleanup | Exercise the runner's actual injected-failure/finally path and inspect only its exact disposable thumbprint in every CurrentUser store. The normal run uses the same cleanup. |
| Filename controls | Reject every BMP Unicode control, format, line separator and paragraph separator by category, plus supplementary format text. Explicitly test U+009D and U+2028 before file access, URL handling and native execution. |
| PowerShell launcher | Poison WINDIR, SystemRoot and PATH; execute the generated launcher in default cmd from a project containing powershell.cmd. Only the Windows system-directory executable runs. Check every documented launcher and drive guidance. |
| Metadata display | Synthetic foreign and selected subjects contain newlines, ESC, spoofed thumbprint/agent-note lines and overlong text. Preview, confirmation, setup, verification and native output escape controls into one line and cap metadata at 512 characters. No foreign certificate or private key is created. |
| Release version | Install guide tag equals VERSION. |
| Existing publisher | Preview discloses a different publisher and thumbprint. Missing separate REPLACE consent prevents native work. Matching consent reaches only a harmless recorder, then the unchanged foreign signature is rejected and the original preserved. |
| SDK discovery | Reject overrides, renamed cmd.exe, poisoned PATH/ProgramFiles and copied SignTool beside junk DLL data. Use the Microsoft-signed machine SDK installation. Untrusted copies are never executed. |
| Approval and console | Refuse absent/changed plans and incorrect SIGN answers. A real CreatePseudoConsole session displays the production prompt, accepts the correct plan answer and rejects a wrong one. Absent consoles, redirected input/output and -NonInteractive are refused. Hidden classic windows are accepted because managed APIs cannot check visibility. Refusal text remains visible even with stderr suppressed. Agent labels and process ancestry are not approval checks. |
| Snapshot integrity | A separate watcher swaps the snapshot before real offline signing. Digest comparison rejects it. Also reject a corrupt signature and preserve a concurrent build. Verify private ACLs and snapshot cleanup. |
| EXE and DLL | For supported layouts, compare approved and signed SHA-256 Authenticode digests, CMS mathematics and exact publisher before atomic replacement. This managed PE check does not call Windows SIP. Unsupported layouts report `content-comparison: not possible` and require Windows integrity and the exact publisher. Public trust remains separate. |
| MSI | Reject a generated 4096-byte-sector MSI when Windows SIP integrity fails. Copy the logical entries into 512-byte compound storage and verify successful SIP integrity, the exact signer and only the expected untrusted-root failure from Windows policy verification. |
| Closed sessions | Each recognised session error fails after the private snapshot is written; the original stays unchanged and the snapshot is removed. The 60-second provider deadline, calm MCP wording, audit reasons and saved Always trust are checked with a fake provider. |

MSI requires `Get-AuthenticodeSignature` on the locked signed snapshot with status
Valid or NotTrusted and the exact publisher; HashMismatch and uncertain status refuse
replacement. Independent MSI SIP content comparison is unavailable. No publicly
trusted MSI release is claimed.

The suite also covers unsafe timestamp URLs, exact native argument boundaries,
preview-only behavior, publisher pinning, changed bytes/options, one-statement
commands, tag-pinned user-level installation, UNC/device/stream rejection,
restricted setup metadata, untrusted project text, untrusted publisher rejection
and HashMismatch after signed-byte tampering.

The runner exits **0 on pass, 1 on failure**, including cleanup failure, and ends
with `RESULT: <n> checks passed.` No saved execution policy is changed.

Exact refusal text for piped input or a missing interactive console:

```text
Please run the confirmation command in your own Windows PowerShell window. Redirected input or a missing interactive console cannot confirm signing. Nothing signed.
```

No real issued certificate, SimplySign login, purchase, identity flow, token, live
timestamp service or public-trust success is exercised. Windows certificate
queries may contact certificate services. Scripted test answers do not prove
human presence. Fixture overrides exist only in temporary test copies; console
automation and modified helpers remain possible. Only key-provider approval closes
that gap. Agents must not run the final command or type its confirmation for real
signing. Keep SimplySign sessions open only while signing and close them afterwards.

Authenticode excludes signature storage and some format fields. A second PE
WIN_CERTIFICATE, a PE checksum change or an MSI trailer after signing can pass
the content check. Same-account code can also modify helpers and interfere with
the final handoff. Private ACLs and locks are not a same-account boundary.
