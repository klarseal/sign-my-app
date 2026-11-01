# Local server tests

Run from the repository root with Node 20+. No packages or test framework need
installing.

```powershell
npm.cmd --prefix mcp test
npm.cmd --prefix mcp run test:desktop
```

The first runs **only the non-desktop Node tests** and never shows a window
(plain equivalent: `node mcp/tests/run-tests.mjs non-desktop`). The second runs
**only the desktop tests** (`node mcp/tests/run-tests.mjs desktop`). They open
topmost windows titled `TEST ONLY - nothing will be signed` and click them, so run
them only on an idle desktop you aren't using. `npm.cmd` also works under Windows
PowerShell's default `Restricted` policy without changing it. Every test file must
be listed in `run-tests.mjs` as desktop or non-desktop before either command runs.

## What the non-desktop tests cover

- Real stdio server processes: current discovery and MRTR, older initialization,
  tool discovery, malformed and oversized input, notifications, cancellation,
  concurrency and secret-free failures.
- Approval: accepted, declined, cancelled, malformed and default answers; flat
  form defaults; replay, expiry and abort; unknown bypass arguments and detectable
  unsafe modes; the 1.5-second automatic-decline cutoff, which opens the window
  instead of counting as a person's decline.
- Display of hostile names: controls, line breaks, bidirectional and zero-width
  characters, separators, private-use characters, edge padding and literal escape
  notation. No name can add an approval line.
- Paths: allowed output folders, drives and profile roots refused, traversal,
  junctions, UNC/device paths, international paths, prefix collisions and size limits.
- Always for this project: exact folder, certificate, store and timestamp scope;
  landing folders refused; revocation, including corrupt state; private ACL on the
  trust folder; audit records.
- Closed certificate sessions, unchanged-plan recovery and resuming only the
  remaining batch files.
- No run-time compilation: shipped MCP and helper sources may load installed .NET
  assemblies by name, but never compile source, declare native code or emit code.
- On Windows, an end-to-end `sign_files` run in an isolated copy, signed offline
  with a disposable certificate through the real helpers. Headless copies replace
  the native window with a stub that fails the test if it is ever reached.

## Certificates

Windows tests create one non-exportable, one-day, self-signed code signing
certificate named `CN=sign-my-app disposable test <32 lowercase hex characters>`
using the Microsoft Software Key Storage Provider. Setup enumeration in the copied
installation is replaced with a lookup of only that certificate. Cleanup removes
that exact self-signed subject and thumbprint from every CurrentUser store,
including its private key, then checks it is gone. Cleanup failures fail the suite.
Temporary folders live inside the repository as `.test-*` and are removed
afterwards. Real certificates are never selected.

Verification is expected to fail for the untrusted disposable publisher and the
missing timestamp. No login, real publisher signing, live timestamp service or
public-trust success is exercised here. Same-account malicious code remains outside
what these local checks can protect against.

Also run the PowerShell suite described in [the repository test notes](../../tests/README.md).
Run the two suites one after the other, not at the same time.

See the [client record](client-results.md) for installs and real client runs.
