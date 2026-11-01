# Sign my app

Sign your Windows app without leaving the conversation with your coding agent.

You've built something. Signing puts your verified business name on it and lets Windows check that the file hasn't changed since you signed it. We think unsigned programs aren't professional, and we'd like your first signed release to feel easy.

One free plugin for Claude Code and Codex holds both parts: a signing skill and a
small [local MCP server](mcp/README.md) that runs on your own Windows PC. Install
it, then tell your coding agent: **"sign my app"**.

## Install

Tell Claude Code or Codex:

> **Install the Klarseal MCP v1.1.0 from github.com/klarseal/sign-my-app.**

Your agent follows [the install guide](mcp/INSTALL-FOR-AGENTS.md). It checks
Windows, Git and Node 20+, installs the plugin outside your app project, and asks
you one question: which build output folder may be signed. Existing folders are
never replaced. Then start a new session (in a Claude Code terminal,
`/reload-plugins` is enough) and say **"sign my app"**.

Prefer to type the commands yourself?

**Claude Code**

```text
claude plugin marketplace add klarseal/sign-my-app#v1.1.0
claude plugin install sign-my-app@klarseal
```

**Codex**

```text
codex plugin marketplace add klarseal/sign-my-app --ref v1.1.0
codex plugin add sign-my-app@klarseal
```

`#v1.1.0` and `--ref v1.1.0` pin the release. A fresh plugin signs nothing until
you choose your build output folder; ask your agent to finish setup with the
install guide. No npm install, account, hooks or permission-mode changes.

## What it looks like

> **You:** sign my app
>
> **Agent:** I found `bin\Release\MyApp.exe`. Your certificate shows the publisher **Your Company Ltd**. A Sign window shows the file, its SHA-256 hash, the publisher and the timestamp service. Check them and choose Sign once when it looks right.
>
> **You:** [clicks Sign once]
>
> **Agent:** Your app is signed and timestamped. Windows confirms the publisher is Your Company Ltd and that the file hasn't changed since you signed it.

If you ship an installer, the agent helps you sign your app files first, rebuild the
installer with them, then sign the installer.

## Where it has been seen working

- **Claude desktop app (Code tab):** in a real signing run, a separate Sign window
  opened. One click signed the file, and the MCP verified and timestamped it.
- **Claude Code in a terminal, and Codex:** you should see an approval card in the
  chat or the same Sign window. We haven't seen this in a real signing run yet.
  If something looks different, please open an issue.

## What it never does

- **Only you approve.** Nothing is signed until you choose Sign once, or until you have chosen **Always for this project** for that exact folder and certificate. Never set up automatic answers. Without the MCP, you run the final command yourself.
- **It never sees your password.** Passwords, phone codes, tokens and private keys stay with you. You sign in to your signing app yourself.
- It never orders a certificate, opens an account or completes an identity check for you.
- It has no account of its own, sends no telemetry and does not call Klarseal services.
- It compiles no code while running and installs no packages.

## How to undo

- **Always for this project:** say **"Forget signing trust for this project"**, or
  delete `%LOCALAPPDATA%\Klarseal\SignMyApp\project-trust.json` to forget every project.
- **The plugin:** `claude plugin uninstall sign-my-app@klarseal` or
  `codex plugin remove sign-my-app@klarseal`. If your agent cloned the release,
  also delete `.claude\skills\sign-my-app` or `.agents\skills\sign-my-app` in your
  user folder; Claude Code otherwise keeps loading it.
- **The local signing log:** delete `%LOCALAPPDATA%\Klarseal\SignMyApp`.

## Need a certificate?

You can get one at klarseal.com:
[Get a Standard code signing certificate](https://klarseal.com/code-signing/standard/?utm_source=github&utm_medium=repo&utm_campaign=sign-my-app).

Klarseal sells Certum code signing certificates. Certum validates and issues them.

A registered business can order, and a sole trader or micro company counts for
Standard (OV). OV means Organization Validation: the business registration and the
person named on the order are checked. It's a great first certificate.

For stronger identity validation, choose EV, short for Extended Validation. It adds
checks on the business and the person authorised to act for it. EV is also required
to open a Windows Hardware Developer Program account for driver submissions, and a
customer's purchasing team may require it. Klarseal sells EV to registered
organisations only.
[Compare Standard and EV](https://klarseal.com/compare/ev-vs-ov-code-signing/?utm_source=github&utm_medium=repo&utm_campaign=sign-my-app).

EU and UK orders currently need a VAT number. EV orders in those markets also need a
company registration number. If you haven't registered a business yet, check the
registration requirements in your country before ordering.

Already have a code signing certificate? You can use it if Windows SignTool can access it.

## What you need

- A Windows PC with Windows PowerShell 5.1 or later.
- Microsoft SignTool, included in the [Windows SDK](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads) (choose **Windows SDK Signing Tools for Desktop Apps**).
- Your code signing certificate set up on that PC. If you use SimplySign, you'll also need its desktop and mobile apps.
- Claude Code or Codex, with [Node.js](https://nodejs.org/) 20 or later for the local MCP.
  Other coding agents can follow the skill's [`AGENTS.md`](AGENTS.md) without the MCP.
- [Git](https://git-scm.com/), to download it.

## How it works

The agent finds your built `.exe`, `.dll` and `.msi` files and checks SignTool and
your certificate. Before anything is signed, it shows you the exact files, SHA-256
hashes, publisher name and timestamp service. With the MCP, you approve in its Sign
window or approval card, and it signs and verifies in the same conversation.
Without the MCP, run the printed approval command yourself, outside the agent.

The signing command requests a timestamp, which records that the signature existed
at that time. The agent then checks the signature and timestamp and explains the
result. Windows also applies its own download and security checks.

You complete the identity check for your certificate order and sign in to your
signing app yourself. For SimplySign, sign in through SimplySign Desktop using the
code from SimplySign Mobile, and close the session when you've finished signing.

The skill covers app and installer signing on Windows. macOS notarisation and
Microsoft's driver-submission process are outside this workflow.

For a full walkthrough, see
[Klarseal's signing guide](https://klarseal.com/guides/sign-an-exe-with-signtool/?utm_source=github&utm_medium=repo&utm_campaign=sign-my-app).

## Before sharing your release

Check the signature and timestamp on every file you plan to distribute. A signature
identifies the publisher and lets Windows check for changes to the signed file.

## Run the helpers yourself

Use the absolute path of your installed skill. The examples below use a Codex
installation; replace `C:\Users\YOUR-USER\.agents\skills\sign-my-app` with your
actual installation path (for Claude Code, the `.claude\skills\sign-my-app` path).
Agents resolve this path from the loaded skill's absolute location, never from the
app repository or current folder. Helpers build printed commands from their own
script location.

Check that the helper path starts where you installed the skill.

`-ExecutionPolicy Bypass` applies only to that PowerShell run; it does not change
your saved execution policy. A managed Group Policy can still prevent execution.
Relative app file paths resolve against the installed skill folder; full paths
avoid ambiguity.

Commands below use Windows' own PowerShell at
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. Change the drive
if Windows is installed elsewhere. Generated commands resolve the system directory
through `[Environment]::SystemDirectory`, independent of project files and
environment variables.

Check your setup:

```powershell
& "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\Users\YOUR-USER\.agents\skills\sign-my-app\scripts\Test-SigningSetup.ps1"
```

Preview a signing command. This leaves the app file unchanged:

```powershell
& "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\Users\YOUR-USER\.agents\skills\sign-my-app\scripts\Invoke-Sign.ps1" -FilePath 'C:\build\MyApp.exe' -Thumbprint '<40 hex characters>'
```

Choose the publisher thumbprint listed by the setup check. The preview pins that
certificate with `/sha1` and prints a `Confirm-Sign.ps1` command containing the file
SHA-256 and plan hash. Review it, then run that exact command yourself in Windows
PowerShell outside your coding agent. Type `SIGN <plan hash>` at its prompt, using
the full displayed plan hash. The helper checks that the file and plan still match.
Manual signing calls require both the plan and that typed confirmation. The
installed MCP bridge instead supplies its internal plan confirmation after your
form or native-window answer; no tool argument can skip that approval.

Check the signature:

```powershell
& "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\Users\YOUR-USER\.agents\skills\sign-my-app\scripts\Test-Signature.ps1" -FilePath 'C:\build\MyApp.exe'
```

Replace the example path with the full path to your built app.

The confirmation command changes that file and contacts the displayed timestamp
service. Signature verification may follow certificate-controlled AIA, CRL and
OCSP URLs, including local or private addresses. Verify only files you trust to
trigger those requests. The helper prints this notice before checking the file;
normal Windows chain and revocation checks remain enabled.

## Security details

Typing is a check against mistakes and a misled agent following this skill.
Redirected stdin and hosts without an interactive console are refused. Both
confirmations read directly from the console in your own Windows PowerShell
window. This blocks ordinary piped answers, but console automation, modified
helpers and same-account malicious code remain possible; typing does not prove
a person is present. Using the installed skill's
absolute helper paths keeps the app repository from choosing what runs.
For the manual path, the agent prepares and previews; the
person must run the printed command in their own terminal. Agents **must not** run
that command, call signing directly outside the MCP approval flow, or type the confirmation.
`Invoke-Sign.ps1 -Run` is refused. Process ancestry and agent names do not prove
a person is at the keyboard and are not used as approval checks.

If a file already carries another publisher's signature, the preview names that
publisher and its thumbprint. The person must also type `REPLACE <existing
thumbprint>` before the signature can be replaced. Check ownership before doing so;
do not overwrite third-party files that belong to someone else.

The tool cannot protect against malicious code already running under your own
account. Only approval at the key provider closes that gap. Open your SimplySign
session only while signing, and close it afterwards. Keep the installed skill and
signing tools outside the control of app projects.

SignTool is selected only from Windows Kits under the machine's real Program
Files directories and must have a valid Microsoft signature. Project paths, PATH
and ProgramFiles environment variables cannot select it. There is no tool-path
override.

Signing uses a separate snapshot in a private directory on the original file's
volume. Its ACL allows only the current user and SYSTEM, where Windows supports
these permissions. SignTool needs write access, so the snapshot cannot stay write
locked while signing. During verification it denies writes and renames on the
signed snapshot. The Windows MSI provider can rewrite storage during digest checks,
so it receives a separate disposable verification copy. The helper also pins the
snapshot hash before and after verification. It compares the signed snapshot's
SHA-256 Authenticode content digest with the approved bytes' digest, and checks
signature integrity and the exact publisher thumbprint. Public trust and timestamps
are checked separately by `Test-Signature.ps1`. A mismatch leaves the original
untouched. It also refuses replacement if the original changed, then releases the
verification locks to replace it atomically. The private ACL remains in place, but
same-account code can interfere with that final handoff. A changed file or plan
requires a fresh preview.
Authenticode excludes signature storage and some format fields from its digest;
this is a content check, not whole-file equality after signing. ACLs, file locks
and hash checks do not make this a boundary against malicious same-account code.
After signing, a second PE `WIN_CERTIFICATE`, a PE checksum change, or an MSI
trailer can pass this check. These are same-account limits, even when the approved
content digest and selected publisher still match.

UNC/device paths, symbolic links and file names containing control characters
(including bidirectional text controls), quotes or shell characters are refused.
Rename those files first. Timestamp URLs must use HTTP(S) and a public host,
without spaces, quotes or credentials.

Certificate and file metadata displays escape Unicode control, format and line
separator characters, nonstandard spaces, braille blank and private-use characters
visibly and stop at 512 characters. Such characters are refused in file paths;
ordinary spaces remain supported. Backslashes are doubled
in these displays. Native-tool output follows the same rule. Printed executable
commands retain the exact validated paths and arguments for review and execution.

## Testing

v1.1.0 signed a real app with an issued certificate in the Claude desktop app, as
described above. Earlier releases were tested end to end with an issued certificate
through the printed command.

The automated suites in `tests/` and `mcp/tests/` use temporary self-signed
certificates that they create and remove themselves. See the
[skill test notes](tests/README.md), the [MCP test notes](mcp/tests/README.md) and
the [client record](mcp/tests/client-results.md) for what they cover and their limits.

## Releases

The release tag is the value stored in `VERSION`, created with
`git tag ((Get-Content -LiteralPath .\VERSION -Raw).Trim())`. Tests reject README
install tags that differ from `VERSION`. Install a tag, not a moving branch.
What changed in each release: [CHANGELOG.md](CHANGELOG.md).

Released under the [MIT licence](LICENSE). Provided AS IS, without warranty of any kind.

Independent project by Klarseal. Not affiliated with, endorsed by or sponsored by Anthropic or OpenAI. Claude, Claude Code and Codex belong to their owners and are named only to say which clients this works with.
