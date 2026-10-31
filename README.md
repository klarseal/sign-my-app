# Sign my app

A free skill that lets your coding agent walk you through signing your Windows app, step by step.

You've built something. Signing puts your verified business name on it and lets Windows check that the file hasn't changed since you signed it. We think unsigned programs aren't professional, and we'd like your first signed release to feel easy.

Install the skill, then tell your coding agent: **"sign my app"**.

## Install

Pick your agent and paste its three lines into Windows PowerShell. Each one downloads the tagged release (`v1.0.1`, the value in `VERSION`) into your user skills folder, outside your app project.

**Claude Code**

```powershell
$destination = Join-Path $env:USERPROFILE '.claude\skills\sign-my-app'
git -c advice.detachedHead=false clone --branch 'v1.0.1' --depth 1 https://github.com/klarseal/sign-my-app $destination
if ($LASTEXITCODE -eq 0) { Remove-Item -LiteralPath (Join-Path $destination '.git') -Recurse -Force }
```

Start a fresh Claude Code session and say **"sign my app"**, or use `/sign-my-app`.

**Codex**

```powershell
$destination = Join-Path $env:USERPROFILE '.agents\skills\sign-my-app'
git -c advice.detachedHead=false clone --branch 'v1.0.1' --depth 1 https://github.com/klarseal/sign-my-app $destination
if ($LASTEXITCODE -eq 0) { Remove-Item -LiteralPath (Join-Path $destination '.git') -Recurse -Force }
```

Start a fresh Codex session and say **"sign my app"**. The user-level skill path is
documented in [OpenAI's skill documentation](https://learn.chatgpt.com/docs/build-skills).

**Other coding agents**

Clone the same tag into a user tools folder outside your app project, remove its
`.git` folder, and point your agent's user-level instructions at its absolute
`AGENTS.md` path.

If the folder already exists, `git clone` stops without changing it. Look at what's
there before you replace it.

## What it looks like

> **You:** sign my app
>
> **Agent:** I found `bin\Release\MyApp.exe`. Your certificate shows the publisher **Your Company Ltd**. Here's the plan: the file, its SHA-256 hash, the publisher, the signing command and the timestamp service. When it looks right, copy the command below into your own PowerShell window and type the confirmation it asks for.
>
> **You:** Done.
>
> **Agent:** Your app is signed and timestamped. Windows confirms the publisher is Your Company Ltd and that the file hasn't changed since you signed it.

If you ship an installer, the agent helps you sign your app files first, rebuild the
installer with them, then sign the installer.

## What it never does

- **It never signs for you.** The agent prepares and shows you everything. You run the final command yourself, in your own terminal.
- **It never sees your password.** Passwords, phone codes, tokens and private keys stay with you. You sign in to your signing app yourself.
- It never orders a certificate, opens an account or completes an identity check for you.
- It has no account of its own, sends no telemetry and does not call Klarseal services.

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
- A coding agent that can read the installed instructions.
- [Git](https://git-scm.com/), to download the skill.

## How it works

The agent finds your built `.exe`, `.dll` and `.msi` files and checks SignTool and
your certificate. Before anything is signed, it shows you the exact files, SHA-256
hashes, publisher name, signing command and timestamp service. You review them and
run the printed approval command yourself, outside the agent.

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
The signing function itself requires both the plan and that typed confirmation,
including if called directly.

Check the signature:

```powershell
& "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\Users\YOUR-USER\.agents\skills\sign-my-app\scripts\Test-Signature.ps1" -FilePath 'C:\build\MyApp.exe'
```

Replace the example path with the full path to your built app.

The confirmation command changes that file and contacts the displayed timestamp
service. Signature verification may contact Windows certificate services.

## Security details

Typing is a check against mistakes and a misled agent following this skill.
A script running under the same account can pipe `SIGN <plan hash>` into the
command; typing does not prove a person is present. Using the installed skill's
absolute helper paths keeps the app repository from choosing what runs.
The agent prepares and previews; the
person must run the printed command in their own terminal. Agents **must not** run
that command, call signing directly, or type the confirmation.
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
separator characters visibly and stop at 512 characters. Backslashes are doubled
in these displays. Native-tool output follows the same rule. Printed executable
commands retain the exact validated paths and arguments for review and execution.

## Testing

This release was tested end to end with a real issued code signing certificate.

The automated suite in `tests/` uses a temporary self-signed certificate that it
creates and removes itself. See the [test record](tests/README.md) for what it
covers and its limits.

## Releases

The release tag is the value stored in `VERSION`, created with
`git tag ((Get-Content -LiteralPath .\VERSION -Raw).Trim())`. Tests reject README
install tags that differ from `VERSION`. Install a tag, not a moving branch.

Released under the [MIT licence](LICENSE). Provided AS IS, without warranty of any kind.

Independent project by Klarseal. Not affiliated with, endorsed by or sponsored by Anthropic or OpenAI. Claude, Claude Code and Codex belong to their owners and are named only to say which clients this works with.
