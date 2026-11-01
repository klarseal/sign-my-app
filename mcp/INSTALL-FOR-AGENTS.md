# Install Klarseal for Claude Code or Codex

When asked **"Install the Klarseal MCP v1.1.0 from github.com/klarseal/sign-my-app."**
(or the same request without a version, which means this release, `v1.1.0`),
install the skill and MCP together as one plugin. Do not expect an absent skill to
discover itself. Read this file from the repository first. No package registry or
npm install is needed.

1. Check Windows, `git --version`, and `node --version` (20+). If unavailable,
   explain the missing prerequisite; do not download and run an installer.
2. Resolve the user's home/skills folder. Clone tag `v1.1.0` outside the app
   project: Claude uses `.claude\skills\sign-my-app`; Codex uses
   `.agents\skills\sign-my-app`. Honour `CLAUDE_CONFIG_DIR` or `CODEX_HOME` in
   isolated tests (use their `skills\sign-my-app` child). **If the destination
   exists, stop and ask; never replace it.** Run:
   `git -c advice.detachedHead=false clone --branch 'v1.1.0' --depth 1 https://github.com/klarseal/sign-my-app <destination>`.
   Check clone success. Resolve `<destination>\.git`, verify it is inside that
   exact new destination, then remove only that `.git` directory with PowerShell
   `Remove-Item -LiteralPath ... -Recurse -Force`.
3. Inspect the app's build configuration separately. Find its built output folder
   without running a build or binary. Ask one question: **"Use <absolute output
   folder> as this project's allowed signing output folder?"** If there is no
   build yet, ask for the intended output folder. Wait for the person's answer.
   Use the actual build output folder, never a drive, drive child (such as
   `C:\src`), user-profile root, source repository, or folder above a project.
4. Prefer the bundled plugin. Write the confirmed absolute folder as a JSON array
   into the installed clone's `mcp/output-roots.json` (UTF-8, no BOM). This is path
   restriction configuration, never signing trust. The bundled MCP starts with
   the equivalent `--allow-root <folder>` restriction and refuses file tools until
   configured. Register only the `v1.1.0` clone from step 2 through the client's
   command. The install/add command takes its release from that local marketplace,
   rather than accepting a separate release-ref argument:

   Claude Code: `claude plugin marketplace add <destination>`, then
   `claude plugin install sign-my-app@klarseal`.
   Codex: `codex plugin marketplace add <destination>`, then
   `codex plugin add sign-my-app@klarseal`.

   Confirm with the client's `plugin list` and MCP status. Claude: have the
   person run `/reload-plugins` (or `/reload-plugins --force` if requested by the
   client); interactive terminals can connect without restarting. Desktop/`-p`
   reloads do not connect newly added MCP servers until a new session. Codex
   needs a **new session**. After activation, check MCP status and list tools;
   report connected only when observed. Do not sign as an installation check.
5. If plugins are unavailable, the clone is already the skill. Register the MCP
   through the client's command, preserving the confirmed folder:

   `claude mcp add --transport stdio --scope user klarseal -- node <destination>\mcp\server.mjs --allow-root <folder>`

   `codex mcp add klarseal -- node <destination>\mcp\server.mjs --allow-root <folder>`

   Use absolute paths and the resolved Node executable where possible. Confirm
   with `claude mcp get klarseal` / `claude mcp list`, or `codex mcp get klarseal`
   / `codex mcp list`. A new session may be needed to load the fallback skill and
   server. Do not leave both a plugin server and a duplicate manual registration.
6. Finish with one line saying connected/pending activation, and whether a new
   session is needed. Then the person can say **"sign my app"**.

Never change permission modes, add hooks or auto-approvals, ask for a password,
or manufacture an approval-form answer. Client permission authorises the tool;
our form separately approves its computed plan. Certificate login stays private.

Manual plugin installs without a local clone (the person still chooses an output
folder afterwards, as below):

- Claude Code: `claude plugin marketplace add klarseal/sign-my-app#v1.1.0`,
  then `claude plugin install sign-my-app@klarseal`. If that client cannot pin
  a marketplace ref, use the tag-pinned local clone in step 2 and register that
  local marketplace through `claude plugin marketplace add <destination>`.
  Check the registered source/ref before installing; an existing unpinned
  marketplace must not silently stand in for the pinned source. A tag can be
  moved by its publisher; this pins a release ref, not an immutable commit.
  Run `/reload-plugins` in an interactive terminal. No restart is normally needed.
- Codex CLI: `codex plugin marketplace add klarseal/sign-my-app --ref v1.1.0`,
  then `codex plugin add sign-my-app@klarseal`. Start a new session.

The plugin starts with no allowed folders. For a manual marketplace install,
find its installed path using `plugin list --json`, confirm the output folder,
write that installed copy's `mcp/output-roots.json`, and reload/start the session.
Do not change `project-trust.json`: only the person's approval answer creates trust.

Sources checked 2026-11-01: [Claude plugin commands, pinned sources and reload](https://code.claude.com/docs/en/plugins/cli-reference),
[Codex plugins and new sessions](https://learn.chatgpt.com/docs/plugins),
[Codex plugin command arguments](https://learn.chatgpt.com/docs/developer-commands#codex-plugin),
[OpenAI plugin packaging](https://developers.openai.com/plugins/build/plugins).

To undo: `claude plugin uninstall sign-my-app@klarseal` or
`codex plugin remove sign-my-app@klarseal`, then delete the clone folder from
step 2 too; Claude Code otherwise keeps loading it from its skills folder. Saying
"Forget signing trust for this project" removes
Always trust. If tag `v1.1.0` cannot be fetched, stop and tell the person; do not
silently install a different ref.
