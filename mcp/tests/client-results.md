# Client record

What has been seen with real clients, and what hasn't yet.

## Signing

| Client | Seen |
| --- | --- |
| Claude desktop app, Code tab | Real signing run with an issued certificate. The client declined the in-chat approval card automatically, so the MCP opened its separate Sign window. One click signed the file; the MCP verified it and confirmed the timestamp, and Always for this project was saved. |
| Claude Code in a terminal | Not yet seen in a real signing run. Expect the approval card in the chat, or the same Sign window. |
| Codex | Not yet seen in a real signing run. Expect the approval card in the chat, or the same Sign window. |

An earlier build in the Claude desktop app returned at once without showing any
card or window. That is why an automatic decline in under 1.5 seconds now opens
the window instead of counting as your answer.

## Installation

Checked for v1.1.0 on Windows with Node 24.16.0, Claude Code 2.1.308 and
2.1.173, and Codex CLI 0.159.2. Every run used a fresh `CLAUDE_CONFIG_DIR` or
`CODEX_HOME`, a tag-pinned clone of `v1.1.0` with `.git` removed, and an
`mcp/output-roots.json` naming a temporary build folder, as in steps 2 and 4 of
the [agent guide](../INSTALL-FOR-AGENTS.md). Nothing was signed.

| Step | Claude Code (both versions) | Codex |
| --- | --- | --- |
| Add the clone as a marketplace | `claude plugin marketplace add <clone>`: exit 0, marketplace `klarseal` | `codex plugin marketplace add <clone>`: exit 0, marketplace `klarseal` |
| Install | `claude plugin install sign-my-app@klarseal`: exit 0 | `codex plugin add sign-my-app@klarseal`: exit 0 |
| Check | `plugin list`: `sign-my-app@klarseal` 1.1.0 enabled. `mcp list`: `plugin:sign-my-app:klarseal` Connected. | `plugin list`: installed, enabled, 1.1.0. `mcp list`: `klarseal` (stdio). The installed server answered `initialize` and listed 8 tools. |
| Undo | `claude plugin uninstall sign-my-app@klarseal`: exit 0 | `codex plugin remove sign-my-app@klarseal`: exit 0 |

Claude Code also sees the clone in its skills folder as a plugin. While the
installed plugin exists, that copy is not loaded twice; after uninstalling, it
loads again until the folder is deleted. The guide and README say so.

The GitHub forms `klarseal/sign-my-app#v1.1.0` (Claude Code) and
`klarseal/sign-my-app --ref v1.1.0` (Codex) fetched the requested tag from GitHub
in both clients. Before the `v1.1.0` tag was published, that check used an older
tag and stopped, as expected, at its missing plugin manifest.

Asking the agent in words ("Install the Klarseal MCP v1.1.0 from
github.com/klarseal/sign-my-app.") needs a signed-in model, so these checks ran
the guide's commands directly.

## Limits

Client hooks, auto-allow and bypass modes can answer approval prompts, and no
client tells the server which of these are on. A person's answer and an automatic
one look the same to the server. See the [MCP README](../README.md) for the
protections and their limits.
