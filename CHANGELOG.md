# Changelog

## v1.1.0

- Sign in the conversation. A local MCP server finds your built files, asks you in
  a separate Sign window (or an approval card in the chat), then signs, verifies
  and timestamps. No terminal command or typed hash needed.
- One plugin for Claude Code and Codex holds both the skill and the MCP.
- **Always for this project** lets you skip the question for one exact build folder
  and certificate. Say "Forget signing trust for this project" to undo it.
- No code is compiled at run time.
- Seen working in a real signing run in the Claude desktop app. In Claude Code in a
  terminal and in Codex, the approval hasn't been seen in a real signing run yet.

## v1.0.1

- Quieter install lines.

## v1.0.0

- First release: a skill that previews signing and prints a hash-bound command for
  you to run yourself.
