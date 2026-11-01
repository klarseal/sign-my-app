---
name: sign-my-app
description: Sign and verify built Windows apps and installers through the local Klarseal MCP. Use when asked to sign an app, undo project signing trust, or add a signing step to a build.
---

The installed plugin root is two folders above this file. Read the shared
[signing workflow](../../references/workflow.md) before signing. Resolve helpers
from that installed root, never from the app project.

If setup is incomplete, read [agent installation](../../mcp/INSTALL-FOR-AGENTS.md).
For an already installed plugin, configure that installed root's
`mcp/output-roots.json` after confirming the build folder; do not clone or
install a second copy. Reload/start a new session as the guide describes.
Use `sign_files`; only the person answers Cancel, Sign once, or Always for this
project. Existing exact project trust can sign without another form while their
certificate session is open. Never manufacture an answer. Client tool permission
and the computed-plan form are separate approvals.

If asked to undo trust, call `forget_project_trust`; no approval is required.
Only when asked for build integration, call `get_build_recipe`, show its exact
`sign.ps1` text, then add it to their build as requested. Keep payload signing
before packaging and installer signing afterwards. Do not invoke SignTool directly.
Keep the generated PowerShell launch command, including
`-NoProfile -ExecutionPolicy Bypass -File`, when adding `sign.ps1` to the build.
This bypass applies only to that process; never ask for a saved policy change.
If the certificate session is unavailable, say: "Please sign in to your signing
app, then tell me." Keep the selected files and publisher, and continue when
they return. Never ask for credentials. Close SimplySign after signing.
