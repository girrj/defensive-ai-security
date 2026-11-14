# Playbook: harmful action by an AI coding agent

**Triggers:** `ai_agent_*` Sigma rules, `ai_agent_destructive_command` YARA-L, or a developer reporting that an agent deleted, leaked, or changed something unexpectedly.

AI coding agents (Claude Code, Codex, and similar tools) run commands with the developer's own privileges. When one causes harm, there are three possible causes, and each has a different fix:

| Cause | Typical evidence | Fix |
| --- | --- | --- |
| **Misread request** | The session shows the user asked for something nearby ("clean up the build"), and the agent went too far | Tighten the permission settings, and require confirmation for destructive commands |
| **Prompt injection** | Right before the action, the agent read a file, web page, issue, or tool output that contained instructions | Treat the content source as hostile, and restrict network and file access in agent sessions |
| **Misuse by a person** | The user explicitly asked for the action | Handle as an insider or policy issue, not as an agent issue |

## 1. Triage

- [ ] From EDR, get the process tree: the agent process → shell → command. Note the working directory and the user.
- [ ] Ask the developer for the session transcript or log. Agent tools usually keep these locally. Copy it before the developer closes or clears the session.
- [ ] Find the human's last few messages before the action. Then find what the agent read between those messages and the action.

## 2. Contain

- [ ] **Destructive action:** stop the agent session. Check whether version control, the recycle bin, snapshots, or backups can restore the data, and stop writes to the volume if file recovery is needed.
- [ ] **Credential access or transfer:** treat the credentials as exposed. Rotate cloud keys, SSH keys, and tokens, and check the provider's audit logs for use from new IPs.
- [ ] **Security setting change:** revert it centrally and confirm that the EDR is healthy.

## 3. Determine the cause

- [ ] Compare the action with the human's request. Did the agent do what was asked, something next to it, or the opposite?
- [ ] Search the content the agent read for imperative instructions aimed at an AI ("ignore previous", "run the following", hidden HTML comments, invisible Unicode).
- [ ] Check whether the agent's permission prompts were bypassed or set to auto-approve.

## 4. Prevent

- Enforce agent permission settings centrally: deny lists for destructive and credential-related commands, and confirmation for network transfers.
- Run agents on untrusted repositories in a container or VM without production credentials.
- Keep the `ai_agent_*` detections enabled. They still fire when agent-side controls are off.
