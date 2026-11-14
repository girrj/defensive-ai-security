# MCP server security checklist

The Model Context Protocol (MCP) connects AI clients (Claude, Copilot, IDE agents) to tools and data. Each MCP server is code that runs with the user's privileges and returns text the model trusts. Treat a new MCP server like a new browser extension that also holds API keys.

## Before approving a server

- [ ] **Source**: official vendor, or a known maintainer with an active repository. Check the publisher matches the brand, because typosquatted names are common.
- [ ] **Pinned version**: install a specific version or commit, never `latest`. Record the package hash.
- [ ] **Code review or scan**: look for outbound network calls, shell execution, and file access beyond the server's purpose. Scanners exist for MCP servers and agent skills (see [defensive-tools.md](defensive-tools.md#mcp-and-agent-supply-chain)).
- [ ] **Tool descriptions**: read every tool's name and description. Descriptions go into the model's context, and hidden instructions inside them ("tool poisoning") steer the agent. Scan them with `prompt_injection.yar`.
- [ ] **Permissions needed**: list the files, network destinations, and credentials it needs. Refuse servers that ask for more than their purpose requires.
- [ ] **Transport**: local stdio, or remote HTTP. For remote servers, check who operates them, where the data goes, and how authentication works.

## Deployment

- [ ] **Least privilege**: run under a dedicated account, or in a container with only the directories and network destinations it needs.
- [ ] **No standing secrets in configuration files**: use a credential broker or OS keychain, and give the server scoped, short-lived tokens.
- [ ] **Separate trust levels**: don't load a server that reads untrusted content (web fetch, email, tickets) in the same session as a server that can take high-impact actions (shell, database writes, payments), unless a human approves each action.
- [ ] **Confirmation on write actions**: configure the client to ask before tools that change state.
- [ ] **Inventory**: keep a register of approved servers, with version, owner, purpose, and permissions. Unknown servers found on endpoints are findings.

## Monitoring

- [ ] EDR telemetry covers the client and server processes: Sigma `mcp_server_spawns_shell_or_recon` and `mcp_server_download_or_credential_access`.
- [ ] Tool-call logs (tool name, arguments, result size, user) go to the SIEM.
- [ ] Alert on new MCP server packages appearing on endpoints, by hunting for `@modelcontextprotocol/`, `mcp-server`, or `fastmcp` in process command lines.
- [ ] Re-review servers on every version change. Server behavior can change after approval.

## When something goes wrong

Follow [llm-application-compromise.md](../playbooks/llm-application-compromise.md). For MCP specifically:

1. Disable the server in client configurations fleet-wide (MDM or configuration management).
2. Rotate every credential the server had access to.
3. Pull tool-call logs and agent transcripts for the period the server was installed.
4. Check the server's package for changes between the approved version and the installed one.
