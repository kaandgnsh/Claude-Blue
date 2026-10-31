---
name: mcp-server-security-review
description: Review Model Context Protocol (MCP) servers and client configurations — server provenance and pinning, tool description poisoning, authorization (OAuth 2.1 per the MCP spec, no token passthrough), confused-deputy risks, local server sandboxing, secret handling, and tool-call logging. Use when installing or approving an MCP server, building one, or assessing MCP use in coding assistants and agents.
license: MIT
metadata:
  category: ai-security
  version: "2.0.0"
  verification: documented
---

# MCP Server Security Review

## Threats

| Threat | Description |
|---|---|
| Malicious or compromised server | Local stdio servers run as your user with your files and credentials; remote servers see every tool call |
| Tool poisoning | Tool names/descriptions/outputs contain hidden instructions that steer the model (indirect prompt injection via metadata) |
| Rug pull | Server updates change tool behaviour/descriptions after approval |
| Token passthrough / confused deputy | Server forwards the client's token to downstream APIs, or uses its own broad credentials on behalf of any user |
| Excessive scopes | OAuth scopes far beyond tool needs |
| Data exfiltration | Tools that fetch URLs or send data externally |
| Session hijack | Weak session IDs on HTTP transports |

## Review checklist

- [ ] **Provenance**: known publisher, source available, version pinned (package version/commit/container digest), dependencies scanned (`sca-dependency-risk`).
- [ ] **Tools**: read each tool's description and schema for hidden/odd instructions; minimal tool set enabled; destructive tools require client-side approval.
- [ ] **Local servers**: run in a sandbox/container with minimal filesystem and network access; no broad home-directory access; secrets supplied via env from a manager, not committed config.
- [ ] **Remote servers**: HTTPS; authorization per the MCP spec (OAuth 2.1 with PKCE, resource indicators/audience-bound tokens); server validates tokens issued **for itself** and does not pass client tokens through to upstream APIs; per-user authorization for upstream calls.
- [ ] **Logging**: tool calls and parameters logged on the client and server; alerts for unusual tools or volumes.
- [ ] **Change control**: re-review on version updates; monitor tool description changes (hash descriptions).
- [ ] **Client config**: project-level MCP configs in repositories can be injection vectors — require approval before enabling servers defined by a repo.

## Output

`Server | Version/digest | Transport | Tools (side effects) | Auth model | Sandbox | Findings | Decision`

## Related skills

`agent-tool-permission-review`, `prompt-injection-review`, `sca-dependency-risk`, `oauth-app-review`

## References

- MCP specification — Security best practices: https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
- MCP specification — Authorization: https://modelcontextprotocol.io/specification/draft/basic/authorization
- OWASP GenAI Security Project: https://genai.owasp.org/
