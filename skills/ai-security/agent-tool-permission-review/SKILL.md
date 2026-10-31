---
name: agent-tool-permission-review
description: Review AI agent and copilot tool permissions for excessive agency (OWASP LLM06:2025) — tool inventory, identity used for each tool call (user-delegated vs. service), scopes, side effects, human-in-the-loop approvals, sandboxing of code execution, rate limits, and audit logging. Use when deploying an AI agent, coding assistant, or automation that lets an LLM call tools, APIs or shell commands.
license: MIT
metadata:
  category: ai-security
  version: "2.0.0"
  verification: documented
---

# Agent Tool Permission Review

## Tool inventory

For every tool/function/MCP server the agent can call:

`Tool | Operation(s) | Side effects (read/write/delete/send/pay/execute) | Identity used | Scope/permissions | Data reachable | Approval required? | Rate limit | Logged?`

## Principles

1. **Minimal toolset**: remove generic tools when specific ones suffice (a `send_email(to=fixed-domain)` beats `http_request(any_url)`; a `query_orders(user)` beats raw SQL).
2. **User-delegated identity**: tool calls execute with the end user's permissions (OAuth on-behalf-of, scoped tokens), not a powerful shared service account — prevents confused-deputy escalation.
3. **Read-only default**; write/delete/send actions require explicit human approval with a faithful preview of parameters.
4. **Sandbox code execution**: containers/microVMs without network or with egress allow-lists, no host mounts, no credentials, CPU/time limits.
5. **Constrain parameters server-side** (validate schemas, allow-lists for recipients/paths/domains); never trust the model to self-limit.
6. **Budget & rate limits** per session/user to bound damage and cost (LLM10 unbounded consumption).
7. **Audit**: log each tool call (who, which tool, parameters, result status) to the SIEM; alert on anomalous sequences (bulk reads followed by external sends).
8. **Kill switch** to disable tools/agent quickly.

## Coding agents (e.g., in IDE/CLI)

Restrict shell/file permissions with allow-lists, require approval for network and destructive commands, run in containers/devcontainers for untrusted repos, don't expose production credentials in the environment, review hooks/config files (they can be injection vectors through repository content).

## Test

Attempt (authorized) prompt-injection-driven misuse of each write tool (`prompt-injection-review`), privilege boundaries (can user A's session read user B's data via the agent?), and approval bypass (does a multi-step plan circumvent confirmation?).

## Related skills

`prompt-injection-review`, `mcp-server-security-review`, `trust-boundary-analysis`, `llm-gateway-controls`

## References

- OWASP LLM06:2025 Excessive Agency: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
- OWASP Agentic AI – Threats and Mitigations: https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
- NIST AI RMF 1.0: https://www.nist.gov/itl/ai-risk-management-framework
