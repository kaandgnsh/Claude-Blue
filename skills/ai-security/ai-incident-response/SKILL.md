---
name: ai-incident-response
description: Respond to AI/LLM security incidents — successful prompt injection or jailbreak with impact, data leakage through a model or RAG, agent misuse of tools, compromised model artifacts or API keys, abuse of AI endpoints (cost/resource attacks) — including evidence collection of prompts and tool calls, containment and model/prompt rollback. Use when an AI feature caused or enabled a security incident.
license: MIT
metadata:
  category: ai-security
  version: "2.0.0"
  verification: documented
---

# AI Incident Response

## Incident types

| Type | Examples |
|---|---|
| Injection with impact | Assistant exfiltrated email contents via rendered link; agent executed attacker-supplied command |
| Data leakage | RAG answered with documents the user shouldn't access; model output reproduced another tenant's data |
| Credential/key abuse | Stolen LLM provider API keys used for resale ("LLMjacking"), cloud AI service abuse |
| Model supply chain | Malicious model file executed code on a data scientist workstation or inference server |
| Resource abuse | Unbounded consumption driving cost or outage |
| Harmful output | Policy-violating content delivered to customers |

## Evidence to collect

Prompt and conversation logs (system prompt version, user inputs, retrieved chunks with document IDs, tool calls with parameters and results, model/version, temperature), gateway logs (`llm-gateway-controls`), application logs, provider usage logs/billing, identity of the user/session, the triggering content (malicious document/web page/email) preserved as evidence.

## Containment options

- Disable the affected tool/connector or the feature (feature flag/kill switch).
- Remove poisoned content from indexes; re-index.
- Roll back prompt/model/guardrail version.
- Rotate exposed API keys; set provider spend limits; block abusive accounts.
- For malicious model artifacts: treat host as compromised (`linux-incident-triage`), rotate credentials on it.

## Analysis

Reconstruct the chain: content source → retrieval/ingestion → model behaviour → action/output → impact. Determine all users exposed to the same poisoned content or feature behaviour (query logs for the document ID or tool pattern). Feed new test cases into `llm-security-evaluation` regression suites.

## Reporting

Map to OWASP LLM Top 10 and MITRE ATLAS techniques; assess privacy notification (`privacy-incident-assessment`); consider AI-specific regulatory duties (e.g., EU AI Act serious-incident reporting for high-risk systems, where applicable).

## Related skills

`prompt-injection-review`, `llm-gateway-controls`, `model-artifact-security`, `incident-command`

## References

- MITRE ATLAS (case studies & techniques): https://atlas.mitre.org/
- OWASP GenAI Incident Response Guide: https://genai.owasp.org/resource/genai-incident-response-guide-1-0/
- NIST AI 600-1 Generative AI Profile: https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
