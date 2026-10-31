---
name: llm-gateway-controls
description: Design and review controls at an LLM/AI gateway or proxy (LiteLLM, cloud AI gateways, Azure API Management AI policies, commercial AI firewalls) — authentication and per-user attribution, approved models and providers, prompt/response logging with privacy, DLP and secret redaction, injection/jailbreak classifiers, rate and spend limits, and shadow-AI discovery. Use when governing enterprise use of LLM APIs, preventing sensitive data leakage to AI services, or monitoring AI usage.
license: MIT
metadata:
  category: ai-security
  version: "2.0.0"
  verification: documented
---

# LLM Gateway Controls

## Control set

| Control | Purpose |
|---|---|
| Central gateway for all LLM API traffic | Visibility, single enforcement point; block direct egress to AI provider APIs from servers |
| Strong auth + per-user/app identity | Attribution of prompts and spend; no shared provider keys in apps |
| Model/provider allow-list | Only approved models/regions/data-processing terms (no-training, retention terms) |
| Input DLP & secret redaction | Detect and mask secrets, credentials, PII, classified content before sending (`telemetry-minimization` patterns) |
| Injection/jailbreak detection | Classifiers on inputs and retrieved content (e.g., prompt shields); log and optionally block |
| Output filtering | PII, secrets, unsafe content; markdown/image URL stripping for exfil prevention |
| Rate limits & budgets | Per user/app token and cost caps (LLM10) |
| Logging | Prompts/responses/tool calls to restricted store with retention and access audit; metadata to SIEM |
| Key management | Provider keys in a vault, rotated; alert on usage anomalies (LLMjacking) |

## Shadow AI discovery

Proxy/DNS logs for AI SaaS domains (chat assistants, transcription, code assistants), CASB app catalogs, browser extension inventory, OAuth grants to AI apps (`oauth-app-review`), expense reports. Provide an approved alternative rather than only blocking.

## Example: LiteLLM proxy config fragment (illustrative)

```yaml
model_list:
  - model_name: approved-chat
    litellm_params:
      model: azure/<deployment>
      api_base: os.environ/AZURE_API_BASE
      api_key: os.environ/AZURE_API_KEY
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
litellm_settings:
  max_budget: 1000
  budget_duration: 30d
```
Check the current LiteLLM docs for guardrail and per-key budget configuration syntax.

## Review output

`Control | Implemented | Coverage (apps/users) | Evidence | Gap | Recommendation`

## Related skills

`ai-incident-response`, `prompt-injection-review`, `dlp-alert-triage`, `shadow-it-discovery`

## References

- OWASP LLM02:2025 Sensitive Information Disclosure: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
- OWASP LLM10:2025 Unbounded Consumption: https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/
- LiteLLM proxy docs: https://docs.litellm.ai/docs/simple_proxy
- Azure API Management AI gateway capabilities: https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities
