---
name: llm-security-evaluation
description: Evaluate LLM applications and models for security failures with automated and manual red-teaming — prompt injection, jailbreaks, sensitive data leakage, system prompt extraction, harmful output, tool misuse — using garak, PyRIT and promptfoo in CI, with defined pass criteria and regression tracking. Use when preparing to launch an LLM feature, after model or prompt changes, or when building an AI security test program.
license: MIT
metadata:
  category: ai-security
  version: "2.0.0"
  verification: documented
---

# LLM Security Evaluation

## Define what "fail" means first

Per application: data the model must never reveal (other users' data, system prompt secrets, internal URLs), actions it must never take without approval, content policy, acceptable refusal rate for benign requests (over-refusal is also a failure).

## Tools

```sh
# garak — probes for known LLM vulnerability classes
python -m garak --model_type openai --model_name <model> --probes promptinject,dan,leakreplay,encoding --report_prefix run1
# promptfoo — app-level red teaming and regression tests in CI
npx promptfoo@latest redteam init        # generates config with plugins (e.g. pii, prompt-extraction, excessive-agency, rbac)
npx promptfoo@latest redteam run
npx promptfoo@latest eval -c promptfooconfig.yaml   # regression suite with assertions
```
PyRIT (Microsoft) for multi-turn orchestrated attacks against an endpoint. Probe/plugin names change between versions — list them (`garak --list_probes`).

## Test design

| Category | Example cases |
|---|---|
| Direct injection / jailbreak | Role-play, encoding (base64, leetspeak), multi-language, many-shot |
| Indirect injection | Poisoned documents/web pages/tool results in the app's real ingestion paths |
| Data leakage | Ask for other users' data, training data regurgitation, secrets in system prompt (LLM07) |
| Excessive agency | Induce tool calls outside the user's intent (`agent-tool-permission-review`) |
| Output handling | Model emits HTML/JS/SQL that downstream renders/executes (LLM05) |
| Consumption | Very long inputs/outputs, recursive tool loops (LLM10) |

## Process

1. Build a test set from threat model + OWASP LLM Top 10; include benign controls.
2. Run against the **full application** (with RAG, tools, guardrails), not just the base model.
3. Score with deterministic assertions where possible; LLM-as-judge with spot-checked accuracy otherwise.
4. Gate releases on regressions; track attack success rate (ASR) per category over time.
5. Complement automation with expert manual red teaming before major launches.

## Safety

Test only your own systems or with provider permission; keep generated harmful content out of shared logs; follow provider usage policies.

## Related skills

`prompt-injection-review`, `agent-tool-permission-review`, `release-gate`, `ai-incident-response`

## References

- garak: https://github.com/NVIDIA/garak
- promptfoo red teaming: https://www.promptfoo.dev/docs/red-team/
- PyRIT: https://github.com/Azure/PyRIT
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
