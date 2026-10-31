---
name: rag-security-review
description: Review retrieval-augmented generation (RAG) systems — document-level access control at retrieval time, ingestion pipeline trust (poisoned or injected documents), vector store security and tenant isolation, embedding inversion/leakage, citation integrity, and logging. Use when building or assessing enterprise search copilots, chat-with-your-docs features, or vector databases (OWASP LLM08:2025).
license: MIT
metadata:
  category: ai-security
  version: "2.0.0"
  verification: documented
---

# RAG Security Review

## Key risks

| Risk | Description | Control |
|---|---|---|
| Permission bypass | Retriever returns chunks the user can't access in the source system | Enforce source ACLs at query time (filter by user/group IDs synced from source; re-check on read), not only at ingestion |
| Over-sharing amplification | RAG surfaces content that was technically shared too broadly ("everyone" links) | Fix source permissions; sensitivity-label-aware retrieval; exclude restricted labels |
| Indirect prompt injection | Malicious instructions inside indexed docs | `prompt-injection-review`; restrict who can write to indexed sources; content provenance in prompts |
| Data poisoning | Attacker inserts false info to steer answers | Source allow-lists, ingestion review for external sources, provenance and citations |
| Cross-tenant leakage | Shared vector index without tenant filter | Separate indexes/namespaces per tenant or mandatory tenant filter enforced server-side |
| Embedding leakage | Embeddings can be partially inverted to recover text | Treat vectors as sensitive as the source text; encrypt, restrict access |
| Stale/deleted data | Deleted source documents remain in the index | Deletion propagation, re-index schedules, retention |
| Logging exposure | Prompts/answers containing sensitive data stored widely | Restricted logs, retention, redaction (`telemetry-minimization`) |

## Review steps

1. Diagram ingestion → chunking → embedding → vector store → retrieval → prompt assembly → LLM → output.
2. For each source: who can write, how ACLs are captured, sync frequency, deletion handling.
3. Test (authorized test users): user without access to doc X asks questions only X can answer — expect refusal/no citation.
4. Check vector DB security: authentication, network exposure, encryption, admin access, backups.
5. Verify citations link to source with the user's own access.

## Output

`Source | Write access | ACL enforcement point | Tenant isolation | Injection exposure | Findings | Fix`

## Related skills

`prompt-injection-review`, `data-classification`, `llm-gateway-controls`, `trust-boundary-analysis`

## References

- OWASP LLM08:2025 Vector and Embedding Weaknesses: https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/
- OWASP LLM02:2025 Sensitive Information Disclosure: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
- NIST AI 600-1 Generative AI Profile: https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
