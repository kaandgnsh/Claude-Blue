---
name: model-artifact-security
description: Secure ML model supply chains and artifacts — unsafe serialization (pickle, joblib, PyTorch .pt/.bin, Keras Lambda layers), scanning with ModelScan/picklescan/fickling, preferring safetensors, model provenance and signing, registry access control, trust_remote_code risks, and dataset poisoning checks. Use when downloading models from hubs (Hugging Face), operating a model registry, or reviewing ML pipelines (OWASP LLM03/LLM04).
license: MIT
metadata:
  category: ai-security
  version: "2.0.0"
  verification: documented
---

# Model Artifact Security

## Serialization risk

| Format | Risk |
|---|---|
| Python pickle / joblib / PyTorch legacy `.pt`, `.bin`, `.pkl` | **Arbitrary code execution on load** (`__reduce__`) |
| Keras `.h5`/`.keras` with Lambda layers | Code execution on load (safe_mode mitigates in Keras 3) |
| ONNX, TensorFlow SavedModel | Lower risk but custom ops/graphs can still be abused |
| **safetensors** | Tensors only, no code — preferred |
| GGUF | Weights + metadata; parser vulnerabilities possible in loaders |

`torch.load(path, weights_only=True)` (default since PyTorch 2.6) restricts unpickling to tensors/primitives — do not override for untrusted files.

## Scanning

```sh
pip install modelscan && modelscan -p ./downloaded_model/
pip install picklescan && picklescan --path ./model.bin
fickling --check-safety model.pkl          # static analysis of pickle opcodes
```
Hugging Face shows pickle/malware scan results per file — still scan locally.

## Supply-chain controls

- Allow-list approved publishers/models; mirror approved models into an internal registry (MLflow, SageMaker Model Registry, Vertex Model Registry, Artifactory) — production loads only from there, pinned by revision/commit hash (`revision=` in `from_pretrained`).
- Avoid `trust_remote_code=True` unless the remote code is reviewed and pinned.
- Sign models and verify on load (e.g., OpenSSF Model Signing / Sigstore-based `model_signing`).
- Generate model cards/AI-BOMs (CycloneDX ML-BOM) recording datasets, base models, licences.
- Registry access: write access restricted; changes audited; separate dev/prod.

## Training data integrity

Provenance of datasets, access control on training buckets, poisoning checks (outlier/duplicate detection, label audits), and evaluation on trusted holdout sets after each retrain.

## Related skills

`sca-dependency-risk`, `artifact-signing`, `sbom-generation`, `ai-incident-response`

## References

- OWASP LLM03:2025 Supply Chain: https://genai.owasp.org/llmrisk/llm032025-supply-chain/
- ModelScan: https://github.com/protectai/modelscan
- Hugging Face pickle security: https://huggingface.co/docs/hub/security-pickle
- OpenSSF model signing: https://github.com/sigstore/model-transparency
- safetensors: https://github.com/huggingface/safetensors
