# Model Card — Orion AI Assistant

**Version:** 1.0.0  
**Date:** 2026-07-24  
**Model:** llama3.2 (via Ollama)  
**Application:** SEC_AI_Chatbot (Orion Enterprise AI Assistant)

---

## Model Details

| Field | Value |
|---|---|
| Base model | Meta Llama 3.2 |
| Runtime | Ollama (local inference) |
| Context window | ~128K tokens (model-dependent) |
| Modality | Text only |
| Languages | English (primary) |
| Deployment mode | On-premise, air-gapped capable |

---

## Intended Use

### In-scope
- Internal employee Q&A and general assistance
- Document analysis from uploaded `.txt`, `.pdf`, `.docx` files
- Knowledge retrieval from uploaded context

### Out-of-scope
- Customer-facing or public-facing deployments (without additional hardening)
- Handling of classified or legally privileged documents
- Autonomous decision-making or action execution
- Medical, legal, or financial advice

---

## Security Posture

All seven security phases have been applied to this deployment:

| Phase | Control | Status |
|---|---|---|
| 1 | Secrets management, structured logging, secure error handling | ✅ |
| 2 | JWT authentication, session validation, protected endpoints | ✅ |
| 3 | Rate limiting, request size limits, prompt/response length caps | ✅ |
| 4 | File extension whitelist, MIME validation, UUID filenames, path traversal guard | ✅ |
| 5 | Prompt injection detection, indirect injection detection, system prompt enforcement, output sanitization | ✅ |
| 6 | Security headers (CSP, X-Frame-Options, HSTS), restricted CORS, Pydantic validation, output encoding | ✅ |
| 7 | Audit logging, security event logging, rotating file handler | ✅ |

---

## Known Limitations

- **Hallucination:** The model may generate plausible-sounding but factually incorrect information. All responses should be verified by the user.
- **Injection residual risk:** Regex-based injection detection catches known patterns but cannot guarantee detection of novel zero-day jailbreak techniques.
- **No memory:** The model has no persistent memory between sessions. Context is limited to the current conversation window.
- **Document size:** Extracted document text is bounded by `MAX_PROMPT_CHARS`. Very large documents will be truncated.
- **Language:** The model performs best in English. Other languages may produce degraded quality.
- **Local inference latency:** Response times depend on host hardware. GPU acceleration is recommended for production workloads.

---

## Data Handling

- **Uploaded files** are stored with UUID filenames. Original filenames are never written to disk.
- **Uploaded files are not automatically deleted** after the session. Implement a scheduled cleanup job for production.
- **Conversation history** is held in browser memory only — it is not persisted server-side.
- **Logs** may contain usernames and IP addresses. Ensure log files are access-controlled and rotated.

---

## Evaluation

This model card does not include formal benchmark evaluations. The model's security controls have been validated through:

- Manual red-team testing (prompt injection, MIME mismatch, path traversal)
- Automated pytest suite (`tests/`)
- Static analysis: Semgrep (run separately by operator)
- Dependency audit: `pip-audit` (run separately by operator)

---

## Contact / Maintainer

Internal security team — refer to your organization's AI governance policy for escalation paths.
