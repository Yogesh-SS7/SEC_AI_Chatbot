# Threat Model — SEC_AI_Chatbot (Orion AI Assistant)

**Version:** 1.0.0  
**Date:** 2026-07-24  
**Methodology:** STRIDE  
**Scope:** FastAPI backend + Ollama LLM + browser frontend

---

## System Overview

```
[Browser Client]
      │  HTTPS (JWT Bearer)
      ▼
[FastAPI Backend]  ──── [Ollama LLM (local)]
      │
      ├── /token    (authentication)
      ├── /chat     (AI conversation)
      └── /upload   (document ingestion)
      │
      ├── [uploads/]  (UUID-named files)
      └── [logs/]     (rotating structured logs)
```

**Trust boundaries:**
- **Untrusted:** Everything arriving over the network (user input, uploaded files, HTTP headers)
- **Trusted:** Server-side config (`.env`), system prompt files, the Ollama service (local only)

---

## STRIDE Threat Analysis

### 1. Spoofing

| Threat | Control | Residual Risk |
|---|---|---|
| Attacker impersonates a valid user | JWT authentication (Phase 2); rate-limited login (Phase 3) | LOW — token forgery requires SECRET_KEY compromise |
| Token replay after logout | JWTs have a configurable expiry (`JWT_EXPIRE_MINUTES`) | MEDIUM — no server-side token revocation list |

**Recommendation:** Implement a token blocklist (Redis/DB) for high-security deployments.

---

### 2. Tampering

| Threat | Control | Residual Risk |
|---|---|---|
| Malicious file upload (executable disguised as .txt) | Extension whitelist + MIME validation + UUID filename (Phase 4) | LOW |
| Path traversal via crafted filename | UUID rename + absolute path resolution guard (Phase 4) | LOW |
| Client injects system-role message in chat payload | `enforce_system_prompt()` strips client system roles (Phase 5) | LOW |
| Attacker modifies JWT payload | JWT signed with HS256 + SECRET_KEY (Phase 2) | LOW — requires key compromise |

---

### 3. Repudiation

| Threat | Control | Residual Risk |
|---|---|---|
| User denies performing an action | Structured `audit_log()` records user + action + timestamp (Phase 7) | LOW |
| Security incident goes unrecorded | `security_event()` logs all flagged events (Phase 7) | LOW |
| Log tampering | Logs written to append-only rotating files | MEDIUM — no cryptographic log integrity (e.g. WORM storage) |

**Recommendation:** Ship logs to a centralised SIEM (Splunk, Datadog) for tamper-evidence.

---

### 4. Information Disclosure

| Threat | Control | Residual Risk |
|---|---|---|
| System prompt leakage via AI response | Output sanitization checks leakage signals (Phase 5) | MEDIUM — regex-based, novel phrasings may evade |
| Stack traces exposed to client | Secure error handling (Phase 1) — generic error messages only | LOW |
| `.env` / secrets exposed in logs | Structured logging never logs secret values | LOW |
| Sensitive data in uploaded files leaked via AI | Context isolation wraps document text with delimiter instructions (Phase 5) | MEDIUM — model-dependent |
| Log files contain PII | Logs record usernames and IPs — access control required | MEDIUM |

---

### 5. Denial of Service

| Threat | Control | Residual Risk |
|---|---|---|
| Brute-force login | Rate limit: 5/min on `/token` (Phase 3) | LOW |
| Chat flooding | Rate limit: 10/min on `/chat` (Phase 3) | LOW |
| Oversized HTTP body | `ContentSizeLimitMiddleware` (Phase 3) | LOW |
| Oversized file upload | `MAX_UPLOAD_SIZE_BYTES` check (Phase 4) | LOW |
| Token exhaustion via very long prompts | `MAX_PROMPT_CHARS` limit (Phase 3) | LOW |
| Ollama hung request | `OLLAMA_TIMEOUT` (Phase 3) | LOW |

---

### 6. Elevation of Privilege

| Threat | Control | Residual Risk |
|---|---|---|
| Prompt injection overrides AI role | Direct injection regex detection (Phase 5) | MEDIUM — novel attack patterns may evade |
| Indirect injection via uploaded document | Document text scanned before LLM submission (Phase 5) | MEDIUM — model-dependent compliance |
| Attacker gains unauthorized API access | JWT required on all sensitive endpoints (Phase 2) | LOW |
| Clickjacking to steal session | `X-Frame-Options: DENY` (Phase 6) | LOW |
| Cross-site script execution | CSP `script-src 'self'` + `html.escape()` output encoding (Phase 6) | LOW |

---

## Assets Prioritized by Impact

| Asset | Sensitivity | Primary Control |
|---|---|---|
| `JWT_SECRET_KEY` | CRITICAL | Stored in `.env`, never logged |
| `APP_PASSWORD` | HIGH | Stored in `.env`, rate-limited auth |
| System prompt content | HIGH | Phase 5 output sanitization |
| Uploaded document content | MEDIUM | UUID storage, context isolation |
| Conversation history | MEDIUM | Browser memory only, not persisted |
| Application logs | MEDIUM | File permissions, rotation |

---

## Residual Risks (Accepted)

1. **Novel prompt injection techniques** — regex patterns catch known vectors; LLM-based classifiers would improve coverage but add latency and cost.
2. **No token revocation** — JWT expiry is the only logout mechanism.
3. **Log integrity** — logs are not cryptographically signed; a compromised server could alter them.
4. **HSTS disabled in dev** — must be enabled (`HSTS_ENABLED=true`) when deploying on HTTPS.
5. **Single-user app** — no RBAC; all authenticated users have identical permissions.

---

## Out of Scope

- Network-layer attacks (DDoS, TLS downgrade) — handled at infrastructure/CDN level
- Ollama model supply chain — trusted as a local, pinned model
- Physical access to the server
