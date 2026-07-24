# Hardening Guide

## Security Hardening Journey

### Phase 1 – Foundation
- **Objective:** Secure application configuration and error handling.
- **Security Controls Implemented:** `.env` file integration; generic exception handlers.
- **Files Modified:** `config.py`, `main.py`, `.env`
- **Why the Change Was Necessary:** Hardcoded secrets and verbose stack traces provided attackers with high-value targets and reconnaissance data.
- **Security Benefit:** Prevents secret leakage in version control and obscures internal architecture.
- **Trade-offs:** Generic error messages can make client-side debugging slightly more difficult.
- **Current Status:** Complete.

### Phase 2 – Authentication & Access Control
- **Objective:** Ensure only authorized users can access the AI features.
- **Security Controls Implemented:** JWT-based Bearer authentication (`PyJWT`).
- **Files Modified:** `auth.py`, `main.py`, `requirements.in`
- **Why the Change Was Necessary:** The endpoints were entirely public, allowing anonymous abuse.
- **Security Benefit:** Establishes identity and accountability for all requests.
- **Trade-offs:** Requires clients to manage and attach tokens to requests.
- **Current Status:** Complete.

### Phase 3 – Abuse Prevention
- **Objective:** Prevent Denial of Service (DoS) and brute-force attacks.
- **Security Controls Implemented:** `slowapi` rate limiting (token: 5/min, chat: 10/min); `ContentSizeLimitMiddleware`; prompt length caps.
- **Files Modified:** `main.py`, `config.py`
- **Why the Change Was Necessary:** Unbounded requests could exhaust server RAM, CPU, and LLM context windows.
- **Security Benefit:** Guarantees resource availability and limits brute-forcing.
- **Trade-offs:** Legitimate heavy users may be temporarily blocked if limits are too strict.
- **Current Status:** Complete.

### Phase 4 – Secure File Handling
- **Objective:** Neutralize malicious document uploads.
- **Security Controls Implemented:** UUID file renaming; MIME sniffing (`python-magic`); strict extension whitelists; upload size limits.
- **Files Modified:** `main.py`, `config.py`
- **Why the Change Was Necessary:** Attackers could upload executable files (`.exe`) or use `../` to overwrite critical system files.
- **Security Benefit:** Eradicates path traversal and ensures only benign document formats are parsed.
- **Trade-offs:** Discarding original filenames impacts user experience if the UUIDs are exposed to the client.
- **Current Status:** Complete.

### Phase 5 – AI Security Controls
- **Objective:** Defend the LLM against adversarial manipulation.
- **Security Controls Implemented:** `ai_firewall.py` (regex-based injection detection, strict system prompt enforcement, contextual document wrapping, output sanitization).
- **Files Modified:** `ai_firewall.py`, `main.py`
- **Why the Change Was Necessary:** LLMs are highly susceptible to instruction overrides and data exfiltration.
- **Security Benefit:** Mitigates Direct/Indirect Prompt Injection and prevents cross-site scripting (XSS) via AI output.
- **Trade-offs:** Regex-based filtering can block legitimate user queries (false positives).
- **Current Status:** Complete.

### Phase 6 – Web Security
- **Objective:** Harden the HTTP transport and API input layer.
- **Security Controls Implemented:** `SecurityHeadersMiddleware` (CSP, HSTS, X-Frame-Options); Pydantic request validation.
- **Files Modified:** `main.py`
- **Why the Change Was Necessary:** Browsers require explicit instructions to block XSS and Clickjacking attacks.
- **Security Benefit:** Enforces strict client-side browser security policies and guarantees API payload integrity.
- **Current Status:** Complete.

### Phase 7 – Monitoring & Logging
- **Objective:** Establish an irrefutable audit trail.
- **Security Controls Implemented:** Structured JSON logging (`logger.py`); discrete `security_event` and `audit_log` functions; lockfile generation (`pip-tools`).
- **Files Modified:** `logger.py`, `main.py`, `requirements.txt`
- **Why the Change Was Necessary:** Security incidents could not be detected or investigated historically.
- **Security Benefit:** Enables rapid incident response and strict dependency supply chain security.
- **Current Status:** Complete.
