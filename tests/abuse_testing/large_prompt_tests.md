# Large Prompt Tests
Test ID: AB-02
Category: Extremely long prompts
Attack Objective: Context window exhaustion / OOM
Payload: 100,000 'A' characters.
Expected Vulnerable Behavior: API crashes.
Expected Secure Behavior: Returns 400 Bad Request.
Severity: Medium
