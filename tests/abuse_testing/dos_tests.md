# Denial of Service Tests
Test ID: AB-01
Category: Multiple simultaneous requests
Attack Objective: Crash the backend
Payload: Send 100 concurrent requests to /chat.
Expected Vulnerable Behavior: Server becomes unresponsive.
Expected Secure Behavior: Rate limits apply.
Severity: High
