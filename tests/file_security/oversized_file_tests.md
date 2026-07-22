# Oversized File Tests
Test ID: FS-02
Category: Large files
Attack Objective: Cause DoS via memory exhaustion
Payload: 5GB empty file
Expected Vulnerable Behavior: Server crashes or hangs.
Expected Secure Behavior: Rejects file over size limit (e.g. 5MB).
Severity: High
