# Malicious File Tests
Test ID: FS-01
Category: Unsupported extensions
Attack Objective: Upload an executable file
Payload: `report.pdf.exe`
Expected Vulnerable Behavior: Saves file with .exe extension.
Expected Secure Behavior: Rejects file or sanitizes extension.
Severity: Medium
