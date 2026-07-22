# Path Traversal Tests
Test ID: FS-03
Category: Filename traversal
Attack Objective: Write file outside uploads directory
Payload: `../../system.txt`
Expected Vulnerable Behavior: Overwrites critical system files.
Expected Secure Behavior: Strips path characters and saves in uploads/.
Severity: Critical
