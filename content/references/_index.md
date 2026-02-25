---
title: "Cheat Sheets"
---

One-pager cheat sheets for red team operations — techniques, implementations, and tooling.

### Offense

- [Active Directory Attacks](/references/ad-attacks/) — Kerberos, ACL abuse, credential harvesting, trust exploitation, ADCS
- [Lateral Movement](/references/lateral-movement/) — Pass-the-Hash, WMI, DCOM, RDP, Kerberos-based movement
- [Process Injection](/references/process-injection/) — CreateRemoteThread, DLL injection, shellcode injection, hollowing, APC
- [Persistence](/references/persistence/) — Registry, services, scheduled tasks, WMI, COM hijacking, bootkits
- [Privilege Escalation](/references/privilege-escalation/) — Token manipulation, UAC bypass, service exploits, kernel exploits
- [Initial Access](/references/initial-access/) — Phishing, drive-by, supply chain, trusted relationship, exploitation
- [Evasion](/references/evasion/) — AMSI bypass, ETW patching, unhooking, syscalls, obfuscation

### Infrastructure & OPSEC

- [Infrastructure](/references/infrastructure/) — C2 setup, redirectors, domain management, phishing, payload delivery
- [OPSEC](/references/opsec/) — Host/network artifacts, C2 patterns, identity management, tooling discipline
- [Cloud Attacks](/references/cloud-attacks/) — Azure/AWS/GCP enumeration, privilege escalation, persistence, lateral movement

### Development

- [PE Parsing & Custom Loaders](/references/pe-parsing/) — PEB walking, export/import tables, manual mapping, syscalls, evasion
