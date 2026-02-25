---
title: "Cheat Sheets"
---

One-pager cheat sheets for red team operations — techniques, implementations, and tooling.

### Offense

- [Active Directory Attacks](/references/ad-attacks/) — Kerberos, ACL abuse, credential harvesting, trust exploitation, ADCS
- [Credential Attacks & DPAPI](/references/credential-attacks/) — LSASS dumps, SAM/registry, DPAPI, NTLM relay, Kerberos creds
- [Lateral Movement](/references/lateral-movement/) — Pass-the-Hash, WMI, DCOM, RDP, Kerberos-based movement
- [Process Injection](/references/process-injection/) — CreateRemoteThread, DLL injection, shellcode injection, hollowing, APC
- [Persistence](/references/persistence/) — Registry, services, scheduled tasks, WMI, COM hijacking, bootkits
- [Privilege Escalation](/references/privilege-escalation/) — Token manipulation, UAC bypass, service exploits, kernel exploits
- [Initial Access](/references/initial-access/) — Phishing, drive-by, supply chain, trusted relationship, exploitation
- [Evasion](/references/evasion/) — AMSI bypass, ETW patching, unhooking, syscalls, obfuscation

### Infrastructure & OPSEC

- [Infrastructure](/references/infrastructure/) — C2 setup, redirectors, domain management, phishing, payload delivery
- [Phishing & Social Engineering](/references/phishing/) — Target profiling, pretext dev, email infra, vishing, physical SE, payload delivery
- [OPSEC](/references/opsec/) — Host/network artifacts, C2 patterns, identity management, tooling discipline
- [Cloud Attacks](/references/cloud-attacks/) — Azure/AWS/GCP enumeration, privilege escalation, persistence, lateral movement

### Exploit Development

- [Heap Exploitation (Windows)](/references/heap-exploitation/) — NT heap, segment heap, LFH, use-after-free, overflow, pool corruption
- [Kernel Exploitation (Windows)](/references/kernel-exploitation/) — Driver attack surface, pool exploitation, token abuse, BYOVD, callbacks

### Development

- [PE Parsing & Custom Loaders](/references/pe-parsing/) — PEB walking, export/import tables, manual mapping, syscalls, evasion
- [Shellcode Development (Windows x64)](/references/shellcode-dev/) — PIC fundamentals, API resolution, encoding, syscall shellcode, evasion stubs
