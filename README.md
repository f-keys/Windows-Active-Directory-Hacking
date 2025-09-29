# Windows-Active-Directory-Hacking
> Study notes / lab guide — educational use and authorized testing only.  
> Reference: TCM Academy.

---

## Table of contents
- [Overview](#overview)
- [Lab setup](#lab-setup)
- [Initial attack vectors](#initial-attack-vectors)
  - [LLMNR Poisoning](#llmnr-poisoning)
  - [SMB Relay](#smb-relay)
  - [IPV6 / mitm6](#ipv6--mitm6)
  - [Passback attacks](#passback-attacks)
- [Gaining shells / lateral movement](#gaining-shells--lateral-movement)
- [Post-compromise enumeration](#post-compromise-enumeration)
  - [ldapdomaindump](#ldapdomaindump)
  - [BloodHound / PlumHound / PingCastle](#bloodhound--plumhound--pingcastle)
- [Post-compromise attacks & persistence](#post-compromise-attacks--persistence)
  - [Pass-the-Hash / Pass-the-Password](#pass-the-hash--pass-the-password)
  - [Kerberoasting](#kerberoasting)
  - [Token impersonation (meterpreter/incognito)](#token-impersonation-meterpreterincognito)
  - [LNK file attacks](#lnk-file-attacks)
  - [GPP / cPassword](#gpp--cpassword)
- [Domain compromise: NTDS & Golden Tickets](#domain-compromise-ntds--golden-tickets)
- [Mitigations summary](#mitigations-summary)
- [Responsible use & license](#responsible-use--license)

---

## Overview
Concise, lab-oriented notes about offensive techniques against Windows Active Directory environments. Intended for authorized labs and learning only.

---

## Lab setup
- Minimal lab: 1 Windows Server (Domain Controller — e.g., Windows Server 2022) and two Windows 10/11 clients.
- Rename the DC for your lab (example used in notes: `UNCLE-DC`).
- Promote the server to a Domain Controller by installing **Active Directory Domain Services**.
- Example forest name used in these notes: `FKEYS.local`.
- Install **Active Directory Certificate Services** if you plan to experiment with certificate-based attacks later.

> **Note:** remove or replace real hostnames/IPs/credentials before publishing.

---

## Initial attack vectors

### LLMNR Poisoning
- **High-level:** LLMNR (and NetBIOS name resolution) can allow an attacker on the same subnet to respond to name resolution requests and capture NTLM challenge/response hashes.
- **Tool (example):**
```bash
# responder: listen on interface eth0, verbose, log, etc.
sudo responder -I eth0 -ldwPv
