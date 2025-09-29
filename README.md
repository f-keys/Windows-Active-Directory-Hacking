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
High-level flow: attacker responds to victim LLMNR/NetBIOS queries → victim authenticates using NTLM challenge/response → attacker captures hash.

Cracking (example):

bash
Copy code
# hash cracking (example from notes)
hashcash -m 5600 hashes.txt /path/to/wordlist/
Mitigation:

Disable LLMNR via Group Policy where possible.

Enforce strong network segmentation and least privilege for resources.


SMB Relay attacks
High-level: Instead of capturing hashes and offline cracking, relay captured NTLM challenge/response directly to another SMB/LDAP/LDAPS service to authenticate as the victim.

Prerequisites for success:

SMB signing not enforced on the target.

The relayed account must have sufficient privileges on the target (often local admin).

Responder config: you can toggle/protect protocols via /etc/responder/Responder.conf (e.g., enable/disable SMB/HTTP listeners).

Example tools / commands (high-level):

bash
Copy code
# responder - listen for requests on interface eth0
sudo responder -I eth0 -ldwPv

# impacket's relay tool to target services listed in target.txt
impacket-ntlmrelayx -tf target.txt -smb2support
Mitigation:

Enforce SMB signing.

Disable NTLM where possible / use NTLMv2 + sign/secure channel.

Apply account tiering and limit local admin scope.


Gaining shells / lateral movement (overview)
Metasploit psexec module — noisy, often detected in live environments. Example Metasploit settings shown in lab notes (RHOSTS, SMBDomain, SMBUser, SMBPass).

Using NTLM/SAM hashes obtained from relays or dumps to authenticate remotely (e.g., with psexec.py or impacket tools).

bash
Copy code
# example: psexec via impacket
psexec.py DOMAIN/user:@ip-address
Mitigations: monitoring, endpoint detection, and reducing credential re-use.


IPV6 attacks (mitm6)
High-level: mitm6 abuses Windows behavior that queries for IPv6 addresses; an attacker can reply and route authentication to an attacker-controlled relay, then ntlmrelayx relays to an LDAP/LDAPS or SMB target.

Tools / example commands (high-level only):

bash
Copy code
# mitm6 advertises IPv6 on the network for domain fkeys.local
mitm6 -d fkeys.local

# relay captured credentials to an LDAPS target (example)
ntlmrelayx.py -6 -t ldaps://<IP_of_DC> -wh anything.fkeys.local -l lootbox
What these do (high-level):

mitm6 advertises IPv6 to victims so their authentication can be redirected.

ntlmrelayx listens for incoming NTLM auth and relays it to the specified target service.

Mitigations (summary):

Block DHCPv6 and router advertisements via Windows Firewall/GPO if IPv6 is not used internally.

Disable Windows Auto-Proxy Discovery (WAD) if not required.

Enable LDAP signing and LDAP channel binding.

Put administrative accounts into Protected Users or mark them as sensitive to prevent impersonation via delegation.


Passback attacks
Briefly referenced in notes; these involve relaying or reusing authentication contexts back to other services — mitigation focuses on disabling NTLM/relay protections and enforcing signing.

Post-compromise enumeration
A. ldapdomaindump
High-level: gather directory information over LDAP(S).

bash
Copy code
ldapdomaindump ldaps://<ip_of_DC> -u 'DOMAIN\User' -p 'password'
Note: Do not leave plaintext credentials in the repo. Replace with placeholders.


B. BloodHound (data collection)
Use collectors such as bloodhound-python or other ingestors to collect data and import JSON into the BloodHound UI.

bash
Copy code
bloodhound-python -d <DOMAIN> -u <user> -p <password> -ns <ip_of_DC> -c all
Upload resulting JSON files to BloodHound for graph analysis.


C. PlumHound
Similar concept: collect data for graph analysis and checking Neo4j connectivity:

bash
Copy code
PlumHound.py --easy -p <neo4j_password>
PlumHound.py -x tasks/default.tasks -p neo4j1

D. PingCastle
Enumerative assessment tool (see PingCastle docs).

Post-compromise attacks (selected)
Pass-the-Hash / Pass-the-Password (overview)
Tools: crackmapexec, secretsdump, impacket suite.

Examples (high-level):

bash
Copy code
# enumerate SMB using username/password
crackmapexec smb <ip/CIDR> -u <user> -d <domain> -p <password>

# pass-the-hash example using crackmapexec
crackmapexec smb <ip/CIDR> -u administrator -H <ntlm_hash> --local-auth
Use of --sam to dump SAM hashes, --shares to enumerate share permissions.

Dumping hashes: impacket-secretsdump can retrieve many artifacts (SAM, LSA secrets, cached creds).

bash
Copy code
impacket-secretsdump 'DOMAIN\\user:Password'@<ip-address>
impacket-secretsdump administrator@<ip_address> -hashes <LM:NT>
Mitigation summary: limit account re-use, rotate local admin passwords (PAM), disable unnecessary accounts, enforce least privilege.


Kerberoasting (overview)
High-level: requests service tickets (TGS) for SPNs associated with service accounts — offline cracking against those tickets can reveal service-account passwords if weak.

Tool example (high-level):

bash
Copy code
impacket-GetUserSPNs FKEYS.local/bjames:Password! -dc-ip 192.168.182.139 -request
Crack captured ticket blobs with hashcat (mode for RC4/HASH type shown in notes).

bash
Copy code
hashcat -m 13100 krb.txt /usr/share/wordlists/rockyou.txt
Mitigation: strong passwords for service accounts, managed service accounts (gMSA), least privilege.


Token impersonation (meterpreter + incognito)
High-level: once you have an interactive shell (e.g., meterpreter), use token utilities (incognito) to list and impersonate tokens available on the host.

High-level flow: gain shell → list tokens → impersonate a token → perform actions as impersonated principal.

Mitigation: reduce local token availability, restrict privileged user logons on endpoints, use account tiering.


LNK file attacks
High-level: malicious shortcut files (.lnk) can be used to trigger remote requests or execute payloads when a user browses a share.

Mitigation: restrict file share write access, monitor for unexpected executable references in shares.


GPP / cPassword attacks (high-level)
Group Policy Preferences historically allowed storing passwords in cpassword — these values can be decrypted if present. Ensure GPP is not used for storing secrets and that legacy GPP items are audited and removed.

Domain compromise: NTDS & Golden Tickets
Dumping NTDS.dit
High-level: NTDS.dit stores AD database contents including password hashes. Dumping and cracking yields full domain credential lists.

Mitigation: protect domain controllers, restrict DC access, monitor tools and unusual system activity.

Golden Ticket attacks (high-level)
High-level: compromise of the Kerberos KRBTGT account allows forging Ticket Granting Tickets (TGTs) — effectively, domain-wide persistent access.

Mitigation: protect KRBTGT, monitor replication and privileged account changes, regularly rotate KRBTGT keys in large enterprise processes if compromise suspected.

Mitigations summary
Disable LLMNR and NetBIOS name resolution where possible.

Enforce SMB signing and disable NTLM where feasible.

Enable LDAP signing and channel binding.

Reduce local admin reuse; implement Privileged Access Management (PAM).

Protect DCs, limit exposure, monitor sensitive log sources.

Use account tiering, Protected Users, and least privilege principles.

