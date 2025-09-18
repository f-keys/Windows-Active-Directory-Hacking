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


