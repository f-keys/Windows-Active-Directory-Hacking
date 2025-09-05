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

you can also use the sam hash that was gotten from ntlmrelay.py to gain shell. Here, you are gaining shell as in administrator. To do this, You meed to set the SMBUser to administrator. you can also remove the SMBDomain that was previously set as it is not needed. we are loggin locally as in admin. Then finally set eh SMBPass withe the admin sam hashes
<img width="917" height="201" alt="image" src="https://github.com/user-attachments/assets/781b0459-7d41-409b-a135-9d77cc64f8a3" />





3. The use of psexec.py tool
