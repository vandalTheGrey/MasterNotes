
# Questions

Connect to the target machine using haris credentials port 13389. Try to collect BloodHound data from a non-domain joined machine. Use DONE as answer when finished.
# RDP 
```
xfreerdp /u:haris /p:Hackthebox /v:10.129.204.226:13389 /dynamic-resolution /drive:/home/p3ta/htb/,p3ta
```

You can either transfer files by mounting a drive with xfreerdp or use impacket-smbserver to create a share.
# SMBserver
```
sudo impacket-smbserver share ./ -smb2support -user test -password test
```


I ended up using /drive to transfer my tools

![[Pasted image 20231113112839.png]]

More information on collection methods 

https://blog.compass-security.com/2022/05/bloodhound-inner-workings-part-2/

Since we are running as a local user we need to authenticate to the domain.

# Runas
```
C:\>runas /netonly /user:INLANEFREIGHT\htb-student cmd.exe
Enter the password for INLANEFREIGHT\htb-student:
Attempting to start cmd.exe as user "INLANEFREIGHT\htb-student" ...
```

# Netview
Confirmation that we have successfully authenticated 
```
Microsoft Windows [Version 10.0.19044.1826]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>net view \\inlanefreight.htb\
Shared resources at \\inlanefreight.htb\



Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
CertEnroll  Disk           Active Directory Certificate Services share
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.
```

![[Pasted image 20231113113728.png]]