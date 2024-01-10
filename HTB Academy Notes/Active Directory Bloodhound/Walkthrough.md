---
created: 2023-11-13T10:59:30 (UTC -08:00)
tags: []
source: https://enterprise.hackthebox.com/academy-lab/6224/3329/modules/69/2074
author: 
---

# HTB Enterprise

> ## Excerpt
> SharpHound has many interesting options that help us define what information we want and how we can collect it. This section will explore some of the most common options we can use in SharpHound, and links to the official documentation as a reference for all SharpHound options.

---
# Active Directory BloodHound Module

## Section Questions Writeup

#### **Tier**: 3

#### **Difficulty**: Medium

#### **Type**: Offensive

#### **Created By**: mrb3n

#### **Co-Authors**: ippsec-3, plaintextHTB

## Section Questions and their Answers

| Section | Question Number | Answer |
| --- | --- | --- |
| SharpHound - Data Collection from Windows (Part 2) | Question 1 | DONE |
| Nodes | Question 1 | SRV01 |
| Nodes | Question 2 | HTB-STUDENT |
| Nodes | Question 3 | SERVERS |
| Nodes | Question 4 | FIREWALL\_MANAGER |
| Analyzing BloodHound Data | Question 1 | BACKUPS |
| Analyzing BloodHound Data | Question 2 | AddKeyCredentialLink |
| Analyzing BloodHound Data | Question 3 | DCSync |
| Analyzing BloodHound Data | Question 4 | Workstations |
| Analyzing BloodHound Data | Question 5 | 7 |
| Analyzing BloodHound Data | Question 6 | DC01 |
| Analyzing BloodHound Data | Question 7 | htb-student |
| BloodHound for BlueTeams | Question 1 | 30 |
| BloodHound for BlueTeams | Question 2 | WS01 |
| BloodHound for BlueTeams | Question 3 | SCREENSAVER |
| BloodHound for BlueTeams | Question 4 | MemberOf |
| Skills Assessment | Question 1 | jorge |
| Skills Assessment | Question 2 | ENTERPRISE ADMINS |
| Skills Assessment | Question 3 | WriteOwner |
| Skills Assessment | Question 4 | ESTER |
| Skills Assessment | Question 5 | JORGE |
| Skills Assessment | Question 6 | 30.76 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# SharpHound - Data Collection from Windows

## Question 1

### "Repeat the examples in the section and type DONE as the answer when you are finished."

Students will begin by initiating an RDP session (`htb-student:HTBRocks!`) to connect to the target:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTBRocks! /dynamic-resolution
```

```shell-session
┌─[eu-academy-1]─[10.10.15.73]─[htb-ac594497@htb-8lhfwtxnmo]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.228 /u:htb-student /p:HTBRocks! /dynamic-resolution

[20:19:15:760] [2092:2093] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[20:19:15:760] [2092:2093] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[20:19:15:760] [2092:2093] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[20:19:15:760] [2092:2093] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
<SNIP>
```

Then, students need to launch an elevated Command Prompt and navigate to `C:\Tools`, where the SharpHound.exe is located and can then be ran:

Code: cmd

```cmd
cd C:\tools
SharpHound.exe
```

```cmd-session
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\Tools\

C:\Tools>SharpHound.exe

2023-03-02T14:30:01.8643045-06:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-03-02T14:30:02.0674608-06:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-03-02T14:30:02.1144271-06:00|INFORMATION|Initializing SharpHound at 2:30 PM on 3/2/2023
2023-03-02T14:30:50.5205672-06:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts,

<SNIP>

2023-03-02T14:32:26.8799226-06:00|INFORMATION|Status: 141 objects finished (+141 1.46875)/s -- Using 41 MB RAM
2023-03-02T14:32:26.8799226-06:00|INFORMATION|Enumeration finished in 00:01:36.1041246
2023-03-02T14:32:27.0049183-06:00|INFORMATION|Saving cache with stats: 101 ID to type mappings.
 105 name to SID mappings.
 1 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-03-02T14:32:27.0205503-06:00|INFORMATION|SharpHound Enumeration Completed at 2:32 PM on 3/2/2023! Happy Graphing!
```

Because the neo4j database is already running on the target, students are free to simply launch Bloodhound from the current Command Prompt:

Code: cmd

```cmd
cd Bloodhound
BloodHound.exe
```

```cmd-session
C:\Tools>cd BloodHound

C:\Tools\BloodHound>BloodHound.exe

C:\Tools\BloodHound>
(node:3040) electron: The default of contextIsolation is deprecated and will be changing from false to true in a future release of Electron.  See https://github.com/electron/electron/issues/23506 for more information
(node:5052) [DEP0005] DeprecationWarning: Buffer() is deprecated due to security and usability issues. Please use the Buffer.alloc(), Buffer.allocUnsafe(), or Buffer.from() methods instead.
```

From the newly launched Bloodhound dashboard, students must enter credentials (`neo4j:Password123`) and then Login:

![Active_Directory_BloodHound_Walkthrough_Image_1.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_1.png)

Upon being greeted by the dashboard, students need to click the Upload Data button on the right hand side.

![Active_Directory_BloodHound_Walkthrough_Image_2.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_2.png)

And select the newly created BloodHound zip file:

![Active_Directory_BloodHound_Walkthrough_Image_3.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_3.png)

![Active_Directory_BloodHound_Walkthrough_Image_4.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_4.png)

After a brief moment, the data will be imported. Students are encouraged to explore the BloodHound tool and acquired domain data, familiarizing themselves with the tool and its interface.

Answer: `DONE`

# SharpHound - Data Collection from Windows (Part 2)

## Question 1

### "Connect to the target machine using haris credentials port 13389. Try to collect BloodHound data from a non-domain joined machine. Use DONE as answer when finished."

Students will begin by initiating an RDP session (`haris:Hackthebox`) to connect to the target on the alternate port 13389:

Code: shell

```shell
xfreerdp /v:STMIP:13389 /u:haris /p:Hackthebox /dynamic-resolution
```

```shell-session
┌─[eu-academy-1]─[10.10.15.73]─[htb-ac594497@htb-8lhfwtxnmo]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.226:13389 /u:haris /p:Hackthebox /dynamic-resolution

[21:03:19:105] [3555:3556] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[21:03:19:105] [3555:3556] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[21:03:19:105] [3555:3556] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[21:03:19:105] [3555:3556] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
<SNIP>
```

Then, students need to determine if they are on a domain-joined machine or not, utilizing an elevated Command Prompt:

Code: cmd

```cmd
echo %USERDOMAIN%
hostname
```

```cmd-session
Microsoft Windows [Version 10.0.19044.1826]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>echo %USERDOMAIN%
WS02

C:\Windows\system32>hostname
WS02
```

Seeing that the `%USERDOMAIN%` environment variable matches the hostname of the machine, students will know that the machine is not on a domain but rather a basic workgroup.

Therefore, students may to configure the DNS server to the IP 172.16.230.3. Using the current RDP session, students will navigate to Control Panel -> Network and Internet -> Network Connections. By right clicking on Ethernet0, students will click Properties:

![Active_Directory_BloodHound_Walkthrough_Image_5.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_5.png)

Choosing IPv4 and clicking Properties once again:

![Active_Directory_BloodHound_Walkthrough_Image_6.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_6.png)

Students need to ensure the DNS server is set to 172.16.130.3 and press OK:

![Active_Directory_BloodHound_Walkthrough_Image_7.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_7.png)

Using the Command Prompt from prior, students need to spawn a new instance of cmd.exe as a domain user:

Code: cmd

```cmd
runas /netonly /user:INLANEFREIGHT\htb-student cmd.exe
```

```cmd-session
C:\Windows\system32>runas /netonly /user:INLANEFREIGHT\htb-student cmd.exe

Enter the password for INLANEFREIGHT\htb-student:
Attempting to start cmd.exe as user "INLANEFREIGHT\htb-student" ...
```

Forcing a new Command Prompt to appear:

![Active_Directory_BloodHound_Walkthrough_Image_8.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_8.png)

Students need to confirm that they can interact with the Domain Controller via hostname:

Code: cmd

```cmd
net view \\inlanefreight.htb\
```

```shell-session
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

Now, students should be able to run the SharpHound against the inlanefreight.htb domain:

Code: cmd

```cmd
SharpHound.exe -d inlanefreight.htb
```

```cmd-session
C:\Windows\system32>C:\Tools\SharpHound.exe -d inlanefreight.htb

2023-03-02T14:01:28.0213701-08:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-03-02T14:01:28.2728057-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-03-02T14:01:28.3025190-08:00|INFORMATION|Initializing SharpHound at 2:01 PM on 3/2/2023
<SNIP>
2023-03-02T14:04:02.9273460-08:00|INFORMATION|Enumeration finished in 00:02:34.0393251
2023-03-02T14:04:03.0523373-08:00|INFORMATION|Saving cache with stats: 101 ID to type mappings.
 105 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-03-02T14:04:03.0679648-08:00|INFORMATION|SharpHound Enumeration Completed at 2:04 PM on 3/2/2023! Happy Graphing!
```

Students are encourage to explore other tactics shown in the section, such as writing the SharpHound output to a shared folder.

Answer: `DONE`

# BloodHound.py - Data Collection from Linux

## Question 1

### "Repeat the examples in the section and type DONE as the answer when you are finished."

Students need to download `bloodhound.py` and install it:

Code: shell

```shell
git clone https://github.com/fox-it/BloodHound.py -q & cd BloodHound.py/
sudo python3 setup.py install
```

```shell-session
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~]
└──╼ [★]$ git clone https://github.com/fox-it/BloodHound.py -q & cd BloodHound.py/
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~/BloodHound.py]
└──╼ [★]$ sudo python3 setup.py install

running install
running bdist_egg
running egg_info
creating bloodhound.egg-info
writing bloodhound.egg-info/PKG-INFO
<SNIP>
Using /usr/lib/python3/dist-packages
Finished processing dependencies for bloodhound==1.6.1
```

Then, students need to use `bloodhound.py` to gather data from the domain controller only, using kerberos to authenticate as (`htb-student:HTBRocks!`):

Code: shell

```shell
python3 bloodhound.py -d inlanefreight.htb -c DCOnly -u htb-student -p HTBRocks! -ns 10.129.204.226 --kerberos
```

```shell-session
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~/BloodHound.py]
└──╼ [★]$ python3 bloodhound.py -d inlanefreight.htb -c DCOnly -u htb-student -p HTBRocks! -ns 10.129.204.226 --kerberos
INFO: Found AD domain: inlanefreight.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.inlanefreight.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Connecting to LDAP server: dc01.inlanefreight.htb
INFO: Found 34 users
INFO: Found 60 groups
INFO: Found 5 gpos
INFO: Found 6 ous
INFO: Found 19 containers
INFO: Found 8 computers
INFO: Found 0 trusts
INFO: Done in 00M 02S
```

Once finished, students need to confirm the data was gathered and saved on their attack host:

Code: shell

```shell
ls | grep .json
```

```shell-session
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~/BloodHound.py]
└──╼ [★]$ ls | grep .json

20230304165415_computers.json
20230304165415_containers.json
20230304165415_domains.json
20230304165415_gpos.json
20230304165415_groups.json
20230304165415_ous.json
20230304165415_users.json
```

Students are encouraged to explore both NTLM and kerberos authentication methods using `bloodhound.py`.

Answer: `DONE`

# Nodes

## Question 1

### "To which computer is user Sarah, an administrator?"

Students need to first start the `neo4j` service prior to using `Bloodhound`:

Code: shell

```shell
sudo service neo4j start
bloodhound
```

```shell-session
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~]
└──╼ [★]$ sudo service neo4j start
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~]
└──╼ [★]$ bloodhound
(node:6531) electron: The default of contextIsolation is deprecated and will be changing from false to true in a future release of Electron.  See https://github.com/electron/electron/issues/23506 for more information
```

Giving it a few moments to launch, students will be greeted by the login screen where they can authenticate as `neo4j:neo4j`.

![Active_Directory_BloodHound_Walkthrough_Image_9.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_9.png)

Then, students need to upload the `BH.zip` file:

![Active_Directory_BloodHound_Walkthrough_Image_10.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_10.png)

Upon the completion of the Upload, students need to search for Sarah and go to the `Node Info` tab, scrolling down to `First Degree Local Admin` within the LOCAL ADMIN RIGHTS:

![Active_Directory_BloodHound_Walkthrough_Image_11.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_11.png)

![Active_Directory_BloodHound_Walkthrough_Image_12.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_12.png)

From the graphic generated, students will see that Sarah is AdminTo SRV01.

Answer: `SRV01`

# Nodes

## Question 2

### "Who is a first-degree remote desktop user on the computer WS01?"

Using the previously uploaded Bloodhound data, students need to search for WS01 and go to the `Node Info` tab, eventually scrolling down to `First Degree Remote Desktop Users` within the INBOUND EXECUTION RIGHTS:

![Active_Directory_BloodHound_Walkthrough_Image_13.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_13.png)

![Active_Directory_BloodHound_Walkthrough_Image_14.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_14.png)

From the graphic generated, students will see that `htb-student` is AdminTo WS01.

Answer: `htb-student`

# Nodes

## Question 3

### "Within which OU the computer SRV01 is located?"

Using the previously uploaded Bloodhound data, students need to search for SRV01 and go to the `Node Info` tab, selecting `See Computer within Domain/OU Tree` within OVERVIEW:

![Active_Directory_BloodHound_Walkthrough_Image_15.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_15.png)

![Active_Directory_BloodHound_Walkthrough_Image_16.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_16.png)

From the graphic generated, students will see that `SRV01` is within `SERVERS` OU.

Answer: `SERVERS`

# Nodes

## Question 4

### "Which non-default Group Policy affects all users?"

Using the previously uploaded Bloodhound data, students need to search for `Users` (making sure to select the container rather than group). From the `Node Info` tab, students need to select `GPOs Affecting This Container` within Affecting GPOs:

![Active_Directory_BloodHound_Walkthrough_Image_17.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_17.png)

![Active_Directory_BloodHound_Walkthrough_Image_18.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_18.png)

From the graphic generated, students will see that `FIREWALL_MANAGER` `GPO` affecting USERS containers

Answer: `FIREWALL_MANAGER`

# Edges

## Question 1

### "Repeat the examples in the section and type DONE as the answer when you are finished."

Students are highly encouraged to repeat the examples in the section, and once finished, type `DONE` as the answer.

Answer: `DONE`

# Analyzing BloodHound Data

## Question 1

### "What's the name of a non-default GPO that affects the Domain Controller container and can be used to escalate privileges in the Domain?"

Students need to first start the `neo4j` service prior to using `Bloodhound`:

Code: shell

```shell
sudo service neo4j start
bloodhound
```

```shell-session
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~]
└──╼ [★]$ sudo service neo4j start
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~]
└──╼ [★]$ bloodhound
(node:6531) electron: The default of contextIsolation is deprecated and will be changing from false to true in a future release of Electron.  See https://github.com/electron/electron/issues/23506 for more information
```

Giving it a few moments to launch, students will be greeted by the login screen where they can authenticate as `neo4j:neo4j`.

![Active_Directory_BloodHound_Walkthrough_Image_9.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_9.png)

Then, students need to upload the `BH.zip` file:

![Active_Directory_BloodHound_Walkthrough_Image_10.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_10.png)

After the upload has finished, students need to search for `DOMAIN CONTROLLERS` container and go to the `Node Info` tab, clicking `GPOs Affecting This OU` within Affecting GPOS:

![Active_Directory_BloodHound_Walkthrough_Image_19.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_19.png)

![Active_Directory_BloodHound_Walkthrough_Image_20.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_20.png)

From the graphic generated, students will see that `BACKUPS` `GPO` affecting `DOMAIN CONTROLLERS` `containers`.

Answer: `BACKUPS`

# Analyzing BloodHound Data

## Question 2

### "Using the attached data, find what rights the user Sarah has over the user Nicole."

Using the previously uploaded `BloodHound` data, students need to utilize the `Pathfind` feature, setting the start node as `SARAH` and the target note `NICOLE`:

![Active_Directory_BloodHound_Walkthrough_Image_21.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_21.png)

![Active_Directory_BloodHound_Walkthrough_Image_22.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_22.png)

From the graphic generated, students will know that `AddKeyCredentialLink` is the edge `SARAH` can use to compromise `NICOLE`.

Answer: `AddKeyCredentialLink`

# Analyzing BloodHound Data

## Question 3

### "Find what attack the Enterprise Admins group can execute over the Domain object."

Using the previously uploaded BloodHound data `BH.zip`, students need to utilize the `Pathfind` feature, setting the start node as `ENTERPRISE ADMINS` and the target note `INLANEFREIGHT.HTB`:

![Active_Directory_BloodHound_Walkthrough_Image_23.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_23.png)

Followed by students right clicking on the Help option for `GenericAll` and selecting the `Abuse Info` tab:

![Active_Directory_BloodHound_Walkthrough_Image_24.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_24.png)

There, students will find that `BloodHound` reveals the exact usage of a `DCSync` attack as a result of the `GenericAll` edge.

Answer: `DCSync`

# Analyzing BloodHound Data

## Question 4

### "Which OU is affected by the GPO ScreenSaver?"

Using the previously uploaded Bloodhound data `BH.zip`, students need to search for the `SCREENSAVER` GPO and go to the Node info tab, selecting `Directly Affected OUs` within AFFECTED OBJECTS:

![Active_Directory_BloodHound_Walkthrough_Image_25.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_25.png)

![Active_Directory_BloodHound_Walkthrough_Image_26.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_26.png)

From the graphic generated, students will know that `SCREENSAVER` GPO has a `GPLink` to the `OU` `WORKSTATIONS`.

Answer: `WORKSTATIONS`

# Analyzing BloodHound Data

## Question 5

### "How many incoming explicit object controllers exist in the Domain Users group?"

Using the previously uploaded Bloodhound data `BH.zip`, students need to search for the `Domain Users` group and go to the `Node Info` tab, selecting `Explicit Object Controllers` within `INBOUND CONTROL RIGHTS`:

![Active_Directory_BloodHound_Walkthrough_Image_27.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_27.png)

Students will find `7` incoming explicit object controllers on the `DOMAIN USERS` group.

Answer: `7`

# Analyzing BloodHound Data

## Question 6

### "Which host is Julio's user connected to? (only hostname)"

Using the previously uploaded Bloodhound data `BH.zip`, students need to search for the `JULIO` user and go to the Node info tab, selecting `SESSIONS` within OVERVIEW:

![Active_Directory_BloodHound_Walkthrough_Image_28.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_28.png)

![Active_Directory_BloodHound_Walkthrough_Image_29.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_29.png)

From the graphic generated, students will see that JULIO HasSession to `DC01`.

Answer: `DC01`

# Analyzing BloodHound Data

## Question 7

### "Which other user has a session on another computer?"

Using the previously uploaded Bloodhound data (`BH.zip`), students need to search for the `DOMAIN USERS` user and go to the Node info tab, selecting `SESSIONS` within OVERVIEW:

![Active_Directory_BloodHound_Walkthrough_Image_30.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_30.png)

![Active_Directory_BloodHound_Walkthrough_Image_31.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_31.png)

From the graphic generated, students will know that `HTB-STUDENT` HasSession to `WS01`.

Answer: `HTB-STUDENT`

# Cypher Queries

## Question 1

### "Use the file BH.zip from previous section and repeat the examples in the section and type DONE as the answer when you are finished."

Students are highly encouraged to repeat the examples in the section, and once finished, type `DONE` as the answer.

Answer: `DONE`

# BloodHound for BlueTeams

## Question 1

### "Using BlueHound custom dashboard. What percentage of users have a path to Domain Admins? (Do not include %)

Students need to first connect to the spawned target (`htb-student:HTBRocks!`) using RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTBRocks! /dynamic-resolution
```

```shell-session
┌─[eu-academy-1]─[10.10.15.19]─[htb-ac594497@htb-5876putejx]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.228 /u:htb-student /p:HTBRocks! /dynamic-resolution

[15:47:06:030] [2767:2768] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:47:06:031] [2767:2768] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[15:47:06:031] [2767:2768] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[15:47:06:031] [2767:2768] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
<SNIP>
```

Once the connection has been established, students will open File Explorer , navigate to `C:\Tools\BlueHound` and launch BlueHound.exe as administrator:

![Active_Directory_BloodHound_Walkthrough_Image_32.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_32.png)

Upon clicking Login, students need to authenticate (`neo4j:Password123`) to the database:

![Active_Directory_BloodHound_Walkthrough_Image_33.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_33.png)

![Active_Directory_BloodHound_Walkthrough_Image_34.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_34.png)

Now, students have access to the `BlueHound` dashboard, but they still need to import a configuration file. Therefore, students need to Click on `Import Config` -> `Select From File` -> `C:\Tools\bluehound_dashboard_htb.txt` and `LOAD DASHBOARD`:

![Active_Directory_BloodHound_Walkthrough_Image_35.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_35.png)

![Active_Directory_BloodHound_Walkthrough_Image_36.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_36.png)

![Active_Directory_BloodHound_Walkthrough_Image_37.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_37.png)

Subsequently, students need to click `Data Import` --> `RUN ALL`:

![Active_Directory_BloodHound_Walkthrough_Image_38.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_38.png)

![Active_Directory_BloodHound_Walkthrough_Image_39.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_39.png)

Students need to wait a few moments to allow the import to finish. Once completed, students must go to the Configuration Tab and fill out the corresponding information:

`Domain Controllers`: `DOMAIN CONTROLLERS@INLANEFREIGHT.HTB` `Domain Admins Group`: `DOMAIN ADMINS@INLANEFREIGHT.HTB` `CROWN JEWELS`: `SRV01.INLANEFREIGHT.HTB`

![Active_Directory_BloodHound_Walkthrough_Image_40.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_40.png)

Once complete, students need to click on `Query Runner` and `RUN ALL` (waiting a few moments for it to finish):

![Active_Directory_BloodHound_Walkthrough_Image_41.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_41.png)

Finally, students need to go to the `Dashboard` tab:

![Active_Directory_BloodHound_Walkthrough_Image_42.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_42.png)

There, they will see the `Users with Paths to DA`, which is `30`%.

Answer: `30`

# BloodHound for BlueTeams

## Question 2

### "Using BlueHound custom dashboard. Which computer has more Administrators?"

After completing the data import and collection from the previous questions, students need to navigate to Dashboard and look at `Computers by # of User's Admins`:

![Active_Directory_BloodHound_Walkthrough_Image_43.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_43.png)

Students will find `WS01` has a higher `ADMIN_COUNT` than the domain controller.

Answer: `WS01`

# BloodHound for BlueTeams

## Question 3

### "Using BlueHound custom dashboard. Domain User's group has dangerous permission over 3 objects, a user, a computer and a gpo. What's the name of the GPO?"

From the current `BlueHound` session, students need to go to the `Dashboard` tab and see the `Dangerous permissions "Domain Users"`:

![Active_Directory_BloodHound_Walkthrough_Image_44.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_44.png)

![Active_Directory_BloodHound_Walkthrough_Image_45.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_45.png)

There, students will see the user `Elieser`, the Computer SRV01 and the GPO `SCREENSAVER`.

Answer: `SCREENSAVER`

# BloodHound for BlueTeams

## Question 4

### "Which relationship (edge) do we need to remove to break the path between David and Domain Admins?"

From the previously established RDP session, students need to open Command Prompt as administrator and execute `Plumhound.py`:

```cmd
cd C:\Tools\PlumHound
python PlumHound.py -p Password123 -ap "DAVID@INLANEFREIGHT.HTB" "DOMAIN ADMINS@INLANEFREIGHT.HTB"
```

```cmd-session
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\Tools\PlumHound

C:\Tools\PlumHound>python PlumHound.py -p Password123 -ap "DAVID@INLANEFREIGHT.HTB" "DOMAIN ADMINS@INLANEFREIGHT.HTB"

        PlumHound 1.5.2
        For more information: https://github.com/plumhound
        --------------------------------------
        Server: bolt://localhost:7687
        User: neo4j
        Password: *****
        Encryption: False
        Timeout: 300
        --------------------------------------
        Task: Analyzer Path
        Start Node: DAVID@INLANEFREIGHT.HTB
---------------------------------------------------------------------
Analyzing paths between DAVID@INLANEFREIGHT.HTB and DOMAIN ADMINS@INLANEFREIGHT.HTB
---------------------------------------------------------------------
Removing the relationship MemberOf between DAVID@INLANEFREIGHT.HTB and DOMAIN ADMINS@INLANEFREIGHT.HTB breaks the path!
INFO    Tasks Generation Completed
Tasks: []
Executing Tasks |██████████████████████████████████████████████████| Tasks 0 / 0  in 0.1s (0.00/s)

        Completed 0 of 0 tasks.

```

From the output, students will see that removing the relationship `MemberOf` between `David` and `Domain Admins` breaks the path.

Answer: `MemberOf`

# Skills Assessment

## Question 1

### "Which user, with the exception of the Administrator and Intern user, does not explicitly have the ForceChangePassword edge but can change the password of the Active Directory user Sarah?"

Students first need to download [SA.zip](https://academy.hackthebox.com/storage/modules/69/SA.zip):

```shell
wget https://academy.hackthebox.com/storage/modules/69/SA.zip
```

```shell-session
┌─[us-academy-1]─[10.10.14.200]─[htb-ac413848@htb-qdtjrp0ojw]─[/tmp]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/69/SA.zip

--2023-03-07 14:43:58--  https://academy.hackthebox.com/storage/modules/69/SA.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 98008 (96K) [application/zip]
Saving to: ‘SA.zip’

SA.zip              100%[===================>]  95.71K  --.-KB/s    in 0.004s  

2023-03-07 14:43:58 (24.4 MB/s) - ‘SA.zip’ saved [98008/98008]
```

Subsequently, students need to start `neoj4` and then launch `BloodHound`:

```shell
sudo neo4j start
bloodhound
```

```shell-session
┌─[eu-academy-1]─[10.10.15.19]─[htb-ac594497@htb-hdrahhexud]─[~]
└──╼ [★]$ sudo neo4j start

Directories in use:
home:         /var/lib/neo4j
config:       /etc/neo4j
logs:         /var/log/neo4j
plugins:      /var/lib/neo4j/plugins
import:       /var/lib/neo4j/import
data:         /var/lib/neo4j/data
certificates: /var/lib/neo4j/certificates
licenses:     /var/lib/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
Started neo4j (pid:5801). It is available at http://localhost:7474
There may be a short delay until the server is ready.
┌─[eu-academy-1]─[10.10.15.19]─[htb-ac594497@htb-hdrahhexud]─[~]
└──╼ [★]$ bloodhound
```

Then, students need to upload `SA.zip` to begin the analysis:

![Active_Directory_BloodHound_Walkthrough_Image_46.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_46.png)

Once the data has been uploaded, students need to search for `SARAH` and select the green user (which is the Active Directory account), right clicking and selecting `Shortest Path Here`:

![Active_Directory_BloodHound_Walkthrough_Image_47.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_47.png)

![Active_Directory_BloodHound_Walkthrough_Image_48.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_48.png)\`

From the graphic generated, students will find that `JORGE` member of `DOMAIN ADMINS` has `GenericAll`, which also allow `JORGE` to change `Sarah`'s password.

Answer: `JORGE`

# Skills Assessment

## Question 2

### "Which group, other than Domain Admins, has direct WriteOwner privileges over the GPO "VPN CONFIGURATION"?"

Using the previously uploaded `SA.zip`, students need to first enable `Query Debug Mode` under `Settings`:

![Active_Directory_BloodHound_Walkthrough_Image_49.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_49.png)

Now, students need to search for `VPN CONFIGURATION` `GPO`, right click and select `Shortest Path to Here`:

![Active_Directory_BloodHound_Walkthrough_Image_50.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_50.png)

However, students need to modify the Raw Query, replacing `shortestPath` with `allshortestPaths`:

![Active_Directory_BloodHound_Walkthrough_Image_51.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_51.png)

![Active_Directory_BloodHound_Walkthrough_Image_52.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_52.png)

Alternatively, students can use another cypher query:

```cmd
Cypher Query: MATCH p=((g:Group)-[r:WriteOwner]->(o:GPO {name: "VPN CONFIGURATION@INLANEFREIGHT.HTB"})) WHERE NOT g.name CONTAINS "DOMAIN ADMINS" RETURN p
```

This query returns the variable `p`, which meets the criteria of being a group possessing the `WriteOwner` edge in a one-way relationship to the GPO `VPN CONFIGURATION@INLANEFREIGHT.HTB`. The group `g` must also not be `Domain Admins`:

![Active_Directory_BloodHound_Walkthrough_Image_53.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_53.png)

From the graphic generated, students will see the group `ENTERPRISE ADMINS` has direct `WriteOwner` over `VPN CONFIGURATION` `GPO`.

Answer: `ENTERPRISE ADMINS`

# Skills Assessment

## Question 3

### "The intern Active Directory user has DCSync rights. What other first-degree rights does he have in another object that he can use to compromise the Active Directory? (Use the edge as the answer)"

Using the previously uploaded `SA.zip`, students need to utilize a cypher query to find the other edge representing a possible domain compromise:

```cmd
MATCH p = allshortestPaths((n)-[*1..]->(c))  WHERE n.name =~ '(?i)INTERN.*' AND NOT c=n  RETURN p
```

This query looks for the shortest paths between nodes `n` and `c`, where the name of the node matches a regular expression for names starting with `INTERN`. It returns the entire path `p` for every path found. And if nodes `n` and `c` are the same, it returns nothing:

![Active_Directory_BloodHound_Walkthrough_Image_54.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_54.png)

From the graphic generated, students will know the other object `DC01` to which the `INTERN` user has `WriteOwner` and can be used to compromise the Domain.

Answer: `WriteOwner`

# Skills Assessment

## Question 4

### "Which Azure user, who has no Azure AD admin roles assigned, can execute commands on the DB002 machine?"

Using the previously uploaded `SA.zip`, students need search for `DB002`, right click and select `Shortest Path to Here`:

![Active_Directory_BloodHound_Walkthrough_Image_55.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_55.png)

![Active_Directory_BloodHound_Walkthrough_Image_56.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_56.png)

From the graphic generated, students will know that the user `ESTER` which has the edge `AZOwns` over `DB002`. Subsequently, students need to click the user `ESTER` and go to the `Node Info` tab:

![Active_Directory_BloodHound_Walkthrough_Image_57.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_57.png)

Within `OVERVIEW`, students will know the `Azure AD Admin Roles` is `0`, which means `ESTER` is not member of any `Azure Role`.

Answer: `Ester`

# Skills Assessment

## Question 5

### "Which Azure user has a path to add himself as Global Administrator?"

Using the previously uploaded `SA.zip`, students need to search for `GLOBAL ADMINISTRATORS`, right clicking to select `Shortest Path to Here`:

![Active_Directory_BloodHound_Walkthrough_Image_58.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_58.png)

![Active_Directory_BloodHound_Walkthrough_Image_59.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_59.png)

From the graphic generated, students will know that the user `JORGE` which has the edge `AZOwns` over `Azure_Manager` `Service Principal`.

Looking closely, students will find `Azure_Manager` has `AZPrivilegedRoleAdmin`. Consequently, they need to click the edge and see the `ABUSE` info tab:

![Active_Directory_BloodHound_Walkthrough_Image_60.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_60.png)

![Active_Directory_BloodHound_Walkthrough_Image_61.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_61.png)

This means that the user, `Jorge`, can add himself as `Global Administrator`.

Answer: `Jorge`

# Skills Assessment

## Question 6

### "Find the percentage of users with a path to GLOBAL ADMINISTRATOR. Submit the number as your answer (to two decimal points, i.e., 11.78)."

Students need to utilize a cypher query from within the `neo4j` console.

Navigating to http://localhost:7474/browser, students will need to enter their username and password:

![Active_Directory_BloodHound_Walkthrough_Image_62.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_62.png)

Then, students need to use a cypher query to search for nodes labeled `AZUser` and `AZRole`, specifying that the results contain only nodes whose name starts with `GLOBAL ADMIN`, then performing a count of the number of `AZUser` nodes and finding the shortest paths, to return the percentage of `AZUser` nodes that have a path to `GLOBAL ADMIN`:

```cmd
MATCH (u:AZUser) MATCH (g:AZRole) WHERE g.name STARTS WITH 'GLOBAL ADMIN' WITH g, COUNT(u) as userCount MATCH p = shortestPath((u:AZUser)-[*1..]->(g)) RETURN 100.0 * COUNT(DISTINCT u) / userCount as percent
```

![Active_Directory_BloodHound_Walkthrough_Image_63.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_63.png)

![Active_Directory_BloodHound_Walkthrough_Image_64.png](https://academy.hackthebox.com/storage/walkthroughs/60/Active_Directory_BloodHound_Walkthrough_Image_64.png)

Alternatively, students can use a different cypher query, attaining the same value `30.76`:

```cmd
MATCH (totalUsers:AZUser) MATCH p=shortestPath((UsersWithPath:AZUser)-[r*1..]->(o:AZRole {name:'GLOBAL ADMINISTRATOR@DEFAULT DIRECTORY'})) WITH COUNT(DISTINCT(totalUsers)) as totalUsers, COUNT(DISTINCT(UsersWithPath)) as UsersWithPath RETURN 100.0 * UsersWithPath / totalUsers AS percentUsersToDA
```

Answer: `30.76`