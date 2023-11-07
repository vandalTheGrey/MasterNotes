## BloodHound Overview

___

## Active Directory Access Management

Access management in Active Directory is complex, and it is easy to introduce vulnerabilities or bad practices in day-to-day configurations.

Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.

Because the attack surface and the amount of data produced in Active Directory environments are highly complex and evolving, and because we needed a way to automate the collection and analysis of this data, [@\_wald0](https://www.twitter.com/_wald0), [@harmj0y](https://twitter.com/harmj0y), and [@CptJesus](https://twitter.com/CptJesus) created [BloodHound](https://github.com/BloodHoundAD/BloodHound).

## BloodHound Overview

[BloodHound](https://github.com/BloodHoundAD/BloodHound) is an open-source tool used by attackers and defenders alike to analyze Active Directory domain security. The tool collects a large amount of data from an Active Directory domain. It uses the graph theory to visually represent the relationship between objects and identify domain attack paths that would have been difficult or impossible to detect with traditional enumeration. As of version 4.0, BloodHound now also supports Azure. Although the primary purpose of this module will be Active Directory, we will introduce AzureHound in the section [Azure Enumeration](https://academy.hackthebox.com/module/69/section/2070).

Data to be utilized by BloodHound is gathered using the [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) collector, which is available in PowerShell and C#. We will discuss data collection in the following sections.

___

## BloodHound Graph Theory & Cypher Query Language

`BloodHound` utilizes [Graph Theory](https://en.wikipedia.org/wiki/Graph_theory), which are mathematical structures used to model pairwise relations between objects. A graph in this context is made up of [nodes](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html) (Active Directory objects such as users, groups, computers, etc.) which is connected by [edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) (relations between an object such as a member of a group, AdminTo, etc.). We will discuss nodes and edges further in another section, but let's do an example to see how BloodHound works.

The tool uses [Cypher Query Language](https://neo4j.com/docs/getting-started/current/cypher-intro/) to analyze relationships. Cypher is Neo4j’s graph query language that lets us retrieve data from the graph. It is like SQL for graphs, and was inspired by SQL so it lets us focus on what data we want out of the graph (not how to go get it). It is the easiest graph language to learn by far because of its similarity to other languages and intuitiveness. We will discuss more about Cypher quries later in this module.

The below diagram shows two nodes, `A` and `B`. In this example, we can only go from node `A` to node `B`, not the other way.

![image](https://academy.hackthebox.com/storage/modules/69/BH_nodes6.png)

This could simulate `A` as the user `Grace` and `B` as the group `SQL Admins`, the line between the two is the edge, which in this case is `MemberOf`. The next graphic show us that in BloodHound, where the user `Grace` is a member of the `SQL Admins` group.

![text](https://academy.hackthebox.com/storage/modules/69/grace_to_SQLAdmin.jpg)

Let's see a more complex relationship between nodes. The following graphic shows eight (8) nodes and ten (10) edges. Node `H` can reach node `G`, but no node has a direct path to node `H`. To get to node `C` from node `A`, we can hop to node `G`, move to node `F`, and then to node `C`, but that's not the shortest path. One of the BloodHound capabilities is to look for the shortest path. In this example, the shortest path from node `A` to node `C` is one hop through node `B`.

![image](https://academy.hackthebox.com/storage/modules/69/BH_node_edges6.png)

In the previous example, we used BloodHound to find that `Grace` is a member of `SQL Admins`, which is pretty simple to discover. We can use the `Active Directory Users and Computers` GUI or the `net user grace /domain` command. With only this information, we can conclude that `Grace` doesn't have any path to the `Domain Admins` group, but that is where BloodHound is much more helpful in helping us identify those relationships between nodes that are not easy to locate.

Let's use BloodHound as our map navigator and ask how to get from the user `Grace` to the `Domain Admins` group. Here's the result:

![text](https://academy.hackthebox.com/storage/modules/69/grace-to-da.jpg)

This means that `Grace`, as a member of the `SQL Admins` group, can change `Peter`'s password. Authenticate with `Peter`'s new password and perform operations as a member of the `Domain Admins` group. Although `Peter` is not a member directly, he is a member of a group that is.

___

## BloodHound for Enterprise

The [SpecterOps](https://specterops.io/) team that created BloodHound also created [BloodHound Enterprise](https://bloodhoundenterprise.io/). An Attack Path Management solution that continuously maps and quantifies Active Directory Attack Paths. Ideal for enterprises that want to constantly monitor the different types of on-premises and cloud attack paths, prioritize their actions, obtain remediation guidance, and continuously measure their security posture.

The good thing about this project is that the BloodHound for Enterprise team uses a common library between the commercial and the [FOSS](https://en.wikipedia.org/wiki/Free_and_open-source_software) project and introduces [SharpHound Common](https://github.com/BloodHoundAD/SharpHoundCommon): one code base from which both FOSS SharpHound and SharpHound Enterprise are built. This code base enables, among other things:

-   Improved [documentation](https://bloodhoundad.github.io/SharpHoundCommon/index.html).
-   Improves the quality and stability of SharpHound for everyone.

___

## Moving On

Now that we have covered graph theory and how `BloodHound` works with nodes and edges to find the shortest paths, let's move on and collect some data that we can ingest into `BloodHound` and start manipulating.

___

## Module Exercises

Throughout this module, you will connect to various target hosts via the Remote Desktop Protocol (RDP) to complete the exercises. We will provide any necessary credentials with each exercise, and the RDP connection can be made via `xfreerdp` from the Pwnbox as follows:

#### Connecting via RDP

```
p3ta@htb[/htb]$ xfreerdp /v:<target IP address> /u:htb-student /p:<password>

```

After logging in to the target host, all tools can be found in the `C:\Tools` directory.

___

## BloodHound Setup and Installation

BloodHound use [Neo4j](https://neo4j.com/), a graph database management system designed to store, manage, and query data represented in a graph. It is a NoSQL database that uses a graph data model to represent and store data, with nodes and edges representing the data and relationships, respectively. This allows Neo4j to represent complex and interconnected data structures more intuitively and efficiently than traditional relational databases.

[Neo4j](https://neo4j.com/) is written in Java and requires a Java Virtual Machine (JVM) to run.

BloodHound can be installed on Windows, Linux, and macOS. We will need to install Java and Neo4j and then download the BloodHound GUI. We can also build the BloodHound GUI from the source, but we won't cover that step in this section. If you want to build from the source, you can read [BloodHound official documentation](https://bloodhound.readthedocs.io/en/latest/index.html).

We will do the installation in 3 steps:

1.  Install Java.
2.  Install Neo4j.
3.  Install BloodHound.

**Note:** BloodHound 4.2 is installed in PwnBox and ready to use. Both binaries are in the path, you can use `sudo neo4j console` to start the Neo4j database and `bloodhound` to launch BloodHound GUI.

BloodHound is installed on the target machine. It is not necessary to install it. To run it we would only need to start the database with the following command `net start neo4j` and execute `bloodhound.exe` which is in the `C:\Tools` folder.

___

## Windows Installation

We first need to download and install [Java Oracle JDK 11](https://www.oracle.com/java/technologies/javase-jdk11-downloads.html). We need to register an account before downloading Java from their website. Once we download the installation file, we can silently install it using the following command:

#### Install Java Silently

```
PS C:\htb> .\jdk-11.0.17_windows-x64_bin.exe /s
```

Next, we need to install `Neo4j`. We can get the complete list of available versions in the [Neo4j Download Center](https://neo4j.com/download-center/#community). We will use Neo4j 4.4, the latest version at the time of writing is [Neo4j 4.4.16](https://go.neo4j.com/download-thanks.html?edition=community&release=4.4.16&flavour=winzip). Once downloaded, open Powershell, running as administrator, and extract the content of the file:

#### Unzip Neo4j

```
PS C:\htb> Expand-Archive .\neo4j-community-4.4.16-windows.zip .
```

**Note:** Neo4j 5, the latest version, suffers from severe performance regression issues, this is why we are not using version 5. For more information visit: [BloodHound Official Documentation](https://bloodhound.readthedocs.io/en/latest/installation/windows.html).

Next, we need to install Neo4j. To install it as a service, we need to move to the `.\neo4j-community-*\bin\` directory and execute the following command `neo4j.bat install-service`:

#### Install Neo4j Service

```
PS C:\htb> .\neo4j-community-4.4.16\bin\neo4j.bat install-service
Neo4j service installed.
```

**Note:** At this point, we may see an error about Java not being found or the wrong version of Java running. Ensure your **JAVA\_HOME** environment variable is set to the JDK folder (example: C:\\Program Files\\Java\\jdk-11.0.17); this is done automatically after installation. Still, if the installation fails, we must ensure everything is configured correctly.

Once the service is installed, we can start the service:

#### Start Service

```
PS C:\htb> net start neo4j
The Neo4j Graph Database - neo4j service is starting..
The Neo4j Graph Database - neo4j service was started successfully.
```

## Configure Neo4j Database

To configure the Neo4j database, open a web browser and navigate to the Neo4j web console at [http://localhost:7474/](http://localhost:7474/):

![text](https://academy.hackthebox.com/storage/modules/69/neo4j_web_console.jpg)

Authenticate to Neo4j in the web console with username `neo4j` and password `neo4j`, leave the database empty, and once prompted, change the password.

![text](https://academy.hackthebox.com/storage/modules/69/neo4j_change_password.jpg)

## Download BloodHound GUI

1.  Download the latest version of the BloodHound GUI for Windows from [https://github.com/BloodHoundAD/BloodHound/releases](https://github.com/BloodHoundAD/BloodHound/releases).

![text](https://academy.hackthebox.com/storage/modules/69/bloodhound_download.jpg)

**Note:** We may get a warning from the Browser or the AV that the file is malicious. Ignore and allow the download.

2.  Unzip the folder and double-click BloodHound.exe.
    
3.  Authenticate with the credentials you set up for neo4j.
    

![text](https://academy.hackthebox.com/storage/modules/69/bloodhound_authentication.jpg)

___

## Linux Installation

The first thing we need to do is download and install `Java Oracle JDK 11`. We will update our apt sources to install the correct package:

#### Updating APT sources to install Java

```
p3ta@htb[/htb]# echo "deb http://httpredir.debian.org/debian stretch-backports main" | sudo tee -a /etc/apt/sources.list.d/stretch-backports.list
# sudo apt-get update
...SNIP...

```

With this update, if Java is not installed when we try to install Neo4j, it will automatically install it as part of the Neo4j installation. Let's add the apt sources for Neo4j installation:

#### Updating APT sources to install Neo4j

```
p3ta@htb[/htb]$ wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
$ echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
$ sudo apt-get update
...SNIP...

```

Before installing Neo4j, we need to install the `apt-transport-https` package with apt:

#### Installing required packages

```
p3ta@htb[/htb]$ sudo apt-get install apt-transport-https
...SNIP...

```

Now we can install Neo4j. Let's first list the available options and pick the latest 4.4.X version.

#### Installing Neo4j

```
p3ta@htb[/htb]$ sudo apt list -a neo4j 
sudo apt list -a neo4j 
Listing... Done
neo4j/stable 1:5.3.0 all [upgradable from: 1:4.4.12]
neo4j/stable 1:5.2.0 all
neo4j/stable 1:5.1.0 all
neo4j/stable 1:4.4.16 all
neo4j/stable 1:4.4.15 all
neo4j/stable 1:4.4.14 all
neo4j/stable 1:4.4.13 all
neo4j/stable,now 1:4.4.12 all [installed,upgradable to: 1:5.3.0]
neo4j/stable 1:4.4.11 all
neo4j/stable 1:4.4.10 all
neo4j/stable 1:4.4.9 all
...SNIP...

```

At the time of writting. The latest version is Neo4j 4.4.16, let's install that version with the following command:

#### Installing Neo4j 4.4.X

```
p3ta@htb[/htb]$ sudo apt install neo4j=1:4.4.16 -y
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following packages will be upgraded:
  neo4j
1 upgraded, 0 newly installed, 0 to remove, and 236 not upgraded.
Need to get 106 MB of archives.
After this operation, 1,596 kB of additional disk space will be used.
Get:1 https://debian.neo4j.com stable/4.4 amd64 neo4j all 1:4.4.16 [106 MB]
Fetched 106 MB in 2s (55.9 MB/s)
...SNIP...

```

Next, we need to make sure we are using Java 11. We can update which java version our operating system will use with the following command:

#### Change Java version to 11

```
p3ta@htb[/htb]$ sudo update-alternatives --config java
There are 2 choices for the alternative java (providing /usr/bin/java).

  Selection    Path                                         Priority   Status
------------------------------------------------------------
  0            /usr/lib/jvm/java-13-openjdk-amd64/bin/java   1311      auto mode
* 1            /usr/lib/jvm/java-11-openjdk-amd64/bin/java   1111      manual mode
  2            /usr/lib/jvm/java-13-openjdk-amd64/bin/java   1311      manual mode

Press <enter> to keep the current choice[*], or type selection number: 1

```

**Note:** Option 1 correspond to Java 11. The option may be different in your system.

We can start `Neo4j` as a console application to verify it starts up without errors:

#### Running Neo4j as console

```
p3ta@htb[/htb]$ cd /usr/bin
$ sudo ./neo4j console
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
2023-01-05 20:04:26.679+0000 INFO  Starting...
2023-01-05 20:04:27.369+0000 INFO  This instance is ServerId{fb3f5e13} (fb3f5e13-5dfd-49ee-b068-71ad7f5ce997)
2023-01-05 20:04:29.103+0000 INFO  ======== Neo4j 4.4.16 ========
2023-01-05 20:04:30.562+0000 INFO  Performing postInitialization step for component 'security-users' with version 3 and status CURRENT
2023-01-05 20:04:30.562+0000 INFO  Updating the initial password in component 'security-users'
2023-01-05 20:04:30.862+0000 INFO  Bolt enabled on localhost:7687.
2023-01-05 20:04:31.881+0000 INFO  Remote interface available at http://localhost:7474/
2023-01-05 20:04:31.887+0000 INFO  id: 613990AF56F6A7BDDA8F79A02F0ACED758E04015C5B0809590687C401C98A4BB
2023-01-05 20:04:31.887+0000 INFO  name: system
2023-01-05 20:04:31.888+0000 INFO  creationDate: 2022-12-12T15:59:25.716Z
2023-01-05 20:04:31.888+0000 INFO  Started.

```

To start and stop the service, we can use the following commands:

#### Start Neo4j

```
p3ta@htb[/htb]$ sudo systemctl start neo4j

```

#### Stop Neo4j

```
p3ta@htb[/htb]$ sudo systemctl stop neo4j

```

**Note:** It is very common for people to host Neo4j on a Linux system but use the BloodHound GUI on a different system. Neo4j, by default, only allows local connections. To allow remote connections, open the neo4j configuration file located at `/etc/neo4j/neo4j.conf` and edit this line:

#dbms.default\_listen\_address=0.0.0.0

Remove the # character to uncomment the line. Save the file, then start neo4j up again

## Configure Neo4j Database

To configure the Neo4j database, we will do the same steps we did on Windows:

Open a web browser and navigate to the Neo4j web console at [http://localhost:7474/](http://localhost:7474/):

![text](https://academy.hackthebox.com/storage/modules/69/neo4j_web_console.jpg)

Change Neo4j default credentials. Authenticate to neo4j in the web console with username `neo4j` and password `neo4j`, leave the database empty, and once prompted, change the password.

![text](https://academy.hackthebox.com/storage/modules/69/neo4j_change_password.jpg)

## Download BloodHound GUI

1.  Download the latest version of the BloodHound GUI for Linux from [https://github.com/BloodHoundAD/BloodHound/releases](https://github.com/BloodHoundAD/BloodHound/releases).

![text](https://academy.hackthebox.com/storage/modules/69/bloodhound_download_linux.jpg)

2.  Unzip the folder, then run BloodHound with the `--no-sandbox` flag:

#### Unzip BloodHound

```
p3ta@htb[/htb]$ unzip BloodHound-linux-x64.zip 
Archive:  BloodHound-linux-x64.zip
   creating: BloodHound-linux-x64/
  inflating: BloodHound-linux-x64/BloodHound
  ...SNIP...

```

#### Execute BloodHound

```
p3ta@htb[/htb]$ cd BloodHound-linux-x64/
$ ./BloodHound --no-sandbox

```

3.  Authenticate with the credentials you set up for neo4j.

![text](https://academy.hackthebox.com/storage/modules/69/bloodhound_authentication.jpg)

## MacOS Install

To install BloodHound in MacOS, we can follow the steps provided in [BloodHound official documentation](https://bloodhound.readthedocs.io/en/latest/index.html).

___

## Updating BloodHound requirements (Linux)

In case we have already installed BloodHound, and we need to update it to support the latest version, we can update Neo4j and Java with the following commands:

#### Update Neo4j

```
p3ta@htb[/htb]$ wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
$ echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
$ sudo apt-get update
...SNIP...

```

#### Install Neo4j 4.4.X

```
p3ta@htb[/htb]$ sudo apt install neo4j=1:4.4.16 -y
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following packages will be upgraded:
  neo4j
1 upgraded, 0 newly installed, 0 to remove, and 236 not upgraded.
Need to get 106 MB of archives.
After this operation, 1,596 kB of additional disk space will be used.
Get:1 https://debian.neo4j.com stable/4.4 amd64 neo4j all 1:4.4.16 [106 MB]
Fetched 106 MB in 2s (55.9 MB/s)
...SNIP...

```

**Note:** Make sure to change the Java version to 11 as mention in the installation steps.

___

## Recovering Neo4j Credentials

In case we can't access the Neo4j database with the default credentials, we can follow the next steps to reset the default credentials:

1.  Stop neo4j if it is running

```
p3ta@htb[/htb]$ sudo systemctl stop neo4j

```

2.  edit `/etc/neo4j/neo4j.conf`, and uncomment `dbms.security.auth_enabled=false`.
    
3.  Start neo4j console:
    

```
p3ta@htb[/htb]$ sudo neo4j console
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
2023-01-05 20:49:46.214+0000 INFO  Starting
...SNIP...

```

4.  Navigate to [http://localhost:7474/](http://localhost:7474/) and click `Connect` to log in without credentials.
    
5.  Set a new password for the `neo4j` account with the following query: `ALTER USER neo4j SET PASSWORD 'Password123';`
    

![text](https://academy.hackthebox.com/storage/modules/69/neo4j_password_recovery1.jpg)

6.  Stop neo4j service.
    
7.  Edit `/etc/neo4j/neo4j.conf`, and comment out the `dbms.security.auth_enabled=false`.
    
8.  Start Neo4j and use the new password.
    

___

___

[SharpHound](https://github.com/BloodHoundAD/SharpHound) is the official data collector tool for [BloodHound](https://github.com/BloodHoundAD/BloodHound), is written in C# and can be run on Windows systems with the .NET framework installed. The tool uses various techniques to gather data from Active Directory, including native Windows API functions and LDAP queries.

The data collected by SharpHound can be used to identify security weaknesses in an Active Directory environment to attack it or to plan for remediation.

This section will discover the basic functionalities of enumerating Active Directory using SharpHound and how to do it.

## Basic Enumeration

By default SharpHound, if run without any options, will identify the domain to which the user who ran it belongs and will execute the default collection. Let's execute SharpHound without any options.

**Note:** To follow the exercise start the target machine and connect via RDP with the following credentials `htb-student:HTBRocks!`.

#### Running SharpHound without any option

```
C:\tools> SharpHound.exe
2023-01-10T09:10:27.5517894-06:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-01-10T09:10:27.6678232-06:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-01-10T09:10:27.6834781-06:00|INFORMATION|Initializing SharpHound at 9:10 AM on 1/10/2023
2023-01-10T09:11:12.0547392-06:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-01-10T09:11:12.2081156-06:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.HTB
2023-01-10T09:11:12.2394159-06:00|INFORMATION|Producer has finished, closing LDAP channel
2023-01-10T09:11:12.2615280-06:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-01-10T09:11:42.6237001-06:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2023-01-10T09:12:12.6416076-06:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 37 MB RAM
2023-01-10T09:12:42.9758511-06:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 37 MB RAM
2023-01-10T09:12:43.2077516-06:00|INFORMATION|Consumers finished, closing output channel
2023-01-10T09:12:43.2545768-06:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-01-10T09:12:43.3771345-06:00|INFORMATION|Status: 94 objects finished (+94 1.032967)/s -- Using 42 MB RAM
2023-01-10T09:12:43.3771345-06:00|INFORMATION|Enumeration finished in 00:01:31.1684392
2023-01-10T09:12:43.4617976-06:00|INFORMATION|Saving cache with stats: 53 ID to type mappings.
 53 name to SID mappings.
 1 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-01-10T09:12:43.4617976-06:00|INFORMATION|SharpHound Enumeration Completed at 9:12 AM on 1/10/2023! Happy Graphing!
```

The 2nd line in the output above indicates the collection method used by default: `Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote`. Those methods mean that we will collect the following:

1.  Users and Computers.
2.  Active Directory security group membership.
3.  Domain trusts.
4.  Abusable permissions on AD objects.
5.  OU tree structure.
6.  Group Policy links.
7.  The most relevant AD object properties.
8.  Local groups from domain-joined Windows systems and local privileges such as RDP, DCOM, and PSRemote.
9.  User sessions.
10.  All SPN (Service Principal Names).

To get the information for local groups and sessions, SharpHound will attempt to connect to each domain-joined Windows computer from the list of computers it collected. If the user from which SharpHound is running has privileges on the remote computer, it will collect the following information::

1.  The members of the local administrators, remote desktop, distributed COM, and remote management groups.
2.  Active sessions to correlate to systems where users are interactively logged on.

**Note:** Gathering information from domain-joined machines, such as local group membership and active sessions, is only possible if the user session from which SharpHound is being executed has Administrator rights on the target computer.

Once SharpHound terminates, by default, it will produce a zip file whose name starts with the current date and ends with BloodHound. This zip archive contains a group of JSON files:

![image](https://academy.hackthebox.com/storage/modules/69/bh_zip.png)

## Importing Data into BloodHound

1.  Start the `neo4j` database service:

#### Start Service

```
PS C:\htb> net start neo4j
The Neo4j Graph Database - neo4j service is starting..
The Neo4j Graph Database - neo4j service was started successfully.
```

2.  Launch `C:\Tools\BloodHound\BloodHound.exe` and log in with the following credentials:

```
Username: neo4j
Password: Password123
```

![text](https://academy.hackthebox.com/storage/modules/69/BH_login.png)

3.  Click the upload button on the far right, browse to the zip file, and upload it. You will see a status showing upload % completion.

![text](https://academy.hackthebox.com/storage/modules/69/bh_upload_data.jpg)

**Note:** We can upload as many zip files as we want. BloodHound will not duplicate the data but add data not present in the database.

4.  Once the upload is complete, we can analyze the data. If we want to view information about the domain, we can type `Domain:INLANEFREIGHT.HTB` into the search box. This will show an icon with the domain name. If you click the icon, it will display information about the node (the domain), how many users, groups, computers, OUs, etc.

![text](https://academy.hackthebox.com/storage/modules/69/bh_node_domain.jpg)

5.  Now, we can start analyzing the information in the bloodhound and find the paths to our targets.

**Note:** If the computers names do not appear when importing the files, we can import the file again to correct it.


Include front/back template

___

​

[SharpHound](https://github.com/BloodHoundAD/SharpHound) is the official data collector tool for [BloodHound](https://github.com/BloodHoundAD/BloodHound), is written in C# and can be run on Windows systems with the .NET framework installed. The tool uses various techniques to gather data from Active Directory, including native Windows API functions and LDAP queries.

​

The data collected by SharpHound can be used to identify security weaknesses in an Active Directory environment to attack it or to plan for remediation.

​

This section will discover the basic functionalities of enumerating Active Directory using SharpHound and how to do it.

​

## Basic Enumeration

​

By default SharpHound, if run without any options, will identify the domain to which the user who ran it belongs and will execute the default collection. Let's execute SharpHound without any options.

​

**Note:** To follow the exercise start the target machine and connect via RDP with the following credentials `htb-student:HTBRocks!`.

​

#### Running SharpHound without any option

​

```

C:\tools> SharpHound.exe

2023-01-10T09:10:27.5517894-06:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound

2023-01-10T09:10:27.6678232-06:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote

Download

\`\`\`

Before using SharpHound, we need to be able to resolve the DNS names of the target domain, and if we have network access to the domain's DNS server, we can configure our network card DNS settings to that server. If this is not the case, we can set up our \[hosts file\](https://en.wikiversity.org/wiki/Hosts\_file/Edit) and include the DNS names of the domain controller.

\*\*Note:\*\* Note that even when using the DNS name in the host file, you may introduce some errors due to name resolution issues that do not exist in the file or are misconfigured.

2\. Configure the DNS server to the IP \`172.16.130.3\` (Domain Controller Internal IP). In this exercise the DNS are already configured, there is no need to change them.

!\[text\](https://academy.hackthebox.com/storage/modules/69/configure\_dns.jpg)

3\. Run \`cmd.exe\` and execute the following command to launch another \`cmd.exe\` with the htb-student credentials. It will ask for a password. The password is \`HTBRocks!\`:

\`\`\`

C:\\htb> runas /netonly /user:INLANEFREIGHT\\htb-student cmd.exe

Enter the password for INLANEFREIGHT\\htb-student:

Attempting to start cmd.exe as user "INLANEFREIGHT\\htb-student" ...

\`\`\`

!\[text\](https://academy.hackthebox.com/storage/modules/69/runas\_netonly.jpg)

\*\*Note:\*\* \`runas /netonly\` does not validate credentials, and if we use the wrong credentials, we will notice it while trying to connect through the network.

4\. Execute \`net view \\\\inlanefreight.htb\\\` to confirm we had successfully authenticated.

\`\`\`

C:\\htb> net view \\\\inlanefreight.htb\\

Shared resources at \\\\inlanefreight.htb\\

Share name Type Used as Comment.

\-------------------------------------------------------------------------------

NETLOGON Disk Logon server share

SYSVOL Disk Logon server share

The command completed successfully.

\`\`\`

5\. Run SharpHound.exe with the option \`--domain\`:

\`\`\`

C:\\Tools> SharpHound.exe -d inlanefreight.htb

2023-01-12T09:25:21.5040729-08:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound

2023-01-12T09:25:21.6603414-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote

2023-01-12T09:25:21.6760332-08:00|INFORMATION|Initializing SharpHound at 9:25 AM on 1/12/2023

2023-01-12T09:25:22.0197242-08:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote

2023-01-12T09:25:22.2541585-08:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.HTB

2023-01-12T09:25:22.3010985-08:00|INFORMATION|Producer has finished, closing LDAP channel

2023-01-12T09:25:22.3010985-08:00|INFORMATION|LDAP channel closed, waiting for consumers

2023-01-12T09:25:52.3794310-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM

2023-01-12T09:26:21.3792883-08:00|INFORMATION|Consumers finished, closing output channel

2023-01-12T09:26:21.4261266-08:00|INFORMATION|Output channel closed, waiting for output task to complete

Closing writers

2023-01-12T09:26:21.4885564-08:00|INFORMATION|Status: 94 objects finished (+94 1.59322)/s -- Using 44 MB RAM

2023-01-12T09:26:21.4885564-08:00|INFORMATION|Enumeration finished in 00:00:59.2357019

2023-01-12T09:26:21.5665717-08:00|INFORMATION|Saving cache with stats: 53 ID to type mappings.

53 name to SID mappings.

1 machine sid mappings.

2 sid to domain mappings.

0 global catalog mappings.

2023-01-12T09:26:21.5822432-08:00|INFORMATION|SharpHound Enumeration Completed at 9:26 AM on 1/12/2023! Happy Graphing!

\`\`\`

\## Up Next

We explore some use cases of SharpHound on Windows and how we can collect information from the domain we are attacking.

The following section will see how we can collect information from Linux.



