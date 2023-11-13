Active Directory BloodHound

BloodHound Overview

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

# SharpHound - Data Collection from Windows

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

In the following sections, we will see how to collect Active Directory information from Windows and Linux and how to analyze the information we collect.

SharpHound has many interesting options that help us define what information we want and how we can collect it. This section will explore some of the most common options we can use in SharpHound, and links to the official documentation as a reference for all SharpHound options.

___

## SharpHound Options

We can use `--help` to list all SharpHound options. The following list corresponds to version 1.1.0:

#### SharpHound Options

```
C:\Tools> SharpHound.exe --help
2023-01-10T13:08:39.2519248-06:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
SharpHound 1.1.0
Copyright (C) 2023 SpecterOps

  -c, --collectionmethods      (Default: Default) Collection Methods: Group, LocalGroup, LocalAdmin, RDP, DCOM, PSRemote, Session, Trusts, ACL, Container,
                               ComputerOnly, GPOLocalGroup, LoggedOn, ObjectProps, SPNTargets, Default, DCOnly, All

  -d, --domain                 Specify domain to enumerate

  -s, --searchforest           (Default: false) Search all available domains in the forest

  --stealth                    Stealth Collection (Prefer DCOnly whenever possible!)

  -f                           Add an LDAP filter to the pregenerated filter.

  --distinguishedname          Base DistinguishedName to start the LDAP search at

  --computerfile               Path to file containing computer names to enumerate

  --outputdirectory            (Default: .) Directory to output file too

  --outputprefix               String to prepend to output file names

  --cachename                  Filename for cache (Defaults to a machine specific identifier)

  --memcache                   Keep cache in memory and don't write to disk

  --rebuildcache               (Default: false) Rebuild cache and remove all entries

  --randomfilenames            (Default: false) Use random filenames for output

  --zipfilename                Filename for the zip

  --nozip                      (Default: false) Don't zip files

  --zippassword                Password protects the zip with the specified password

  --trackcomputercalls         (Default: false) Adds a CSV tracking requests to computers

  --prettyprint                (Default: false) Pretty print JSON

  --ldapusername               Username for LDAP

  --ldappassword               Password for LDAP

  --domaincontroller           Override domain controller to pull LDAP from. This option can result in data loss

  --ldapport                   (Default: 0) Override port for LDAP

  --secureldap                 (Default: false) Connect to LDAP SSL instead of regular LDAP

  --disablecertverification    (Default: false) Disables certificate verification when using LDAPS

  --disablesigning             (Default: false) Disables Kerberos Signing/Sealing

  --skipportcheck              (Default: false) Skip checking if 445 is open

  --portchecktimeout           (Default: 500) Timeout for port checks in milliseconds

  --skippasswordcheck          (Default: false) Skip check for PwdLastSet when enumerating computers

  --excludedcs                 (Default: false) Exclude domain controllers from session/localgroup enumeration (mostly for ATA/ATP)

  --throttle                   Add a delay after computer requests in milliseconds

  --jitter                     Add jitter to throttle (percent)

  --threads                    (Default: 50) Number of threads to run enumeration with

  --skipregistryloggedon       Skip registry session enumeration

  --overrideusername           Override the username to filter for NetSessionEnum

  --realdnsname                Override DNS suffix for API calls

  --collectallproperties       Collect all LDAP properties from objects

  -l, --Loop                   Loop computer collection

  --loopduration               Loop duration (Defaults to 2 hours)

  --loopinterval               Delay between loops

  --statusinterval             (Default: 30000) Interval in which to display status in milliseconds

  -v                           (Default: 2) Enable verbose output

  --help                       Display this help screen.

  --version                    Display version information.
```

## [Collection Methods](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html#collectionmethod)

The option `-collectionmethod` or `-c` allows us to specify what kind of data we want to collect. In the help menu above, we can see the list of collection methods. Let's describe some of them that we haven't covered:

-   `All`: Performs all collection methods except `GPOLocalGroup`.
-   `DCOnly`: Collects data only from the domain controller and will not try to get data from domain-joined Windows devices. It will collect users, computers, security groups memberships, domain trusts, abusable permissions on AD objects, OU structure, Group Policy, and the most relevant AD object properties. It will attempt to correlate Group Policy-enforced local groups to affected computers.
-   `ComputerOnly`: This is the opposite of `DCOnly`. It will only collect information from domain-joined computers, such as user sessions and local groups.

Depending on the scenario we are in, we will choose the method that best suits our needs. Let's see the following use case:

We are in an environment with 2000 computers, and they have a SOC with some network monitoring tools. We use the `Default` collection method but forget the computer from where we run SharpHound, which will try to connect to every computer in the domain.

Our attack host started generating traffic to all workstations, and the SOC quarantined our machine.

In this scenario, we should use `DCOnly` instead of `All` or `Default`, as it generates only traffic to the domain controller. We could pick the most interesting target machine and add them to a list (e.g: `computers.txt`). Then, we would rerun SharpHound using the `ComputerOnly` collection method and the `--computerfile` option to try to enumerate only the computers in the `computers.txt` file.

It is essential to know the methods and their implications. The following table, created by [SadProcessor](https://twitter.com/SadProcessor), shows a general reference of the communication protocols used by each method and information on each technique, among other things:

![text](https://academy.hackthebox.com/storage/modules/69/SharpHoundCheatSheet.jpg)

**Note:** This table was created for an older version of SharpHound. Some options no longer exist, and others have been modified, but it still provides an overview of the collection methods and their implications. For more information, visit the [BloodHound documentation page](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html).

## Common used flags

If we get credentials from a user other than the context from which we are running, we can use the `--ldapusername` and `--ldappassword` options to run SharpHound using those credentials.

Another flag we find helpful is `-d` or `--domain`. Although this option is assigned by default, if we are in an environment where multiple domains exist, we can use this option to ensure that SharpHound will collect the information from the domain we specify.

SharpHound will capture the domain controller automatically, but if we want to target a specific DC, we can use the option `--domaincontroller` followed by the IP or FQDN of the target domain controller. This option could help us target a forgotten or secondary domain, which may have less security or monitoring tools than the primary domain controller. Another use case for this flag is if we are doing port forward, we can specify an IP and port to target. We can use the flag `--ldapport` to select a port.

## Randomize and hide SharpHound Output

It is known that SharpHound, by default, generates different `.json` files, then saves them in a `zip` file. It also generates a randomly named file with a `.bin` extension corresponding to the cache of the queries it performs. Defense teams could use these patterns to detect bloodhound. One way to try to hide these traces is by combining some of these options:

| **Option** | **Description** |
| --- | --- |
| `--memcache` | Keep cache in memory and don't write to disk. |
| `--randomfilenames` | Generate random filenames for output, including the zip file. |
| `--outputprefix` | String to prepend to output file names. |
| `--outputdirectory` | Directory to output file too. |
| `--zipfilename` | Filename for the zip. |
| `--zippassword` | Password protects the zip with the specified password. |

For example, we can use the `--outputdirectory` to target a shared folder and randomize everything. Let's start a shared folder in our PwnBox:

#### Start the shared folder with username and password

```
p3ta@htb[/htb]$ sudo impacket-smbserver share ./ -smb2support -user test -password test
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

Now let's connect to the shared folder and save SharpHound output there:

#### Connect to the shared folder with username and password

```
C:\htb> net use \\10.10.14.33\share /user:test test
The command completed successfully.
```

#### Running SharpHound and saving the output to a shared folder

```
C:\htb> C:\Tools\SharpHound.exe --memcache --outputdirectory \\10.10.14.33\share\ --zippassword HackTheBox --outputprefix HTB --randomfilenames
2023-01-11T11:31:43.4459137-06:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-01-11T11:31:43.5998704-06:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-01-11T11:31:43.6311043-06:00|INFORMATION|Initializing SharpHound at 11:31 AM on 1/11/2023
2023-01-11T11:31:55.0551988-06:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-01-11T11:31:55.2710788-06:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.HTB
2023-01-11T11:31:55.3089182-06:00|INFORMATION|Producer has finished, closing LDAP channel
2023-01-11T11:31:55.3089182-06:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-01-11T11:32:25.7331485-06:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2023-01-11T11:32:41.7321172-06:00|INFORMATION|Consumers finished, closing output channel
2023-01-11T11:32:41.7633662-06:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-01-11T11:32:52.2310202-06:00|INFORMATION|Status: 94 objects finished (+94 1.678571)/s -- Using 42 MB RAM
2023-01-11T11:32:52.2466171-06:00|INFORMATION|Enumeration finished in 00:00:56.9776773
2023-01-11T11:33:09.4855302-06:00|INFORMATION|SharpHound Enumeration Completed at 11:33 AM on 1/11/2023! Happy Graphing!
```

#### Unzipping the file

```
p3ta@htb[/htb]$ unzip ./HTB_20230111113143_5yssigbd.w3f
Archive:  ./HTB_20230111113143_5yssigbd.w3f
[./HTB_20230111113143_5yssigbd.w3f] HTB_20230111113143_hjclkslu.2in password: 
  inflating: HTB_20230111113143_hjclkslu.2in  
  inflating: HTB_20230111113143_hk3lxtz3.1ku  
  inflating: HTB_20230111113143_kghttiwp.jbq  
  inflating: HTB_20230111113143_kdg5svst.4sc  
  inflating: HTB_20230111113143_qeugxqep.lya  
  inflating: HTB_20230111113143_xsxzlxht.awa  
  inflating: HTB_20230111113143_51zkhw0e.bth

```

Now we can upload our data to BloodHound:

![text](https://academy.hackthebox.com/storage/modules/69/bh_upload_random_data.jpg)

**Note:** If we set a password to the zip file, we will need to unzip it first, but if we didn't, we could import the file as is, with the random name and extension and it will import it anyway.

## Session Loop Collection Method

When a user establishes a connection to a remote computer, it creates a session. The session information includes the username and the computer or IP from which the connection is coming. While active, the connection remains in the computer, but after the user disconnects, the session becomes idle and disappears in a few minutes. This means we have a small window of time to identify sessions and where users are active.

**Note:** In Active Directory environments, it is important to understand where users are connected because it helps us understand which computers to compromise to achieve our goals.

Let's open a command prompt in the target machine and type `net session` to identify if there are any session active:

#### Looking for Active Sessions

```
C:\htb> net session
There are no entries in the list.
```

There are no active sessions, which means that if we run SharpHound right now, it will not find any session on our computer. When we run the SharpHound default collection method, it also includes the `Session` collection method. This method performs one round of session collection from the target computers. If it finds a session during that collection, it will collect it, but if the session expires, we won't have such information. That's why SharpHound includes the option `--loop`. We have a couple of options to use with loops in SharpHound:

| **Option** | **Description** |
| --- | --- |
| `--Loop` | Loop computer collection. |
| `--loopduration` | Duration to perform looping (Default 02:00:00). |
| `--loopinterval` | Interval to sleep between loops (Default 00:00:30). |
| `--stealth` | Perform "stealth" data collection. Only touch systems are the most likely to have user session data. |

If we want to search sessions for the following hour and query each computer every minute, we can use SharpHound as follow:

#### Session Loop

```
C:\Tools> SharpHound.exe -c Session --loop --loopduration 01:00:00 --loopinterval 00:01:00
2023-01-11T14:15:48.9375275-06:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-01-11T14:15:49.1382880-06:00|INFORMATION|Resolved Collection Methods: Session
2023-01-11T14:15:49.1695244-06:00|INFORMATION|Initializing SharpHound at 2:15 PM on 1/11/2023
2023-01-11T14:16:00.4571231-06:00|INFORMATION|Flags: Session
2023-01-11T14:16:00.6108583-06:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.HTB
2023-01-11T14:16:00.6421492-06:00|INFORMATION|Producer has finished, closing LDAP channel
2023-01-11T14:16:00.6421492-06:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-01-11T14:16:00.7268495-06:00|INFORMATION|Consumers finished, closing output channel
2023-01-11T14:16:00.7424755-06:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-01-11T14:16:00.9587384-06:00|INFORMATION|Status: 4 objects finished (+4 Infinity)/s -- Using 35 MB RAM
2023-01-11T14:16:00.9587384-06:00|INFORMATION|Enumeration finished in 00:00:00.3535475
2023-01-11T14:16:01.0434611-06:00|INFORMATION|Creating loop manager with methods Session
2023-01-11T14:16:01.0434611-06:00|INFORMATION|Starting looping
2023-01-11T14:16:01.0434611-06:00|INFORMATION|Waiting 30 seconds before starting loop
2023-01-11T14:16:31.0598479-06:00|INFORMATION|Looping scheduled to stop at 01/11/2023 15:16:31
2023-01-11T14:16:31.0598479-06:00|INFORMATION|01/11/2023 14:16:31 - 01/11/2023 15:16:31
2023-01-11T14:16:31.0598479-06:00|INFORMATION|Starting loop 1 at 2:16 PM on 1/11/2023
2023-01-11T14:16:31.0754340-06:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.HTB
2023-01-11T14:16:31.0754340-06:00|INFORMATION|Producer has finished, closing LDAP channel
2023-01-11T14:16:31.0754340-06:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-01-11T14:16:42.1893741-06:00|INFORMATION|Consumers finished, closing output channel
2023-01-11T14:16:42.1893741-06:00|INFORMATION|Output channel closed, waiting for output task to complete
...SNIP...
```

Watch the video [How BloodHound's session collection works](https://www.youtube.com/watch?v=q86VgM2Tafc) from the SpecterOps team for a deeper explanation of this collection method. Here is another excellent [blog post from Compass Security](https://blog.compass-security.com/2022/05/bloodhound-inner-workings-part-2/) regarding session enumeration by Sven Defatsch.

**Note:** BloodHound video was recorded before Microsoft introduced the requirement to be an administrator to collect session data.

## Running from Non-Domain-Joined Systems

Sometimes we might need to run SharpHound from a computer, not a domain member, such as when conducting a HackTheBox attack or internal penetration test with only network access.

In these scenarios, we can use `runas /netonly /user:<DOMAIN>\<username> <app>` to execute the application with specific user credentials. The `/netonly` flag ensures network access using the provided credentials.

Let's use a computer that is not a member of the domain for this and complete the following steps:

1.  Connect via RDP to the target IP and port 13389 using the following credentials: `haris:Hackthebox`.

#### Connect via RDP to the

```
p3ta@htb[/htb]$ xfreerdp /v:10.129.204.207:13389 /u:haris /p:Hackthebox /dynamic-resolution /drive:.,linux                 
[12:13:14:635] [173624:173625] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[12:13:14:635] [173624:173625] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr                      
[12:13:14:635] [173624:173625] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd                 
[12:13:14:635] [173624:173625] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprd
...SNIP...

```

Before using SharpHound, we need to be able to resolve the DNS names of the target domain, and if we have network access to the domain's DNS server, we can configure our network card DNS settings to that server. If this is not the case, we can set up our [hosts file](https://en.wikiversity.org/wiki/Hosts_file/Edit) and include the DNS names of the domain controller.

**Note:** Note that even when using the DNS name in the host file, you may introduce some errors due to name resolution issues that do not exist in the file or are misconfigured.

2.  Configure the DNS server to the IP `172.16.130.3` (Domain Controller Internal IP). In this exercise the DNS are already configured, there is no need to change them.

![text](https://academy.hackthebox.com/storage/modules/69/configure_dns.jpg)

3.  Run `cmd.exe` and execute the following command to launch another `cmd.exe` with the htb-student credentials. It will ask for a password. The password is `HTBRocks!`:

```
C:\htb> runas /netonly /user:INLANEFREIGHT\htb-student cmd.exe
Enter the password for INLANEFREIGHT\htb-student:
Attempting to start cmd.exe as user "INLANEFREIGHT\htb-student" ...
```

![text](https://academy.hackthebox.com/storage/modules/69/runas_netonly.jpg)

**Note:** `runas /netonly` does not validate credentials, and if we use the wrong credentials, we will notice it while trying to connect through the network.

4.  Execute `net view \\inlanefreight.htb\` to confirm we had successfully authenticated.

```
C:\htb> net view \\inlanefreight.htb\
Shared resources at \\inlanefreight.htb\

Share name  Type  Used as  Comment.

-------------------------------------------------------------------------------
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.
```

5.  Run SharpHound.exe with the option `--domain`:

```
C:\Tools> SharpHound.exe -d inlanefreight.htb
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
```
---
created: 2023-11-13T11:42:52 (UTC -08:00)
tags: []
source: https://enterprise.hackthebox.com/academy-lab/6224/3329/modules/69/2076
author: 
---

# HTB Enterprise

> ## Excerpt
> SharpHound does not have an official data collector tool for Linux. However, Dirk-jan Mollema created BloodHound.py, a Python-based collector for BloodHound based on Impacket, to allow us to collect Active Directory information from Linux for BloodHound.

---

# BloodHound from Linux
___

[SharpHound](https://github.com/BloodHoundAD/SharpHound) does not have an official data collector tool for Linux. However, [Dirk-jan Mollema](https://twitter.com/_dirkjan) created [BloodHound.py](https://github.com/fox-it/BloodHound.py), a Python-based collector for BloodHound based on Impacket, to allow us to collect Active Directory information from Linux for BloodHound.

___

## Installation

We can install [BloodHound.py](https://github.com/fox-it/BloodHound.py) with `pip install bloodhound` or by cloning its repository and running `python setup.py install`. To run, it requires `impacket`, `ldap3`, and `dnspython`. The tool can be installed via pip by typing the following command:

#### Install BloodHound.py

```
p3ta@htb[/htb]$ pip install bloodhound
Defaulting to user installation because normal site-packages is not writeable
Collecting bloodhound
  Downloading bloodhound-1.6.0-py3-none-any.whl (80 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 81.0/81.0 kB 1.8 MB/s eta 0:00:00
Requirement already satisfied: ldap3!=2.5.0,!=2.5.2,!=2.6,>=2.5 in /home/plaintext/.local/lib/python3.9/site-packages (from bloodhound) (2.9.1)
Requirement already satisfied: pyasn1>=0.4 in /usr/local/lib/python3.9/dist-packages (from bloodhound) (0.4.6)
Requirement already satisfied: impacket>=0.9.17 in /home/plaintext/.local/lib/python3.9/site-packages (from bloodhound) (0.10.1.dev1+20220720.103933.3c6713e3)
Requirement already satisfied: future in /usr/lib/python3/dist-packages (from bloodhound) (0.18.2)
Requirement already satisfied: dnspython in /usr/local/lib/python3.9/dist-packages (from bloodhound) (2.2.1)
Requirement already satisfied: charset-normalizer in /home/plaintext/.local/lib/python3.9/site-packages (from impacket>=0.9.17->bloodhound) (2.0.12)
Requirement already satisfied: six in /usr/local/lib/python3.9/dist-packages (from impacket>=0.9.17->bloodhound) (1.12.0)
Requirement already satisfied: pycryptodomex in /usr/lib/python3/dist-packages (from impacket>=0.9.17->bloodhound) (3.9.7)
Requirement already satisfied: ldapdomaindump>=0.9.0 in /usr/lib/python3/dist-packages (from impacket>=0.9.17->bloodhound) (0.9.3)
Requirement already satisfied: dsinternals in /home/plaintext/.local/lib/python3.9/site-packages (from impacket>=0.9.17->bloodhound) (1.2.4)
Requirement already satisfied: flask>=1.0 in /usr/lib/python3/dist-packages (from impacket>=0.9.17->bloodhound) (1.1.2)
Requirement already satisfied: pyOpenSSL>=21.0.0 in /home/plaintext/.local/lib/python3.9/site-packages (from impacket>=0.9.17->bloodhound) (22.1.0)
Requirement already satisfied: cryptography<39,>=38.0.0 in /home/plaintext/.local/lib/python3.9/site-packages (from pyOpenSSL>=21.0.0->impacket>=0.9.17->bloodhound) (38.0.3)
Requirement already satisfied: cffi>=1.12 in /usr/local/lib/python3.9/dist-packages (from cryptography<39,>=38.0.0->pyOpenSSL>=21.0.0->impacket>=0.9.17->bloodhound) (1.12.3)
Requirement already satisfied: pycparser in /usr/local/lib/python3.9/dist-packages (from cffi>=1.12->cryptography<39,>=38.0.0->pyOpenSSL>=21.0.0->impacket>=0.9.17->bloodhound) (2.19)
Installing collected packages: bloodhound
Successfully installed bloodhound-1.6.0

```

To install it from the source, we can clone the [BloodHound.py GitHub repository](https://github.com/fox-it/BloodHound.py) and run the following command:

#### Install BloodHound.py from the source

```
p3ta@htb[/htb]$ git clone https://github.com/fox-it/BloodHound.py -q
$ cd BloodHound.py/
$ sudo python3 setup.py install
running install
running bdist_egg
running egg_info
creating bloodhound.egg-info
writing bloodhound.egg-info/PKG-INFO
writing dependency_links to bloodhound.egg-info/dependency_links.txt
writing entry points to bloodhound.egg-info/entry_points.txt
writing requirements to bloodhound.egg-info/requires.txt
writing top-level names to bloodhound.egg-info/top_level.txt
writing manifest file 'bloodhound.egg-info/SOURCES.txt'
reading manifest file 'bloodhound.egg-info/SOURCES.txt'
writing manifest file 'bloodhound.egg-info/SOURCES.txt'
installing library code to build/bdist.linux-x86_64/egg
running install_lib
running build_py
creating build
creating build/lib
creating build/lib/bloodhound
copying bloodhound/__init__.py -> build/lib/bloodhound
copying bloodhound/__main__.py -> build/lib/bloodhound
...SNIP...

```

## BloodHound.py Options

We can use `--help` to list all `BloodHound.py` options. The following list corresponds to version 1.6.0:

#### BloodHound.py options

```
p3ta@htb[/htb]$ python3 bloodhound.py 
usage: bloodhound.py [-h] [-c COLLECTIONMETHOD] [-d DOMAIN] [-v] [-u USERNAME] [-p PASSWORD] [-k] [--hashes HASHES] [-no-pass] [-aesKey hex key]
                     [--auth-method {auto,ntlm,kerberos}] [-ns NAMESERVER] [--dns-tcp] [--dns-timeout DNS_TIMEOUT] [-dc HOST] [-gc HOST]
                     [-w WORKERS] [--exclude-dcs] [--disable-pooling] [--disable-autogc] [--zip] [--computerfile COMPUTERFILE]
                     [--cachefile CACHEFILE]

Python based ingestor for BloodHound
For help or reporting issues, visit https://github.com/Fox-IT/BloodHound.py

optional arguments:
  -h, --help            show this help message and exit
  -c COLLECTIONMETHOD, --collectionmethod COLLECTIONMETHOD
                        Which information to collect. Supported: Group, LocalAdmin, Session, Trusts, Default (all previous), DCOnly (no computer
                        connections), DCOM, RDP,PSRemote, LoggedOn, Container, ObjectProps, ACL, All (all except LoggedOn). You can specify more
                        than one by separating them with a comma. (default: Default)
  -d DOMAIN, --domain DOMAIN
                        Domain to query.
  -v                    Enable verbose output

authentication options:
  Specify one or more authentication options. 
  By default Kerberos authentication is used and NTLM is used as fallback. 
  Kerberos tickets are automatically requested if a password or hashes are specified.

  -u USERNAME, --username USERNAME
                        Username. Format: username[@domain]; If the domain is unspecified, the current domain is used.
  -p PASSWORD, --password PASSWORD
                        Password
  -k, --kerberos        Use kerberos
  --hashes HASHES       LM:NLTM hashes
  -no-pass              don't ask for password (useful for -k)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  --auth-method {auto,ntlm,kerberos}
                        Authentication methods. Force Kerberos or NTLM only or use auto for Kerberos with NTLM fallback

collection options:
  -ns NAMESERVER, --nameserver NAMESERVER
                        Alternative name server to use for queries
  --dns-tcp             Use TCP instead of UDP for DNS queries
  --dns-timeout DNS_TIMEOUT
                        DNS query timeout in seconds (default: 3)
  -dc HOST, --domain-controller HOST
                        Override which DC to query (hostname)
  -gc HOST, --global-catalog HOST
                        Override which GC to query (hostname)
  -w WORKERS, --workers WORKERS
                        Number of workers for computer enumeration (default: 10)
  --exclude-dcs         Skip DCs during computer enumeration
  --disable-pooling     Don't use subprocesses for ACL parsing (only for debugging purposes)
  --disable-autogc      Don't automatically select a Global Catalog (use only if it gives errors)
  --zip                 Compress the JSON output files into a zip archive
  --computerfile COMPUTERFILE
                        File containing computer FQDNs to use as allowlist for any computer based methods
  --cachefile CACHEFILE
                        Cache file (experimental)

```

As BloodHound.py uses `impacket`, options such as the use of hashes, ccachefiles, aeskeys, kerberos, among others, are also available for BloodHound.py.

___

## Using BloodHound.py

To use BloodHound.py in Linux, we will need `--domain` and `--collectionmethod` options and the authentication method. Authentication can be a username and password, an NTLM hash, an AES key, or a ccache file. BloodHound.py will try to use the Kerberos authentication method by default, and if it fails, it will fall back to NTLM.

Another critical piece is the domain name resolution. If our DNS server is not the domain DNS server, we can use the option `--nameserver`, which allows us to specify an alternative name server for queries.

#### Running BloodHound.py

```
p3ta@htb[/htb]$ bloodhound-python -d inlanefreight.htb -c DCOnly -u htb-student -p HTBRocks! -ns 10.129.204.207 -k                                                                    
INFO: Found AD domain: inlanefreight.htb                                                                                                                                   
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (inlanefreight.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.inlanefreight.htb                 
INFO: Found 1 domains                                                                                                                                                      
INFO: Found 1 domains in the forest                                                  
INFO: Connecting to LDAP server: dc01.inlanefreight.htb                                                                                                                    
INFO: Found 6 users                  
INFO: Found 52 groups                                                                                                                                                      
INFO: Found 2 gpos                                                                   
INFO: Found 1 ous                                                                                                                                                          
INFO: Found 19 containers                                                            
INFO: Found 3 computers                                                              
INFO: Found 0 trusts                                                                 
INFO: Done in 00M 11S

```

**Note:** Kerberos authentication requires the host to resolve the domain FQDN. This means that the option `--nameserver` is not enough for Kerberos authentication because our host needs to resolve the DNS name KDC for Kerberos to work. If we want to use Kerberos authentication, we need to set the DNS Server to the target machine or configure the DNS entry in our hosts' file.

Let's add the DNS entry in our hosts file:

#### Setting up the /etc/hosts file

```
p3ta@htb[/htb]$ echo -e "\n10.129.204.207 dc01.inlanefreight.htb dc01 inlanefreight inlanefreight.htb" | sudo tee -a /etc/hosts

10.129.204.207 dc01.inlanefreight.htb dc01 inlanefreight inlanefreight.htb

```

Use BloodHound.py with Kerberos authentication:

#### Using BloodHound.py with Kerberos authentication

```
p3ta@htb[/htb]$ bloodhound-python -d inlanefreight.htb -c DCOnly -u htb-student -p HTBRocks! -ns 10.129.204.207 --kerberos
INFO: Found AD domain: inlanefreight.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.inlanefreight.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Connecting to LDAP server: dc01.inlanefreight.htb
INFO: Found 6 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 3 computers
INFO: Found 0 trusts
INFO: Done in 00M 11S

```

**Note:** Kerberos Authentication is the default authentication method for Windows. Using this method instead of NTLM makes our traffic look more normal.

## BloodHound.py Output files

Once the collection finishes, it will produce the JSON files, but by default, it won't zip the content as SharpHound does. If we want the content to be placed in a zip file, we need to use the option `--zip`.

#### List All Collections of BloodHound.py

```
p3ta@htb[/htb]$ ls
20230112171634_computers.json   20230112171634_domains.json  20230112171634_groups.json  20230112171634_users.json
20230112171634_containers.json  20230112171634_gpos.json     20230112171634_ous.json

```

___

## Using the Data

Now that we have seen various ways to ingest data for the `INLANEFREIGHT.HTB` domain and import it into the `BloodHound` GUI let's analyze the results and look for some common issues.

# Navigating the BloodHound GUI

---
created: 2023-11-13T11:58:40 (UTC -08:00)
tags: []
source: https://enterprise.hackthebox.com/academy-lab/6224/3329/modules/69/2076
author: 
---

# HTB Enterprise

> ## Excerpt
> The BloodHound GUI is the primary location for analyzing the data we collected using SharpHound. It has a user-friendly interface to access the data we need quickly.

---
## Navigating the BloodHound GUI

The BloodHound GUI is the primary location for analyzing the data we collected using SharpHound. It has a user-friendly interface to access the data we need quickly.

We will explore BloodHound graphical interface and see how we can take advantage of it.

___

## Getting Access to BloodHound Interface

In the section [BloodHound Setup and Installation](https://academy.hackthebox.com/module/69/section/2073), we discuss connecting to BloodHound GUI. We need to ensure the neo4j database is running, execute the BloodHound application, and log in with the username and password we defined.

When we log in successfully, BloodHound will perform the query: `Find all Domain Admins` and display the users that belong to the group.

![text](https://academy.hackthebox.com/storage/modules/69/bh_access_interface.jpg)

This area is known as the `Graph Drawing Area`, where BloodHound displays nodes and their relationship using edges. We can interact with the graph, move objects, zoom in or zoom out (with the mouse scroll or the bottom right buttons), click on nodes to see more information, or right-click them to perform different actions.

![text](https://academy.hackthebox.com/storage/modules/69/bh_gif_test4.gif)

Let's describe those options:

| **Command** | **Description** |
| --- | --- |
| Set as Starting Node | Set this node as the starting point in the pathfinding tool. Click this, and we will see this node’s name in the search bar. Then, we can select another node to target after clicking the pathfinding button. |
| Set as Ending Node | Set this node as the target node in the pathfinding tool. |
| Shortest Paths to Here | This will perform a query to find all shortest paths from any arbitrary node in the database to this node. This may cause a long query time in neo4j and an even longer render time in the BloodHound GUI. |
| Shortest Paths to Here from Owned | Find attack paths to this node from any node you have marked as owned. |
| Edit Node | This brings up the node editing modal, where you can edit current properties on the node or even add our custom properties to the node. |
| Mark Group as Owned | This will internally set the node as owned in the neo4j database, which you can then use in conjunction with other queries such as “Shortest paths to here from Owned”. |
| Mark/Unmark Group as High Value | Some nodes are marked as “high value” by default, such as the domain admins group and enterprise admin group. We can use this with other queries, such as “shortest paths to high-value assets”. |
| Delete Node | Deletes the node from the neo4j database. |

The `Graph Drawing Area` lets us also interact with `Edges`. They represent the link between two nodes and help us understand how we will move from one object to another. As BloodHound has many edges is challenging to keep track of how we can abuse every single one. The BloodHound team included a `help menu` under edges, where we can see information, examples, and references on how to abuse every single edge.

![text](https://academy.hackthebox.com/storage/modules/69/bh_edges_helpmenu2.gif)

## Search Bar

The search bar is one of the elements of BloodHound that we will use the most. We can search for specific objects by their name or type. If we click on a node we searched, its information will be displayed in the node info tab.

If we want to search for a specific type, we can prepend our search with node type, for example, `user:peter` or `group:domain`. Let's see this in action:

![text](https://academy.hackthebox.com/storage/modules/69/bh_search_bar_node_info2.gif)

Here's the complete list of node types we can prepend to our search:

Active Directory

-   Group
-   Domain
-   Computer
-   User
-   OU
-   GPO
-   Container

Azure

-   AZApp
-   AZRole
-   AZDevice
-   AZGroup
-   AZKeyVault
-   AZManagementGroup
-   AZResourceGroup
-   AZServicePrincipal
-   AZSubscription
-   AZTenant
-   AZUser
-   AZVM

## Pathfinding

Another great feature in the search bar is `Pathfinding`. We can use it to find an attack path between two given nodes.

For example, we can look for an attack path from `ryan` to `Domain Admins`. The path result is:

`Ryan > Mark > HelpDesk > ITSecurity > Domain Admins`

This path contains the edge `ForceChangePassword`; let's say we want to avoid changing users' passwords. We can use the filter option, uncheck `ForceChangePassword`, and search for the path without this edge. The result is:

`Ryan > AddSelf > Tech_Support > Testinggroup > HelpDesk > ITSecurity > Domain Admins`

![text](https://academy.hackthebox.com/storage/modules/69/bh_pathfinding2.gif)

## Upper Right Menu

We will find various options to interact with in the top right corner. Let's explain some of these options:

![text](https://academy.hackthebox.com/storage/modules/69/bh_upper_right_menu_3.gif)

-   `Refresh`: reruns the previous query and shows the results
    
-   `Export Graph`: Saves the current graph in JSON format so it can be imported later. We can also save the current graph as a picture in PNG format.
    
-   `Import Graph`: We can display the JSON formatted graph we exported.
    

![text](https://academy.hackthebox.com/storage/modules/69/bh_export_png2.gif)

-   `Upload Data`: Uploads SharpHound, BloodHound.py, or AzureHound data to Neo4j. We can select the upload data with the upload button or drag and drop the JSON or zip file directly into the BloodHound window.

![text](https://academy.hackthebox.com/storage/modules/69/bh_upload_data_3.gif)

**Note:** When we upload, BloodHound will add any new data but ignore any duplicated data.

**Note:** Zip files cannot be password protected from being uploaded.

-   `Change Layout Type`: Changes between hierarchical or force-directed layouts.
    
-   `Settings`: Allows us to adjust the display settings for nodes and edges, enabling query to debug mode, low detail mode, and dark mode.
    
    -   `Node Collapse Threshold`: Collapse nodes at the end of paths that only have one relationship. 0 to Disable, Default 5.
    -   `Edge Label Display`: When to display edge labels. If Always Display, edges such as MemberOf, Contains, etc., will always be said.
    -   `Node Label Display`: When to display node labels. If Always Display, node names, user names, computer names, etc., will always be displayed.
    -   `Query Debug Mode`: Raw queries will appear in Raw Query Box. We will discuss more on this in the [Cypher Queries](https://academy.hackthebox.com/module/69/section/2081) section.
    -   `Low Detail Mode`: Graphic adjustments to improve performance.
    -   `Dark Mode`: Enable Dark mode for the interface.

![text](https://academy.hackthebox.com/storage/modules/69/bh_settings.jpg)

-   `About`: Shows information about the author and version of the software.

## Shortcuts

There are four (4) shortcuts that we can take advantage from:

| **Shortcut** | **Description** |
| --- | --- |
| `CTRL` | Pressing CTRL will cycle through the three different node label display settings - default, always show, always hide. |
| `Spacebar` | Pressing the spacebar will bring up the spotlight window, which lists all currently drawn nodes. Click an item in the list, and the GUI will zoom into and briefly highlight that node. |
| `Backspace` | Pressing backspace will return to the previous graph result rendering. This is the same functionality as clicking the Back button in the search bar. |
| `S` | Pressing the letter s will toggle the expansion or collapse of the information panel below the search bar. This is the same functionality as clicking the More Info button in the search bar. |

## Database Info

The BloodHound Database Info tab gives users a quick overview of their current BloodHound database status. Here, users can view the database's number of sessions, relationships, ACLs, Azure objects and relationships, and Active Directory Objects.

Additionally, there are several options available for managing the database.:

| **Option** | **Description** |
| --- | --- |
| `Clear Database` | Lets users completely clear the database of all nodes, relationships, and properties. This can be useful when starting a new assessment or dealing with outdated data. |
| `Clear Sessions` | Lets users clear all saved sessions from the database. |
| `Refresh Database Stats` | Updates the displayed statistics to reflect any changes made to the database. |
| `Warming Up Database` | Is a process that puts the entire database into memory, which can significantly speed up queries. However, this process can take some time to complete, especially if the database is large. |

# Nodes
---
created: 2023-11-13T12:39:43 (UTC -08:00)
tags: []
source: https://enterprise.hackthebox.com/academy-lab/6224/3329/modules/69/2076
author: 
---

# HTB Enterprise

> ## Excerpt
> Nodes are the objects we interact with using BloodHound. These represent Active Directory and Azure objects. However, this section will only focus on Active Directory objects.

---
## Nodes

Nodes are the objects we interact with using BloodHound. These represent Active Directory and Azure objects. However, this section will only focus on Active Directory objects.

When we run SharpHound, it collects specific information from each node based on its type. The nodes that we will find in BloodHound according to version 4.2 are:

| **Node** | **Description** |
| --- | --- |
| Users | Objects that represent individuals who can log in to a network and access resources. Each user has a unique username and password that allows them to authenticate and access resources such as files, folders, and printers. |
| Groups | Used to organize users and computers into logical collections, which can then be used to assign permissions to resources. By assigning permissions to a group, you can easily manage access to resources for multiple users at once. |
| Computers | Objects that represent the devices that connect to the network. Each computer object has a unique name and identifier that allows it to be managed and controlled within the domain. |
| Domains | A logical grouping of network resources, such as users, groups, and computers. It allows you to manage and control these resources in a centralized manner, providing a single point of administration and security. |
| GPOs | Group Policy Objects, are used to define and enforce a set of policies and settings for users and computers within an Active Directory domain. These policies can control a wide range of settings, from user permissions to network configurations. |
| OUs | Organizational Units, are containers within a domain that allow you to group and manage resources in a more granular manner. They can contain users, groups, and computers, and can be used to delegate administrative tasks to specific individuals or groups. |
| Containers | Containers are similar to OUs, but are used for non-administrative purposes. They can be used to group objects together for organizational purposes, but do not have the same level of administrative control as OUs. |

We will briefly describe each node type and discuss some essential elements to consider. We will share reference links to the official BloodHound documentation, where all the nodes' details, properties, and descriptions are available.

___

## Nodes Elements

The `Node Info` tab displays specific information for each node type, categorized into various areas. We will highlight similarities shared among different types of nodes.

## [Users](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#users)

The following example shows the sections for the `user` node type:

![text](https://academy.hackthebox.com/storage/modules/69/bh_node_users_elements.jpg)

| **Category** | **Description** |
| --- | --- |
| Overview | General information about the object. |
| Node Properties | This section displays default information about the node |
| Extra Properties | This section displays some other information about the node, plus all other non-default, string-type property values from Active Directory if you used the –CollectAllProperties flag. |
| Group Membership | This section displays stats about Active Directory security groups the object belongs to. |
| Local Admin Rights | Displays where the object has admin rights |
| Execution Rights | Refers to the permissions and privileges a user, group, or computer has to execute specific actions or commands on the network. This can include RDP access, DCOM execution, SQL Admin Rights, etc. |
| Outbound Object Control | Visualize the permissions and privileges that a user, group, or computer has over other objects in the AD environment |
| Inbound Control Rights | Visualize the permissions and privileges of other objects (users, groups, domains, etc.) over a specific AD object. |

Within the node info tab, we can identify where this user is an administrator, what other object it controls, and more.

![text](https://academy.hackthebox.com/storage/modules/69/bh_node_user2.gif)

**Note:** For the following `node types`, we will only describe the sections that are unique for each one.

## [Computers](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#Computers)

The following example shows the sections for the `computer` node type:

![text](https://academy.hackthebox.com/storage/modules/69/bh_node_computer.jpg)

| **Category** | **Description** |
| --- | --- |
| Local Admins | Refers to the users, groups, and computers granted local administrator privileges on the specific computer. |
| Inbound Execution Rights | Display all the objects (users, groups, and computers) that have been granted execution rights on the specific computer |
| Outbound Execution Rights | Refers to the rights of the specific computer to execute commands or scripts on other computers or objects in the network. |

## [Groups](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#Groups)

The following example shows the sections for the `Groups` node type:

![text](https://academy.hackthebox.com/storage/modules/69/bh_node_groups.jpg)

| **Category** | **Description** |
| --- | --- |
| Group Members | Refers to the users, groups, and computer members of the specific group. |

## [Domains](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#Domains)

The following example shows the sections for the `Domains` node type:

![text](https://academy.hackthebox.com/storage/modules/69/bh_node_domain_new.jpg)

| **Category** | **Description** |
| --- | --- |
| Foreign Members | Are users or groups that belong to a different domain or forest than the one currently being analyzed |
| Inbound Trusts | Refers to trust relationships where another domain or forest trusts the current domain. This means that the users and groups from the trusted domain can access resources in the current domain and vice versa. |
| Outbound Trusts | Refers to trust relationships where the current domain or forest trusts another domain. This means that the users and groups from the current domain can access resources in the trusted domain and vice versa. |

In the Domain Overview section, we had an option named `Map OU Structure`. This one is helpful if we want a high-level overview of the Active Directory and how it is organized.

![text](https://academy.hackthebox.com/storage/modules/69/bh_domain_map_ou2.gif)

## [Organizational Units (OUs)](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#OUs)

The following example shows the sections for the `OU` node type:

![text](https://academy.hackthebox.com/storage/modules/69/bh_node_ou.jpg)

| **Category** | **Description** |
| --- | --- |
| Affecting GPOs | Refers to the group policy objects (GPOs) affecting the specific OU or container. |
| Descendant Objects | Refers to all objects located within a specific OU or container in the Active Directory (AD) environment. |

## [Containers](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#Containers)

The following example shows the sections for the `Containers` node type:

![text](https://academy.hackthebox.com/storage/modules/69/bh_node_containers.jpg)

## [GPOs](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#GPOs)

The following example shows the sections for the `GPO` node type:

![text](https://academy.hackthebox.com/storage/modules/69/bh_node_gpo.jpg)

| **Category** | **Description** |
| --- | --- |
| Affected Objects | Refers to the users, groups, and computers affected by the specific group policy object (GPO) in the Active Directory (AD) environment. |

If we want to know which objects are affected by a GPO, we can quickly do this from here, as we can see in the following image:

![text](https://academy.hackthebox.com/storage/modules/69/bh_gpo_affected_object2.gif)



