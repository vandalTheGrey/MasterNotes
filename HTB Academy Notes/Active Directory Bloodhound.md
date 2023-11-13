Active Directory BloodHound 
BloodHound Overview 
BloodHound Overview 
 Active Directory Access Management 
Access management in Active Directory is complex, and it is easy to introduce vulnerabilities or bad practices in day-to-day configurations. 
Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to
give privileges to a user that are not supposed to exist. 
Because the attack surface and the amount of data produced in Active Directory environments are highly complex and evolving, and because we
needed a way to automate the collection and analysis of this data, @_wald0, @harmj0y, and @CptJesus created BloodHound. 
BloodHound Overview 
BloodHound is an open-source tool used by attackers and defenders alike to analyze Active Directory domain security. The tool collects a large
amount of data from an Active Directory domain. It uses the graph theory to visually represent the relationship between objects and identify
domain attack paths that would have been difficult or impossible to detect with traditional enumeration. As of version 4.0, BloodHound now also
supports Azure. Although the primary purpose of this module will be Active Directory, we will introduce AzureHound in the section Azure
Enumeration. 
Data to be utilized by BloodHound is gathered using the SharpHound collector, which is available in PowerShell and C#. We will discuss data
collection in the following sections. 
 BloodHound Graph Theory & Cypher Query Language 
BloodHound utilizes Graph Theory, which are mathematical structures used to model pairwise relations between objects. A graph in this context
is made up of nodes (Active Directory objects such as users, groups, computers, etc.) which is connected by edges (relations between an object
such as a member of a group, AdminTo, etc.). We will discuss nodes and edges further in another section, but let’s do an example to see how
BloodHound works. 
The tool uses Cypher Query Language to analyze relationships. Cypher is Neo4j’s graph query language that lets us retrieve data from the graph.
It is like SQL for graphs, and was inspired by SQL so it lets us focus on what data we want out of the graph (not how to go get it). It is the easiest
graph language to learn by far because of its similarity to other languages and intuitiveness. We will discuss more about Cypher quries later in
this module. 
The below diagram shows two nodes, A and B. In this example, we can only go from node A to node B, not the other way. 
image 
This could simulate A as the user Grace and B as the group SQL Admins, the line between the two is the edge, which in this case is MemberOf.
The next graphic show us that in BloodHound, where the user Grace is a member of the SQL Admins group. 
text 
Let’s see a more complex relationship between nodes. The following graphic shows eight (8) nodes and ten (10) edges. Node H can reach node G,
but no node has a direct path to node H. To get to node C from node A, we can hop to node G, move to node F, and then to node C, but that’s not
the shortest path. One of the BloodHound capabilities is to look for the shortest path. In this example, the shortest path from node A to node C is
one hop through node B. 
image 
In the previous example, we used BloodHound to find that Grace is a member of SQL Admins, which is pretty simple to discover. We can use the
Active Directory Users and Computers GUI or the net user grace /domain command. With only this information, we can conclude that
Grace doesn’t have any path to the Domain Admins group, but that is where BloodHound is much more helpful in helping us identify those
relationships between nodes that are not easy to locate. 
Let’s use BloodHound as our map navigator and ask how to get from the user Grace to the Domain Admins group. Here’s the result: 
text 
This means that Grace, as a member of the SQL Admins group, can change Peter’s password. Authenticate with Peter’s new password and
perform operations as a member of the Domain Admins group. Although Peter is not a member directly, he is a member of a group that is. 
BloodHound for Enterprise 
The SpecterOps team that created BloodHound also created BloodHound Enterprise. An Attack Path Management solution that continuously
maps and quantifies Active Directory Attack Paths. Ideal for enterprises that want to constantly monitor the different types of on-premises and
cloud attack paths, prioritize their actions, obtain remediation guidance, and continuously measure their security posture. 
The good thing about this project is that the BloodHound for Enterprise team uses a common library between the commercial and the FOSS
project and introduces SharpHound Common: one code base from which both FOSS SharpHound and SharpHound Enterprise are built. This code
base enables, among other things: 
Improved documentation.
Improves the quality and stability of SharpHound for everyone. 
 Moving On 
Now that we have covered graph theory and how BloodHound works with nodes and edges to find the shortest paths, let’s move on and collect
some data that we can ingest into BloodHound and start manipulating. 
 Module Exercises 
Throughout this module, you will connect to various target hosts via the Remote Desktop Protocol (RDP) to complete the exercises. We will
provide any necessary credentials with each exercise, and the RDP connection can be made via xfreerdp from the Pwnbox as follows: 
Connecting via RDP 
p3ta@htb[/htb]$ xfreerdp /v:<target IP address> /u:htb-student /p:<password>
  After logging in to the target host, all tools can be found in the C:\Tools directory. 
