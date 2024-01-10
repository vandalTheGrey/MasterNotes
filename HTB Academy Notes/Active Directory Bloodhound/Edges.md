
BloodHound uses edges to represent the relationships between objects in the Active Directory (AD) environment. These relationships can include user-to-user, user-to-group, group-to-group, user-to-computer, and many others. Each edge represents a line that connects two objects, with the direction of the line indicating the direction of the relationship.

![text](https://academy.hackthebox.com/storage/modules/69/bh_edge_da_ws01.jpg)

**Example:** `Domain Admins` has the `AdminTo` edge on `WS01`.

Edges represent the privileges, permissions, and trust relationships between objects in an AD environment. These edges create a graph representation of the AD environment, allowing red and blue teamers to visualize and quickly analyze the relationships between objects. This can be useful in identifying potential security vulnerabilities, such as users with excessive privileges or access to the sensitive server. It can also help determine the possible attack paths that adversaries can use to move laterally and escalate privileges.

In this section, we will explore how to abuse edges.

___

## List of Edges

The following is a list of the edges available for Active Directory in BloodHound:

|  | List of Edges |  |
| --- | --- | --- |
| [AdminTo](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#adminto) | [MemberOf](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#adminto) | [HasSession](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#hassession) |
| [ForceChangePassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#forcechangepassword) | [AddMembers](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#addmembers) | [AddSelf](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#addself) |
| [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp) | [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp) | [ExecuteDCOM](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp) |
| [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp) | [AllowedToDelegate](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [DCSync](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) |
| [GetChanges/GetChangesAll](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [GenericAll](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [WriteDacl](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) |
| [GenericWrite](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [WriteOwner](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [WriteSPN](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) |
| [Owns](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [AddKeyCredentialLink](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [ReadLAPSPassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) |
| [ReadGMSAPassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [Contains](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [AllExtendedRights](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) |
| [GPLink](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [AllowedToAct](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [AddAllowedToAct](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) |
| [TrustedBy](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [SyncLAPSPassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate) | [HasSIDHistory](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/) |
| [WriteAccountRestrictions](https://dirkjanm.io/abusing-forgotten-permissions-on-precreated-computer-objects-in-active-directory/) |  |  |

## How to abuse an edge

An edge will allow us to move from one object to another. Let's see the following example. We are in an internal pentest, and the company gave us `Grace` credentials. Our goal is to get access to `SRV01`. We executed SharpHound and used the pathfinding option to see if there was a path from `Grace` to `SRV01`, and we got the following result:

![text](https://academy.hackthebox.com/storage/modules/69/bh_edge_grace_srv01.jpg)

Although `Grace` does not have direct privileges to connect to `SRV01`, Grace is a member of the `PasswordReset` group, which has privileges to change Rosy's account password. Rosy has privileges to connect to `SRV01` via `RDP`.

To abuse these edges, we need to change the password to the user Rosy and use his account to connect to `SRV01`. We don't need to do anything with the first edge, `MemberOf`, because being members of the `PasswordReset` group, we inherit its privileges, therefore we only need to worry about abusing the `ForceChangePassword` edge and then connect via RDP to the target machine.

If we don't know how to abuse an edge, we can right-click the edge and see the help provided in BloodHound.

![text](https://academy.hackthebox.com/storage/modules/69/bh_edge_help2.gif)

Let's do the same for `ForceChangePassword`:

![text](https://academy.hackthebox.com/storage/modules/69/bh_edge_forcechangepassword.jpg)

The `Abuse Info tab` said we had two methods to abuse this edge. The first is to use the built-in net.exe binary in Windows (e.g., `net user rosy NewRossyCreds! /domain`) or use PowerView or SharpView function `Set-DomainUserPassword`. Both methods have their opsec consideration.

**Note:** `Opsec Consideration` refer to the potential risks and attack may pose. We can relate to how easy it would be to detect the attack we are executing. It is important to read the Opsec Consideration tab if we want to go under the radar.

Let's use PowerView to change Rosy's password using the Grace account.

#### Import PowerView Module

```
PS C:\htb> Set-ExecutionPolicy Bypass -Force
PS C:\htb> Import-Module C:\tools\PowerView.ps1
```

Create a PSCredential object with Grace's credentials:

```
PS C:\htb> $SecPassword = ConvertTo-SecureString 'Password11' -AsPlainText -Force
PS C:\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\grace', $SecPassword)
```

Then create a secure string object for the password we want to set to Rosy:

```
PS C:\htb> $UserPassword = ConvertTo-SecureString 'NewRossyCreds!' -AsPlainText -Force
```

Use the function `Set-DomainUserPassword` with the option `-Identity`, which corresponds to the account we want to change its password (rosy), add the option `-AccountPassword` with the variable that has the new password, use the option `-Credential` to execute this command using Grace's credentials. Finally, set the option `-Verbose` to see if the change was successful.

```
PS C:\htb> Set-DomainUserPassword -Identity rosy -AccountPassword $UserPassword -Credential $Cred -Verbose
VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'rosy'
VERBOSE: [Set-DomainUserPassword] Password for user 'rosy' successfully reset
```

We can now connect via RDP to `SRV01` using `Rosy` account.

## BloodHound Playground

One of the things we wanted to achieve with this BloodHound module was to create a playground to test as many BloodHound edges as possible. This is because sometimes we want to try a concept before applying it in a Pentest or understand why a specific command fails during a CTF. So we created multiple vulnerabilities in this lab for these tests and practiced as many edges as we wanted.

The following table will find a list of credentials and the edges to abuse.

| **Username** | **Password** | **Edge** | **Target** |
| --- | --- | --- | --- |
| grace | Password11 | ForceChangePassword | rosy |
| rosy | Password99 | CanRDP, CanPSRemote, ExecuteDCOM | SRV01 |
| sarah | Password12 | AdminTo | SRV01 |
| martha | Password13 | AddMembers | ITManagers |
| victor | Password14 | AddSelf | ITManagers |
| ester | Password15 | AllowedToDelegate | SRV01 |
| peter | Licey2023 | DCSync | INLANEFREIGHT |
| pedro | Password17 | GenericAll (User) | ester |
| pedro | Password17 | GenericAll (Group) | ITAdmins |
| pedro | Password17 | GenericAll (Computer) | WS01 |
| pedro | Password17 | GenericAll (Domain) | INLANEFREIGHT |
| carlos | Password18 | WriteDacl (User) | juliette |
| carlos | Password18 | WriteDacl (Group) | FirewallManagers |
| carlos | Password18 | WriteDacl (Computer) | SRV01 |
| carlos | Password18 | WriteDacl (Domain) | INLANEFREIGHT |
| indhi | Password20 | WriteOwner (User) | juliette |
| indhi | Password20 | WriteOwner (Group) | FirewallManagers |
| indhi | Password20 | WriteOwner (Computer) | SRV01 |
| indhi | Password20 | WriteOwner (Domain) | INLANEFREIGHT |
| svc\_backups | BackingUpSecure1 | WriteDacl | BACKUPS (GPO) |
| svc\_backups | BackingUpSecure1 | WriteOwner | BACKUPS (GPO) |
| svc\_backups | BackingUpSecure1 | GenericWrite | BACKUPS (GPO) |
| indhi | Password20 | WriteSPN | nicole |
| nicole | Password21 | GenericWrite | albert |
| sarah | Password12 | AddKeyCredentialLink | indhi |
| elieser | Password22 | Owns (User) | nicole |
| daniela | Password23 | AddKeyCredentialLink | SRV01 |
| cherly | Password24 | ReadLAPSPassword | LAPS01 |
| cherly | Password24 | ReadGMSAPassword | svc\_devadm |
| elizabeth | Password26 | AllExtendedRights (User) | elieser |
| gil | Password28 | AddAllowedToAct | DC01 |

To find the attack path use the search box and the path-finding option.

![text](https://academy.hackthebox.com/storage/modules/69/bh_path_finding_3.gif)

## Next Steps

This is a useful section to learn if you need to practice any BloodHound attack vector. Take the time to practice and come back to this section when you need to refresh any concept.

In the following section, we will see some additional options that BloodHound offers to analyze the information and look for methods to achieve our goal.

___