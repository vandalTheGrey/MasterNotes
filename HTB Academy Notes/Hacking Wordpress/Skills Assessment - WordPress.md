
# NMAP
```
❯ nmap -sCV -T4 -Pn 10.129.2.37
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-15 13:17 PST
Nmap scan report for 10.129.2.37
Host is up (0.083s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:31:c0:f2:74:ba:29:32:5d:15:ae:43:c5:3a:2c:ab (RSA)
|   256 b5:64:dc:0a:bc:2d:d9:aa:1e:42:b2:50:34:73:0f:40 (ECDSA)
|_  256 5e:7e:8a:b9:e7:73:5c:be:00:f2:5f:19:d6:d3:23:e3 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Inlane Freight
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.74 seconds
```

Knowing that the company is inlanefrieght we can identify that its inlanefreight.local and identify that blog.inlanefreight is something. Add that to our hosts file. 
![[Pasted image 20231215132115.png]]

![[Pasted image 20231215132819.png]]

# WPscan

![[Pasted image 20231215133053.png]]

## Question: 1
What version of word press is running

![[Pasted image 20231215133107.png]]

## Question: 2 
What theme is running 

![[Pasted image 20231215133224.png]]

## Question: 3
Submit the contents of the flag file in the directory with directory listing enabled.

Copy paste the WP scan results into a text file
![[Pasted image 20231215134318.png]]
## Question : 4
Identify the only non-admin WordPress user. 

Enumerate users
```
wpscan --url http://blog.inlanefreight.local/ -e u
```

![[Pasted image 20231215134004.png]]
## Question: 5
Use a vulnerable plugin to download a file containing a flag value via an unauthenticated file download.

email-subscribers is vulnerable
https://www.exploit-db.com/exploits/48698

![[Pasted image 20231215140725.png]]

![[Pasted image 20231215140711.png]]
## Question: 6
What plugin is vulnerable to LFI

![[Pasted image 20231215135851.png]]
Enumerate just the plugings
```
wpscan --url http://blog.inlanefreight.local/ --api-token 51vO4v72sy7CxiqSaaIMsSH6V6SHKlPNmrmg7vcydB8 -e vp --plugins-detection mixed -t 64
```

![[Pasted image 20231215135841.png]]

## Question 7
Use the LFI to identify a system user whose name starts with the letter "f".

![[Pasted image 20231215140901.png]]

## Question: 8
Get a shell and Erika contents
```
wpscan --url blog.inlanefreight.local -U erika -P /usr/share/wordlists/rockyou.txt
```

![[Pasted image 20231215141609.png]]

Login as erika

Lets look at the themes and try a php revserseshell from the 404 template page 

Identify the theme that can be modified 

![[Pasted image 20231215142325.png]]

Inject your payload
![[Pasted image 20231215142206.png]]

Now navigate to 
```
http://blog.inlanefreight.local/wp-content/themes/twentysixteen/404.php
```

![[Pasted image 20231215142724.png]]