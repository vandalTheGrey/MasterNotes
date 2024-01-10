# Bloodhound
execute bloodhound from linux machine 
```
bloodhound-python -d inlanefreight.htb -c DCOnly -u htb-student -p HTBRocks! -ns 10.129.204.226 -k
```

## Adjusting hostfile to use kerberos authentication
```
echo -e "\n10.129.204.226 dc01.inlanefreight.htb dc01 inlanefreight inlanefreight.htb" | sudo tee -a /etc/hosts
```

## Bloodhound with Kerberos authentication
```
bloodhound-python -d inlanefreight.htb -c DCOnly -u htb-student -p HTBRocks! -ns 10.129.204.226 --kerberos
```

![[Pasted image 20231113115640.png]]