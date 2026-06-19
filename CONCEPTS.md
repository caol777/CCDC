# Security Concepts — Why Everything in These Scripts Matters

This document explains the security reasoning behind every technique used in these scripts.
Written for teaching purposes — not just *what* we do, but *why* it works and *what happens if you skip it*.

---

## Table of Contents
1. [Linux Authentication Files](#1-linux-authentication-files)
2. [SSH Hardening](#2-ssh-hardening)
3. [PAM — Pluggable Authentication Modules](#3-pam--pluggable-authentication-modules)
4. [Linux Persistence Mechanisms](#4-linux-persistence-mechanisms)
5. [C2 Frameworks and Beacons](#5-c2-frameworks-and-beacons)
6. [Firewall Fundamentals](#6-firewall-fundamentals)
7. [Web Server Security](#7-web-server-security)
8. [Database Security](#8-database-security)
9. [Windows and Active Directory](#9-windows-and-active-directory)
10. [Windows Persistence](#10-windows-persistence)
11. [Password Security](#11-password-security)
12. [Logging and Forensics](#12-logging-and-forensics)
13. [Competition Mindset](#13-competition-mindset)

---

## 1. Linux Authentication Files

These four files are the core of who can log in to a Linux system and what they can do.
Red teams attack them immediately because compromising one gives persistent access.

### `/etc/passwd`
**What it is:** A list of every user account on the system.
Each line is: `username:x:UID:GID:comment:home:shell`

**Why it matters:**
- The `x` in field 2 means the password is stored in `/etc/shadow`. If you ever see an actual password hash here, the shadow file security has been bypassed.
- **UID 0** is root. If an attacker adds a new user with UID 0, that user has full root access regardless of username. Example of a backdoor: `hacker:x:0:0::/root:/bin/bash`
- The shell field controls what shell a user gets. `/bin/bash` = full shell. `/sbin/nologin` or `/bin/false` = no login. Service accounts should always have `/sbin/nologin`.
- **What to check:** Any account with UID 0 that isn't `root`. Any unexpected account with `/bin/bash`.

**Correct permissions:** `644` (world-readable, root-writable). `firstrun.sh` enforces this.

### `/etc/shadow`
**What it is:** The actual password hashes for every user. Only readable by root.

**Why it matters:**
- If an attacker can read this file, they can take it offline and crack the hashes with tools like `hashcat` or `john`.
- If they can *write* to it, they can set any password they want, including blank passwords.
- Password format: `$6$` = SHA-512 (good), `$1$` = MD5 (weak, crackable in seconds), blank field = no password required (critical vulnerability).
- **What to check:** Any account with a blank password hash field or an MD5 hash.

**Correct permissions:** `600` (root read/write only). `firstrun.sh` enforces this.

### `/etc/group`
**What it is:** Defines groups and their members.
Each line is: `groupname:x:GID:member1,member2`

**Why it matters:**
- The `sudo` and `wheel` groups grant root-level command execution via `sudo`.
- The `docker` group is effectively root — Docker can mount the host filesystem.
- The `shadow` group can read `/etc/shadow`.
- **What to check:** Any unexpected users in `sudo`, `wheel`, `docker`, or `shadow` groups. Our `login.sh` inject script shows this automatically.

### `/etc/sudoers` and `/etc/sudoers.d/`
**What it is:** Defines exactly who can run what commands as root via `sudo`.

**Why it matters:**
- A single bad line here gives an attacker root. Classic backdoor: `ALL ALL=(ALL) NOPASSWD: ALL` — lets anyone run anything as root without a password.
- The `.d/` directory is frequently overlooked. Files dropped here are automatically included, making it a popular red team persistence spot.
- **What to check:** Any `NOPASSWD` entries for broad commands. Any unfamiliar files in `/etc/sudoers.d/`. Our `bad.sh` script displays the full sudoers configuration.

---

## 2. SSH Hardening

SSH is the front door to every Linux box. These settings in `/etc/ssh/sshd_config` directly control how hard that door is to break down.

### `PermitRootLogin no`
**Why:** If root can log in directly over SSH, an attacker only needs one credential — root's password — to have full control. With this disabled, they need to compromise a regular user first, then escalate. Two steps instead of one.

### `PermitEmptyPasswords no`
**Why:** Self-explanatory. Accounts with no password set should never be allowed to log in over SSH. Without this setting, a misconfigured account is an open door.

### `AllowTcpForwarding no`
**Why:** TCP forwarding lets someone use your SSH connection as a tunnel to reach other systems on your network. Red teams use this for lateral movement — they compromise one box, then tunnel through it to attack internal systems that aren't exposed to the internet.

### `X11Forwarding no`
**Why:** X11 forwarding tunnels graphical application windows over SSH. It's almost never needed on a server and adds attack surface. Historically has had exploitable vulnerabilities.

### `AuthorizedKeysFile`
**Why it matters:** SSH key authentication bypasses passwords entirely. If a red team drops their public key into `~root/.ssh/authorized_keys`, they have permanent root access regardless of what password is set. Our `persist_hunt.sh` checks every home directory and root's SSH directory for unexpected authorized keys.

---

## 3. PAM — Pluggable Authentication Modules

**What it is:** PAM is the authentication framework that sits underneath SSH, `sudo`, login, and every other authentication method on Linux. It's a series of modules that chain together to verify identity.

**Why it matters for attackers:** Because PAM is universal, a single malicious PAM module can intercept every login on the system — SSH, console, `sudo`, everything. This is one of the most powerful persistence techniques available.

**How a PAM backdoor works:**
1. Attacker compiles a malicious `pam_unix.so` or drops a new module like `pam_exec.so`
2. They add a line to `/etc/pam.d/sshd` like: `auth sufficient pam_exec.so /tmp/backdoor.sh`
3. `sufficient` means "if this module succeeds, stop checking and grant access"
4. Their backdoor script always returns success, letting anyone log in with any password

**What we do about it:**
- `firstrun.sh` backs up all PAM config files and library hashes at competition start
- `pom.sh` can restore PAM from backup or reinstall from the distro's package manager
- `persist_hunt.sh` compares current PAM module hashes against the backup baseline

---

## 4. Linux Persistence Mechanisms

Persistence means "I can leave and come back." Red teams plant persistence as soon as they get in so that even if you change passwords, they still have access.

### Systemd Unit Files
**What it is:** Systemd is the init system on most modern Linux distributions. It manages services that start at boot.

**Why it's used for persistence:** An attacker can create a file like `/etc/systemd/system/updater.service` that looks like a legitimate service but runs their C2 beacon at every boot. User-level systemd in `~/.config/systemd/user/` is even sneakier because it runs without root.

**What to look for:** Unit files in `/etc/systemd/system/` or `/lib/systemd/system/` that were recently created and have unfamiliar names. Our `persist_hunt.sh` checks modification times.

### Cron Jobs
**What it is:** A scheduler that runs commands at specified times.

**Locations to check:**
- `/etc/crontab` — system-wide crontab
- `/etc/cron.d/` — drop-in cron files
- `/var/spool/cron/crontabs/` — per-user crontabs
- `/etc/cron.hourly/`, `/etc/cron.daily/` etc. — scripts that run on schedule

**Why it's used for persistence:** A cron job that runs every minute and calls a reverse shell will re-establish the attacker's connection even if you kill it. `firstrun.sh` saves all crontab state at the start of competition as baseline evidence.

### Shell Profiles
**Files:** `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `/etc/profile`, `/etc/profile.d/*.sh`

**Why it's used for persistence:** Every time a user opens a shell, these files execute. Appending a reverse shell command here is persistent and subtle. Our `persist_hunt.sh` checks these files for anything that looks like a network callback.

### `authorized_keys`
**Why it's used for persistence:** SSH key authentication does not require a password and is not affected by password changes. If an attacker adds their public key here, changing the account's password does nothing — they still have access.

### LD_PRELOAD Hijacking
**What it is:** `LD_PRELOAD` is an environment variable that tells the dynamic linker to load a specific library *before* any others when a program starts.

**Why it's dangerous:** An attacker can create a malicious shared library that overrides standard functions like `read()` or `write()`. If `LD_PRELOAD` is set in `/etc/environment` or `/etc/ld.so.preload`, it affects every program on the system — a rootkit-level technique.

**What to look for:** Entries in `/etc/environment`, `/etc/ld.so.preload`, and unusual `.so` files in standard library directories.

### SUID Binaries
**What it is:** A SUID (Set User ID) binary runs with the permissions of the file's *owner* rather than the user who executes it. `/usr/bin/passwd` is a legitimate SUID binary owned by root — it needs root permissions to write to `/etc/shadow`.

**Why it's dangerous:** If an attacker creates or modifies a SUID root binary, anyone who executes it gets root. Classic example: `cp /bin/bash /tmp/.hidden_bash; chmod +s /tmp/.hidden_bash` creates a hidden bash that anyone can run as root.

**What to look for:** SUID binaries that aren't in the standard list, especially ones in `/tmp/` or world-writable directories. `firstrun.sh` saves the full SUID list at start; `bad.sh` audits them.

### Kernel Modules
**What it is:** Kernel modules are code that loads directly into the Linux kernel. Legitimate uses include device drivers.

**Why it's dangerous:** A malicious kernel module is a true rootkit. It runs in kernel space, can hide processes and files from `ls` and `ps`, intercept system calls, and is almost invisible to userspace tools. This is the hardest persistence mechanism to detect and remove.

**What to look for:** Modules loaded with `lsmod` that aren't associated with known hardware or software. `persist_hunt.sh` checks recently loaded modules and compares against expected ones.

---

## 5. C2 Frameworks and Beacons

**What is C2?** Command and Control — the infrastructure an attacker uses to remotely control compromised machines. A "beacon" is the malware running on your machine that periodically calls home.

### How beacons work
1. Attacker sets up a listener on their server
2. Malware on your machine "beacons out" — makes an outbound connection to the attacker's server at regular intervals
3. The attacker sends commands back over this connection
4. Because the connection is *outbound* from your machine, many firewalls allow it by default

### Why outbound matters
Most organizations block inbound connections but allow outbound. A beacon calling out to port 443 (HTTPS) looks like normal web traffic. This is why our firewall scripts block *both* inbound and outbound by default, only allowing explicitly permitted traffic.

### Known C2 port signatures
- **Metasploit:** 4444 (default listener)
- **Cobalt Strike:** 50050 (team server)
- **Sliver:** 31337, 8888
- **Merlin:** 443 (blends with HTTPS)
- **Empire/Starkiller:** 1337

### How `persist_hunt.sh` detects C2
- Checks for processes with known C2 tool names (sliver, merlin, covenant, etc.)
- Looks for listening processes on known C2 ports
- Finds processes running from `/tmp/`, `/dev/shm/` (memory-only execution)
- Detects processes running from deleted binaries (fileless malware — executed then deleted from disk)

---

## 6. Firewall Fundamentals

### iptables (Linux)
**What it is:** The kernel-level packet filtering framework on Linux. Rules are processed in order and the first matching rule wins.

**Three chains:**
- **INPUT** — traffic coming *into* this machine
- **OUTPUT** — traffic leaving *from* this machine
- **FORWARD** — traffic passing *through* this machine (router behavior)

**Two policies:**
- **ACCEPT** — let it through
- **DROP** — silently discard (attacker gets no response, doesn't know if you're there)

**Why default-deny matters:**
Setting `-P INPUT DROP` means anything not explicitly allowed is blocked. This is the right starting point. Default-allow (the opposite) means you have to know every attack to block it — impossible. Default-deny means you only have to know your own services.

**Why we block OUTPUT too:**
A default-deny outbound policy means that even if an attacker gets code running on your box, their beacon can't call home. This is one of the most effective defenses against C2 and is often overlooked.

### pf (BSD)
**What it is:** Packet Filter — BSD's equivalent of iptables. Used on FreeBSD and OpenBSD.

**Key difference from iptables:** Rules are evaluated top-to-bottom and the *last matching rule wins* (opposite of iptables). `block all` at the bottom is the equivalent of iptables default-deny.

**Why `kldload pf` only on FreeBSD:** OpenBSD ships with pf compiled directly into the kernel — it's always available. FreeBSD ships pf as a loadable kernel module, so it needs to be loaded first with `kldload pf` before `pfctl` works.

### UFW (Ubuntu/Debian)
**What it is:** Uncomplicated Firewall — a frontend that generates iptables rules. Easier syntax but less portable.

**Why we have both `fw.sh` and `ufw.sh`:** `fw.sh` works on everything (RHEL, Alpine, Arch, BSD). `ufw.sh` is Ubuntu/Debian only and is provided as an alternative for teams more comfortable with UFW syntax.

---

## 7. Web Server Security

### Hiding server version (`ServerTokens Prod` / `server_tokens off`)
**Why:** By default, Apache and nginx announce their exact version number in every HTTP response header. An attacker seeing `Apache/2.4.49` can immediately look up known CVEs for that exact version. `ServerTokens Prod` reduces this to just "Apache" — no version, no CVE shortcut.

### Disabling directory listing (`Options -Indexes` / `autoindex off`)
**Why:** If a web server can't find `index.html` in a directory, default-enabled directory listing shows the entire contents of that folder to any visitor. Attackers use this to find backup files, configuration files, source code, and other sensitive data they weren't meant to see.

### Disabling TRACE (`TraceEnable Off`)
**Why:** The HTTP TRACE method echoes back whatever it receives. This enables a Cross-Site Tracing (XST) attack — a way to steal cookies and credentials even when `HttpOnly` flags are set.

### Security headers
- **`X-Frame-Options: SAMEORIGIN`** — prevents your site from being loaded in an iframe on another domain, blocking clickjacking attacks
- **`X-Content-Type-Options: nosniff`** — stops browsers from guessing the content type, preventing MIME-type confusion attacks
- **`X-XSS-Protection: 1; mode=block`** — enables the browser's built-in XSS filter
- **`Referrer-Policy`** — controls how much information is sent in the `Referer` header to other sites

### Blocking sensitive file extensions
Files like `.bak`, `.sql`, `.env`, `.old` are backup copies that developers forget to delete. They often contain database credentials, API keys, or full source code. Blocking these at the web server level means they're never served even if they exist on disk.

### PHP `disable_functions`
**Why:** PHP functions like `exec()`, `system()`, `shell_exec()`, and `passthru()` let PHP code run operating system commands. These are the functions webshells use. Disabling them in `php.ini` means even if an attacker uploads a webshell, it can't execute commands.

---

## 8. Database Security

### Anonymous users
**What they are:** MySQL accounts with a blank username (`''`). Any connection attempt matches them if no other user matches first.

**Why it's dangerous:** An attacker connecting to MySQL without providing a username at all will be authenticated as the anonymous user. They bypass every password control.

### Remote root login
**What it is:** A MySQL root account with a `Host` value other than `localhost` — meaning root can log in from any IP address.

**Why it's dangerous:** Combined with a weak password (or no password), this means anyone on the network can attempt to brute-force your database root account. MySQL root = full control over all databases.

### `LOCAL INFILE`
**What it is:** A MySQL feature that lets SQL queries read files directly from the filesystem.

**Why it's dangerous:** `SELECT LOAD_FILE('/etc/passwd')` — from inside MySQL, an attacker can read any file the MySQL process has access to. This is a data exfiltration vector that works even if they can't get a shell.

### `bind-address = 127.0.0.1`
**Why:** By default MySQL listens on all network interfaces — meaning it's reachable from other machines on the network. Binding to localhost means MySQL only accepts connections from the same machine. Application code running locally still works, but remote attacks against the database port are impossible.

---

## 9. Windows and Active Directory

### Pass-the-Hash (PTH)
**What it is:** Windows NTLM authentication can be exploited without knowing the actual password. An attacker who steals the NTLM hash of an account (from memory via tools like Mimikatz) can use that hash directly to authenticate — they never need to crack it.

**Mitigations:**
- Require NTLMv2 (registry key)
- Enable `LocalAccountTokenFilterPolicy` controls to limit remote admin access
- Use Protected Users security group for privileged accounts

### Zerologon (CVE-2020-1472)
**What it is:** A critical vulnerability in the Netlogon protocol that allows an unauthenticated attacker to set the domain controller's computer account password to blank, effectively giving them domain admin rights instantly.

**Why it's still relevant:** Unpatched DCs are still common in competition environments. The fix is a registry key that enforces secure Netlogon connections — `ADHardening.ps1` applies this.

### Kerberoasting
**What it is:** Service accounts in AD have Service Principal Names (SPNs). Any authenticated domain user can request a Kerberos service ticket encrypted with the service account's password hash. The attacker takes this ticket offline and cracks the hash.

**Why service account passwords matter:** A service account with password `Summer2023!` will be cracked in seconds. Strong, long, random passwords make Kerberoasting computationally infeasible.

### LDAP Signing
**What it is:** Digitally signing LDAP traffic prevents an attacker from intercepting and modifying directory queries and responses.

**Why it matters:** Without LDAP signing, an LDAP relay attack lets an attacker intercept authentication attempts and relay them to the domain controller to authenticate as the victim.

### PrintNightmare (CVE-2021-34527)
**What it is:** A vulnerability in the Windows Print Spooler service that allows any authenticated user to load arbitrary DLLs with SYSTEM privileges.

**Why it's still relevant:** The Print Spooler service runs by default on almost every Windows machine. Disabling it (when printing isn't needed) completely eliminates this attack surface. `ADHardening.ps1` disables it.

### Defender ASR Rules (Attack Surface Reduction)
**What they are:** Windows Defender rules that block specific behaviors associated with malware, even if the malware isn't in any signature database.

**Key rules:**
- Block Office applications from creating child processes (stops macro malware)
- Block credential stealing from `lsass.exe` (stops Mimikatz)
- Block process creation from PSExec and WMI (stops lateral movement)
- Block JavaScript/VBScript from launching executables (stops dropper scripts)

---

## 10. Windows Persistence

### Registry Run Keys
**What they are:** Registry keys that automatically execute programs when a user logs in or the system starts.

**Key locations:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` — runs for all users at login
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — runs for the current user at login
- `HKLM\...\RunOnce` — runs once then deletes itself

**Why it's used:** Simple, effective, hard to miss unless you're looking. Red teams often use names that blend in with legitimate software.

### Scheduled Tasks
**What they are:** The Windows equivalent of cron — programs that run at specified times or events.

**Why it's used for persistence:** A scheduled task can run at login, at boot, every minute, or on any system event. Tasks that run from `%TEMP%`, `%APPDATA%`, or with random GUID-like names are suspicious. `PersistHunt.ps1` flags these.

### WMI Subscriptions
**What it is:** Windows Management Instrumentation can trigger scripts in response to system events — a process starting, a user logging in, a file being created.

**Why it's the hardest Windows persistence to find:**
- WMI subscriptions survive reboots
- They don't appear in the registry
- They don't appear in scheduled tasks
- They don't show up in `msconfig` or startup folders
- Only visible through WMI queries themselves

**How `PersistHunt.ps1` detects them:** Queries `__EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding` WMI classes directly and flags any subscriptions that exist.

### Service Binary Path Manipulation
**What it is:** Windows services have a `PathName` property pointing to the executable that runs as the service. If an attacker modifies this path (or the binary itself), they can run arbitrary code as SYSTEM on every boot.

---

## 11. Password Security

### Why passphrases instead of complex passwords
`firstrun.sh` and `ADuserPassChange.ps1` generate passwords like `RedAppleTreeMoon123!` instead of `P@ssw0rd!`.

**The math:** A random 4-word passphrase from a 1000-word list has 1000^4 = 10^12 combinations. A typical "complex" 8-character password (`P@ssw0rd`) has far fewer effective combinations because people are predictable. Passphrases are stronger *and* easier for your team to remember and type under pressure.

### Why we change passwords immediately at competition start
Red teams often start with credentials found in OSINT, leaked from previous competitions, or from weak defaults. Changing all passwords in the first 5 minutes removes this attack vector before they can use it.

### Domain vs local accounts
- **Local accounts** — live on each individual machine in `/etc/shadow` (Linux) or the local SAM database (Windows). `passwd.sh` changes these.
- **Domain accounts** — live in Active Directory. Only the DC knows the real password. Changing it on the DC propagates everywhere. Linux machines that are domain-joined cache credentials in SSSD.
- **SSSD cache** — when a domain-joined Linux box authenticates a user, it caches the credentials locally. After the AD person changes the password, the Linux box still has the old hash cached. `flush_domain_cache.sh` clears this so the new password works.

---

## 12. Logging and Forensics

### Why logging matters in CCDC
Injects often ask you to prove what happened — "show evidence of the attack," "how many times was this account brute-forced?" Without logs, you can't answer. With logs, you can answer quickly and earn inject points.

### Key Linux log files
- `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL) — all authentication events: SSH logins, `sudo` usage, PAM events
- `/var/log/syslog` / `/var/log/messages` — general system events
- `/var/log/apache2/access.log`, `/var/log/nginx/access.log` — web server requests (look for webshell hits)
- `/var/log/audit/audit.log` — kernel-level audit events when auditd is running

### `auditd`
**What it is:** The Linux Audit Daemon records security events at the kernel level — file access, system calls, user commands. Unlike bash history (which can be cleared by the attacker), audit records are much harder to tamper with without leaving evidence.

### `snoopy`
**What it is:** A PAM module that intercepts every command executed on the system and logs it to syslog. Because it hooks at the PAM level, it captures commands even from shells that have `HISTFILE=/dev/null` (no history).

### `pspy64`
**What it is:** A Linux tool that monitors the `/proc` filesystem to watch process creation events in real time — without needing root. You see every command run by every user, including cron jobs and scripts the red team runs. Essential for catching red team activity live.

### Windows Event IDs to know
- **4624** — Successful login
- **4625** — Failed login (watch for brute force)
- **4720** — User account created (attacker creating backdoor account)
- **4732** — User added to privileged group
- **4688** — Process created (with command line logging enabled)
- **4663** — Object access (file read/write, if auditing enabled)
- **7045** — New service installed (common persistence method)

---

## 13. Competition Mindset

### Default-deny everything
Start every system in a locked-down state. Allow only what is explicitly needed. This applies to firewalls, file permissions, SQL user grants, and web server configurations. It is always easier to open a door than to figure out which doors are open and close them.

### Baseline first, hunt second
The most powerful forensics technique is comparison. `firstrun.sh` captures the entire state of the system at competition start — users, ports, processes, SUID binaries, cron jobs. Every subsequent check compares against that baseline. A new user appearing in `/etc/passwd` is caught by `userdiff.sh`. A new listening port is caught by `netdiff.sh`. Without a baseline, you're looking for something wrong in a system you don't fully know.

### Speed vs completeness tradeoff
In a competition, a script that covers 80% of hardening in 5 minutes beats a perfect script that takes 20 minutes. Red teams are active from minute one. The scripts in this repo are designed to be fast — run in the right order and you're hardened before most red team activity begins.

### Assume compromise
In CCDC, the machines are handed to you pre-compromised. Red teams have had access before you. Always treat every machine as already owned. This means:
- Check persistence mechanisms even before changing passwords
- Look for webshells in web root directories
- Audit who has SSH authorized keys
- Check for unexpected cron jobs and services

### Documentation wins points
CCDC scoring includes both service availability (scored automatically) and inject points (scored by humans reading your reports). Every script that saves its output to a file is giving you evidence for inject answers. Screenshots of `persist_hunt.sh` output showing `[BAD]` findings directly answer "was this machine compromised?" inject questions.

### The attack chain
Understanding how attackers move helps you prioritize:
1. **Initial access** — phishing, public exploit, weak credentials
2. **Execution** — run code on the target
3. **Persistence** — ensure they can return (everything in section 4 and 10)
4. **Privilege escalation** — go from limited user to root/SYSTEM
5. **Defense evasion** — hide their presence (rootkits, log clearing)
6. **Credential access** — steal passwords/hashes for lateral movement
7. **Lateral movement** — move from one machine to others
8. **Exfiltration / impact** — steal data or cause damage

Our scripts focus heavily on steps 3 (persistence), 5 (evasion detection), and 6 (credential security) because those are the stages where blue teams can most effectively detect and interrupt red team activity during a competition.
