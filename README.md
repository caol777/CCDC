# CCDC Scripts

Blue team scripts for CCDC competitions. Covers Linux hardening, Windows AD hardening, password management, persistence hunting, web server stability, and C2 detection.

> **Tool reference:** See [TOOLS.md](TOOLS.md) for what every installed tool does and how to use it during competition.

---

## Competition Workflow

### Step 1 — First thing on every Linux box
```bash
# Edit the IPs at the top of the firewall script first
nano Linux/fw.sh           # set DISPATCHER, LOCALNETWORK, CCSHOST at the top

bash Linux/firstrun.sh     # installs tools, backs up /etc /bin /var/www, hardens SSH/PHP
bash Linux/fw.sh           # locks down firewall
bash Linux/passwd.sh       # changes all LOCAL account passwords, saves CSV to /tmp/
```

### Step 2 — Coordinate with the Windows/AD person
```bash
# AFTER the AD person changes domain passwords in Windows AD:
bash Linux/flush_domain_cache.sh    # flushes SSSD/Winbind cache on THIS machine
                                    # run on every domain-joined Linux box
```

### Step 3 — Harden services on Linux
```bash
bash Linux/pom.sh          # backup/reinstall PAM modules
bash Linux/webdb.sh        # enumerate web/DB services and check configs

# Web server boxes only:
bash Linux/webharden.sh    # harden Apache/nginx (hide version, disable dir listing, security headers)
bash Linux/webwatch.sh &   # starts watchdog — keeps nginx/apache/PHP/MySQL alive
                            # or cron: */2 * * * * /path/to/webwatch.sh NOLOOP=1

# Database boxes only:
bash Linux/mysqharden.sh   # harden MySQL/MariaDB (remove anon users, set root pass, bind localhost)
```

### Step 4 — On Windows (run via Run.ps1 dispatcher or manually)
```powershell
# From dumbssh — use their Run.ps1 to deploy to ALL Windows boxes at once
.\Run.ps1 -Connect                                    # connect to all boxes via WinRM
.\Run.ps1 -Script .\ADHardening.ps1 -Out .\out\      # run hardening on all
.\Run.ps1 -Script .\Log.ps1 -Out .\out\               # enable logging on all

# On the DC specifically:
.\ADuserPassChange.ps1 -UserPassword "Summer2024!" -AdminPassword "Admin@2024!" -AdminUsers "bob,alice"
```

### Step 5 — Hunt for persistence (run throughout competition)
```bash
# Linux
bash Linux/persist_hunt.sh         # C2/persistence + auth file audit (21 checks total)
bash Linux/bad.sh                  # SUID/caps/sudoers audit
bash injects/login.sh             # login counts + top attacker IPs

# Differential checks (requires firstrun.sh baseline)
bash Linux/userdiff.sh             # new users/groups since start?
bash Linux/netdiff.sh              # new ports/connections since start?

# Compile everything into one IR report for injects/evidence
bash Linux/ir_report.sh            # → /tmp/IR_REPORT_HOST_TIMESTAMP.txt
```
```powershell
# Windows
.\PersistHunt.ps1                  # registry run keys, WMI subs, tasks, C2 ports, etc.
```

---

## Linux Scripts

### `env.sh`
Set these variables before running `fw.sh`.
```bash
export DISPATCHER="10.0.0.50"       # Your blue team management IP
export LOCALNETWORK="10.0.0.0/24"   # Internal subnet
export CCSHOST="10.0.0.1"           # Scoring engine / NAT router IP
source Linux/env.sh
```

### `firstrun.sh`
**Run first on every Linux box.** Installs tools, hardens SSH, hardens PHP, backs up `/etc`, `/bin`, `/var/www`, captures baseline port and process snapshots (needed by `netdiff.sh` / `userdiff.sh`).
```bash
bash Linux/firstrun.sh
# Optional: set BCK=/your/path to change backup location (default: /tmp/initial)
```

### `passwd.sh`
Changes **local** account passwords only (root + UID≥1000). Generates random 4-word passphrases (e.g. `EagleMoonCyberRock123!`). Saves results to `/tmp/passwd_TIMESTAMP.csv`.
> For domain accounts — use `flush_domain_cache.sh` after AD changes passwords.
```bash
bash Linux/passwd.sh
cat /tmp/passwd_*.csv   # review credentials
```

### `flush_domain_cache.sh`
Run on domain-joined Linux boxes **immediately after** the AD person changes passwords in Windows. Flushes SSSD/Winbind/Kerberos cache so Linux machines accept the new domain passwords.
```bash
bash Linux/flush_domain_cache.sh
```

### `fw.sh`
**Universal firewall script** — auto-detects the OS and uses the right tool:
- **Linux (any)** — raw iptables (stops firewalld/ufw first, works on RHEL, Debian, Alpine, etc.)
- **FreeBSD** — pf (loads kernel module, writes `/etc/pf.conf`)
- **OpenBSD** — pf (already built-in, no kldload needed)

Edit the 3 IP values at the top of the script, then run it.
```bash
nano Linux/fw.sh           # set DISPATCHER, LOCALNETWORK, CCSHOST at the top
bash Linux/fw.sh
# Uncomment service port templates inside for scored services (80, 443, 3306, etc.)
```

### `ufw.sh`
UFW alternative for **Ubuntu/Debian only** — use this instead of `fw.sh` if you prefer UFW syntax.
```bash
nano Linux/ufw.sh          # set DISPATCHER, LOCALNETWORK, CCSHOST at the top
bash Linux/ufw.sh
# Uncomment service port templates inside for scored services
```
> **Which to use?** `fw.sh` works everywhere. `ufw.sh` is Ubuntu/Debian only. For RHEL, just use `fw.sh` — it handles firewalld automatically.

### `fw_simple.sh` / `ufw_simple.sh`
**Fallback scripts — no IP addresses needed.** Use these if you don't know the network layout yet or entered wrong IPs in `fw.sh`/`ufw.sh`. Just uncomment the ports that are scored on the box and run.
```bash
# iptables version (works on any Linux, RHEL, BSD with iptables)
bash Linux/fw_simple.sh

# UFW version (Ubuntu/Debian only)
bash Linux/ufw_simple.sh
```
Both scripts: deny all inbound by default, allow all outbound, SSH (22) open, known C2 ports blocked. Uncomment service port lines inside for anything else that needs to be reachable.

### `pom.sh`
PAM backup, restore, and reinstall script.
```bash
bash Linux/pom.sh              # backup PAM config and libraries
REINSTALL=1 bash Linux/pom.sh  # reinstall PAM packages from distro repo
REVERT=1 bash Linux/pom.sh     # restore PAM from backup
```

### `webdb.sh`
Enumerate web and database services — shows active ports, vhost config, SQL weak credentials, PHP disabled functions.
```bash
bash Linux/webdb.sh
COLOR=1 bash Linux/webdb.sh    # colored output
```

### `webwatch.sh`
Keeps nginx/apache/PHP-FPM/MySQL alive. Detects and quarantines webshells. Hardens WordPress uploads directories.
```bash
nohup bash Linux/webwatch.sh &                          # background daemon (30s loop)
NOLOOP=1 bash Linux/webwatch.sh                         # single run (for cron)
WP_BACKUP=/backups/wp.tar.gz bash Linux/webwatch.sh &   # auto-restore WP from backup

# Cron option (every 2 minutes):
# */2 * * * * NOLOOP=1 bash /path/to/webwatch.sh
```

### `mysqharden.sh`
MySQL / MariaDB hardening. Auto-connects using weak/default credentials, then:
- Sets a strong root password (configure at top of script)
- Removes anonymous users
- Removes remote root login
- Drops test database
- Flags blank-password accounts
- Restricts `bind-address` to localhost
- Disables `LOCAL INFILE`
```bash
nano Linux/mysqharden.sh   # set NEW_ROOT_PASS and BIND_LOCALHOST_ONLY
bash Linux/mysqharden.sh
```

### `webharden.sh`
Apache / nginx hardening. Auto-detects which server is running and hardens both if present:
- Hides server version (`ServerTokens Prod`, `server_tokens off`)
- Disables directory listing (`Options -Indexes`, `autoindex off`)
- Disables TRACE method
- Adds security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection)
- Blocks `.htaccess`, `.bak`, `.sql`, `.env` and other sensitive file access
- Restricts HTTP methods to GET/POST/HEAD
```bash
bash Linux/webharden.sh
```

### `bad.sh`
Security audit — SUID/SGID binaries, binary capabilities, world-writable files, sudoers, LD_PRELOAD.
```bash
bash Linux/bad.sh
```

### `inventory.sh`
System inventory — hostname, IP, OS, users, groups, running services, listening ports.
```bash
bash Linux/inventory.sh
```

### `persist_hunt.sh`
**All-in-one security hunter (21 checks).** Covers persistence/C2 AND authentication file auditing in one script.
```bash
bash Linux/persist_hunt.sh
# Output saved to /tmp/persist_hunt_TIMESTAMP.txt
LOOK_BACK_MINUTES=60 bash Linux/persist_hunt.sh   # adjust lookback window
```
**Persistence/C2 (§1-15):** recently modified system binaries, libraries, systemd units, cron, RC scripts, shell profiles, authorized_keys, LD_PRELOAD, executables in /tmp, deleted-binary processes, C2 IOCs, unexpected SUID, kernel modules, PAM module integrity.

**Auth file audit (§16-21):** `/etc/passwd` (extra UID 0, service accounts with shells, duplicate UIDs), `/etc/shadow` (empty hashes, wrong permissions), `/etc/group` (privileged group membership, docker=root), `/etc/sudoers` + `.d/` (NOPASSWD, !authenticate, temp path rules), `/etc/ssh/sshd_config` (PermitRootLogin, PermitEmptyPasswords, ForceCommand backdoors), `/etc/pam.d/` (pam_permit.so, pam_exec.so from temp).

### `netdiff.sh`
Shows new listening ports and established connections since `firstrun.sh` baseline. New entries = possible C2 activity.
```bash
bash Linux/netdiff.sh
```

### `userdiff.sh`
Shows new or modified users/groups since `firstrun.sh` baseline. New entries = backdoor account.
```bash
bash Linux/userdiff.sh
```

### `ipban.sh`
Quickly ban an IP with iptables.
```bash
BANIP=1.2.3.4 bash Linux/ipban.sh
```

### `krs.sh`
**Reverse shell killer daemon.** Loops every 10 seconds killing any process that matches common reverse shell patterns (nc, bash, python, perl, etc.) AND has an IP address in its command line arguments.
```bash
nohup bash Linux/krs.sh &    # run in background throughout competition
```
> Note: aggressive — will also kill legitimate `curl`/`wget` commands that connect to IPs. Use with caution on web servers.

### `snoopy.sh`
Install and enable snoopy (logs all executed commands to syslog).
```bash
bash Linux/snoopy.sh
```

### `tmux.sh`
Sets up a tmux session for managing multiple panes/machines.
```bash
bash Linux/tmux.sh
```

---

## Windows Scripts

### `ADuserPassChange.ps1`
Bulk-change all AD user passwords at once. No per-user prompts.
```powershell
.\ADuserPassChange.ps1 -UserPassword "Summer2024!" -AdminPassword "Admin@2024!" `
    -AdminUsers "bob,alice" -Exclude "svc_sql"

# Auto-generate random passwords for regular users:
.\ADuserPassChange.ps1 -UserPassword YOLO -AdminPassword "Admin@2024!"

# Credentials saved to: C:\Windows\Temp\ad_passwords_TIMESTAMP.csv
```
> Skips `krbtgt`, `Guest`, `DefaultAccount`, `seccdc`, `blackteam` automatically.

### `PassChange.ps1`
Change passwords on **local** (non-domain) Windows accounts.
```powershell
.\PassChange.ps1
```

### `ADHardening.ps1`
Comprehensive headless AD/Windows hardening. Runs on DC or member server.
```powershell
.\ADHardening.ps1

# Update $allowedAdmins at the top with your team's DA accounts before running
```
Applies: SMBv1 disable, PTH mitigations (WDigest/LM/NTLMv2/LSA PPL), 15 Defender ASR rules, remove all Defender exclusions, PrintNightmare fix, Zerologon fix (DC), noPac fix (DC), LDAP signing, UAC hardening, BITS lockdown, full audit policy.

### `Log.ps1`
Enable comprehensive logging across the machine.
```powershell
.\Log.ps1
# PS transcription logs go to C:\PSLogs\
# View in Event Viewer: Security log, Microsoft-Windows-PowerShell/Operational
```
Enables: all auditpol categories, PS script block/transcription/module logging, process creation cmdline, IIS logging, SMB signing, share lockdown to Read-only, Sysmon startup.

### `SoftHarden.ps1`
Firewall setup + malicious port blocking + SMBv1 disable.
```powershell
.\SoftHarden.ps1
```

### `FirewallAndRules.ps1`
Full AD-aware firewall ruleset. Sets inbound/outbound rules for AD, DNS, SMB, RPC, LDAP, Kerberos.
```powershell
.\FirewallAndRules.ps1
```

### `PersistHunt.ps1`
**Windows C2 / Persistence hunter.** Checks: registry run keys, scheduled tasks, services from unusual paths, WMI event subscriptions, startup folders, C2-named processes, outbound C2 port connections, named pipes, Defender exclusions, suspicious PowerShell history, recently modified system files, LOLBAS processes.
```powershell
.\PersistHunt.ps1
# Output saved to C:\Windows\Temp\persist_hunt_TIMESTAMP.txt
```

### `ServiceAuditing.ps1`
Compares running services against a known-good baseline list. Flags anything unexpected.
```powershell
.\ServiceAuditing.ps1
# Output: services_snapshot.csv
```

### `BackupAD.ps1` / `RestoreAD.ps1`
Backup and restore Active Directory.
```powershell
.\BackupAD.ps1
.\RestoreAD.ps1
```

### `BackupDns.ps1` / `RestoreDNS.ps1`
Backup and restore DNS zone data.
```powershell
.\BackupDns.ps1
.\RestoreDNS.ps1
```

### `Monitoring.ps1`
Lightweight process/event monitoring.

### `ProcessInjectionDetector.ps1`
Detects common process injection patterns.

### `ToolInstall.ps1`
Installs common blue team tools.

### `winrm.ps1`
Configure WinRM for remote management (needed before using `Run.ps1`).

---

## Rootkit Detection

### Linux
`firstrun.sh` installs `rkhunter` and `unhide` automatically.
```bash
rkhunter --check --sk          # scan for rootkits, skip key prompts
rkhunter --update              # update signatures first if internet available
chkrootkit                     # second opinion scanner

unhide proc                    # find hidden processes
unhide sys                     # find hidden system resources

# Package-based file integrity (catches replaced system binaries)
debsums -ca                    # Debian/Ubuntu — checks all package file hashes
rpm -Va                        # RHEL/CentOS — verifies all RPM package files

# Manual: check for processes with deleted binaries (classic rootkit technique)
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Check for hidden kernel modules
lsmod | grep -viE "(known_module|another)"
cat /proc/modules
```

### Windows
```powershell
# Defender full scan
Start-MpScan -ScanType FullScan

# Check for hidden processes (compare WMI vs Task Manager)
$wmiProcs = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
$psProcs  = Get-Process | Select-Object -ExpandProperty Id
Compare-Object $wmiProcs $psProcs   # entries only in WMI = possibly hidden

# Check for unsigned drivers (rootkits often load unsigned kernel modules)
Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -notmatch "^C:\\Windows" } |
    Select-Object Name, PathName, State

# Sigcheck from Sysinternals (if available)
# sigcheck -nobanner -vt C:\Windows\System32\*.dll
```

---

## Quick Reference

| Problem | Script |
|---|---|
| First thing on a Linux box | `firstrun.sh` |
| Linux local password change | `passwd.sh` |
| Domain password timing issue | `flush_domain_cache.sh` (run after AD changes) |
| Linux firewall lockdown | `env.sh` → `fw.sh` |
| Keep web server alive | `webwatch.sh` |
| Linux persistence + auth file audit | `persist_hunt.sh` (21 checks) |
| New users/ports since start? | `userdiff.sh` / `netdiff.sh` |
| AD bulk password change | `ADuserPassChange.ps1` |
| Windows hardening (headless) | `ADHardening.ps1` |
| Enable Windows logging | `Log.ps1` |
| Windows persistence/C2 check | `PersistHunt.ps1` |
| Unknown services on Windows | `ServiceAuditing.ps1` |
