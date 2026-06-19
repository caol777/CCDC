# CCDC-Scripts — Complete Changes Summary

Full record of every file created or modified. Use this to replicate all changes on another machine.

---

## QUICK REFERENCE TABLE

| File | Status | What Changed |
|---|---|---|
| `CONCEPTS.md` | NEW | Full security concepts teaching guide |
| `README.md` | MODIFIED | Reordered steps, added ir_report.sh |
| `Linux/bad.sh` | MODIFIED | Added tee to timestamped log file |
| `Linux/inventory.sh` | MODIFIED | Added tee to timestamped log file |
| `Linux/firstrun.sh` | MODIFIED | Use pre-downloaded tools from tools/ folder |
| `Linux/ir_report.sh` | NEW | IR report assembler — pulls all outputs into one file |
| `Linux/mysqharden.sh` | NEW | MySQL/MariaDB hardening script |
| `Linux/webharden.sh` | NEW | Apache/nginx hardening script |
| `injects/login.sh` | MODIFIED | Added tee, attacker IP analysis, recent logins |
| `injects/README.md` | REWRITTEN | Inject response guide with script-to-question mapping |
| `ansible/vars.yml` | NEW | Backup admin variables |
| `ansible/inventory.ini` | NEW | Linux + Windows inventory template |
| `ansible/create_admin.yml` | NEW | Playbook to deploy backup admin everywhere |
| `ansible/README.md` | NEW | Ansible setup and usage guide |
| `Windows/UserAuditing.ps1` | MODIFIED | Configurable $AcceptedUsers array |
| `Windows/ftp.ps1` | MODIFIED | All hardcoded values replaced with config block |
| `tools/README.md` | NEW | Instructions for pre-downloading tools |

---

## ROOT LEVEL

---

### `CONCEPTS.md` — NEW FILE

Full teaching document explaining the "why" behind every script. Covers:

- **Linux Persistence Detection** — systemd units, cron jobs, PAM backdoors, SUID binaries, LD_PRELOAD, authorized_keys, how attackers use each and how to detect them
- **Firewall Architecture** — iptables default-deny inbound/outbound, UFW, pf, why order of rules matters
- **Web Server Hardening** — hiding server versions, disabling directory listing, blocking sensitive files, TRACE method attacks, security headers explained
- **Database Hardening** — why anonymous MySQL users are dangerous, remote root login risks, LOCAL INFILE as data exfil vector, bind-address restriction
- **Windows AD Hardening** — Defender ASR rules, Zerologon patch, Kerberoasting mitigation, PrintNightmare disablement
- **Ansible Automation** — why you need a backup admin, SSH key-based auth, WinRM for Windows
- **Web Application Pentesting** — OWASP Top 10 overview, module-by-module explanation of the framework

---

### `README.md` — MODIFIED

**What changed:**
- Moved `mysqharden.sh` and `webharden.sh` from Step 5 to Step 3 (they belong with service hardening, not threat hunting)
- Added `ir_report.sh` to Step 5 — run it after all hunting scripts to compile one report

---

## LINUX FOLDER

---

### `Linux/bad.sh` — MODIFIED

**What changed:** Added 3 lines at the top to save all output to a timestamped file in `/tmp/`:

```bash
LOGFILE="/tmp/bad_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee -a "$LOGFILE") 2>&1
echo "Output saved to: $LOGFILE"
```

**Why:** The script audits SUID binaries, sudoers, world-writable files, capabilities, and LD_PRELOAD. Without saving output, evidence is lost when the terminal closes. The `/tmp/bad_TIMESTAMP.txt` file is also picked up by `ir_report.sh`.

---

### `Linux/inventory.sh` — MODIFIED

**What changed:** Added 3 lines at the top identical to bad.sh:

```bash
LOGFILE="/tmp/inventory_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee -a "$LOGFILE") 2>&1
echo "Output saved to: $LOGFILE"
```

**Why:** Inventory output (ports, users, services, containers, OS info) is essential for inject responses. Without saving to file, you have to run it again during the inject — slow and error-prone.

---

### `Linux/firstrun.sh` — MODIFIED

**What changed:** The section that downloads `pspy64` and `linpeas.sh` was updated to check the `tools/` folder first before downloading from the internet:

```bash
# Before (always downloaded):
wget https://github.com/.../pspy64 -O /tmp/pspy64

# After (uses local copy if available, fallback to download):
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/../tools/pspy64" ]; then
    cp "$SCRIPT_DIR/../tools/pspy64" /tmp/pspy64
else
    wget https://github.com/.../pspy64 -O /tmp/pspy64 || true
fi
```

**Why:** Competition environments often have no internet access. Pre-downloading tools to `tools/` and copying from there is faster and more reliable.

---

### `Linux/ir_report.sh` — NEW FILE

Full IR report assembler. Pulls together:
1. Baseline snapshots from `firstrun.sh` at `/tmp/initial/`
2. Current system state (users, ports, processes, crontabs)
3. Diff against baseline (new users, new ports, changed groups)
4. Output from `persist_hunt.sh` → `/tmp/persist_hunt_*.txt`
5. Output from `bad.sh` → `/tmp/bad_*.txt`
6. Output from `login.sh` → `/tmp/login_report_*.txt`
7. Output from `inventory.sh` → `/tmp/inventory_*.txt`
8. Top attacker IPs extracted from auth logs
9. Firewall state (iptables + ufw)
10. Web server and database process state, recently modified web files

**Output:** `/tmp/IR_REPORT_HOSTNAME_TIMESTAMP.txt`

**Usage:**
```bash
# Run hunting scripts first, then:
bash Linux/ir_report.sh

# View:
less /tmp/IR_REPORT_*.txt
```

---

### `Linux/mysqharden.sh` — NEW FILE

Non-interactive MySQL/MariaDB hardening. Equivalent to `mysql_secure_installation` but fully automated.

**What it does, step by step:**
1. Auto-detects `mysql` vs `mariadb` binary
2. Tries to connect with no password, then common weak passwords (`root`, `password`, `toor`, `mysql`), then reads `/etc/mysql/debian.cnf` maintenance credentials
3. Sets a strong root password (configurable at top of script via `NEW_ROOT_PASS`)
4. Removes all anonymous users
5. Removes remote root login (`root@%`)
6. Drops test database and removes test DB grants
7. Lists all accounts with blank passwords
8. Restricts `bind-address = 127.0.0.1` in config files
9. Disables `LOCAL INFILE` (data exfil prevention)
10. Restarts the service

**Configure before running:**
```bash
NEW_ROOT_PASS="Str0ng_R00t_P@ss!"   # change this
BIND_LOCALHOST_ONLY=true             # false if app servers are remote
```

---

### `Linux/webharden.sh` — NEW FILE

Apache and nginx hardening. Auto-detects which is running and hardens both if present. Safe to run multiple times (idempotent).

**Apache hardening (harden_apache function):**
- `ServerTokens Prod` — hides Apache version from HTTP headers
- `ServerSignature Off` — removes version from error pages
- `TraceEnable Off` — blocks XST (Cross-Site Tracing) attacks
- `FileETag None` — stops inode info leaking via ETags
- Adds security headers: `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`, removes `X-Powered-By` and `Server`
- Enables `mod_headers` (Debian/Ubuntu)
- Disables directory listing (`Options -Indexes`) in all configs
- Blocks `.htaccess`, `.htpasswd`, `.bak`, `.sql`, `.log`, `.sh`, `.inc` access
- Restricts HTTP methods to `GET POST HEAD` only
- Enables `mod_ssl` if available

**nginx hardening (harden_nginx function):**
- `server_tokens off` — hides nginx version
- Writes security headers to `/etc/nginx/conf.d/security.conf`
- Disables `autoindex on` in all site configs
- Blocks access to hidden files (`.git`, `.env`, `.htaccess`)
- Blocks sensitive file extensions (`.bak`, `.sql`, `.log`, `.sh`, etc.)
- Tests config with `nginx -t` before restarting

---

## INJECTS FOLDER

---

### `injects/login.sh` — MODIFIED

**What was there before:** Basic login count script — counted `Accepted password` and `Failed password` in auth logs and listed sudo/wheel members.

**What was added:**
```bash
# Line 3-7 — output saved to file
LOGFILE="/tmp/login_report_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee -a "$LOGFILE") 2>&1
echo "Login Report — $(hostname) — $(date)"
echo "Output saved to: $LOGFILE"

# Lines 39-44 — top attacker IPs (new section)
echo "Top attacking source IPs (failed logins):"
for log in /var/log/secure /var/log/auth.log /var/log/messages; do
  [ -f "$log" ] || continue
  grep 'Failed password' "$log" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' | sort | uniq -c | sort -nr | head -10
done

# Lines 46-48 — recent successful logins (new section)
echo "Recent successful logins (last 20):"
last -20 2>/dev/null | head -20
```

**Why:** Injects frequently ask "who attacked us" and "what IPs were involved" — the attacker IP section answers that directly. `last` shows recent successful logins which answers "was the account used."

---

### `injects/README.md` — COMPLETELY REWRITTEN

**What it was:** Basic git clone and usage instructions.

**What it is now:** A practical inject response guide. Maps every common inject question to the exact script and output file.

**Inject questions covered:**
- "How many failed/successful login attempts?" → `login.sh`
- "Which accounts have admin/root access?" → `triage.ps1`, `/etc/group`
- "What services/ports are running?" → `wininfo.ps1`, `inventory.sh`
- "Was this machine compromised? Provide evidence." → `persist_hunt.sh`, `PersistHunt.ps1`
- "What SUID binaries / dangerous permissions exist?" → `bad.sh`
- "What is the current firewall state?" → `iptables`, `triage.ps1`
- "What processes were running?" → `triage.ps1`, `/tmp/initial/processes`
- "What scheduled tasks / cron jobs exist?" → `triage.ps1`, `/tmp/initial/cron*`
- "Provide an inventory of this machine" → `inventory.sh`, `wininfo.ps1`
- "What users exist on this machine?" → `/etc/passwd`, `triage.ps1`
- "Who attacked us? What IPs were involved?" → `login.sh` attacker IP section

**Output file table** — maps every script to its output location:
| Script | Output |
|---|---|
| `firstrun.sh` | `/tmp/initial/` |
| `ir_report.sh` | `/tmp/IR_REPORT_HOST_TIMESTAMP.txt` |
| `persist_hunt.sh` | `/tmp/persist_hunt_TIMESTAMP.txt` |
| `bad.sh` | `/tmp/bad_TIMESTAMP.txt` |
| `inventory.sh` | `/tmp/inventory_TIMESTAMP.txt` |
| `injects/login.sh` | `/tmp/login_report_TIMESTAMP.txt` |
| `injects/triage.ps1` | `C:\IR\TRIAGE\HOST_timestamp\` |
| `injects/wininfo.ps1` | `Inventory_HOST_timestamp\` |
| `PersistHunt.ps1` | `C:\Windows\Temp\PersistHunt_TIMESTAMP.txt` |

**Fastest path for any Linux inject:**
```bash
bash Linux/persist_hunt.sh
bash Linux/bad.sh
bash injects/login.sh
bash Linux/ir_report.sh
less /tmp/IR_REPORT_*.txt
```

**Firewall rollback commands** (emergency restore) included for both Linux and Windows.

---

## WINDOWS FOLDER

---

### `Windows/UserAuditing.ps1` — MODIFIED

**What was there before:** Hardcoded list of allowed usernames baked into the script.

**What changed:** Replaced the hardcoded list with a configurable `$AcceptedUsers` array at the top so you edit one place before competition:

```powershell
# EDIT BEFORE RUNNING — accounts to KEEP enabled
$AcceptedUsers = @(
    "administrator",
    "ccdc_admin"      # add competition accounts here
)
```

Also added output showing which accounts were disabled and which were kept:
```powershell
Write-Host "[DONE] Disabled $($disabled.Count) account(s): $($disabled -join ', ')"
Write-Host "Kept active: $($acclist -join ', ')"
```

**What it does:** Iterates all local user accounts. Anyone NOT in `$AcceptedUsers` gets disabled with `net user /active:no`. Run this early to lock out red team accounts immediately.

---

### `Windows/ftp.ps1` — MODIFIED

**What was there before:** All server names, usernames, IPs, paths, and passwords hardcoded throughout the script body.

**What changed:** Added a configuration block at the very top — all values defined once, nothing hardcoded inline:

```powershell
# EDIT BEFORE RUNNING
$FtpSiteName   = "Default FTP Site"
$FtpUser       = "ftp_user"
$FtpUserPass   = "Ch@ngeMe2024!"
$FtpRootPath   = "C:\FTP"
$FtpCertDns    = "ftp.local"
$TrustedIPs    = @("10.0.0.5", "10.0.0.6")
```

**What the full script does:**
- Installs `Web-FTP-Server`, `Web-FTP-Service`, `Web-FTP-Ext`, `Web-Security` Windows features
- Creates self-signed TLS certificate
- Requires SSL on both control and data channels
- Creates dedicated FTP local user with restricted folder permissions
- Disables anonymous auth, enables basic auth
- Configures passive port range (50000–50100)
- Firewall rules: trusted IPs only on port 21, blocks everything else
- Enables detailed FTP audit logging
- Disables SSL 3.0, TLS 1.0, TLS 1.1 via registry
- Enables user isolation (each user sees only their directory)
- Blocks all IPs except `$TrustedIPs` at IIS level
- Disables directory browsing
- Removes write permissions for Users group on FTP root

---

### `Windows/ADHardening.ps1` — PRE-EXISTING (no changes made)

**What it does:** Full AD and Windows hardening. Run as Administrator on a DC or domain-joined machine. Auto-detects if it's a DC and applies DC-specific fixes.

**Hardening applied:**
- **SMB** — disables SMBv1, keeps SMBv2, enforces LDAP signing (client + server)
- **PTH mitigations** — disables LM hash storage, enforces NTLMv2, disables WDigest (clears plaintext from LSASS), enables LSA PPL (Protected Process Light), enables LSASS audit logging
- **Defender** — enables cloud block, behavior monitoring, real-time protection, removes ALL Defender exclusions, enables 15 ASR rules
- **PrintNightmare** — stops and disables Print Spooler, restricts driver installation to admins
- **Zerologon (DC only)** — sets `FullSecureChannelProtection=1`, removes vulnerable channel allowlist
- **noPac (DC only)** — sets `MachineAccountQuota=0` on the domain
- **UAC** — enforces elevation prompt on secure desktop
- **BITS** — disables BITS download bandwidth (prevents C2 downloads via BITS)
- **Audit policy** — enables success/failure for Logon, Account Logon, Account Management, Privilege Use, Object Access
- **Misc** — disables Guest, disables WinRM/PSRemoting, enables all firewall profiles
- **Domain Admins audit** — disables any DA account not in `$allowedAdmins` list

**Output:** `C:\SecurityConfigLog.txt`

**Configure before running:**
```powershell
$allowedAdmins = @("Administrator", "your_team_account")
```

---

### `Windows/FirewallAndRules.ps1` — PRE-EXISTING (no changes made)

**What it does:** Full firewall lockdown + AD-specific rules. Use on Domain Controllers.

**Steps performed:**
1. Exports existing firewall rules to `C:\fwbackup.wfw` (emergency restore point)
2. Sets all profiles to default-deny inbound AND outbound, enables stealth mode
3. Deletes ALL pre-existing firewall rules (`Remove-NetFirewallRule` with no filter)
4. Configures RPC dynamic port range to 5000–5100 (registry)
5. Creates allowed rules:
   - SMB inbound/outbound (445)
   - Web traffic inbound (80, 443)
   - DNS inbound/outbound (TCP+UDP 53)
   - NTP outbound (UDP 123)
   - RPC endpoint mapper (135) and dynamic ports (5000–5100)
   - Windows Update outbound (443)
   - Kerberos PCR (464 TCP+UDP)
   - AD rules: ICMP, LDAP (389), Global Catalog (3268/3269), NetBIOS (138), SAM (445), LDAPS (636), W32Time (123), RPC, ADWS (9389)
   - AD outbound: all TCP/UDP outbound allowed

**⚠️ Warning:** Deletes ALL existing rules before creating new ones. Make sure `C:\fwbackup.wfw` is saved first.

**Restore:**
```powershell
netsh advfirewall import "C:\fwbackup.wfw"
```

---

### `Windows/PersistHunt.ps1` — PRE-EXISTING (no changes made)

**What it does:** Scans all common red team persistence and C2 locations. Output saved to `C:\Windows\Temp\persist_hunt_TIMESTAMP.txt`.

**12 checks performed:**

| # | Check | What it looks for |
|---|---|---|
| 1 | Registry run keys | 12 run key locations, flags entries pointing to Temp/AppData/encoded commands |
| 2 | Scheduled tasks | Tasks running from suspicious paths or with encoded/download args |
| 3 | Suspicious services | Services running from Temp/Users paths or non-standard service accounts |
| 4 | WMI subscriptions | `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding` — all flagged BAD |
| 5 | Startup folders | All files in AllUsers and CurrentUser startup folders |
| 6 | Suspicious processes | Processes matching C2 names (beacon, sliver, apollo, mythic, havoc) or running from Temp |
| 7 | Network connections | Established connections to known C2 ports (4444, 1337, 31337, 8443, 9001, 50050, etc.) |
| 8 | Named pipes | Pipes matching Cobalt Strike/Sliver/Mythic patterns |
| 9 | Defender exclusions | Any path, process, or extension exclusion = BAD |
| 10 | PowerShell history | Searches all user PS history for download cradles, base64, IEX |
| 11 | Modified system files | EXE/DLL/SYS files in System32/SysWOW64 modified in last 2 hours |
| 12 | LOLBAS processes | Running instances of mshta, wscript, cscript, certutil, bitsadmin, rundll32, etc. |

**Output:** Color-coded `[BAD]` (red), `[WARN]` (yellow), `[OK]` (green) + full log file.

---

### `Windows/SoftHarden.ps1` — PRE-EXISTING (no changes made)

**What it does:** Lighter-weight hardening — firewall lockdown + known bad port blocking + SMB.

**Steps performed:**
1. Exports firewall backup to `C:\fwbackup.wfw`
2. Sets all profiles to default-deny inbound/outbound
3. Blocks known C2/malware ports (4444, 1337, 31337, 5555, 6666-6669, 9001, 12345, 12346, 27374) both inbound and outbound TCP+UDP
4. Lists all PIDs with associated process names (`netstat -ano` mapped to `Get-Process`)
5. Disables SMBv1, keeps SMBv2

**Note:** Contains commented-out WIP code for auto-creating critical rules — not active yet.

---

### `Windows/ServiceAuditing.ps1` — PRE-EXISTING (no changes made)

**What it does:** Compares all running services against a known-good whitelist and flags extras.

**Steps performed:**
1. Defines `$servnames` — comprehensive whitelist of ~200 known legitimate Windows services (including base Windows, AD services, DNS, IIS, FTP, SMTP, WinRM)
2. Snapshots all running services with `Get-WmiObject Win32_Service` → exports to `services_snapshot.csv`
3. Finds all services NOT in the whitelist — prints them with name, path, start mode, run-as account
4. Saves original states to `orig_service_states.csv` for rollback

**To stop and disable a found malicious service:**
```powershell
Stop-Service -Name <malservname> -Force
Set-Service -Name <malservname> -StartupType Disabled
```

**To restore original states:**
```powershell
$orig = Import-Csv .\orig_service_states.csv
foreach ($r in $orig) {
    Set-Service -Name $r.Name -StartupType $r.StartMode
    if ($r.State -eq 'Running') { Start-Service -Name $r.Name }
}
```

---

### `Windows/PassChange.ps1` — PRE-EXISTING (no changes made)

**What it does:** Interactively prompts for a new password for every local user account, then prints a summary table of all username/password pairs at the end.

**Steps performed:**
1. Gets all local user names with `Get-LocalUser`
2. For each user, prompts `Read-Host -AsSecureString` for a password
3. Sets password with `Set-LocalUser`
4. Collects all user/password pairs into `$results`
5. Prints full summary table at end

**Use for:** Quick local password rotation on non-AD machines. The summary table lets you record all passwords at once.

---

### `Windows/ADuserPassChange.ps1` — PRE-EXISTING (no changes made)

**What it does:** Bulk resets passwords for all AD users. Supports different passwords for admins vs regular users. Can auto-generate random passwords.

**Parameters:**
```powershell
-UserPassword   # password for all regular users (or "YOLO" to auto-generate)
-AdminPassword  # separate password for admin accounts
-AdminUsers     # comma-separated list of accounts to give AdminPassword
-Exclude        # comma-separated accounts to skip entirely
```

**Usage examples:**
```powershell
# Set all users to one password, admins to a stronger one
.\ADuserPassChange.ps1 -UserPassword "Summer2024!" -AdminPassword "Admin@2024!" -AdminUsers "bob,alice"

# Auto-generate a random password for all regular users
.\ADuserPassChange.ps1 -UserPassword "YOLO" -AdminPassword "Admin@2024!"
```

**What it does:**
- Always skips: `krbtgt`, `defaultaccount`, `guest`, `wdagutilityaccount`, `seccdc`, `blackteam`
- Sets password with `Set-ADAccountPassword -Reset`
- Exports all changed accounts/passwords to `C:\Windows\Temp\ad_passwords_TIMESTAMP.csv`
- Prints summary: changed, skipped, failed counts

---

### `Windows/Log.ps1` — PRE-EXISTING (no changes made)

**What it does:** Enables comprehensive logging across all Windows event channels so you can see red team activity.

**What gets enabled:**
- **All audit policy categories** — `auditpol /set /category:* /success:enable /failure:enable`
- **Process creation command-line logging** — every process launch logs its full command line to Event ID 4688
- **PowerShell script block logging** — every PS script/command logged to `Microsoft-Windows-PowerShell/Operational`
- **PowerShell module logging** — all modules logged
- **PowerShell transcription** — full session transcripts saved to `C:\PSLogs\`
- **IIS logging** — enables if IIS present
- **SMB signing** — enforces on both client and server (prevents NTLM relay attacks)
- **SMB share lockdown** — sets all non-system shares to Read-only (except NETLOGON, SYSVOL, ADMIN$, C$, IPC$)
- **Sysmon** — starts if `Sysmon64.exe` or `Sysmon.exe` already in System32

**Where to find the logs:**
- PS Transcription: `C:\PSLogs\`
- Event Viewer: Security log, `Microsoft-Windows-PowerShell/Operational`

---

### `Windows/Monitoring.ps1` — PRE-EXISTING (no changes made)

**What it does:** Two tasks — blocks known C2 ports + lists all listening ports with associated process names.

**Steps performed:**
1. Creates inbound+outbound TCP+UDP block rules for known C2 ports: 4444, 1337, 31337, 5555, 6666–6669, 9001, 12345, 12346, 27374 (skips if rule already exists)
2. Lists all listening TCP connections with: LocalAddress, LocalPort, RemoteAddress, State, ProcessName, ProcessId

**Use for:** Quick situational awareness of what's listening and blocking the most common C2 callback ports.

---

### `Windows/BackupAD.ps1` — PRE-EXISTING (no changes made)

**What it does:** Creates a full AD backup before competition starts. Run on the DC.

**Three phases:**
1. **Database export (IFM)** — `ntdsutil` exports `ntds.dit` and registry hives to `C:\AD_Backup\AD_Database\`
2. **GPO export** — `Backup-Gpo -All` saves all Group Policy Objects to `C:\AD_Backup\GPOs\`
3. **AD snapshot (CSV)** — exports all users with group memberships and all groups to CSV files

**Output:** `C:\AD_Backup\`

**⚠️ Critical:** Move the backup folder to a USB or secondary drive immediately after running. If red team wipes C:\ you lose the backup.

---

### `Windows/RestoreAD.ps1` — PRE-EXISTING (no changes made)

**What it does:** Restores AD from a `BackupAD.ps1` backup. Handles two modes automatically.

**Mode 1 — DSRM (Safe Mode):**
- Detects if running in Directory Services Restore Mode
- Seeds `ntds.dit` from backup to `C:\Windows\NTDS\`
- Prints the exact `ntdsutil` authoritative restore command to run
- Prints the `bcdedit` command to exit safe mode

**Mode 2 — Normal Mode (surgical fixes):**
- Syncs system time
- Imports all GPOs from the backup folder using `Import-GPO`
- Reconstructs missing AD users from the CSV snapshot using `New-ADUser`

**Configure before running:**
```powershell
$BackupPath = "C:\AD_Backup"   # match where BackupAD.ps1 saved to
```

---

### `Windows/BackupDns.ps1` — PRE-EXISTING (no changes made)

**What it does:** Exports all DNS zones and settings to `C:\DNS_Backup\` before competition.

**Steps performed:**
1. Creates `C:\DNS_Backup\` (overwrites if exists)
2. Exports zone list to `ZoneList.csv`
3. Runs `dnscmd /ZoneExport` for every zone → `.dns.bak` files
4. Exports DNS registry settings: `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters` → `DNS_Settings.reg`
5. Moves all `.dns.bak` files from `C:\Windows\System32\dns\` to `C:\DNS_Backup\`

**Output:** `C:\DNS_Backup\` — contains `ZoneList.csv`, `DNS_Settings.reg`, and `*.dns.bak` zone files.

**⚠️ Run this first** before any firewall changes. Move backup off the DC immediately.

---

### `Windows/RestoreDNS.ps1` — PRE-EXISTING (no changes made)

**What it does:** Full DNS recovery from a `BackupDns.ps1` backup. Handles the complete restore sequence including deadlock breaking and AD zone integration.

**4 phases:**

**Phase 0 — Log & Role Healing:**
- Restarts Event Log service, clears System/DNS/Directory Service event logs
- Installs DNS and AD-Domain-Services features if missing
- Points all NICs to `127.0.0.1` for DNS

**Phase 1 — Security & Config:**
- Starts W32Time, forces time resync
- Purges Kerberos tickets for system account (`klist purge -li 0x3e7`)
- Restarts KDC
- Imports `DNS_Settings.reg` from backup

**Phase 2 — Data Reset:**
- Stops DNS and Netlogon services
- Copies `.dns.bak` files back to `C:\Windows\System32\dns\`
- Re-adds each zone with `dnscmd /ZoneAdd /Primary`

**Phase 3 — Breaking Deadlocks:**
- Starts DNS and Netlogon
- Waits for Netlogon to reach Running state
- Runs `ipconfig /registerdns` and `nltest /dsregdns`
- Restarts Netlogon

**Phase 4 — AD Zone Conversion:**
- Retries up to 30 times (every 10 seconds) to convert zones from file-backed to AD-integrated (`dnscmd /ZoneResetType /dsprimary`)
- At attempt 15, purges tickets and restarts KDC/Netlogon/DNS if still failing
- Reports success when first zone shows `IsDsIntegrated = true`

---

### `Windows/winrm.ps1` — PRE-EXISTING (no changes made)

**What it does:** Hardens WinRM to use HTTPS only and restricts access to a trusted IP.

**Configure before running:**
```powershell
$hostname   = "Host01.ccdc.local"   # your machine FQDN
$allowedIP  = "10.0.0.1"            # DC or ops machine IP — only this IP can WinRM in
$maxTimeoutMs = 420000              # 7-minute session timeout
```

**Steps performed:**
1. Creates a self-signed TLS cert for `$hostname` if one doesn't exist
2. Removes any existing HTTP (port 5985) WinRM listener
3. Creates HTTPS (port 5986) listener using the cert thumbprint
4. Removes old "Allow WinRM HTTPS" firewall rule, creates new one restricted to `$allowedIP` only
5. Opens `Set-PSSessionConfiguration` UI to restrict session access to admins only
6. Enables Logon auditing for WinRM access
7. Sets session timeout to `$maxTimeoutMs`

**Verify after running:**
```powershell
Test-WsMan -ComputerName $hostname -UseSSL
```

---

### `Windows/ProcessInjectionDetector.ps1` — PRE-EXISTING (no changes made)

**What it does:** Enables kernel object auditing and dumps Event IDs 4663 and 4688 from the Security log to desktop text files for manual review.

**Steps performed:**
1. Enables `Kernel Object` auditing via `auditpol`
2. Reads `Security.evtx` and extracts **Event ID 4663** (object access — used to detect process memory reads like LSASS dumps) → saves to `C:\Users\<you>\Desktop\4663.txt`
3. Reads `Security.evtx` and extracts **Event ID 4688** (process creation with command line) → saves to `C:\Users\<you>\Desktop\4688.txt`

**What to look for in 4663.txt:**
- Access to `lsass.exe` from non-system processes = credential dumping attempt

**What to look for in 4688.txt:**
- PowerShell with `-enc`, `-nop`, `-bypass`
- `certutil -decode`, `bitsadmin /transfer`
- Unusual parent/child process combinations

**Note:** Requires `Log.ps1` to have been run first (or `auditpol /set /category:* /success:enable /failure:enable`) for meaningful 4688 output.

---

## ANSIBLE FOLDER — ALL NEW FILES

---

### `ansible/vars.yml` — NEW FILE

Configuration file — edit this before running the playbook.

```yaml
backup_admin_username: "ccdc_backup"
backup_admin_password: "Backd00r_CCDC_2025!"
backup_admin_ssh_pubkey: "ssh-ed25519 AAAA... REPLACE_WITH_YOUR_PUBLIC_KEY ccdc_backup"
backup_admin_nopasswd_sudo: true
```

---

### `ansible/inventory.ini` — NEW FILE

Template for all Linux and Windows machines. Fill in your IPs before competition:

```ini
[linux]
web01   ansible_host=10.0.0.10
db01    ansible_host=10.0.0.11

[windows]
dc01    ansible_host=10.0.0.20

[linux:vars]
ansible_user=root
ansible_ssh_private_key_file=~/.ssh/ccdc_backup

[windows:vars]
ansible_user=Administrator
ansible_password=WINDOWS_ADMIN_PASSWORD_HERE
ansible_connection=winrm
ansible_winrm_transport=ntlm
ansible_winrm_server_cert_validation=ignore
```

---

### `ansible/create_admin.yml` — NEW FILE

Ansible playbook that deploys a backup admin account to all Linux and Windows machines simultaneously.

**Linux tasks:**
1. Creates user with bash shell and home directory
2. Adds to `sudo` group (Debian/Ubuntu) or `wheel` group (RHEL/CentOS)
3. Creates `/etc/sudoers.d/ccdc_backup` with `NOPASSWD: ALL` (or password-required, configurable)
4. Creates `~/.ssh` directory with correct permissions
5. Adds SSH authorized key (from `vars.yml`) for passwordless login
6. Unlocks the account (`passwd -u`)

**Windows tasks:**
1. Creates local user with non-expiring password
2. Adds to `Administrators` group
3. Adds to `Remote Desktop Users` group
4. Ensures account is unlocked and enabled

**Usage:**
```bash
# All machines at once
ansible-playbook -i inventory.ini create_admin.yml

# Linux only
ansible-playbook -i inventory.ini create_admin.yml --limit linux

# Windows only
ansible-playbook -i inventory.ini create_admin.yml --limit windows

# Dry run
ansible-playbook -i inventory.ini create_admin.yml --check
```

---

### `ansible/README.md` — NEW FILE

Full setup guide covering:
- Installing Ansible and `pywinrm`
- Generating the backup SSH keypair (`ssh-keygen -t ed25519`)
- Editing `vars.yml` and `inventory.ini`
- All run commands
- How to SSH into Linux backup account after deployment
- How to enable WinRM on Windows machines that don't have it

---

## TOOLS FOLDER

---

### `tools/README.md` — NEW FILE

Instructions for pre-downloading tools for offline competition use.

**Tools to pre-download:**
```bash
# pspy64 — process monitor (no root needed)
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -O tools/pspy64
chmod +x tools/pspy64

# linpeas.sh — Linux privilege escalation checker
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O tools/linpeas.sh
chmod +x tools/linpeas.sh
```

After placing these in `tools/`, `firstrun.sh` will use them instead of trying to download during competition.

---

## HOW TO REPLICATE EVERYTHING

### Step 1 — New files (just copy these)
```
Linux/ir_report.sh          ← paste full file contents
Linux/mysqharden.sh         ← paste full file contents
Linux/webharden.sh          ← paste full file contents
ansible/vars.yml            ← paste full file contents
ansible/inventory.ini       ← paste full file contents
ansible/create_admin.yml    ← paste full file contents
ansible/README.md           ← paste full file contents
CONCEPTS.md                 ← paste full file contents
tools/README.md             ← paste full file contents
```

### Step 2 — Modified files (apply these specific changes)

**`Linux/bad.sh`** — add lines 4-6 (after the shebang and comment):
```bash
LOGFILE="/tmp/bad_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee -a "$LOGFILE") 2>&1
echo "Output saved to: $LOGFILE"
```

**`Linux/inventory.sh`** — add lines 4-6 (after the shebang and comment):
```bash
LOGFILE="/tmp/inventory_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee -a "$LOGFILE") 2>&1
echo "Output saved to: $LOGFILE"
```

**`injects/login.sh`** — add after shebang:
```bash
LOGFILE="/tmp/login_report_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee -a "$LOGFILE") 2>&1
echo "Login Report — $(hostname) — $(date)"
echo "Output saved to: $LOGFILE"
```
And add these two sections at the bottom:
```bash
echo "=========="
echo "Top attacking source IPs (failed logins):"
for log in /var/log/secure /var/log/auth.log /var/log/messages; do
  [ -f "$log" ] || continue
  grep 'Failed password' "$log" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' | sort | uniq -c | sort -nr | head -10
done

echo "=========="
echo "Recent successful logins (last 20):"
last -20 2>/dev/null | head -20
```

**`injects/README.md`** — replace entirely with the new inject response guide (see current file)

**`Windows/UserAuditing.ps1`** — replace the hardcoded user list with the `$AcceptedUsers` config block (see current file)

**`Windows/ftp.ps1`** — replace the hardcoded values throughout with the `$FtpSiteName`, `$FtpUser`, etc. config block at top (see current file)

**`Linux/firstrun.sh`** — find the `wget` lines for `pspy64` and `linpeas.sh`, wrap each with a check:
```bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/../tools/pspy64" ]; then
    cp "$SCRIPT_DIR/../tools/pspy64" /tmp/pspy64
    chmod +x /tmp/pspy64
else
    wget -q https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -O /tmp/pspy64 || true
    chmod +x /tmp/pspy64 2>/dev/null
fi
```

**`README.md`** — move `mysqharden.sh`/`webharden.sh` to Step 3, add `ir_report.sh` to Step 5.

---

**Total new files:** 9  
**Total modified files:** 8  
**Generated:** 2026-06-15

---

## COMPLETE SCRIPT REFERENCE — ALL REMAINING FILES

The section below documents every file in the repository not covered above. These are pre-existing scripts that were not modified during this session. They are documented here for replication purposes.

---

## LINUX FOLDER — REMAINING SCRIPTS

---

### `Linux/flush_domain_cache.sh` — PRE-EXISTING

**Purpose:** Flushes cached domain credentials on Linux machines after AD password changes. Run this on every Linux box right after the Windows team bulk-resets AD passwords, or Linux machines will keep accepting old credentials from cache.

**What it does:**
1. Detects which domain auth service is running (SSSD, Winbind, or realm)
2. **SSSD path:** stops SSSD, deletes all `.ldb` cache files from `/var/lib/sss/db/`, runs `sss_cache -E`, restarts SSSD
3. **Winbind path:** runs `net cache flush` and `wbinfo --flush-cache`, restarts Winbind
4. **Always:** runs `kdestroy -A` to clear all Kerberos ticket caches
5. Warns if neither SSSD nor Winbind is detected

**Usage:**
```bash
sudo bash Linux/flush_domain_cache.sh
```

**When to run:** Immediately after `ADuserPassChange.ps1` is run on the Windows DC. If you skip this, Linux domain-joined boxes will continue accepting old passwords for up to the SSSD cache TTL (typically hours).

---

### `Linux/fw.sh` — PRE-EXISTING

**Purpose:** Full iptables (Linux) or pf (BSD) firewall lockdown with IP whitelist. The "full" firewall — use this if you know the network layout.

**Configure before running (top of file):**
```bash
DISPATCHER="10.0.0.1"        # your blue team machine — gets SSH and full access
LOCALNETWORK="10.0.0.0/24"   # your subnet — full access
CCSHOST="10.0.0.100"         # scoring engine — full access (leave blank if not at NATS)
```

**What it does:**
1. Backs up existing iptables rules to `/tmp/iptables_backup_TIMESTAMP.rules`
2. Disables `ufw` and `firewalld` if running (prevents conflicts)
3. Flushes all existing rules
4. Sets default policy to DROP on INPUT, FORWARD, OUTPUT
5. Allows loopback
6. Allows all traffic from DISPATCHER, LOCALNETWORK, and CCSHOST
7. Allows established/related connections
8. **BSD path:** loads pf module with `kldload pf` (FreeBSD), writes pf ruleset to `/etc/pf.conf`, enables with `pfctl -ef`

**Commented-out port templates** — uncomment for scored services:
```bash
# iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # web
# iptables -A INPUT -p tcp --dport 3306 -j ACCEPT  # mysql
# iptables -A INPUT -p tcp --dport 445 -j ACCEPT   # smb
```

**Restore:**
```bash
iptables-restore < /tmp/iptables_backup_*.rules
```

---

### `Linux/fw_simple.sh` — PRE-EXISTING

**Purpose:** Minimal iptables firewall — allows all outbound, blocks all inbound except explicitly opened ports. Use when you don't know the IP layout yet or `fw.sh` IPs are wrong.

**What it does:**
1. Disables `ufw` and `firewalld`
2. Flushes all rules
3. Sets INPUT to DROP, OUTPUT and FORWARD to ACCEPT
4. Allows established/related inbound connections
5. Allows loopback
6. Opens port 22 (SSH) by default
7. Provides commented-out lines for HTTP, HTTPS, MySQL, PostgreSQL, FTP, SMTP, DNS, SMB, Alt HTTP
8. Explicitly blocks known C2 ports inbound: 4444, 1337, 31337, 5555, 6666

---

### `Linux/ipban.sh` — PRE-EXISTING

**Purpose:** Bans an IP address at the iptables level, saves the rules persistently, and reboots the machine.

**Usage:**
```bash
sudo bash Linux/ipban.sh 192.168.1.50
```

**What it does:**
1. Requires root
2. Detects OS from `/etc/os-release`
3. If an IP is provided as argument: inserts DROP rules for that IP on both INPUT and OUTPUT
4. **Debian/Ubuntu:** saves with `iptables-save > /etc/iptables/rules.v4` and `ip6tables-save`
5. **Fedora/CentOS:** saves with `service iptables save`, enables iptables at boot
6. Reboots the machine after saving (2-second delay)

**Note:** If no IP is provided, rules are still saved and the machine reboots — this effectively makes the current firewall state persistent across reboots.

---

### `Linux/krs.sh` — PRE-EXISTING

**Purpose:** Continuously kills any active reverse shells. Runs in an infinite loop.

**What it does:**
- Every 10 seconds, scans all running processes for: `nc`, `netcat`, `bash`, `sh`, `zsh`, `mkfifo`, `python`, `perl`, `ruby`, `wget`, `curl`
- For each matched process, checks if the command line contains an IP address pattern (`x.x.x.x port`)
- If it finds a match (process with one of those names AND an IP in its args), kills it with `kill -9`

**Usage:**
```bash
nohup bash Linux/krs.sh &
```

**Note:** This is an aggressive kill script. It will terminate any process matching those names that has an IP address in its command line — including legitimate connections. Use cautiously on web/database servers.

---

### `Linux/netdiff.sh` — PRE-EXISTING

**Purpose:** Diff comparison of current listening ports and established connections against the `firstrun.sh` baseline. New entries = possible C2 or backdoor.

**Requires:** `firstrun.sh` to have been run first (creates `$BCK/listen` and `$BCK/estab`).

**What it does:**
1. Checks for `sockstat` (BSD), `netstat`, or `ss` — uses whichever is available
2. Takes a snapshot of current listening ports and established connections
3. `diff`s each against the baseline files at `$BCK` (default `/tmp/initial`)
4. Prints the diff — lines starting with `+` are new (suspicious), lines with `-` were there before but are now gone

**Usage:**
```bash
bash Linux/netdiff.sh
# Or with custom backup dir:
BCK=/root/.initial bash Linux/netdiff.sh
```

---

### `Linux/passwd.sh` — PRE-EXISTING

**Purpose:** Resets passwords for all local Linux users with a valid login shell. Generates random 4-word passphrases from a large built-in word list. Saves all credentials to a CSV file.

**Password format:** `Word1Word2Word3Word4123!` — e.g., `HotelCyberWolfMoon123!`

**Word list:** ~300 words across categories: NATO alphabet, colors, animals, space/science, tech, nature, food, objects, verbs, adjectives.

**What it does:**
1. Loops through all users in `/etc/passwd` with a shell matching `/bin/*sh` or `/usr/bin/*sh`
2. Skips service accounts (UID < 1000) except root
3. Generates a 4-word passphrase using `$RANDOM` for each user
4. Sets password with `chpasswd`
5. Saves `username,password` pairs to `/tmp/passwd_TIMESTAMP.csv`
6. Prints changed/failed counts

**Output:** `/tmp/passwd_TIMESTAMP.csv`

**Note:** Changes LOCAL accounts only. For domain-joined machines, run `flush_domain_cache.sh` after the AD team changes passwords on the DC.

---

### `Linux/persist_hunt.sh` — PRE-EXISTING

**Purpose:** Comprehensive Linux persistence and C2 beacon hunter. The Linux equivalent of `PersistHunt.ps1`. 21 checks covering every major red team persistence technique.

**Output:** `/tmp/persist_hunt_TIMESTAMP.txt` — color-coded `[BAD]`, `[WARN]`, `[OK]`

**Configurable:**
```bash
LOOK_BACK_MINUTES=120   # how far back to check for modified files (default 2h)
```

**21 checks performed:**

| # | Check | What it looks for |
|---|---|---|
| 1 | Recently modified system binaries | `/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin` modified in last N minutes |
| 2 | Recently modified libraries | `.so*` files in `/lib /lib64 /usr/lib` modified recently |
| 3 | Systemd unit files | Recently modified `.service` files; ExecStart pointing to `/tmp/` or `/dev/shm/` |
| 4 | Cron jobs | All cron locations including per-user; flags lines with `curl`, `wget`, `bash -i`, `base64`, `/tmp/` |
| 5 | Init/RC scripts | `/etc/rc.local`, `/etc/init.d/*` checked for suspicious download/shell patterns |
| 6 | Shell profile files | `.bashrc`, `.bash_profile`, `.profile`, `.zshrc` for all users; flags network callbacks |
| 7 | SSH authorized_keys | Lists all keys in every user's `~/.ssh/authorized_keys`; flags recently modified files |
| 8 | LD_PRELOAD / linker hijacks | Checks `/etc/ld.so.preload`, `LD_PRELOAD` env var, suspicious `ld.so.conf` entries |
| 9 | Executables in temp dirs | ELF binaries in `/tmp`, `/dev/shm`, `/var/tmp`, `/run` |
| 10 | Suspicious listening processes | Listeners not matching known-good service names |
| 11 | Processes running from deleted binaries | Fileless malware — process started then binary deleted from disk |
| 12 | C2 framework IOCs | Searches by process name for: realm, sliver, apollo, mythic, beacon, havoc, brute, ratel, ninja; checks staging dirs; checks C2 callback ports (4444, 5555, 6666, 7777, 8443, 9001, 9002, 1337, 31337, 50050, 60000) |
| 13 | Unexpected SUID/SGID binaries | Compares all SUID binaries against known-good list |
| 14 | Suspicious kernel modules | Checks `lsmod` output for names containing: hook, hide, rootkit, sniff, inject, intercept |
| 15 | PAM module integrity | Recently modified `pam_*.so` files; `debsums`/`rpm -Va` PAM verification |
| 16 | `/etc/passwd` integrity | Checks for extra UID 0 accounts, service accounts with login shells, duplicate UIDs, recent modifications |
| 17 | `/etc/shadow` integrity | Permissions check (should be 640), empty password hashes, recent modifications |
| 18 | `/etc/group` integrity | Privileged group membership audit (root, sudo, wheel, adm, shadow, disk, docker, lxd); flags regular users in dangerous groups |
| 19 | Sudoers analysis | `NOPASSWD` entries, `!authenticate`, broad `ALL=(ALL) ALL` rules, sudoers referencing temp paths, recently modified sudoers files |
| 20 | SSH daemon config | `PermitRootLogin yes`, `PermitEmptyPasswords yes`, weak `PasswordAuthentication`, `AuthorizedKeysFile` hijacking, malicious `ForceCommand`, dangerous `AcceptEnv` variables |
| 21 | PAM stack dangerous modules | `pam_permit.so` (bypasses all auth), `pam_exec.so` running from `/tmp/`, `pam_python.so`/`pam_script.so`, recently modified PAM configs |

**Summary line at end:** `Findings: X BAD  Y WARN`

---

### `Linux/pom.sh` — PRE-EXISTING

**Purpose:** PAM (Pluggable Authentication Modules) backup and restore/reinstall utility. Backs up PAM config files and binaries; can restore from backup or reinstall PAM packages from the distro's package manager.

**Key behavior:**
- Without env vars set: backs up `/etc/pam.d/*` to `$BCK/pam.d/` and all `pam_*.so` files to `$BCK/pam_libraries/`
- `REVERT=1` env var: restores PAM config and binaries from backup
- `REINSTALL=1` env var: reinstalls PAM packages from package manager before restoring
- `DISFW=1` env var: temporarily allows outbound traffic (drops OUTPUT policy) for the duration of the reinstall, then re-enables DROP — prevents firewall from blocking package downloads

**Distro support:** Debian, Ubuntu, RHEL/CentOS, SUSE, Alpine (UNTESTED), Slackware (UNTESTED), Arch (UNTESTED), BSD

**Usage:**
```bash
# Backup PAM (run at competition start)
sudo bash Linux/pom.sh

# Restore PAM from backup
sudo REVERT=1 bash Linux/pom.sh

# Reinstall PAM packages then restore
sudo REINSTALL=1 REVERT=1 bash Linux/pom.sh

# If firewall blocks downloads:
sudo REINSTALL=1 REVERT=1 DISFW=1 bash Linux/pom.sh
```

---

### `Linux/snoopy.sh` — PRE-EXISTING

**Purpose:** Installs and configures `snoopy` — a PAM-level command logger that intercepts every command executed on the system, even from shells with no history.

**What it does:**
1. Downloads the snoopy installer from GitHub: `https://github.com/a2o/snoopy/raw/install/install/install-snoopy.sh`
2. Installs snoopy (stable release)
3. Writes `/etc/snoopy.ini` pointing the output file to `$BCK/snoopy.log` (default `$BCK=/root/.cache/initial`)
4. Creates and permissions the log file

**After running, every command executed on the system is logged to `$BCK/snoopy.log`.**

This is much harder for attackers to evade than bash history because it hooks at the PAM level — even shells that explicitly set `HISTFILE=/dev/null` are captured.

---

### `Linux/tmux.sh` — PRE-EXISTING

**Purpose:** Configures tmux with Alt+number keyboard shortcuts for fast window switching during competition.

**What it does:**
1. Verifies a tmux session is running (exits if not)
2. Creates `~/.tmux/` directory if needed
3. Adds key bindings to `~/.tmux.conf` (if not already present):
   - `Alt+1` through `Alt+9` = switch to window 0–8
   - `Alt+g` = open new window
4. Reloads the tmux config with `tmux source-file ~/.tmux.conf`

**Usage:** Run from inside a tmux session. After running, Alt+1 through Alt+9 navigate windows without needing the tmux prefix (`Ctrl+B`).

---

### `Linux/ufw.sh` — PRE-EXISTING

**Purpose:** UFW (Uncomplicated Firewall) lockdown for Ubuntu/Debian — the UFW equivalent of `fw.sh`. Full IP-whitelist mode with default deny inbound AND outbound.

**Configure before running:**
```bash
DISPATCHER="10.0.0.50"       # blue team machine — full access
LOCALNETWORK="10.0.0.0/24"  # internal subnet — full access
CCSHOST="10.0.0.1"          # scoring engine
```

**What it does:**
1. `ufw --force reset` — wipes existing rules
2. Sets default: deny incoming, deny outgoing, deny forward
3. Allows loopback in/out
4. Allows all outbound (scoring engine needs to be able to reach services)
5. Allows all traffic from DISPATCHER, LOCALNETWORK, CCSHOST
6. Provides commented-out templates for web (80/443), MySQL (3306), PostgreSQL (5432), SMB (445), FTP (21), DNS (53)
7. Blocks C2 ports: 4444, 5555, 6666, 1337, 31337
8. Enables UFW with `ufw --force enable`
9. Prints `ufw status verbose` at end

---

### `Linux/ufw_simple.sh` — PRE-EXISTING

**Purpose:** Minimal UFW configuration — no IP restrictions, opens only explicitly named ports. Use when you don't know the network layout yet.

**What it does:**
1. `ufw --force reset`
2. Default: deny incoming, allow outgoing
3. Opens port 22/tcp (SSH) by default
4. Commented templates for: HTTP (80), HTTPS (443), MySQL (3306), PostgreSQL (5432), FTP (21), SMTP (25), DNS (53), SMB (445), Alt HTTP (8080)
5. Blocks C2 ports: 4444, 5555, 6666, 1337, 31337
6. Enables UFW
7. Prints `ufw status verbose`

---

### `Linux/userdiff.sh` — PRE-EXISTING

**Purpose:** Diff comparison of current `/etc/passwd` and `/etc/group` against the `firstrun.sh` baseline. New lines = attacker created a backdoor account or added a user to a group.

**Requires:** `firstrun.sh` to have been run first (creates `$BCK/users` and `$BCK/groups`).

**What it does:**
```bash
diff "$BCK/users" /etc/passwd     # shows new/removed accounts
diff "$BCK/groups" /etc/group     # shows group membership changes
```

Lines starting with `+` in the output are new entries added after the baseline. Any new user or any new group member is a finding.

**Usage:**
```bash
bash Linux/userdiff.sh
# Custom backup dir:
BCK=/root/.initial bash Linux/userdiff.sh
```

---

### `Linux/webdb.sh` — PRE-EXISTING

**Purpose:** Web server and database enumeration and inventory script. Detects running web servers (Apache, nginx), databases (MySQL, MariaDB, MSSQL, PostgreSQL), PHP, and Docker — then reports their configuration details, ports, and tests for weak credentials.

**What it does:**
- Detects OS and enumerates running services
- **Docker:** lists active containers, anonymous mounts, volumes
- **Apache/httpd:** reads virtual host config from sites-enabled and httpd.conf; shows ServerName, DocumentRoot, VirtualHost, Proxy settings
- **nginx:** reads sites-enabled and nginx.conf; shows server, listen, root, server_name, proxy settings
- **MySQL/MariaDB:** tests weak credentials (no password, `root:root`, `root:password`, and `$DEFAULT_PASS` env var); if it can connect, lists all user accounts (user, host, auth plugin) and non-default databases
- **PostgreSQL:** reads pg_hba.conf; tests passwordless login as postgres user; lists non-template databases
- **MSSQL:** detects mssql-server service
- **PHP:** finds all `php.ini` locations; reports `disable_functions` setting (or warns if none are disabled)

**Color support:** Set `COLOR=1` env var for colored output. Set `DEBUG=1` to see stderr.

---

### `Linux/webwatch.sh` — PRE-EXISTING

**Purpose:** Web server watchdog daemon. Keeps nginx, Apache, PHP-FPM, and MySQL alive during competition. Also detects webshells and config tampering.

**Run modes:**
```bash
# Background daemon (restarts every 30s):
nohup bash Linux/webwatch.sh &

# Cron every 2 minutes:
*/2 * * * * /path/to/webwatch.sh

# Run once and exit (for cron):
NOLOOP=1 bash Linux/webwatch.sh
```

**Configurable env vars:**
```bash
WEBROOT="/var/www/html"    # override auto-detected web root
INTERVAL=30                # seconds between checks
LOGFILE="/var/log/ccdc_webwatch.log"
NOLOOP=0                   # set to 1 for cron mode
WP_BACKUP="/tmp/wp.tar.gz" # clean WordPress backup to restore from
```

**What it checks every interval:**
1. **Service restart** (`check_services`): restarts nginx, apache2/httpd, PHP-FPM (auto-detects version), and MySQL/MariaDB if any are down
2. **WordPress integrity** (`check_wordpress`): detects `wp-config.php`; fixes permissions if not 640; flags PHP files modified in `wp-content` in last 10 minutes; greps uploads/cache for `eval`, `base64_decode`, `system`, `shell_exec`, `passthru`; restores from `$WP_BACKUP` if core files are missing
3. **Web root hardening** (`harden_webroot`): writes `.htaccess` blocking PHP execution in uploads directories; quarantines newly created webshell files (PHP files with eval/base64/shell patterns modified in last 5 minutes → moved to `/tmp/quarantine_*`)

**Log:** `/var/log/ccdc_webwatch.log`

---

## WINDOWS FOLDER — REMAINING SCRIPTS

---

### `Windows/ToolInstall.ps1` — PRE-EXISTING

**Purpose:** Downloads and installs Sysinternals tools (Autoruns, TCPView, Process Explorer, Sysmon) and configures Sysmon with the SwiftOnSecurity config.

**What it does:**
1. Creates `C:\Tools\Sysinternals\` and `C:\Tools\Sysinternals\Sysmon\`
2. Downloads from Sysinternals:
   - `Autoruns.zip` → extract to `C:\Tools\Sysinternals\Autoruns\`
   - `TCPView.zip` → extract to `C:\Tools\Sysinternals\TCPView\`
   - `ProcessExplorer.zip` → extract to `C:\Tools\Sysinternals\ProcessExplorer\`
   - `Sysmon.zip` → extract to `C:\Tools\Sysinternals\Sysmon\`
3. Downloads `sysmonconfig-export.xml` from SwiftOnSecurity's GitHub
4. Enables command-line process auditing via registry key
5. Installs Sysmon with `Sysmon64.exe -accepteula -i sysmon-swift.xml` (falls back to `Sysmon.exe`)
6. Verifies `Sysmon64` service is running

**After running:** Sysmon is running with SwiftOnSecurity's ruleset. Every process creation, network connection, file creation, and registry modification is logged to `Microsoft-Windows-Sysmon/Operational`.

---

## INJECTS FOLDER — ALL SCRIPTS

---

### `injects/readme.txt` — PRE-EXISTING

**Purpose:** Quick reference card for Windows-side competition setup. Covers git installation, cloning the repo, execution policy bypass, script run order, user account management, password changes, common port numbers, and Chocolatey installation.

**Key content:**
- **Script run order:** `snapshots.ps1` → `triage.ps1` → `tools.ps1` → `windowfirewallgen.ps1` → `watch.ps1`
- **Firewall rollback:** `netsh advfirewall import "C:\CCDC\Backups\YYYYMMDD_HHMMSS\firewall.wfw"`
- **Execution policy bypass:** `Set-ExecutionPolicy -Scope Process Bypass`
- **Port reference table** — common (80, 443, 3389, 22, 53, 25, 445, 135) vs uncommon/suspicious (4444, 1337, 6666/6667, 8080, 9001–9005)
- **Chocolatey install** one-liner

---

### `injects/snapshots.ps1` — PRE-EXISTING

**Purpose:** Lightweight forensic snapshot — captures the system state before any changes are made. The very first script to run on a Windows machine.

**What it saves to `C:\CCDC\Backups\YYYYMMDD_HHMMSS\`:**
| File | Content |
|---|---|
| `firewall.wfw` | Full firewall policy export (for rollback with `netsh advfirewall import`) |
| `local_users.txt` | Output of `net user` |
| `local_admins.txt` | Output of `net localgroup administrators` |
| `services.txt` | All services sorted by status and name |
| `netstat.txt` | Output of `netstat -ano` |
| `schtasks.txt` | All scheduled tasks verbose listing |

**Usage:** Run this FIRST before touching anything. The `firewall.wfw` file is your only rollback option if you break connectivity.

---

### `injects/triage.ps1` — PRE-EXISTING

**Purpose:** Read-only forensic collection for Windows. Safe baseline snapshot saved to `C:\IR\TRIAGE\<HOST>_<timestamp>\`. Answers most common inject questions.

**Output folder:** `C:\IR\TRIAGE\HOSTNAME_YYYY-MM-DD_HHmm\`

**Files created:**
| File | Content |
|---|---|
| `system.txt` | Hostname, user, OS version/build, manufacturer, BIOS version, domain, IPs |
| `firewall.txt` | All firewall profiles: enabled state, default actions, logging settings |
| `netstat.txt` | Full `netstat -ano` output |
| `shares.txt` | `net share` output |
| `users_admins.txt` | All local users with last logon + local Administrators group members |
| `processes.csv` | Top 200 processes by CPU: name, PID, CPU, memory, path |
| `services.csv` | All services: name, display name, state, start mode, run-as account, binary path |
| `scheduled_tasks.csv` | All scheduled tasks: name, path, state, author |
| `recent_security_events.txt` | Last 200 security events for IDs: 4624, 4625, 4720, 4722–4726, 4732, 4733 |
| `summary.txt` | Quick-glance: firewall state, listening ports, local admins + next step suggestions |

---

### `injects/wininfo.ps1` — PRE-EXISTING

**Purpose:** Windows inventory script — produces a formatted inventory report identical in structure to `linuxinfo.ps1`. Designed for inject answers about what services are running.

**Output:** `Inventory_HOSTNAME_TIMESTAMP\inventory.txt` (in the current directory)

**Report sections:**
- Host name
- OS version and build number
- IPv4 addresses per interface
- Services (inferred from listening ports — mapped to friendly names like "Domain Controller (ldap)", "Database (mysql)", etc.)
- Required Ports (mapped) — port/protocol → service label
- Other Listening Ports (unmapped) — unknown ports
- Evidence (Listening Port → Process → Windows Service) — maps port to PID, process name, and Windows service name
- Containers — Docker container list if Docker is installed

**Port-to-service mapping** covers: SSH, HTTP, HTTPS, RDP, SMB, RPC, DNS, LDAP, LDAPS, Kerberos, MSSQL, MySQL, PostgreSQL, SMTP, POP3, IMAP, WinRM.

---

### `injects/linuxinfo.ps1` — PRE-EXISTING

**Note:** Despite the `.ps1` extension, this is a **Bash script** (has `#!/usr/bin/env bash` shebang).

**Purpose:** Linux inventory script — produces the exact same formatted output as `wininfo.ps1` but runs on Linux using `ss` or `netstat`. Designed so inject reports look identical regardless of OS.

**Output:** `Inventory_HOSTNAME_TIMESTAMP/inventory.txt` (in current directory)

**What it does:**
1. Gets OS info from `/etc/os-release`
2. Gets IPv4 addresses using `ip` or `ifconfig` (no loopback)
3. Gets listeners using `ss -H -lntup` or `netstat -lntup`
4. Parses ss/netstat output to extract: proto, port, PID, process name
5. Maps ports to service labels (same mapping as `wininfo.ps1`)
6. Detects Docker and lists containers

**Report sections** match `wininfo.ps1` exactly: Host, OS, IP Addresses, Services, Required Ports (mapped), Other Listening Ports (unmapped), Evidence, Containers.

---

### `injects/logten.sh` — PRE-EXISTING

**Purpose:** Counts failed and accepted SSH authentication events per-username from system auth logs. Quick answer for "how many login attempts" inject questions.

**What it does:** Reads `/var/log/secure`, `/var/log/auth.log`, `/var/log/messages` (whichever exist) and for each:
- Greps lines containing `Failed password` or `Accepted password`
- Extracts the username from the `for <user>` field (handles both valid users and `invalid user` syntax)
- Counts occurrences per username
- Sorts by count descending

Output shows username → count pairs, highest counts first.

---

### `injects/login.sh` — MODIFIED (documented in main section above)

See the `injects/login.sh` entry in the INJECTS FOLDER section above for full details of what was modified.

---

### `injects/tools.ps1` — PRE-EXISTING

**Purpose:** Downloads and installs the full Sysinternals Suite to `C:\CCDC\Tools\Sysinternals\`. Handles download failure gracefully (assumes tools may already be in repo).

**What it does:**
1. Creates `C:\CCDC\Tools\Sysinternals\`
2. Downloads `SysinternalsSuite.zip` from Sysinternals if `Autoruns.exe` is not already present
3. Extracts the zip
4. Runs `Unblock-File` on every `.exe` in the folder — **critical step** that removes the "downloaded from internet" Mark of the Web block that prevents execution

**Note:** The `Unblock-File` step is essential. Without it, every tool shows a security warning when you try to run it.

---

### `injects/watch.ps1` — PRE-EXISTING

**Purpose:** Comprehensive Windows triage + light automation. More detailed than `triage.ps1`. Supports an optional `ContainmentMode` that disables non-Microsoft scheduled tasks.

**Parameters:**
```powershell
.\watch.ps1                            # triage only, safe
.\watch.ps1 -ContainmentMode          # triage + disable non-Microsoft tasks
.\watch.ps1 -BaseDir "C:\MyFolder"    # custom output directory
```

**Output folder:** `C:\WRCCDC\triage_YYYYMMDD_HHMMSS\`

**Files created:**
| File | Content |
|---|---|
| `SUMMARY.txt` | Quick-view: admins, non-Microsoft tasks, process hints, enabled users |
| `admins.txt` | Local Administrators group members |
| `local_users.txt` | All local users with last logon |
| `services_all.txt` | All services with status and start type |
| `services_running.txt` | Only running services |
| `tasks_all.txt` | All scheduled tasks |
| `tasks_non_microsoft.txt` | Non-`\Microsoft\*` tasks only (prime red team persistence spot) |
| `netstat_ano.txt` | Full netstat output |
| `ipconfig_all.txt` | Full IP config |
| `arp_a.txt` | ARP table |
| `route_print.txt` | Routing table |
| `process_suspicious_hints.txt` | Processes matching known LOLBAS/tool names |
| `event_system_last12h.txt` | System event log last 12 hours |
| `event_application_last12h.txt` | Application event log last 12 hours |
| `event_security_last12h.txt` | Security event log last 12 hours |

**ContainmentMode:** When `-ContainmentMode` is set, any non-Microsoft scheduled tasks currently in Running state are disabled with `Disable-ScheduledTask`. This is logged to `SUMMARY.txt`.

**Process hints:** Flags processes matching: powershell, cmd, wscript, cscript, rundll32, regsvr32, mshta, wmic, bitsadmin, certutil, psexec, schtasks, net, nltest.

---

### `injects/windowfirewallgen.ps1` — PRE-EXISTING

**Purpose:** Scoring-safe Windows Firewall baseline. Block inbound by default, allow outbound, open only the ports you specify. Cleaner and more configurable than `FirewallAndRules.ps1` — designed for non-DC machines.

**Configure before running (top of file):**
```powershell
$AllowedInboundTCP = @(80, 443)      # add all scored service ports here
$AllowedInboundUDP = @()             # e.g. @(53, 123) if providing DNS/NTP
$EnableRDP = $true                   # set false to completely block RDP
$RestrictRDP = $true                 # restrict RDP to internal subnets only
$RdpAllowedRemoteAddresses = @("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
$LogFolder = "$env:SystemRoot\System32\LogFiles\Firewall"
```

**7 steps performed:**
1. Exports current firewall policy to `C:\fwbackup_TIMESTAMP.wfw`
2. Enables firewall on all profiles, sets `DefaultInboundAction = Block`, `DefaultOutboundAction = Allow`, disables multicast unicast responses
3. Enables firewall logging (all allowed + blocked) to `pfirewall.log`, max 32MB
4. Removes any previously created `WRCCDC_*` rules (prevents duplicate rules on rerun)
5. Creates `WRCCDC_TCP_In_<port>` rules for each TCP port in `$AllowedInboundTCP`
6. **RDP handling:** If `$EnableRDP = $true` and `$RestrictRDP = $true`, creates an RDP rule restricted to `$RdpAllowedRemoteAddresses`. If `$EnableRDP = $false`, blocks port 3389 AND sets `fDenyTSConnections=1` in registry
7. Prints all `WRCCDC_*` rules and current profile state

**Tip printed at end:** "If scoring breaks, add the needed port to AllowedInboundTCP and rerun."

---

## ROOT LEVEL — ADDITIONAL SCRIPTS

---

### `enum_hosts.py` — PRE-EXISTING

**Purpose:** Python 3 script that runs `nmap -A` against a target and parses the output to identify the OS type (Windows/Linux) and services running.

**Usage:**
```bash
python3 enum_hosts.py 10.0.0.0/24
# Or interactive:
python3 enum_hosts.py
```

**What it does:**
1. Takes IP or range as argument (or prompts)
2. Runs `sudo nmap -A -oN nmap_out <IP>`
3. Parses the output line by line:
   - Counts OS fingerprint matches for Windows keywords (msrpc, ms-sql, winrm, windows server, etc.) and Linux keywords (ubuntu, debian, fedora, centos, samba, etc.)
   - Identifies services by fingerprint: Domain Controller (kerberos, ldap), FTP, Mail (postfix, dovecot, smtp, imap, pop3), HTTP (apache, nginx, iis, wordpress, etc.), Database (mysql, mssql, postgresql, oracle), Remote (vnc, rdp, ssh, xrdp)
4. Determines OS by whichever fingerprint count is higher
5. Prints summary: IP → OS → Services

**Fingerprint lists:** Very comprehensive — covers 30+ Linux distros, all major Windows versions, 25+ HTTP frameworks/CMSes, all major database and mail systems.

---

### `enum_hosts.ps1` — PRE-EXISTING

**Purpose:** PowerShell version of `enum_hosts.py` — same functionality for running from Windows. Parses nmap output to identify OS and services.

**Usage:**
```powershell
.\enum_hosts.ps1 -IPAddress 10.0.0.0/24
# Or reads existing nmap output file:
.\enum_hosts.ps1 -OutputFile nmap_out
```

**What it does:**
1. If `$OutputFile` doesn't exist: runs `nmap -A -oN $OutputFile $IPAddress`
2. If `$OutputFile` exists: reads it directly (allows re-parsing without re-scanning)
3. Parses output to count Windows and Linux fingerprint matches per host
4. Builds service list from fingerprints (same categories as the Python version)
5. Determines OS by comparing fingerprint counts
6. Prints summary table: Host → OS → Services (comma-separated)

**Identical fingerprint database** to the Python version — fully interchangeable.

---

### `TOOLS.md` — PRE-EXISTING

**Purpose:** Reference guide for every tool installed by `firstrun.sh` and `snoopy.sh`. Explains what each tool does and provides ready-to-use commands.

**Sections:**
- **Network Tools:** `net-tools` (netstat, ifconfig), `iproute2` (ip, ss), `tcpdump`, `nmap`, `socat` — with usage examples for each
- **Firewall:** `iptables` and `ufw` — list, flush, set policy, add rules
- **Process/System Monitoring:** `htop`, `procps` (ps, pgrep, pkill), `whowatch`, `strace`
- **Security/Audit:** `rkhunter`, `unhide`, `debsums`, `auditd`, `rsyslog` — with key commands for each
- **Utilities:** `tmux` (session management, split panes), `curl`, `wget`, `tar`/`gzip`, `sed`, `gcc`/`make`
- **Downloaded by `firstrun.sh`:** `pspy64` (usage: `./pspy64`, `./pspy64 -f`), `linpeas.sh` (usage + download source)
- **Installed by `snoopy.sh`:** How to read snoopy logs from syslog
- **Quick Cheat Sheet:** 15-row table mapping "I need to..." to the exact command

---

## MISC FOLDER

---

### `misc/linuxSplunkForwarderInstal.sh` — PRE-EXISTING

**Purpose:** Fully automated Splunk Universal Forwarder v9.1.1 installation for Debian, Ubuntu, CentOS/Fedora. Installs the forwarder, configures OS-specific log monitors, and points forwarding to a Splunk indexer.

**Configure before running (top of file):**
```bash
SPLUNK_VERSION="9.1.1"
SPLUNK_BUILD="64e843ea36b1"
INDEXER_IP="172.20.241.20"    # your Splunk indexer IP
RECEIVER_PORT="9997"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="Changeme1!"   # change this
```

**What it does:**
1. Validates OS and root access
2. Creates `splunk` system user and group
3. Downloads forwarder tarball with up to 3 retries (first with cert verification, then without)
4. Extracts to `/opt/splunkforwarder/`
5. Writes `user-seed.conf` with admin credentials
6. Configures OS-specific `inputs.conf` monitors:
   - **CentOS:** yum.log, httpd access/error logs, mariadb.log, messages, auth.log, syslog, cron, secure
   - **Fedora:** maillog, dovecot.log, mariadb.log, roundcubemail errors, httpd logs, cron, messages, secure
   - **Ubuntu:** apache2 access/error, apt history, messages, auth.log, syslog
   - **Debian:** DNS query logs, NTP stats, var/log, messages, auth.log, syslog
7. Starts forwarder, accepts license, enables boot-start
8. Configures `add forward-server` to point to `$INDEXER_IP:$RECEIVER_PORT`
9. Restarts forwarder (up to 3 attempts, 30s timeout each)
10. Creates a `/tmp/test.log` file with proper ACLs for Splunk to read
11. **CentOS fix:** Removes `AmbientCapabilities` line from the systemd unit (CentOS compatibility issue); creates a `splunk-fix.service` that re-applies this fix on every boot
12. **Fedora fix:** Reboots the machine after 10 seconds (Fedora requires a reboot for the forwarder to start correctly)

**Note:** The Splunk indexer IP and admin password must be updated before running. Two Ubuntu machines will have the same Splunk source name — manually change the `[default] host=` line in `inputs.conf` on one of them.

---

### `misc/lol.sh` — PRE-EXISTING

**Contents:** Contains only the single character `d`. This is an empty/test file with no functional content. Can be ignored.

---

### `misc/openvpn-install.sh` — PRE-EXISTING

**Purpose:** Full interactive OpenVPN server installer/manager. Third-party script (from github.com/Nyr/openvpn-install, MIT License). Supports Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, Fedora.

**First run (install mode):** Interactive wizard that:
1. Selects the server IP (auto-detects; prompts if multiple; handles NAT with public IP)
2. Selects protocol (UDP recommended, or TCP)
3. Selects port (default 1194)
4. Selects DNS server (system resolvers, Google, 1.1.1.1, OpenDNS, Quad9, AdGuard)
5. Names the first client
6. Installs OpenVPN, OpenSSL, easy-rsa
7. Initializes PKI, creates CA, server certificate, client certificate
8. Generates DH parameters, TLS-crypt key
9. Creates `server.conf` (subnet 10.8.0.0/24, SHA512 auth, TLS-crypt)
10. Configures firewall (firewalld or iptables with NAT/MASQUERADE rules)
11. Enables IP forwarding (`net.ipv4.ip_forward=1`)
12. Handles SELinux port labeling if custom port on enforcing system
13. Creates `~/client.ovpn` with embedded CA cert, client cert, client key, TLS-crypt key

**Already installed (management mode):** Interactive menu:
1. **Add a new client** — generates cert and new `.ovpn` file
2. **Revoke an existing client** — revokes cert, regenerates CRL
3. **Remove OpenVPN** — full uninstall including firewall cleanup
4. **Exit**

---

## SUMMARY OF ALL FILES IN REPOSITORY

| Folder | File | Status | Purpose |
|---|---|---|---|
| `/` | `CONCEPTS.md` | NEW | Security concepts teaching guide |
| `/` | `TOOLS.md` | PRE-EXISTING | Tool reference with usage examples |
| `/` | `README.md` | MODIFIED | Main usage guide |
| `/` | `enum_hosts.py` | PRE-EXISTING | Nmap parser — OS/service detection (Python) |
| `/` | `enum_hosts.ps1` | PRE-EXISTING | Nmap parser — OS/service detection (PowerShell) |
| `Linux/` | `bad.sh` | MODIFIED | SUID/sudoers/capability audit |
| `Linux/` | `firstrun.sh` | MODIFIED | Initial setup, backups, SSH hardening |
| `Linux/` | `flush_domain_cache.sh` | PRE-EXISTING | Flush SSSD/Winbind/Kerberos cache |
| `Linux/` | `fw.sh` | PRE-EXISTING | Full IP-whitelist iptables/pf firewall |
| `Linux/` | `fw_simple.sh` | PRE-EXISTING | Simple inbound-only iptables firewall |
| `Linux/` | `inventory.sh` | MODIFIED | System inventory and enumeration |
| `Linux/` | `ipban.sh` | PRE-EXISTING | IP ban + persistent save + reboot |
| `Linux/` | `ir_report.sh` | NEW | Assembles all IR findings into one report |
| `Linux/` | `krs.sh` | PRE-EXISTING | Continuous reverse shell killer |
| `Linux/` | `mysqharden.sh` | NEW | MySQL/MariaDB hardening automation |
| `Linux/` | `netdiff.sh` | PRE-EXISTING | Diff current ports vs baseline |
| `Linux/` | `passwd.sh` | PRE-EXISTING | Bulk passphrase reset for local accounts |
| `Linux/` | `persist_hunt.sh` | PRE-EXISTING | 21-check persistence and C2 hunter |
| `Linux/` | `pom.sh` | PRE-EXISTING | PAM backup, restore, reinstall |
| `Linux/` | `snoopy.sh` | PRE-EXISTING | Install snoopy command logger |
| `Linux/` | `tmux.sh` | PRE-EXISTING | Configure tmux Alt+number shortcuts |
| `Linux/` | `ufw.sh` | PRE-EXISTING | Full IP-whitelist UFW firewall |
| `Linux/` | `ufw_simple.sh` | PRE-EXISTING | Simple port-only UFW firewall |
| `Linux/` | `userdiff.sh` | PRE-EXISTING | Diff current users/groups vs baseline |
| `Linux/` | `webdb.sh` | PRE-EXISTING | Web server and database enumeration |
| `Linux/` | `webharden.sh` | NEW | Apache/nginx hardening |
| `Linux/` | `webwatch.sh` | PRE-EXISTING | Web server watchdog + webshell detection |
| `Windows/` | `ADHardening.ps1` | PRE-EXISTING | Full AD and Windows hardening |
| `Windows/` | `ADuserPassChange.ps1` | PRE-EXISTING | Bulk AD user password reset |
| `Windows/` | `BackupAD.ps1` | PRE-EXISTING | Full AD database + GPO backup |
| `Windows/` | `BackupDns.ps1` | PRE-EXISTING | DNS zones + registry backup |
| `Windows/` | `FirewallAndRules.ps1` | PRE-EXISTING | Full firewall lockdown for DCs |
| `Windows/` | `Log.ps1` | PRE-EXISTING | Enable all Windows logging channels |
| `Windows/` | `Monitoring.ps1` | PRE-EXISTING | Block C2 ports + list listeners |
| `Windows/` | `PassChange.ps1` | PRE-EXISTING | Interactive local password reset |
| `Windows/` | `PersistHunt.ps1` | PRE-EXISTING | 12-check Windows persistence hunter |
| `Windows/` | `ProcessInjectionDetector.ps1` | PRE-EXISTING | Kernel audit + Event ID 4663/4688 dump |
| `Windows/` | `RestoreAD.ps1` | PRE-EXISTING | AD restore from backup (DSRM + normal) |
| `Windows/` | `RestoreDNS.ps1` | PRE-EXISTING | Full DNS restore with deadlock breaking |
| `Windows/` | `ServiceAuditing.ps1` | PRE-EXISTING | Service whitelist comparison |
| `Windows/` | `SoftHarden.ps1` | PRE-EXISTING | Lighter-weight Windows hardening |
| `Windows/` | `ToolInstall.ps1` | PRE-EXISTING | Install Sysinternals + Sysmon |
| `Windows/` | `UserAuditing.ps1` | MODIFIED | Disable all non-accepted local users |
| `Windows/` | `ftp.ps1` | MODIFIED | Harden IIS FTP site |
| `Windows/` | `winrm.ps1` | PRE-EXISTING | Harden WinRM to HTTPS + IP restriction |
| `ansible/` | `create_admin.yml` | NEW | Deploy backup admin to all machines |
| `ansible/` | `inventory.ini` | NEW | Linux + Windows inventory template |
| `ansible/` | `README.md` | NEW | Ansible setup and usage guide |
| `ansible/` | `vars.yml` | NEW | Backup admin account variables |
| `injects/` | `README.md` | REWRITTEN | Inject response guide |
| `injects/` | `linuxinfo.ps1` | PRE-EXISTING | Linux inventory (Bash, misnamed) |
| `injects/` | `login.sh` | MODIFIED | Login analysis + attacker IPs |
| `injects/` | `logten.sh` | PRE-EXISTING | Quick login count by username |
| `injects/` | `readme.txt` | PRE-EXISTING | Windows quick-start reference card |
| `injects/` | `snapshots.ps1` | PRE-EXISTING | Windows forensic snapshot (first script) |
| `injects/` | `tools.ps1` | PRE-EXISTING | Download + unblock Sysinternals Suite |
| `injects/` | `triage.ps1` | PRE-EXISTING | Read-only Windows forensic collection |
| `injects/` | `watch.ps1` | PRE-EXISTING | Comprehensive Windows triage + automation |
| `injects/` | `windowfirewallgen.ps1` | PRE-EXISTING | Configurable Windows firewall baseline |
| `injects/` | `wininfo.ps1` | PRE-EXISTING | Windows inventory report |
| `misc/` | `linuxSplunkForwarderInstal.sh` | PRE-EXISTING | Automated Splunk forwarder installer |
| `misc/` | `lol.sh` | PRE-EXISTING | Empty test file (no content) |
| `misc/` | `openvpn-install.sh` | PRE-EXISTING | OpenVPN server installer/manager |
| `tools/` | `README.md` | NEW | Instructions for pre-downloading tools |

---

**Total files documented:** 57  
**Updated:** 2026-06-15
