# Inject Response Guide

Quick reference — maps common inject questions to the right script and where to find the output.

> **All Linux script output saves to `/tmp/`** — copy files off before rebooting.
> **Windows triage saves to `C:\IR\TRIAGE\HOST_timestamp\`**
> **firstrun.sh baseline is at `/tmp/initial/`** (or `$BCK/initial/`)

---

## Common Inject Types

### "How many failed/successful login attempts were there?"
```bash
# Linux — saves to /tmp/login_report_TIMESTAMP.txt
bash injects/login.sh
```
Output includes: failed count, success count, top attacker IPs, recent logins, sudo/wheel members.

### "Which accounts have admin/root access?"
```bash
# Linux
cat /tmp/initial/groups          # saved by firstrun.sh at start
cat /etc/group | grep -E '(sudo|wheel|root|docker)'

# Windows
.\injects\triage.ps1             # saves users_admins.txt in C:\IR\TRIAGE\
Get-LocalGroupMember -Group "Administrators"
```

### "What services/ports are running on this machine?"
```bash
# Linux
cat /tmp/initial/listen          # saved by firstrun.sh at start
ss -tlnp                         # current view
```
```powershell
# Windows — saves Inventory_HOST_timestamp\ folder
.\injects\wininfo.ps1
```

### "Was this machine compromised? Provide evidence."
```bash
# Linux — saves to /tmp/persist_hunt_TIMESTAMP.txt
bash Linux/persist_hunt.sh
# Screenshot the [BAD] and [WARN] lines as evidence
```
```powershell
# Windows — saves to C:\Windows\Temp\PersistHunt_TIMESTAMP.txt
.\Windows\PersistHunt.ps1
```

### "What SUID binaries / dangerous permissions exist?"
```bash
# Linux — saves to /tmp/bad_TIMESTAMP.txt
bash Linux/bad.sh
```

### "What is the current firewall state?"
```bash
# Linux
iptables -L -n --line-numbers    # screenshot this

# Windows
.\injects\triage.ps1             # saves firewall.txt in output folder
Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction
```

### "What processes were running? Were any suspicious?"
```bash
# Linux
cat /tmp/initial/processes       # baseline from firstrun.sh
ps aux                           # current
```
```powershell
# Windows
.\injects\triage.ps1             # saves processes.csv in output folder
```

### "What scheduled tasks / cron jobs exist?"
```bash
# Linux
cat /tmp/initial/cron1           # /etc/crontab baseline from firstrun.sh
cat /tmp/initial/cron2           # /var/spool/cron listing
crontab -l                       # current user crontab
```
```powershell
# Windows
.\injects\triage.ps1             # saves scheduled_tasks.csv
```

### "Provide an inventory of this machine"
```bash
# Linux
bash Linux/inventory.sh          # prints to screen, redirect: bash Linux/inventory.sh > /tmp/inv.txt
```
```powershell
# Windows
.\injects\wininfo.ps1            # saves Inventory_HOST_timestamp\ folder
```

### "What users exist on this machine?"
```bash
# Linux
cat /tmp/initial/users           # /etc/passwd baseline from firstrun.sh
cat /etc/passwd                  # current
bash injects/userdiff.sh         # if firstrun baseline exists — shows NEW users
```
```powershell
# Windows — shown in triage.ps1 output
Get-LocalUser | Select Name,Enabled,LastLogon | Format-Table
```

### "Who attacked us? What IPs were involved?"
```bash
# Linux — top attacker IPs from login.sh output
bash injects/login.sh
# Also check:
grep 'Failed password' /var/log/auth.log | grep -oE 'from ([0-9.]+)' | sort | uniq -c | sort -nr
```

---

## Output File Locations

| Script | Output |
|---|---|
| `firstrun.sh` | `/tmp/initial/` — baseline snapshot of entire system |
| `ir_report.sh` | `/tmp/IR_REPORT_HOST_TIMESTAMP.txt` — **full compiled report** |
| `persist_hunt.sh` | `/tmp/persist_hunt_TIMESTAMP.txt` |
| `bad.sh` | `/tmp/bad_TIMESTAMP.txt` |
| `inventory.sh` | `/tmp/inventory_TIMESTAMP.txt` |
| `injects/login.sh` | `/tmp/login_report_TIMESTAMP.txt` |
| `injects/triage.ps1` | `C:\IR\TRIAGE\HOST_timestamp\` |
| `injects/wininfo.ps1` | `Inventory_HOST_timestamp\` (current directory) |
| `PersistHunt.ps1` | `C:\Windows\Temp\PersistHunt_TIMESTAMP.txt` |

---

## Fastest path for any inject (Linux)

```bash
# 1. Run the scripts that feed the report (if not already done)
bash Linux/persist_hunt.sh
bash Linux/bad.sh
bash injects/login.sh

# 2. Compile everything into one IR report file
bash Linux/ir_report.sh

# 3. View / screenshot
less /tmp/IR_REPORT_*.txt
```

---

## Firewall Rollback (emergency)
```powershell
# Windows — restore saved firewall rules
netsh advfirewall import "C:\CCDC\Backups\YYYYMMDD_HHMMSS\firewall.wfw"
```
```bash
# Linux — restore iptables rules saved by fw.sh
iptables-restore < /tmp/fw_backup/rules.v4.old   # pre-lockdown rules
# Or fully unlock:
iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT; iptables -F; iptables -X
```
