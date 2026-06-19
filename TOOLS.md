# Tools Reference

Tools installed and used by these scripts. Knowing what each tool does helps you use them directly during competition.

---

## Installed by `firstrun.sh`

### Network Tools

**`net-tools`** — Legacy network utilities package.
- `ifconfig` — show network interfaces and IPs (older style)
- `netstat` — list open ports and connections (older style, use `ss` on modern systems)
- `arp` — view/manipulate ARP table

**`iproute2` / `iproute`** — Modern network utilities.
- `ip a` — show all interfaces and IPs
- `ip r` — show routing table
- `ss -tlnp` — list listening TCP ports with process names (faster than netstat)
- `ss -tnp` — list established connections

**`tcpdump`** — Capture and inspect live network traffic.
```bash
tcpdump -i eth0 -n                        # watch all traffic on eth0
tcpdump -i any port 4444                  # watch for C2 port
tcpdump -i eth0 -w /tmp/capture.pcap      # save to file
```

**`nmap`** — Port scanner. Use to quickly map what services are running.
```bash
nmap -sV localhost                         # scan your own box for open services
nmap -sV 10.0.0.0/24                      # scan whole subnet
nmap -p 22,80,443,3306 10.0.0.5           # check specific ports on a host
```

**`socat`** — Advanced network relay/proxy tool. Can forward ports, create tunnels, relay traffic.
```bash
socat TCP-LISTEN:8080,fork TCP:10.0.0.5:80   # forward port 8080 → 10.0.0.5:80
```
> Red teams also use socat for C2 — if you see it running unexpectedly, investigate.

---

### Firewall

**`iptables`** — The main Linux packet filter. All `fw.sh` and `fw_simple.sh` rules use this.
```bash
iptables -L -n --line-numbers     # list current rules
iptables -F                       # flush (delete) all rules
iptables -P INPUT DROP            # default drop all inbound
iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # allow SSH
```

**`ufw`** — UFW (Uncomplicated Firewall) — a friendlier frontend to iptables. Used by `ufw.sh`.
```bash
ufw status verbose                # show current rules
ufw allow 80/tcp                  # allow HTTP
ufw deny 4444                     # block port
ufw --force reset                 # wipe all rules and start over
```

---

### Process / System Monitoring

**`htop`** — Interactive process viewer. Better version of `top`.
```bash
htop          # interactive, use F6 to sort by CPU or MEM
```

**`procps`** — Provides `ps`, `top`, `kill`, `pgrep`, `pkill`.
```bash
ps aux                            # all running processes
ps aux | grep suspicious_name     # find a specific process
pgrep -f beacon                   # find process by name pattern
pkill -9 -f beacon                # kill process by name pattern
```

**`whowatch`** — Real-time monitor of who is logged into the system and what they're running. Shows login sessions and active commands live.
```bash
whowatch     # interactive live view of all logged-in users
```

**`strace`** *(Debian/RHEL)* — Trace system calls made by a process. Useful for seeing exactly what a suspicious process is doing.
```bash
strace -p <PID>                   # attach to running process
strace -e trace=network -p <PID>  # watch only network calls
```

---

### Security / Audit

**`rkhunter`** — Rootkit Hunter. Scans for known rootkits, backdoors, and local exploits. Installed and should be run periodically during competition.
```bash
rkhunter --update                 # update signatures (if internet available)
rkhunter --check --sk             # full scan, skip key prompts
rkhunter --check --sk --report-warnings-only   # only show findings
```

**`unhide`** — Detects processes and ports hidden by rootkits by comparing different system views.
```bash
unhide proc      # find hidden processes (compares /proc vs ps output)
unhide sys       # find hidden system resources
unhide brute     # brute-force scan for hidden PIDs (slow but thorough)
```

**`debsums`** *(Debian/Ubuntu only)* — Verifies installed package files against their MD5 checksums. Catches replaced system binaries.
```bash
debsums -ca                       # check all installed files, show failures
debsums -ca 2>/dev/null | grep -v OK    # only show changed/missing files
```

**`auditd`** — Linux Audit Daemon. Records security-relevant events (file access, syscalls, login attempts) to `/var/log/audit/audit.log`.
```bash
systemctl start auditd            # start the audit daemon
auditctl -l                       # list active audit rules
ausearch -m execve -ts recent     # recent command executions
ausearch -f /etc/passwd           # see who touched /etc/passwd
aureport --auth                   # authentication report
```

**`rsyslog`** — System logging daemon. Collects and routes log messages to `/var/log/syslog`, `/var/log/auth.log`, etc.
```bash
tail -f /var/log/auth.log         # watch login/sudo activity live
tail -f /var/log/syslog           # general system events
grep "Failed password" /var/log/auth.log   # SSH brute force attempts
```

---

### Utilities

**`tmux`** — Terminal multiplexer. Lets you split one SSH session into multiple panes, detach/reattach sessions. Essential for managing multiple tasks at once during competition.
```bash
tmux new -s main          # create new session named "main"
tmux attach -t main       # reattach to existing session
# Inside tmux:
# Ctrl+B then %  = split pane vertically
# Ctrl+B then "  = split pane horizontally
# Ctrl+B then D  = detach (session keeps running)
# Ctrl+B then arrows = switch panes
```

**`curl`** — HTTP client. Download files, test web services, send requests.
```bash
curl -I http://localhost              # check HTTP headers
curl -o /tmp/file.sh https://url      # download a file
curl http://localhost/wp-login.php    # test if WordPress is up
```

**`wget`** — File downloader. Simpler than curl for just downloading files.
```bash
wget https://url/file.sh -O /tmp/file.sh
```

**`tar` / `gzip`** — Archiving and compression. Used for backups.
```bash
tar czf /tmp/backup.tar.gz /etc       # backup /etc
tar xzf /tmp/backup.tar.gz            # extract
```

**`sed`** — Stream editor. Used to find/replace text in files non-interactively.
```bash
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
```

**`gcc` / `make`** — C compiler and build tool. Included in case you need to compile tools from source during competition.

---

## Downloaded by `firstrun.sh`

**`pspy64`** — Process spy without root privileges. Watches for new processes as they're created in real-time, including cron jobs and scripts run by other users. Very useful for watching what the red team is running.
```bash
./pspy64                   # watch all process creation events live
./pspy64 -f                # also watch file system events
```
> Downloaded from: `https://github.com/DominicBreuker/pspy/releases`

**`linpeas.sh`** — Linux Privilege Escalation Awesome Script. Automated local enumeration — finds misconfigurations, weak permissions, vulnerable software, credential files. Primarily an offensive tool but useful for finding what the red team might exploit on your boxes.
```bash
bash linpeas.sh            # full scan (noisy, generates a lot of output)
bash linpeas.sh -q         # quiet mode
bash linpeas.sh 2>/dev/null | tee /tmp/linpeas_out.txt
```
> Downloaded from: `https://github.com/peass-ng/PEASS-ng/releases`

---

## Installed by `snoopy.sh`

**`snoopy`** — Hooks into PAM to log every single command executed on the system to syslog. Unlike bash history (which can be cleared), snoopy logs at the kernel level and is much harder to evade.
```bash
# After running snoopy.sh:
tail -f /var/log/auth.log | grep snoopy    # watch commands live
grep snoopy /var/log/syslog                # check all logged commands
```

---

## Quick Cheat Sheet — During Competition

| I need to... | Command |
|---|---|
| See all open ports | `ss -tlnp` |
| See all connections | `ss -tnp` |
| Find a suspicious process | `ps aux \| grep <name>` or `pgrep -f <name>` |
| Kill a suspicious process | `pkill -9 -f <name>` |
| Watch traffic on a port | `tcpdump -i any port <port>` |
| Check who's logged in | `who` or `whowatch` |
| See recent logins | `last \| head -20` |
| See failed SSH logins | `grep "Failed" /var/log/auth.log \| tail -20` |
| Check iptables rules | `iptables -L -n --line-numbers` |
| Scan for rootkits | `rkhunter --check --sk` |
| Find hidden processes | `unhide proc` |
| Verify system files (Debian) | `debsums -ca 2>/dev/null` |
| Verify system files (RHEL) | `rpm -Va 2>/dev/null` |
| Watch all commands run | `./pspy64` |
| Check audit log | `ausearch -m execve -ts recent` |
