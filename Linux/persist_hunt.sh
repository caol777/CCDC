#!/bin/bash
# persist_hunt.sh
# CCDC Persistence & C2 Beacon Hunter
# Checks common red team persistence spots:
#   /bin /sbin /usr/bin /usr/sbin /lib /lib64 /etc/systemd/system
#   cron, rc/init, shell profiles, authorized_keys, LD_PRELOAD,
#   /tmp /dev/shm, suspicious listeners, Realm/Sliver/Mythic IOCs

LOGFILE="/tmp/persist_hunt_$(date +%Y%m%d_%H%M%S).txt"
LOOK_BACK_MINUTES=${LOOK_BACK_MINUTES:-120}  # how many minutes back to check for new files

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
NC='\033[0m'

log()  { echo -e "$1" | tee -a "$LOGFILE"; }
bad()  { echo -e "${RED}[BAD]  $1${NC}" | tee -a "$LOGFILE"; }
warn() { echo -e "${YEL}[WARN] $1${NC}" | tee -a "$LOGFILE"; }
good() { echo -e "${GRN}[OK]   $1${NC}" | tee -a "$LOGFILE"; }
sep()  { echo "========================================" | tee -a "$LOGFILE"; }

sep
log "CCDC PERSISTENCE HUNTER"
log "Host: $(hostname)  Date: $(date)"
log "Looking back: $LOOK_BACK_MINUTES minutes"
log "Output: $LOGFILE"
sep

# -----------------------------------------------------------------------
# 1. RECENTLY MODIFIED SYSTEM BINARIES
# -----------------------------------------------------------------------
sep
log "1. RECENTLY MODIFIED SYSTEM BINARIES (last ${LOOK_BACK_MINUTES}m)"
sep
SYSDIRS="/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin"
FOUND=0
for d in $SYSDIRS; do
    [ -d "$d" ] || continue
    results=$(find "$d" -maxdepth 1 -type f -newer /proc/1/exe -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null)
    if [ -n "$results" ]; then
        while IFS= read -r f; do
            bad "Modified binary: $f  $(ls -la "$f" 2>/dev/null | awk '{print $1,$3,$4,$6,$7,$8}')"
            FOUND=$((FOUND+1))
        done <<< "$results"
    fi
done
[ "$FOUND" -eq 0 ] && good "No recently modified system binaries"

# -----------------------------------------------------------------------
# 2. RECENTLY MODIFIED LIBRARY DIRS
# -----------------------------------------------------------------------
sep
log "2. RECENTLY MODIFIED LIBRARIES (last ${LOOK_BACK_MINUTES}m)"
sep
LIBDIRS="/lib /lib64 /lib32 /usr/lib /usr/lib64 /usr/lib32"
FOUND=0
for d in $LIBDIRS; do
    [ -d "$d" ] || continue
    results=$(find "$d" -type f -name "*.so*" -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null)
    if [ -n "$results" ]; then
        while IFS= read -r f; do
            bad "Modified library: $f"
            FOUND=$((FOUND+1))
        done <<< "$results"
    fi
done
[ "$FOUND" -eq 0 ] && good "No recently modified libraries"

# -----------------------------------------------------------------------
# 3. SYSTEMD PERSISTENCE
# -----------------------------------------------------------------------
sep
log "3. SYSTEMD SERVICE FILES"
sep
FOUND=0
for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
    [ -d "$d" ] || continue
    results=$(find "$d" -type f -name "*.service" -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null)
    if [ -n "$results" ]; then
        while IFS= read -r f; do
            bad "Recently modified service: $f"
            grep -E "^(ExecStart|ExecStartPre|ExecStop|Environment)" "$f" 2>/dev/null | while read -r line; do
                warn "  $line"
            done
            FOUND=$((FOUND+1))
        done <<< "$results"
    fi
done

# Check all enabled services for suspicious exec paths
systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | while read -r svc; do
    execstart=$(systemctl cat "$svc" 2>/dev/null | grep "^ExecStart=" | head -1)
    if echo "$execstart" | grep -qE "(/tmp/|/dev/shm/|/var/tmp/|\.\./)"; then
        bad "Suspicious ExecStart in $svc: $execstart"
    fi
done

[ "$FOUND" -eq 0 ] && good "No recently modified systemd unit files"

# -----------------------------------------------------------------------
# 4. CRON PERSISTENCE
# -----------------------------------------------------------------------
sep
log "4. CRON JOBS"
sep
CRON_FILES="/etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs"
for cf in $CRON_FILES; do
    [ -e "$cf" ] || continue
    if [ -d "$cf" ]; then
        find "$cf" -type f 2>/dev/null | while read -r f; do
            log "  [cron] $f:"
            grep -v "^#\|^$" "$f" 2>/dev/null | while read -r line; do
                if echo "$line" | grep -qE "(/tmp/|/dev/shm/|curl|wget|bash -i|nc |ncat|python.*-c|perl.*-e|base64)"; then
                    bad "    SUSPICIOUS: $line"
                else
                    log "    $line"
                fi
            done
        done
    else
        log "  [cron] $cf:"
        grep -v "^#\|^$" "$cf" 2>/dev/null | while read -r line; do
            if echo "$line" | grep -qE "(/tmp/|/dev/shm/|curl|wget|bash -i|nc |ncat|python.*-c|perl.*-e|base64)"; then
                bad "    SUSPICIOUS: $line"
            else
                log "    $line"
            fi
        done
    fi
done

# Per-user crontabs
getent passwd 2>/dev/null | cut -d: -f1 | while read -r u; do
    ct=$(crontab -l -u "$u" 2>/dev/null | grep -v "^#\|^$")
    if [ -n "$ct" ]; then
        log "  [cron] user=$u:"
        echo "$ct" | while read -r line; do
            if echo "$line" | grep -qE "(/tmp/|/dev/shm/|curl|wget|bash -i|nc |base64)"; then
                bad "    SUSPICIOUS: $line"
            else
                log "    $line"
            fi
        done
    fi
done

# -----------------------------------------------------------------------
# 5. INIT / RC PERSISTENCE
# -----------------------------------------------------------------------
sep
log "5. INIT / RC SCRIPTS"
sep
for f in /etc/rc.local /etc/rc.d/rc.local /etc/init.d/*; do
    [ -f "$f" ] || continue
    if grep -qE "(curl|wget|bash -i|nc |/tmp/|/dev/shm/|base64)" "$f" 2>/dev/null; then
        bad "Suspicious content in $f"
        grep -E "(curl|wget|bash -i|nc |/tmp/|/dev/shm/|base64)" "$f" | while read -r line; do
            warn "  $line"
        done
    fi
done

# -----------------------------------------------------------------------
# 6. SHELL PROFILE PERSISTENCE
# -----------------------------------------------------------------------
sep
log "6. SHELL PROFILE FILES"
sep
PROFILE_FILES=".bashrc .bash_profile .profile .zshrc .bash_logout .zprofile"
getent passwd 2>/dev/null | while IFS=: read -r user _ uid _ _ home _; do
    [ -d "$home" ] || continue
    for pf in $PROFILE_FILES; do
        fp="$home/$pf"
        [ -f "$fp" ] || continue
        if grep -qE "(curl|wget|bash -i|nc |/tmp/|/dev/shm/|base64|exec |eval )" "$fp" 2>/dev/null; then
            bad "Suspicious content in $fp (user=$user)"
            grep -nE "(curl|wget|bash -i|nc |/tmp/|/dev/shm/|base64|exec |eval )" "$fp" | while read -r line; do
                warn "  $line"
            done
        fi
    done
done

# /etc/profile.d
if [ -d /etc/profile.d ]; then
    find /etc/profile.d -type f -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null | while read -r f; do
        bad "Recently modified profile.d script: $f"
    done
fi

# -----------------------------------------------------------------------
# 7. SSH AUTHORIZED_KEYS
# -----------------------------------------------------------------------
sep
log "7. SSH AUTHORIZED_KEYS"
sep
getent passwd 2>/dev/null | while IFS=: read -r user _ uid _ _ home _; do
    [ -d "$home" ] || continue
    ak="$home/.ssh/authorized_keys"
    [ -f "$ak" ] || continue
    count=$(grep -c "ssh-" "$ak" 2>/dev/null || echo 0)
    warn "  $ak: $count key(s) — user=$user"
    cat "$ak" 2>/dev/null | while read -r line; do
        log "    $(echo "$line" | cut -c1-80)..."
    done
done
# Also check for recently modified authorized_keys
find /root /home -name "authorized_keys" -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null | while read -r f; do
    bad "RECENTLY MODIFIED authorized_keys: $f"
done

# -----------------------------------------------------------------------
# 8. LD_PRELOAD / DYNAMIC LINKER HIJACKS
# -----------------------------------------------------------------------
sep
log "8. LD_PRELOAD / LD LINKER HIJACKS"
sep
if [ -f /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
    bad "/etc/ld.so.preload is NOT EMPTY:"
    cat /etc/ld.so.preload | while read -r line; do warn "  $line"; done
else
    good "/etc/ld.so.preload is empty or missing"
fi

if env | grep -q "LD_PRELOAD"; then
    bad "LD_PRELOAD env variable set: $LD_PRELOAD"
fi
if env | grep -q "LD_LIBRARY_PATH"; then
    warn "LD_LIBRARY_PATH set: $LD_LIBRARY_PATH"
fi

grep -rE "^[^#].*ld\.so\." /etc/ld.so.conf /etc/ld.so.conf.d/ 2>/dev/null | while read -r line; do
    if echo "$line" | grep -qE "(/tmp/|/dev/shm/|/var/tmp/)"; then
        bad "Suspicious ld.so.conf entry: $line"
    fi
done

# -----------------------------------------------------------------------
# 9. EXECUTABLES IN /tmp /dev/shm /var/tmp
# -----------------------------------------------------------------------
sep
log "9. EXECUTABLES IN TEMP DIRECTORIES"
sep
FOUND=0
for d in /tmp /dev/shm /var/tmp /run; do
    [ -d "$d" ] || continue
    find "$d" -type f -executable 2>/dev/null | while read -r f; do
        bad "Executable in $d: $f  $(ls -la "$f" 2>/dev/null | awk '{print $1,$3,$4}')"
        file "$f" 2>/dev/null | grep -q "ELF" && warn "  ^ is an ELF binary!"
        FOUND=$((FOUND+1))
    done
done
[ "$FOUND" -eq 0 ] && good "No executables found in temp directories"

# -----------------------------------------------------------------------
# 10. SUSPICIOUS LISTENING PROCESSES
# -----------------------------------------------------------------------
sep
log "10. SUSPICIOUS LISTENING PROCESSES"
sep
if command -v ss >/dev/null 2>&1; then
    ss -tlnp 2>/dev/null | grep -vE "(sshd|nginx|apache|httpd|mysql|postgres|named|ntpd|chronyd|systemd|dbus|avahi)" | while read -r line; do
        warn "  Unusual listener: $line"
    done
elif command -v netstat >/dev/null 2>&1; then
    netstat -tlnp 2>/dev/null | grep -vE "(sshd|nginx|apache|httpd|mysql|postgres|named|ntpd|chronyd|systemd|dbus)" | while read -r line; do
        warn "  Unusual listener: $line"
    done
fi

# -----------------------------------------------------------------------
# 11. PROCESSES WITH DELETED BINARIES (common C2 technique)
# -----------------------------------------------------------------------
sep
log "11. PROCESSES RUNNING FROM DELETED BINARIES"
sep
FOUND=0
ls /proc/*/exe 2>/dev/null | while read -r exelink; do
    if ls -la "$exelink" 2>/dev/null | grep -q "(deleted)"; then
        pid=$(echo "$exelink" | cut -d/ -f3)
        cmdline=$(cat /proc/"$pid"/cmdline 2>/dev/null | tr '\0' ' ')
        bad "Process $pid running from deleted binary: $cmdline"
        FOUND=$((FOUND+1))
    fi
done
[ "$FOUND" -eq 0 ] && good "No processes running from deleted binaries"

# -----------------------------------------------------------------------
# 12. REALM C2 / SLIVER / MYTHIC IOCs
# -----------------------------------------------------------------------
sep
log "12. C2 FRAMEWORK IOCs (Realm, Sliver, Mythic/Apollo, Cobalt Strike)"
sep

# Known C2 process name patterns
C2_PROCS="realm implant sliver apollo mythic beacon havoc brute ratel ninja"
for c2 in $C2_PROCS; do
    pids=$(pgrep -f "$c2" 2>/dev/null)
    if [ -n "$pids" ]; then
        bad "Possible C2 process '$c2' running: PIDs=$pids"
        ps aux | grep "$c2" | grep -v grep | while read -r line; do warn "  $line"; done
    fi
done

# Check for Sliver/Realm staging dirs
for d in /root/.sliver /home/*/.sliver /tmp/.realm /tmp/.sliver /opt/realm /opt/sliver; do
    [ -e "$d" ] && bad "C2 staging directory found: $d"
done

# Suspicious process with no tty and outbound connection (common beaconing pattern)
if command -v ss >/dev/null 2>&1; then
    ss -tnp 2>/dev/null | grep ESTAB | grep -vE "(sshd|nginx|apache|httpd|curl|wget|apt|yum|dnf|docker)" | while read -r line; do
        warn "  Established outbound: $line"
    done
fi

# Common C2 callback ports
C2_PORTS="4444 5555 6666 7777 8443 9001 9002 1337 31337 50050 60000"
for port in $C2_PORTS; do
    if ss -tnp 2>/dev/null | grep -q ":$port\b" || netstat -tnp 2>/dev/null | grep -q ":$port "; then
        bad "Common C2 port $port is in use!"
    fi
done

# -----------------------------------------------------------------------
# 13. SUID/SGID BINARIES NOT IN KNOWN-GOOD LIST
# -----------------------------------------------------------------------
sep
log "13. UNEXPECTED SUID/SGID BINARIES"
sep
KNOWN_SUID="ping ping6 sudo su passwd newgrp chsh chfn mount umount pkexec fusermount traceroute6 at crontab ssh-agent wall write"
find / -perm /6000 -type f 2>/dev/null | while read -r f; do
    base=$(basename "$f")
    if ! echo "$KNOWN_SUID" | grep -qw "$base"; then
        bad "Unexpected SUID/SGID binary: $f  $(ls -la "$f" | awk '{print $1,$3,$4}')"
    fi
done

# -----------------------------------------------------------------------
# 14. RECENTLY ADDED KERNEL MODULES
# -----------------------------------------------------------------------
sep
log "14. LOADED KERNEL MODULES (suspicious)"
sep
if command -v lsmod >/dev/null 2>&1; then
    lsmod 2>/dev/null | tail -n +2 | while read -r name size used; do
        if echo "$name" | grep -qiE "(hook|hide|rootkit|sniff|inject|intercept)"; then
            bad "Suspicious kernel module: $name"
        fi
    done
    good "Kernel module check done (manual review recommended)"
fi

# -----------------------------------------------------------------------
# 15. PAM MODULE INTEGRITY
# -----------------------------------------------------------------------
sep
log "15. PAM MODULE INTEGRITY"
sep
find /lib /lib64 /usr/lib /usr/lib64 -name "pam_*.so" -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null | while read -r f; do
    bad "Recently modified PAM module: $f"
done

if command -v debsums >/dev/null 2>&1; then
    debsums -ca 2>/dev/null | grep "pam" | while read -r line; do
        bad "PAM debsums failure: $line"
    done
elif command -v rpm >/dev/null 2>&1; then
    rpm -Va 2>/dev/null | grep "pam" | while read -r line; do
        bad "PAM rpm verify failure: $line"
    done
fi

# -----------------------------------------------------------------------
# 16. /etc/passwd INTEGRITY
# -----------------------------------------------------------------------
sep
log "16. /etc/passwd INTEGRITY"

# Only root should be UID 0
awk -F: '$3 == 0 {print $1}' /etc/passwd | while read -r u; do
    [ "$u" = "root" ] && continue
    bad "Extra UID 0 account (root-equivalent backdoor): $u"
done

# Service accounts (UID < 1000) with login shells
awk -F: '$3 < 1000 && $1 != "root" {print $1, $3, $7}' /etc/passwd | while read -r user uid shell; do
    if echo "$shell" | grep -qE "(bash|sh|zsh|fish|ksh|csh|tcsh|dash)$"; then
        bad "Service account $user (UID=$uid) has login shell: $shell"
    fi
done

# Duplicate UIDs
awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d | while read -r dup; do
    [ "$dup" -eq 0 ] && continue
    users=$(awk -F: -v u="$dup" '$3==u{printf "%s ", $1}' /etc/passwd)
    bad "Duplicate UID $dup shared by: $users"
done

# Recently modified
if find /etc/passwd -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null | grep -q passwd; then
    bad "/etc/passwd was modified in the last ${LOOK_BACK_MINUTES}m!"
    tail -5 /etc/passwd | while read -r line; do warn "  Recent tail: $line"; done
else
    good "/etc/passwd not recently modified"
fi

# -----------------------------------------------------------------------
# 17. /etc/shadow INTEGRITY
# -----------------------------------------------------------------------
sep
log "17. /etc/shadow INTEGRITY"

if [ ! -r /etc/shadow ]; then
    warn "/etc/shadow not readable (run as root for full check)"
else
    # Permissions should be 640 or 000
    SHADOW_PERMS=$(stat -c "%a" /etc/shadow 2>/dev/null)
    if ! echo "$SHADOW_PERMS" | grep -qE "^(640|000|600)$"; then
        bad "/etc/shadow permissions: $SHADOW_PERMS (should be 640)"
    else
        good "/etc/shadow permissions: $SHADOW_PERMS"
    fi

    # Empty password hash = no password required
    awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | while read -r user; do
        bad "CRITICAL: $user has NO PASSWORD (empty hash in /etc/shadow)"
    done

    if find /etc/shadow -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null | grep -q shadow; then
        bad "/etc/shadow was modified in the last ${LOOK_BACK_MINUTES}m!"
    else
        good "/etc/shadow not recently modified"
    fi
fi

# -----------------------------------------------------------------------
# 18. /etc/group INTEGRITY
# -----------------------------------------------------------------------
sep
log "18. /etc/group — PRIVILEGED GROUP MEMBERSHIP"

PRIV_GROUPS="root sudo wheel adm shadow disk docker lxd kvm libvirt"
for grp in $PRIV_GROUPS; do
    members=$(getent group "$grp" 2>/dev/null | cut -d: -f4)
    [ -z "$members" ] && continue
    warn "Group '$grp' members: $members"
    # Flag regular users (UID >= 1000) in root/shadow/disk
    if echo "$grp" | grep -qE "^(root|shadow|disk)$"; then
        for m in $(echo "$members" | tr ',' ' '); do
            uid=$(id -u "$m" 2>/dev/null)
            [ -n "$uid" ] && [ "$uid" -ge 1000 ] && bad "Regular user '$m' (UID=$uid) in group '$grp' — privilege escalation risk!"
        done
    fi
    # docker = root equivalent
    [ "$grp" = "docker" ] && bad "docker group has members (docker = root): $members"
done

if find /etc/group -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null | grep -q group; then
    bad "/etc/group was modified in the last ${LOOK_BACK_MINUTES}m!"
else
    good "/etc/group not recently modified"
fi

# -----------------------------------------------------------------------
# 19. SUDOERS — DANGEROUS RULES
# -----------------------------------------------------------------------
sep
log "19. SUDOERS ANALYSIS (/etc/sudoers + /etc/sudoers.d/)"

check_sudoers_file() {
    local f="$1"
    grep -nE "NOPASSWD" "$f" 2>/dev/null | while read -r line; do
        bad "NOPASSWD in $f: $line"
    done
    grep -nE "!authenticate" "$f" 2>/dev/null | while read -r line; do
        bad "!authenticate in $f: $line"
    done
    grep -nE "^\s*[^#%].*ALL=\(ALL\).*ALL" "$f" 2>/dev/null | while read -r line; do
        warn "Broad ALL=(ALL) rule in $f: $line"
    done
    grep -nE "(/tmp/|/dev/shm/|/var/tmp/)" "$f" 2>/dev/null | while read -r line; do
        bad "Sudo rule references temp path in $f: $line"
    done
    if find "$f" -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null | grep -q .; then
        bad "$f modified in the last ${LOOK_BACK_MINUTES}m!"
    fi
}

if [ -f /etc/sudoers ]; then
    SUDOERS_PERMS=$(stat -c "%a" /etc/sudoers 2>/dev/null)
    if ! echo "$SUDOERS_PERMS" | grep -qE "^(440|400)$"; then
        bad "/etc/sudoers permissions: $SUDOERS_PERMS (should be 440)"
    else
        good "/etc/sudoers permissions: $SUDOERS_PERMS"
    fi
    check_sudoers_file /etc/sudoers
fi

if [ -d /etc/sudoers.d ]; then
    find /etc/sudoers.d -type f 2>/dev/null | while read -r f; do
        check_sudoers_file "$f"
    done
fi

# -----------------------------------------------------------------------
# 20. SSH DAEMON CONFIG
# -----------------------------------------------------------------------
sep
log "20. SSH DAEMON CONFIG (/etc/ssh/sshd_config + sshd_config.d/)"

check_sshd_file() {
    local f="$1"

    val=$(grep -iE "^\s*PermitRootLogin" "$f" 2>/dev/null | tail -1 | awk '{print $2}')
    if echo "$val" | grep -qiE "^yes$"; then
        bad "PermitRootLogin yes in $f"
    elif [ -n "$val" ]; then
        good "PermitRootLogin $val in $f"
    fi

    val=$(grep -iE "^\s*PermitEmptyPasswords" "$f" 2>/dev/null | tail -1 | awk '{print $2}')
    if echo "$val" | grep -qiE "^yes$"; then
        bad "PermitEmptyPasswords yes in $f — anyone with no password can log in!"
    fi

    val=$(grep -iE "^\s*PasswordAuthentication" "$f" 2>/dev/null | tail -1 | awk '{print $2}')
    if echo "$val" | grep -qiE "^yes$"; then
        warn "PasswordAuthentication yes in $f — brute force possible"
    fi

    # AuthorizedKeysFile pointing to attacker-controlled path
    val=$(grep -iE "^\s*AuthorizedKeysFile" "$f" 2>/dev/null | tail -1)
    if echo "$val" | grep -qE "(/tmp/|/dev/shm/|/var/tmp/|/etc/)"; then
        bad "AuthorizedKeysFile hijack in $f: $val"
    fi

    # ForceCommand backdoor
    val=$(grep -iE "^\s*ForceCommand" "$f" 2>/dev/null)
    if echo "$val" | grep -qE "(/tmp/|/dev/shm/|bash -i|nc |python.*-c|perl.*-e)"; then
        bad "Malicious ForceCommand in $f: $val"
    elif [ -n "$val" ]; then
        warn "ForceCommand set in $f: $val — verify this is intentional"
    fi

    # AcceptEnv passing dangerous vars
    val=$(grep -iE "^\s*AcceptEnv" "$f" 2>/dev/null)
    if echo "$val" | grep -qiE "LD_|PATH|ENV"; then
        bad "AcceptEnv passes dangerous env vars in $f: $val"
    fi

    if find "$f" -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null | grep -q .; then
        bad "$f modified in the last ${LOOK_BACK_MINUTES}m!"
    fi
}

if [ -f /etc/ssh/sshd_config ]; then
    check_sshd_file /etc/ssh/sshd_config
fi
if [ -d /etc/ssh/sshd_config.d ]; then
    find /etc/ssh/sshd_config.d -type f -name "*.conf" 2>/dev/null | while read -r f; do
        check_sshd_file "$f"
    done
fi

# -----------------------------------------------------------------------
# 21. PAM STACK — DANGEROUS MODULES
# -----------------------------------------------------------------------
sep
log "21. PAM STACK (/etc/pam.d/)"

# pam_permit.so = allows ANYTHING — should never be in production
grep -rn "pam_permit.so" /etc/pam.d/ 2>/dev/null | while read -r line; do
    bad "pam_permit.so found (bypasses all auth): $line"
done

# pam_exec.so running scripts from /tmp
grep -rn "pam_exec.so" /etc/pam.d/ 2>/dev/null | while read -r line; do
    if echo "$line" | grep -qE "(/tmp/|/dev/shm/|/var/tmp/)"; then
        bad "pam_exec.so running from temp dir: $line"
    else
        warn "pam_exec.so present: $line — verify this is legitimate"
    fi
done

# pam_python.so / pam_script.so — uncommon, very high risk
grep -rn "pam_python.so\|pam_script.so" /etc/pam.d/ 2>/dev/null | while read -r line; do
    bad "Scripted PAM module found: $line"
done

find /etc/pam.d -type f -mmin -"$LOOK_BACK_MINUTES" 2>/dev/null | while read -r f; do
    bad "Recently modified PAM config: $f"
done

# -----------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------
sep
log "HUNT COMPLETE. Full output: $LOGFILE"
BAD_COUNT=$(grep -c "\[BAD\]" "$LOGFILE" 2>/dev/null || echo 0)
WARN_COUNT=$(grep -c "\[WARN\]" "$LOGFILE" 2>/dev/null || echo 0)
log "Findings: ${RED}${BAD_COUNT} BAD${NC}  ${YEL}${WARN_COUNT} WARN${NC}"
sep
