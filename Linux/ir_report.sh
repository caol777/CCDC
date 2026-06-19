#!/bin/bash
# ir_report.sh — IR Report Assembler
# Pulls together firstrun.sh baseline, all script findings, and current state
# into one readable file you can screenshot or submit as evidence.
#
# Run any time during competition. Safe to run multiple times.
# Output: /tmp/IR_REPORT_<hostname>_<timestamp>.txt

BCK="${BCK:-/tmp}/initial"
HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
STAMP=$(date +%Y%m%d_%H%M%S)
REPORT="/tmp/IR_REPORT_${HOST}_${STAMP}.txt"

# Helper to write a section header
section() {
    echo "" >> "$REPORT"
    echo "########################################################################" >> "$REPORT"
    echo "## $1" >> "$REPORT"
    echo "########################################################################" >> "$REPORT"
}

# Helper to append a file if it exists
append_file() {
    local label="$1"
    local file="$2"
    if [ -f "$file" ]; then
        echo "" >> "$REPORT"
        echo "--- $label ($file) ---" >> "$REPORT"
        cat "$file" >> "$REPORT"
    else
        echo "--- $label : NOT FOUND ($file) ---" >> "$REPORT"
    fi
}

# Helper to append the most recent matching file
append_latest() {
    local label="$1"
    local pattern="$2"
    local latest
    latest=$(ls -t $pattern 2>/dev/null | head -1)
    if [ -n "$latest" ]; then
        echo "" >> "$REPORT"
        echo "--- $label (latest: $latest) ---" >> "$REPORT"
        cat "$latest" >> "$REPORT"
    else
        echo "--- $label : no output file found (run the script first) ---" >> "$REPORT"
    fi
}

# -----------------------------------------------------------------------
echo "Building IR report..."
> "$REPORT"

# HEADER
cat >> "$REPORT" <<EOF
########################################################################
## INCIDENT RESPONSE REPORT
########################################################################
Host:        $HOST
Date/Time:   $(date)
Report file: $REPORT
OS:          $(uname -a 2>/dev/null)
IP(s):       $(hostname -I 2>/dev/null || ip addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | tr '\n' ' ')
Uptime:      $(uptime 2>/dev/null)
########################################################################
EOF

# -----------------------------------------------------------------------
section "1. BASELINE STATE (captured by firstrun.sh at competition start)"

if [ -d "$BCK" ]; then
    append_file "Users at start (/etc/passwd)" "$BCK/users"
    append_file "Groups at start (/etc/group)"  "$BCK/groups"
    append_file "Listening ports at start"       "$BCK/listen"
    append_file "Established connections at start" "$BCK/estab"
    append_file "SUID binaries at start"         "$BCK/suid"
    append_file "Processes at start"             "$BCK/processes"
    append_file "Crontab /etc/crontab"           "$BCK/cron1"
    append_file "Crontab /var/spool listing"     "$BCK/cron2"
    append_file "Crontab root crontab -l"        "$BCK/cron3"
    append_file "Docker containers at start"     "$BCK/docker"
else
    echo "WARNING: Baseline directory $BCK not found." >> "$REPORT"
    echo "firstrun.sh may not have been run, or BCK is set differently." >> "$REPORT"
fi

# -----------------------------------------------------------------------
section "2. CURRENT STATE"

{
    echo "--- Current users ---"
    cat /etc/passwd

    echo ""
    echo "--- Currently logged in ---"
    who 2>/dev/null
    echo ""
    last -20 2>/dev/null

    echo ""
    echo "--- Current listening ports ---"
    ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

    echo ""
    echo "--- Current established connections ---"
    ss -tnp 2>/dev/null | grep ESTAB || netstat -tnp 2>/dev/null | grep ESTABLISHED

    echo ""
    echo "--- Current processes (top CPU) ---"
    ps aux --sort=-%cpu 2>/dev/null | head -30

    echo ""
    echo "--- Sudo/wheel/admin group members ---"
    grep -E '^(sudo|wheel|admin|root)' /etc/group 2>/dev/null

    echo ""
    echo "--- Active crontabs ---"
    crontab -l 2>/dev/null
    ls /var/spool/cron/crontabs/ 2>/dev/null && cat /var/spool/cron/crontabs/* 2>/dev/null
    cat /etc/crontab 2>/dev/null
} >> "$REPORT"

# -----------------------------------------------------------------------
section "3. CHANGES SINCE BASELINE (diff)"

{
    echo "--- New/changed users since start ---"
    if [ -f "$BCK/users" ]; then
        diff "$BCK/users" /etc/passwd 2>/dev/null || echo "(no diff tool or no changes)"
    else
        echo "(no baseline)"
    fi

    echo ""
    echo "--- New/changed groups since start ---"
    if [ -f "$BCK/groups" ]; then
        diff "$BCK/groups" /etc/group 2>/dev/null || echo "(no diff tool or no changes)"
    else
        echo "(no baseline)"
    fi

    echo ""
    echo "--- New listening ports since start ---"
    if [ -f "$BCK/listen" ]; then
        CURRENT_LISTEN=$(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null)
        diff <(cat "$BCK/listen") <(echo "$CURRENT_LISTEN") 2>/dev/null | grep '^[<>]' || echo "(no changes detected)"
    else
        echo "(no baseline)"
    fi
} >> "$REPORT"

# -----------------------------------------------------------------------
section "4. SECURITY FINDINGS — persist_hunt.sh"
append_latest "Persistence & C2 Hunt Results" "/tmp/persist_hunt_*.txt"

# -----------------------------------------------------------------------
section "5. SECURITY FINDINGS — bad.sh (SUID / capabilities / sudoers)"
append_latest "bad.sh Results" "/tmp/bad_*.txt"

# -----------------------------------------------------------------------
section "6. LOGIN ANALYSIS"
append_latest "Login Report" "/tmp/login_report_*.txt"

# -----------------------------------------------------------------------
section "7. INVENTORY"
append_latest "System Inventory" "/tmp/inventory_*.txt"

# -----------------------------------------------------------------------
section "8. FAILED LOGIN ATTACKER IPs (quick extract)"
{
    for log in /var/log/secure /var/log/auth.log /var/log/messages; do
        [ -f "$log" ] || continue
        echo "From $log:"
        grep 'Failed password' "$log" 2>/dev/null \
            | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' \
            | awk '{print $2}' \
            | sort | uniq -c | sort -nr | head -20
        echo ""
    done
} >> "$REPORT"

# -----------------------------------------------------------------------
section "9. FIREWALL STATE"
{
    echo "--- iptables rules ---"
    iptables -L -n --line-numbers 2>/dev/null || echo "(iptables not available)"
    echo ""
    echo "--- ufw status ---"
    ufw status verbose 2>/dev/null || echo "(ufw not available)"
} >> "$REPORT"

# -----------------------------------------------------------------------
section "10. WEBSERVER / DATABASE STATE"
{
    echo "--- Web server processes ---"
    ps aux | grep -E '(apache|nginx|httpd|lighttpd)' | grep -v grep

    echo ""
    echo "--- Database processes ---"
    ps aux | grep -E '(mysql|mariadbd|postgres|mongod)' | grep -v grep

    echo ""
    echo "--- /var/www contents (top level) ---"
    ls -la /var/www/ 2>/dev/null

    echo ""
    echo "--- Recently modified web files (last 60 min) ---"
    find /var/www /srv/www /usr/share/nginx /usr/share/apache2 -type f \
        -newer /tmp -mmin -60 2>/dev/null | head -30
} >> "$REPORT"

# -----------------------------------------------------------------------
echo "" >> "$REPORT"
echo "########################################################################" >> "$REPORT"
echo "## END OF REPORT" >> "$REPORT"
echo "########################################################################" >> "$REPORT"

echo ""
echo "======================================================"
echo "IR Report saved to: $REPORT"
echo "Lines: $(wc -l < "$REPORT")"
echo ""
echo "To view:  less $REPORT"
echo "To copy:  cat $REPORT"
echo "======================================================"
