#!/bin/sh
# netdiff.sh — compare current network connections to firstrun.sh baseline
# New listening ports or established connections = possible C2/attacker activity
# Requires firstrun.sh to have been run first (creates $BCK/listen and $BCK/estab)

if [ -z "$BCK" ]; then
    BCK="/tmp/initial"
fi

if [ ! -f "$BCK/listen" ]; then
    echo "[ERROR] No baseline found at $BCK/listen — run firstrun.sh first"
    exit 1
fi

if command -v sockstat >/dev/null ; then
    LIST_CMD="sockstat -l"
    ESTB_CMD="sockstat -46c"
elif command -v netstat >/dev/null ; then
    LIST_CMD="netstat -tulpn"
    ESTB_CMD="netstat -tupwn"
elif command -v ss >/dev/null ; then
    LIST_CMD="ss -blunt -p"
    ESTB_CMD="ss -buntp"
else
    echo "[ERROR] No netstat/sockstat/ss found"
    exit 1
fi

$LIST_CMD > /tmp/listen_now
$ESTB_CMD > /tmp/estab_now

echo "=== LISTENING PORT CHANGES (baseline vs now) ==="
diff "$BCK/listen" /tmp/listen_now
echo ""
echo "=== ESTABLISHED CONNECTION CHANGES (baseline vs now) ==="
diff "$BCK/estab" /tmp/estab_now

rm -f /tmp/listen_now /tmp/estab_now
