#!/bin/sh
# userdiff.sh — compare current users/groups to firstrun.sh baseline
# New entries = attacker created a backdoor account or added a user to a group
# Requires firstrun.sh to have been run first (creates $BCK/users and $BCK/groups)

if [ -z "$BCK" ]; then
    BCK="/tmp/initial"
fi

if [ ! -f "$BCK/users" ]; then
    echo "[ERROR] No baseline found at $BCK/users — run firstrun.sh first"
    exit 1
fi

echo "=== USER CHANGES (baseline vs now) ==="
diff "$BCK/users" /etc/passwd
echo ""
echo "=== GROUP CHANGES (baseline vs now) ==="
diff "$BCK/groups" /etc/group
