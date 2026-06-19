#!/bin/bash
# flush_domain_cache.sh
# Run this RIGHT AFTER the AD/Windows person changes domain passwords.
# Flushes SSSD/Winbind/realm cache so Linux machines immediately
# accept the new domain passwords instead of the old cached ones.

echo "[*] Flushing domain credential cache on $(hostname)..."

FLUSHED=0

# SSSD (most common on RHEL/Ubuntu/Debian domain-joined)
if systemctl is-active --quiet sssd 2>/dev/null; then
    echo "[*] Stopping SSSD..."
    systemctl stop sssd

    echo "[*] Clearing SSSD cache databases..."
    rm -f /var/lib/sss/db/*.ldb 2>/dev/null
    rm -f /var/lib/sss/db/cache_*.ldb 2>/dev/null

    echo "[*] Running sss_cache flush..."
    sss_cache -E 2>/dev/null

    echo "[*] Restarting SSSD..."
    systemctl start sssd
    sleep 2

    # Verify it came back up
    if systemctl is-active --quiet sssd; then
        echo "[OK] SSSD restarted successfully"
    else
        echo "[ERROR] SSSD failed to restart — check: systemctl status sssd"
    fi
    FLUSHED=$((FLUSHED+1))
fi

# Winbind (Samba/Winbind domain join)
if systemctl is-active --quiet winbind 2>/dev/null; then
    echo "[*] Flushing Winbind cache..."
    net cache flush 2>/dev/null
    wbinfo --flush-cache 2>/dev/null
    systemctl restart winbind
    echo "[OK] Winbind cache flushed"
    FLUSHED=$((FLUSHED+1))
fi

# realm (realmd — used by RHEL/CentOS for AD join)
if command -v realm >/dev/null 2>&1 && realm list 2>/dev/null | grep -q "configured:"; then
    echo "[*] realm domain join detected"
    # realm itself doesn't have a direct flush — SSSD handles it above
    FLUSHED=$((FLUSHED+1))
fi

# Kerberos ticket cache (optional — clears any stale TGTs)
if command -v kdestroy >/dev/null 2>&1; then
    echo "[*] Destroying Kerberos ticket cache..."
    kdestroy -A 2>/dev/null
    echo "[OK] Kerberos tickets cleared"
fi

if [ "$FLUSHED" -eq 0 ]; then
    echo "[WARN] No domain auth service detected (SSSD/Winbind). Is this machine domain-joined?"
    echo "       Check: realm list  OR  wbinfo -t"
else
    echo ""
    echo "[DONE] Domain cache flushed on $(hostname). Users can now log in with new AD passwords."
fi
