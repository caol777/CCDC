#!/bin/bash
# ufw.sh — UFW firewall lockdown for Ubuntu/Debian

# ============================================================
# EDIT THESE BEFORE RUNNING
# ============================================================
DISPATCHER="10.0.0.50"        # Your blue team machine IP (gets full access)
LOCALNETWORK="10.0.0.0/24"    # Your internal subnet (gets full access)
CCSHOST="10.0.0.1"            # Scoring engine IP (leave blank "" if not at NATS)
# ============================================================

echo "[*] Resetting UFW..."
ufw --force reset

echo "[*] Setting default policies (deny in, deny out, deny forward)..."
ufw default deny incoming
ufw default deny outgoing
ufw default deny forward

echo "[*] Allowing loopback..."
ufw allow in on lo
ufw allow out on lo

echo "[*] Allowing established/related connections..."
ufw allow out to any

echo "[*] Allowing DISPATCHER: $DISPATCHER"
ufw allow in from "$DISPATCHER"
ufw allow out to "$DISPATCHER"

echo "[*] Allowing local network: $LOCALNETWORK"
ufw allow in from "$LOCALNETWORK"
ufw allow out to "$LOCALNETWORK"

if [ -n "$CCSHOST" ] && [ "$CCSHOST" != '""' ]; then
    echo "[*] Allowing scoring engine: $CCSHOST"
    ufw allow in from "$CCSHOST"
    ufw allow out to "$CCSHOST"
fi

# ---- Uncomment the services that are scored on THIS box ----
# Web server
# ufw allow in proto tcp to any port 80
# ufw allow in proto tcp to any port 443

# MySQL / MariaDB
# ufw allow in proto tcp to any port 3306

# PostgreSQL
# ufw allow in proto tcp to any port 5432

# SMB (only if scored)
# ufw allow in proto tcp to any port 445

# FTP
# ufw allow in proto tcp to any port 21

# DNS (if this box is a resolver)
# ufw allow in proto udp to any port 53

echo "[*] Blocking common C2/attack ports..."
ufw deny 4444
ufw deny 5555
ufw deny 6666
ufw deny 1337
ufw deny 31337

echo "[*] Enabling UFW..."
ufw --force enable

echo ""
echo "[DONE] UFW configuration complete:"
ufw status verbose
