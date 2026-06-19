#!/bin/bash
# ufw_simple.sh — Simple port-based UFW firewall, no IP restrictions
# Use this if you don't know the network layout yet or got IPs wrong in ufw.sh
# Allows inbound only on ports you explicitly open. All outbound allowed.

# Reset to clean state
ufw --force reset

# Default: block all inbound, allow all outbound
ufw default deny incoming
ufw default allow outgoing

# ---- OPEN THESE PORTS (uncomment what is scored on this box) ----
ufw allow 22/tcp      # SSH
# ufw allow 80/tcp    # HTTP
# ufw allow 443/tcp   # HTTPS
# ufw allow 3306/tcp  # MySQL
# ufw allow 5432/tcp  # PostgreSQL
# ufw allow 21/tcp    # FTP
# ufw allow 25/tcp    # SMTP
# ufw allow 53        # DNS
# ufw allow 445/tcp   # SMB
# ufw allow 8080/tcp  # Alt HTTP
# -----------------------------------------------------------------

# Block known C2 / attack ports
ufw deny 4444
ufw deny 5555
ufw deny 6666
ufw deny 1337
ufw deny 31337

ufw --force enable

echo "[DONE] UFW rules applied:"
ufw status verbose
