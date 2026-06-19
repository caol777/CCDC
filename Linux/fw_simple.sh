#!/bin/sh
# fw_simple.sh — Simple port-based firewall, no IP restrictions
# Use this if you don't know the network layout yet or got IPs wrong in fw.sh
# Allows inbound only on ports you explicitly open. All outbound allowed.

ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)

# Stop conflicting firewall managers
[ -f /etc/ufw/ufw.conf ]         && ufw disable 2>/dev/null
[ -f /etc/firewalld/firewalld.conf ] && systemctl stop firewalld 2>/dev/null

# ---- If something goes wrong, run this to unlock: ----
# iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT; iptables -F; iptables -X
# ------------------------------------------------------

# Flush all existing rules and set defaults
$ipt -P INPUT   ACCEPT
$ipt -P OUTPUT  ACCEPT
$ipt -P FORWARD ACCEPT
$ipt -F
$ipt -X

# Allow already-established connections (keeps current SSH session alive)
$ipt -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Always allow loopback
$ipt -A INPUT  -i lo -j ACCEPT
$ipt -A OUTPUT -o lo -j ACCEPT

# ---- OPEN THESE PORTS (uncomment what is scored on this box) ----
$ipt -A INPUT -p tcp --dport 22   -j ACCEPT   # SSH
# $ipt -A INPUT -p tcp --dport 80   -j ACCEPT   # HTTP
# $ipt -A INPUT -p tcp --dport 443  -j ACCEPT   # HTTPS
# $ipt -A INPUT -p tcp --dport 3306 -j ACCEPT   # MySQL
# $ipt -A INPUT -p tcp --dport 5432 -j ACCEPT   # PostgreSQL
# $ipt -A INPUT -p tcp --dport 21   -j ACCEPT   # FTP
# $ipt -A INPUT -p tcp --dport 25   -j ACCEPT   # SMTP
# $ipt -A INPUT -p tcp --dport 53   -j ACCEPT   # DNS TCP
# $ipt -A INPUT -p udp --dport 53   -j ACCEPT   # DNS UDP
# $ipt -A INPUT -p tcp --dport 445  -j ACCEPT   # SMB
# $ipt -A INPUT -p tcp --dport 8080 -j ACCEPT   # Alt HTTP
# -----------------------------------------------------------------

# Block known C2 / attack ports explicitly
$ipt -A INPUT -p tcp --dport 4444  -j DROP
$ipt -A INPUT -p tcp --dport 5555  -j DROP
$ipt -A INPUT -p tcp --dport 6666  -j DROP
$ipt -A INPUT -p tcp --dport 1337  -j DROP
$ipt -A INPUT -p tcp --dport 31337 -j DROP

# Drop everything else inbound
$ipt -P INPUT DROP

echo "[DONE] Firewall rules applied:"
$ipt -L INPUT -n --line-numbers
