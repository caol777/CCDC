#!/bin/sh

LOGFILE="/tmp/login_report_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee -a "$LOGFILE") 2>&1
echo "Login Report — $(hostname) — $(date)"
echo "Output saved to: $LOGFILE"
echo "=========="

# Function to count successful and failed login attempts
count_logins() {
  local log_file=$1
  local success_count=0
  local fail_count=0

  if [ -f "$log_file" ]; then
    echo "=========="
    echo "$log_file"
    success_count=$(grep 'Accepted password' "$log_file" | wc -l)
    fail_count=$(grep 'Failed password' "$log_file" | wc -l)
    echo "Successful logins: $success_count"
    echo "Failed logins: $fail_count"
    echo "=========="
  fi
}

# Check and count logins in /var/log/secure
count_logins /var/log/secure

# Check and count logins in /var/log/auth.log
count_logins /var/log/auth.log

# Check and count logins in /var/log/messages
count_logins /var/log/messages

echo "=========="
echo "Sudo/Wheel group members:"
cat /etc/group | grep -E '(sudo|wheel)'

echo "=========="
echo "Top attacking source IPs (failed logins):"
for log in /var/log/secure /var/log/auth.log /var/log/messages; do
  [ -f "$log" ] || continue
  grep 'Failed password' "$log" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' | sort | uniq -c | sort -nr | head -10
done

echo "=========="
echo "Recent successful logins (last 20):"
last -20 2>/dev/null | head -20
