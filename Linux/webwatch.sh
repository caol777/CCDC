#!/bin/bash
# webwatch.sh
# CCDC Web Server Watchdog
# Keeps nginx/apache/PHP-FPM/MySQL/WordPress alive during competition.
# Also watches for webshells and config tampering.
#
# Usage:
#   Run once to start in background:  nohup bash webwatch.sh &
#   Or as a cron every 2 min:         */2 * * * * /path/to/webwatch.sh
#
# Optional env vars:
#   WEBROOT    - override web root (default: auto-detect)
#   INTERVAL   - seconds between checks (default: 30)
#   LOGFILE    - log path (default: /var/log/ccdc_webwatch.log)
#   NOLOOP     - set to 1 to run once and exit (good for cron)
#   WP_BACKUP  - path to a tar.gz of clean WordPress install to restore from

INTERVAL=${INTERVAL:-30}
LOGFILE=${LOGFILE:-/var/log/ccdc_webwatch.log}
NOLOOP=${NOLOOP:-0}

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"; }

# -----------------------------------------------------------------------
# Detect service manager
# -----------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
    SYSMGR="systemctl"
elif command -v service >/dev/null 2>&1; then
    SYSMGR="service"
elif command -v rc-service >/dev/null 2>&1; then
    SYSMGR="rc-service"
else
    SYSMGR=""
fi

restart_svc() {
    local svc=$1
    if [ "$SYSMGR" = "systemctl" ]; then
        systemctl restart "$svc" 2>/dev/null && return 0
    elif [ "$SYSMGR" = "service" ]; then
        service "$svc" restart 2>/dev/null && return 0
    elif [ "$SYSMGR" = "rc-service" ]; then
        rc-service "$svc" restart 2>/dev/null && return 0
    fi
    return 1
}

is_running() {
    local svc=$1
    if [ "$SYSMGR" = "systemctl" ]; then
        systemctl is-active --quiet "$svc" 2>/dev/null
    else
        pgrep -x "$svc" >/dev/null 2>&1
    fi
}

# -----------------------------------------------------------------------
# Detect web root
# -----------------------------------------------------------------------
detect_webroot() {
    for d in /var/www/html /var/www /srv/www/htdocs /srv/http /usr/share/nginx/html; do
        [ -d "$d" ] && echo "$d" && return
    done
    # Try nginx config
    nginx_root=$(grep -r "root " /etc/nginx/ 2>/dev/null | grep -v "#" | awk '{print $2}' | tr -d ';' | head -1)
    [ -n "$nginx_root" ] && [ -d "$nginx_root" ] && echo "$nginx_root" && return
    # Try apache config
    apache_root=$(grep -r "DocumentRoot" /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -v "#" | awk '{print $2}' | head -1)
    [ -n "$apache_root" ] && [ -d "$apache_root" ] && echo "$apache_root" && return
    echo "/var/www/html"
}

WEBROOT=${WEBROOT:-$(detect_webroot)}

# -----------------------------------------------------------------------
# Detect PHP-FPM service name
# -----------------------------------------------------------------------
detect_phpfpm() {
    for svc in php-fpm php8.3-fpm php8.2-fpm php8.1-fpm php8.0-fpm php7.4-fpm php7.3-fpm php7.2-fpm; do
        if [ "$SYSMGR" = "systemctl" ] && systemctl list-units --type=service --no-legend 2>/dev/null | grep -q "$svc"; then
            echo "$svc" && return
        fi
        command -v "$svc" >/dev/null 2>&1 && echo "$svc" && return
    done
    echo "php-fpm"
}

PHPFPM=$(detect_phpfpm)

# -----------------------------------------------------------------------
# Service check and restart
# -----------------------------------------------------------------------
check_services() {
    local restarted=0

    # nginx
    if [ -d /etc/nginx ] || command -v nginx >/dev/null 2>&1; then
        if ! is_running nginx; then
            log "ALERT: nginx is DOWN — restarting"
            restart_svc nginx && log "nginx restarted OK" || log "ERROR: nginx failed to restart"
            restarted=$((restarted+1))
        fi
    fi

    # apache2 / httpd
    for apachesvc in apache2 httpd; do
        if [ -d "/etc/$apachesvc" ] || [ -d /etc/apache2 ] || [ -d /etc/httpd ]; then
            if ! is_running "$apachesvc"; then
                log "ALERT: $apachesvc is DOWN — restarting"
                restart_svc "$apachesvc" && log "$apachesvc restarted OK" || log "ERROR: $apachesvc failed to restart"
                restarted=$((restarted+1))
            fi
            break
        fi
    done

    # PHP-FPM
    if ! is_running "$PHPFPM"; then
        if systemctl list-units --type=service --no-legend 2>/dev/null | grep -q "php"; then
            log "ALERT: PHP-FPM ($PHPFPM) is DOWN — restarting"
            restart_svc "$PHPFPM" && log "PHP-FPM restarted OK" || {
                # Try wildcard match
                svcname=$(systemctl list-units --type=service --no-legend 2>/dev/null | grep "php" | awk '{print $1}' | head -1)
                [ -n "$svcname" ] && restart_svc "$svcname" && log "PHP-FPM ($svcname) restarted OK"
            }
            restarted=$((restarted+1))
        fi
    fi

    # MySQL / MariaDB
    for sqlsvc in mysql mariadb mysqld; do
        if systemctl list-units --type=service --no-legend 2>/dev/null | grep -q "$sqlsvc"; then
            if ! is_running "$sqlsvc"; then
                log "ALERT: $sqlsvc is DOWN — restarting"
                restart_svc "$sqlsvc" && log "$sqlsvc restarted OK" || log "ERROR: $sqlsvc failed to restart"
                restarted=$((restarted+1))
            fi
            break
        fi
    done

    return $restarted
}

# -----------------------------------------------------------------------
# WordPress integrity check
# -----------------------------------------------------------------------
check_wordpress() {
    [ -d "$WEBROOT" ] || return

    # Find wp-config.php
    WPCONFIG=$(find "$WEBROOT" -maxdepth 3 -name "wp-config.php" 2>/dev/null | head -1)
    [ -n "$WPCONFIG" ] || return

    WPROOT=$(dirname "$WPCONFIG")
    log "WordPress detected at $WPROOT"

    # Ensure wp-config.php is not world-readable
    perms=$(stat -c "%a" "$WPCONFIG" 2>/dev/null)
    if [ "$perms" != "400" ] && [ "$perms" != "440" ] && [ "$perms" != "600" ]; then
        log "WARN: wp-config.php permissions are $perms — fixing to 640"
        chmod 640 "$WPCONFIG"
    fi

    # Check for PHP files recently modified in wp-content (webshell indicator)
    SUSPICIOUS=$(find "$WPROOT/wp-content" -type f -name "*.php" -mmin -10 2>/dev/null)
    if [ -n "$SUSPICIOUS" ]; then
        log "ALERT: PHP files modified in wp-content in last 10 minutes:"
        echo "$SUSPICIOUS" | while read -r f; do
            log "  $f  ($(stat -c '%y' "$f" 2>/dev/null))"
        done
    fi

    # Check for eval/base64_decode/system in PHP files (webshell patterns)
    if command -v grep >/dev/null 2>&1; then
        SHELLS=$(grep -rlE "(eval\s*\(|base64_decode\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|assert\s*\(\\\$)" \
            "$WPROOT/wp-content/uploads" "$WPROOT/wp-content/cache" 2>/dev/null)
        if [ -n "$SHELLS" ]; then
            log "ALERT: Possible webshells detected:"
            echo "$SHELLS" | while read -r f; do log "  $f"; done
        fi
    fi

    # Restore from backup if provided
    if [ -n "$WP_BACKUP" ] && [ -f "$WP_BACKUP" ]; then
        if [ ! -f "$WPROOT/wp-login.php" ] || [ ! -f "$WPROOT/wp-includes/version.php" ]; then
            log "ALERT: Core WordPress files missing — restoring from $WP_BACKUP"
            tar -xzf "$WP_BACKUP" -C "$WEBROOT" 2>/dev/null && log "WordPress restored OK" || log "ERROR: restore failed"
        fi
    fi
}

# -----------------------------------------------------------------------
# Web root permission hardening
# -----------------------------------------------------------------------
harden_webroot() {
    [ -d "$WEBROOT" ] || return

    # Prevent PHP execution in uploads dirs
    for uploadsdir in $(find "$WEBROOT" -type d -name "uploads" 2>/dev/null); do
        htaccess="$uploadsdir/.htaccess"
        if [ ! -f "$htaccess" ] || ! grep -q "php_flag" "$htaccess" 2>/dev/null; then
            cat > "$htaccess" <<'EOF'
# CCDC: Block PHP execution in uploads
<FilesMatch "\.ph(p[3-9]?|t|tml)$">
    deny from all
</FilesMatch>
php_flag engine off
EOF
            log "Hardened uploads directory: $uploadsdir"
        fi
    done

    # Remove suspicious files in web root
    find "$WEBROOT" -type f -name "*.php" -newer /proc/1/exe -mmin -5 2>/dev/null | while read -r f; do
        if grep -qE "(eval|base64_decode|shell_exec|system|passthru)" "$f" 2>/dev/null; then
            log "ALERT: Webshell detected and quarantined: $f"
            mv "$f" "/tmp/quarantine_$(basename "$f")_$(date +%s)"
        fi
    done
}

# -----------------------------------------------------------------------
# Main loop
# -----------------------------------------------------------------------
log "=== CCDC webwatch started. WEBROOT=$WEBROOT INTERVAL=${INTERVAL}s ==="

while true; do
    check_services
    check_wordpress
    harden_webroot

    [ "$NOLOOP" = "1" ] && break
    sleep "$INTERVAL"
done
