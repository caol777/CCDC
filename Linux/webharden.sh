#!/bin/bash
# webharden.sh — Apache / nginx web server hardening
# Auto-detects which web server is running and hardens both if present
# Run as root. Safe to run multiple times (idempotent).

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
bad()  { echo -e "${RED}[BAD]  $1${NC}"; }
warn() { echo -e "${YEL}[WARN] $1${NC}"; }
good() { echo -e "${GRN}[OK]   $1${NC}"; }
sep()  { echo "========================================"; }

sys=$(command -v systemctl || command -v service)

restart_service() {
    local svc="$1"
    $sys restart "$svc" 2>/dev/null || $sys "$svc" restart 2>/dev/null
}

# -----------------------------------------------------------------------
# APACHE HARDENING
# -----------------------------------------------------------------------
harden_apache() {
    sep; echo "APACHE HARDENING"

    # Locate config directory
    if [ -d /etc/apache2 ]; then
        ADIR=/etc/apache2
        ACONF=$ADIR/apache2.conf
        ASEC=$ADIR/conf-available/security.conf
        [ -d $ADIR/conf-enabled ] && ASEC_ENABLE=true
        APKG=apache2
    elif [ -d /etc/httpd ]; then
        ADIR=/etc/httpd
        ACONF=$ADIR/conf/httpd.conf
        ASEC=$ADIR/conf.d/security.conf
        APKG=httpd
    else
        warn "Apache config directory not found"; return
    fi

    touch "$ASEC"

    # Hide server version and OS from headers
    grep -q "ServerTokens" "$ASEC" || echo "ServerTokens Prod" >> "$ASEC"
    sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$ASEC"
    good "ServerTokens Prod"

    grep -q "ServerSignature" "$ASEC" || echo "ServerSignature Off" >> "$ASEC"
    sed -i 's/^ServerSignature.*/ServerSignature Off/' "$ASEC"
    good "ServerSignature Off"

    # Disable TRACE method (used in XST attacks)
    grep -q "TraceEnable" "$ASEC" || echo "TraceEnable Off" >> "$ASEC"
    sed -i 's/^TraceEnable.*/TraceEnable Off/' "$ASEC"
    good "TraceEnable Off"

    # Disable ETags (leaks inode info)
    grep -q "FileETag" "$ASEC" || echo "FileETag None" >> "$ASEC"
    sed -i 's/^FileETag.*/FileETag None/' "$ASEC"
    good "FileETag None"

    # Add security headers
    if ! grep -q "X-Frame-Options" "$ASEC"; then
        cat >> "$ASEC" <<'EOF'

<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header unset X-Powered-By
    Header unset Server
</IfModule>
EOF
        good "Security headers added"
    fi

    # Enable headers module if on Debian/Ubuntu
    if [ -d /etc/apache2/mods-available ]; then
        a2enmod headers 2>/dev/null && good "mod_headers enabled"
        a2enconf security 2>/dev/null
    fi

    # Disable directory listing globally
    if grep -q "Options Indexes" "$ACONF" 2>/dev/null; then
        sed -i 's/Options Indexes/Options -Indexes/g' "$ACONF"
        bad "Disabled directory listing in $ACONF (was enabled)"
    fi
    # Also check sites-enabled
    if [ -d $ADIR/sites-enabled ]; then
        grep -rl "Options Indexes" $ADIR/sites-enabled/ 2>/dev/null | while read -r f; do
            sed -i 's/Options Indexes/Options -Indexes/g' "$f"
            bad "Disabled directory listing in $f (was enabled)"
        done
    fi
    if [ -d $ADIR/conf.d ]; then
        grep -rl "Options Indexes" $ADIR/conf.d/ 2>/dev/null | while read -r f; do
            sed -i 's/Options Indexes/Options -Indexes/g' "$f"
            bad "Disabled directory listing in $f (was enabled)"
        done
    fi
    good "Directory listing check done"

    # Restrict access to .htaccess and sensitive files
    if ! grep -q "\.htaccess" "$ASEC" 2>/dev/null; then
        cat >> "$ASEC" <<'EOF'

<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>
<FilesMatch "\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|old)$">
    Require all denied
</FilesMatch>
EOF
        good "Blocked .htaccess and sensitive file extensions"
    fi

    # Disable dangerous HTTP methods in default config
    if ! grep -q "LimitExcept" "$ASEC" 2>/dev/null; then
        cat >> "$ASEC" <<'EOF'

<Location "/">
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Location>
EOF
        good "Restricted HTTP methods to GET/POST/HEAD"
    fi

    # Check if mod_ssl is available and ensure TLS config exists
    if [ -d $ADIR/mods-available ] && [ -f $ADIR/mods-available/ssl.load ]; then
        a2enmod ssl 2>/dev/null
        good "mod_ssl enabled"
    fi

    restart_service "$APKG" && good "Apache restarted"
}

# -----------------------------------------------------------------------
# NGINX HARDENING
# -----------------------------------------------------------------------
harden_nginx() {
    sep; echo "NGINX HARDENING"

    NCONF=/etc/nginx/nginx.conf
    NSNIP=/etc/nginx/conf.d/security.conf

    if [ ! -f "$NCONF" ]; then
        warn "nginx.conf not found"; return
    fi

    # Hide nginx version
    if ! grep -q "server_tokens off" "$NCONF"; then
        sed -i '/http {/a\\tserver_tokens off;' "$NCONF"
        good "server_tokens off added to nginx.conf"
    else
        good "server_tokens already off"
    fi

    # Security headers snippet
    cat > "$NSNIP" <<'EOF'
# Security headers — included by nginx.conf http block
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
more_clear_headers Server;
EOF
    good "Security headers written to $NSNIP"

    # Make sure the snippet is included in every server block
    # Check all site configs for missing security directives
    NGINX_SITES=""
    [ -d /etc/nginx/sites-enabled ]  && NGINX_SITES="$NGINX_SITES /etc/nginx/sites-enabled/*"
    [ -d /etc/nginx/conf.d ]         && NGINX_SITES="$NGINX_SITES /etc/nginx/conf.d/*.conf"

    for f in $NGINX_SITES; do
        [ -f "$f" ] || continue
        [ "$f" = "$NSNIP" ] && continue

        # Disable autoindex
        if grep -q "autoindex on" "$f"; then
            sed -i 's/autoindex on/autoindex off/g' "$f"
            bad "Disabled autoindex in $f (was on)"
        fi

        # Block access to hidden files (.git, .env, .htaccess)
        if ! grep -q "location ~ /\\\." "$f"; then
            sed -i '/^}$/i\\tlocation ~ /\\. { deny all; }' "$f"
            good "Blocked hidden file access in $f"
        fi

        # Block backup/sensitive extensions
        if ! grep -q "\.bak" "$f"; then
            cat >> "$f" <<'EOF'

location ~* \.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|old)$ {
    deny all;
}
EOF
            good "Blocked sensitive file extensions in $f"
        fi
    done

    # Test config before restarting
    if nginx -t 2>/dev/null; then
        restart_service nginx && good "nginx restarted"
    else
        bad "nginx config test FAILED — check config manually before restarting"
        nginx -t
    fi
}

# -----------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------
HARDENED=0

if systemctl is-active --quiet apache2 2>/dev/null || \
   systemctl is-active --quiet httpd 2>/dev/null || \
   service apache2 status >/dev/null 2>&1 || \
   service httpd status >/dev/null 2>&1; then
    harden_apache
    HARDENED=$((HARDENED+1))
fi

if systemctl is-active --quiet nginx 2>/dev/null || \
   service nginx status >/dev/null 2>&1; then
    harden_nginx
    HARDENED=$((HARDENED+1))
fi

sep
if [ "$HARDENED" -eq 0 ]; then
    warn "No running Apache or nginx instance found. Nothing was hardened."
else
    good "Hardening applied to $HARDENED web server(s)"
fi
