#!/bin/bash
# mysqharden.sh — MySQL / MariaDB hardening
# Equivalent of mysql_secure_installation but non-interactive + extra checks
# Run as root. Detects MySQL or MariaDB automatically.

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
bad()  { echo -e "${RED}[BAD]  $1${NC}"; }
warn() { echo -e "${YEL}[WARN] $1${NC}"; }
good() { echo -e "${GRN}[OK]   $1${NC}"; }

# ============================================================
# EDIT BEFORE RUNNING
# ============================================================
NEW_ROOT_PASS="Str0ng_R00t_P@ss!"   # new root password to set
BIND_LOCALHOST_ONLY=true             # true = only listen on 127.0.0.1 (set false if app servers are remote)
# ============================================================

# Detect mysql vs mariadb binary
if command -v mysql >/dev/null 2>&1; then
    MYSQL=mysql
elif command -v mariadb >/dev/null 2>&1; then
    MYSQL=mariadb
else
    warn "mysql/mariadb client not found — is the server installed?"
    exit 1
fi

# Try to get a working SQL connection (no password, then common weak ones)
SQLCMD=""
for attempt in \
    "$MYSQL -uroot" \
    "$MYSQL -uroot -proot" \
    "$MYSQL -uroot -ppassword" \
    "$MYSQL -uroot -ptoor" \
    "$MYSQL -uroot -pmysql"; do
    if $attempt -e "SELECT 1;" >/dev/null 2>&1; then
        SQLCMD="$attempt"
        warn "Connected with: $attempt — this is a weak/no credential!"
        break
    fi
done

# Also try reading root password from debian maintenance account
if [ -z "$SQLCMD" ] && [ -f /etc/mysql/debian.cnf ]; then
    MAINT_PASS=$(grep -m1 "^password" /etc/mysql/debian.cnf | awk '{print $3}')
    if [ -n "$MAINT_PASS" ] && $MYSQL -uroot -p"$MAINT_PASS" -e "SELECT 1;" >/dev/null 2>&1; then
        SQLCMD="$MYSQL -uroot -p$MAINT_PASS"
        good "Connected using debian maintenance credentials"
    fi
fi

if [ -z "$SQLCMD" ]; then
    warn "Could not auto-connect — either already hardened or needs manual password."
    echo "  Try: mysql -uroot -p  and supply current root password, then re-run."
    echo "  Or set MYSQL_PWD=<currentpass> and re-run."
    if [ -n "$MYSQL_PWD" ]; then
        if $MYSQL -uroot -e "SELECT 1;" >/dev/null 2>&1; then
            SQLCMD="$MYSQL -uroot"
            good "Connected using MYSQL_PWD env var"
        fi
    fi
    [ -z "$SQLCMD" ] && exit 1
fi

SQL() { $SQLCMD -e "$1" 2>/dev/null; }

echo ""
echo "========================================"
echo "MySQL/MariaDB Hardening"
echo "========================================"

# 1. Set a strong root password
echo "[1] Setting root password..."
SQL "ALTER USER 'root'@'localhost' IDENTIFIED BY '$NEW_ROOT_PASS';" || \
SQL "UPDATE mysql.user SET authentication_string=PASSWORD('$NEW_ROOT_PASS'), plugin='mysql_native_password' WHERE User='root'; FLUSH PRIVILEGES;"
good "Root password updated"

# Update SQLCMD to use new password for remaining commands
SQLCMD="$MYSQL -uroot -p$NEW_ROOT_PASS"
SQL() { $SQLCMD -e "$1" 2>/dev/null; }

# 2. Remove anonymous users
echo "[2] Removing anonymous users..."
ANON=$(SQL "SELECT COUNT(*) FROM mysql.user WHERE User='';" | tail -1)
if [ "$ANON" -gt 0 ] 2>/dev/null; then
    SQL "DELETE FROM mysql.user WHERE User='';"
    SQL "FLUSH PRIVILEGES;"
    bad "Removed $ANON anonymous user(s)"
else
    good "No anonymous users found"
fi

# 3. Remove remote root login
echo "[3] Removing remote root login..."
REMOTE_ROOT=$(SQL "SELECT COUNT(*) FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" | tail -1)
if [ "$REMOTE_ROOT" -gt 0 ] 2>/dev/null; then
    SQL "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');"
    SQL "FLUSH PRIVILEGES;"
    bad "Removed $REMOTE_ROOT remote root login(s)"
else
    good "No remote root logins found"
fi

# 4. Drop test database
echo "[4] Removing test database..."
TEST_DB=$(SQL "SHOW DATABASES LIKE 'test';" | grep -c "test" || echo 0)
if [ "$TEST_DB" -gt 0 ]; then
    SQL "DROP DATABASE IF EXISTS test;"
    SQL "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    SQL "FLUSH PRIVILEGES;"
    warn "Removed test database"
else
    good "No test database found"
fi

# 5. Check for accounts with no password
echo "[5] Checking for accounts with blank passwords..."
BLANK=$(SQL "SELECT User, Host FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL AND plugin='mysql_native_password';" | grep -v "User\|--" | grep -v "^$")
if [ -n "$BLANK" ]; then
    bad "Users with no password:"
    echo "$BLANK" | while read -r line; do bad "  $line"; done
else
    good "No accounts with blank passwords"
fi

# 6. List all users and their hosts for review
echo "[6] Current user/host list:"
SQL "SELECT User, Host, plugin FROM mysql.user;" | while read -r line; do
    warn "  $line"
done

# 7. Restrict bind address to localhost
echo "[7] Checking bind address..."
CNFFILES="/etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mariadb.conf.d/50-server.cnf /etc/my.cnf /etc/mysql/my.cnf"
if [ "$BIND_LOCALHOST_ONLY" = true ]; then
    for f in $CNFFILES; do
        [ -f "$f" ] || continue
        if grep -qE "^\s*bind-address" "$f"; then
            sed -i 's/^\s*bind-address\s*=.*/bind-address = 127.0.0.1/' "$f"
            good "Set bind-address = 127.0.0.1 in $f"
        else
            echo "bind-address = 127.0.0.1" >> "$f"
            good "Added bind-address = 127.0.0.1 to $f"
        fi
    done
else
    warn "BIND_LOCALHOST_ONLY=false — MySQL is listening on all interfaces. Ensure firewall restricts port 3306."
fi

# 8. Disable LOCAL INFILE (data exfiltration vector)
echo "[8] Disabling LOCAL INFILE..."
for f in $CNFFILES; do
    [ -f "$f" ] || continue
    if ! grep -q "local-infile" "$f"; then
        echo "local-infile = 0" >> "$f"
        good "Disabled local-infile in $f"
    fi
done
SQL "SET GLOBAL local_infile = 0;" && good "local_infile disabled at runtime"

# 9. Restart to apply config changes
echo "[9] Restarting MySQL/MariaDB..."
sys=$(command -v systemctl || command -v service)
$sys restart mysql 2>/dev/null || $sys restart mariadb 2>/dev/null || \
$sys mysql restart 2>/dev/null || $sys mariadb restart 2>/dev/null
good "Service restarted"

echo ""
echo "========================================"
echo "Hardening complete. New root password: $NEW_ROOT_PASS"
echo "Save this password to your credentials CSV!"
echo "========================================"
