#!/bin/sh
# The state of the webmail database, to compare before and after RoundcubeDbUser: who is in
# db_dsnw, the MySQL accounts with their privileges, who reads what, the login page and a real login
# with a test mailbox. No password comes out: for each one it only says whose it is.
# Usage: roundcube-db-state.sh   (as root, after RehearsalCurrentSetup)
# The folder of the secrets with the name of DaemoxCP Mail (2026-11-17) or with the one from before.
S=/usr/local/etc/daemoxcp-mail; [ -d "$S" ] || S=/usr/local/etc/mail-panel
F=$S/panel-secrets.properties
R=$S/root-secrets.properties
C=/usr/local/www/roundcube/config/config.inc.php
# The root password is in root's file since step 1 of the separation; before, it was in the panel's file.
secret() { for x in "$R" "$F"; do [ -f "$x" ] && v=$(grep "^$1=" "$x" | cut -d= -f2- | sed 's/\\//g') && [ -n "$v" ] && { echo "$v"; return; }; done; }
W=$(mktemp -d /var/tmp/roundcube-db-state.XXXXXX); trap 'rm -rf "$W"' EXIT
printf "[client]\nuser=root\npassword=\"%s\"\n" "$(secret mysql_root_password)" > "$W/root.cnf"
sql() { mysql --defaults-extra-file="$W/root.cnf" -N -B -e "$1" 2>&1; }
# Logs in with a user and its password, on the given database: "yes" or "no".
reads() {
    printf "[client]\nuser=%s\npassword=\"%s\"\nhost=127.0.0.1\n" "$1" "$2" > "$W/u.cnf"
    mysql --defaults-extra-file="$W/u.cnf" -N -B "$3" -e "SELECT 1" >/dev/null 2>&1 && echo yes || echo no
}
PANEL=$(secret mysql_password); RC=$(secret roundcube_db_password)

echo "== config.inc.php"
stat -f "%Sp %Su:%Sg" "$C"; sha256 -q "$C"
line=$(grep -n "db_dsnw" "$C" | grep -v "^[0-9]*: *//")
user=$(echo "$line" | sed -n "s#.*mysql://\([^:]*\):.*#\1#p")
pass=$(echo "$line" | sed -n "s#.*mysql://[^:]*:\([^@]*\)@.*#\1#p")
who="another one"; [ "$pass" = "$PANEL" ] && who="the panel's"; [ -n "$RC" ] && [ "$pass" = "$RC" ] && who="the webmail's (roundcube_db_password)"
echo "db_dsnw: user $user, password: $who"
echo "== MySQL accounts"
sql "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user IN ('mailpanel','roundcube') ORDER BY 1"
for a in $(sql "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user IN ('mailpanel','roundcube') ORDER BY 1"); do
    u=${a%@*}; h=${a#*@}
    sql "SHOW GRANTS FOR '$u'@'$h'"
done
printf "roundcube account fingerprint: "
sql "SET SESSION print_identified_with_as_hex = ON; SHOW CREATE USER 'roundcube'@'127.0.0.1'" | sha256 -q
echo "== who reads what"
echo "mailpanel on roundcubemail: $(reads mailpanel "$PANEL" roundcubemail)"
echo "mailpanel on mailserver:    $(reads mailpanel "$PANEL" mailserver)"
[ -n "$RC" ] && echo "roundcube on roundcubemail: $(reads roundcube "$RC" roundcubemail)"
[ -n "$RC" ] && echo "roundcube on mailserver:    $(reads roundcube "$RC" mailserver)"
echo "== the webmail"
n=$(awk '/server_name/ && !/_;/ {gsub(";","",$2); print $2; exit}' /usr/local/etc/nginx/nginx.conf)
p=$(awk '/listen/ && !/default_server/ {print $2; exit}' /usr/local/etc/nginx/nginx.conf)
curl -sk -m 15 --resolve "$n:$p:127.0.0.1" -c "$W/jar" -b "$W/jar" -o "$W/login.html" "https://$n:$p/"
echo "login page: $(grep -c rcmloginuser "$W/login.html")"
read box mpass < /root/rehearsal/mailboxes
printf "%s" "$mpass" > "$W/pass"
t=$(grep -o 'name="_token" value="[^"]*"' "$W/login.html" | head -1 | sed 's/.*value="//; s/"$//')
curl -sk -m 20 --resolve "$n:$p:127.0.0.1" -c "$W/jar" -b "$W/jar" -L -o "$W/after.html" \
    --data-urlencode "_task=login" --data-urlencode "_action=login" --data-urlencode "_timezone=UTC" \
    --data-urlencode "_token=$t" --data-urlencode "_user=$box" --data-urlencode "_pass@$W/pass" "https://$n:$p/?_task=login"
echo "real login with a test mailbox: $(grep -c '_task=logout' "$W/after.html") (1 = logged in)"
printf "Dovecot master user (SSO): "; awk -F: '{print (length($2) > 0 ? "hash present" : "HASH EMPTY")}' /usr/local/etc/dovecot/master-users
