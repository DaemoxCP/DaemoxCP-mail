#!/bin/sh
# Lo stato del database della webmail, per confrontare prima e dopo RoundcubeDbUser: chi c'e' in
# db_dsnw, gli account MySQL coi privilegi, chi legge cosa, la pagina d'accesso e un accesso vero
# con una casella di prova. Nessuna password esce: per ognuna si dice solo di chi e'.
# Uso: roundcube-db-state.sh   (da root, dopo RehearsalCurrentSetup)
# La cartella dei segreti col nome di DaemoxCP Mail (17/11/2026) o con quello di prima.
S=/usr/local/etc/daemoxcp-mail; [ -d "$S" ] || S=/usr/local/etc/mail-panel
F=$S/panel-secrets.properties
R=$S/root-secrets.properties
C=/usr/local/www/roundcube/config/config.inc.php
# La password di root sta nel file di root dal passo 1 della separazione; prima stava nel file del pannello.
secret() { for x in "$R" "$F"; do [ -f "$x" ] && v=$(grep "^$1=" "$x" | cut -d= -f2- | sed 's/\\//g') && [ -n "$v" ] && { echo "$v"; return; }; done; }
W=$(mktemp -d /var/tmp/roundcube-db-state.XXXXXX); trap 'rm -rf "$W"' EXIT
printf "[client]\nuser=root\npassword=\"%s\"\n" "$(secret mysql_root_password)" > "$W/root.cnf"
sql() { mysql --defaults-extra-file="$W/root.cnf" -N -B -e "$1" 2>&1; }
# Entra con un utente e la sua password, sul database dato: "si" o "no".
reads() {
    printf "[client]\nuser=%s\npassword=\"%s\"\nhost=127.0.0.1\n" "$1" "$2" > "$W/u.cnf"
    mysql --defaults-extra-file="$W/u.cnf" -N -B "$3" -e "SELECT 1" >/dev/null 2>&1 && echo si || echo no
}
PANEL=$(secret mysql_password); RC=$(secret roundcube_db_password)

echo "== config.inc.php"
stat -f "%Sp %Su:%Sg" "$C"; sha256 -q "$C"
line=$(grep -n "db_dsnw" "$C" | grep -v "^[0-9]*: *//")
user=$(echo "$line" | sed -n "s#.*mysql://\([^:]*\):.*#\1#p")
pass=$(echo "$line" | sed -n "s#.*mysql://[^:]*:\([^@]*\)@.*#\1#p")
who="un'altra"; [ "$pass" = "$PANEL" ] && who="quella del pannello"; [ -n "$RC" ] && [ "$pass" = "$RC" ] && who="quella della webmail (roundcube_db_password)"
echo "db_dsnw: utente $user, password: $who"
echo "== account MySQL"
sql "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user IN ('mailpanel','roundcube') ORDER BY 1"
for a in $(sql "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user IN ('mailpanel','roundcube') ORDER BY 1"); do
    u=${a%@*}; h=${a#*@}
    sql "SHOW GRANTS FOR '$u'@'$h'"
done
printf "impronta dell'account roundcube: "
sql "SET SESSION print_identified_with_as_hex = ON; SHOW CREATE USER 'roundcube'@'127.0.0.1'" | sha256 -q
echo "== chi legge cosa"
echo "mailpanel su roundcubemail: $(reads mailpanel "$PANEL" roundcubemail)"
echo "mailpanel su mailserver:    $(reads mailpanel "$PANEL" mailserver)"
[ -n "$RC" ] && echo "roundcube su roundcubemail: $(reads roundcube "$RC" roundcubemail)"
[ -n "$RC" ] && echo "roundcube su mailserver:    $(reads roundcube "$RC" mailserver)"
echo "== la webmail"
n=$(awk '/server_name/ && !/_;/ {gsub(";","",$2); print $2; exit}' /usr/local/etc/nginx/nginx.conf)
p=$(awk '/listen/ && !/default_server/ {print $2; exit}' /usr/local/etc/nginx/nginx.conf)
curl -sk -m 15 --resolve "$n:$p:127.0.0.1" -c "$W/jar" -b "$W/jar" -o "$W/login.html" "https://$n:$p/"
echo "pagina d'accesso: $(grep -c rcmloginuser "$W/login.html")"
read box mpass < /root/rehearsal/mailboxes
printf "%s" "$mpass" > "$W/pass"
t=$(grep -o 'name="_token" value="[^"]*"' "$W/login.html" | head -1 | sed 's/.*value="//; s/"$//')
curl -sk -m 20 --resolve "$n:$p:127.0.0.1" -c "$W/jar" -b "$W/jar" -L -o "$W/after.html" \
    --data-urlencode "_task=login" --data-urlencode "_action=login" --data-urlencode "_timezone=UTC" \
    --data-urlencode "_token=$t" --data-urlencode "_user=$box" --data-urlencode "_pass@$W/pass" "https://$n:$p/?_task=login"
echo "accesso vero con una casella di prova: $(grep -c '_task=logout' "$W/after.html") (1 = entrata)"
printf "utente master di Dovecot (SSO): "; awk -F: '{print (length($2) > 0 ? "hash presente" : "HASH VUOTO")}' /usr/local/etc/dovecot/master-users
