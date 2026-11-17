#!/bin/sh
# I guasti veri del banco, uno per controllo di RoundcubeDbUser (reperti, punto 124):
#   roundcube-db-faults.sh plant|clear NOME
# Le copie di config.inc.php vanno in /root/rcdb, la cartella del banco.
# Ognuno si pianta prima di avviare il pannello e si toglie dopo, a mano.
# La cartella dei segreti col nome di DaemoxCP Mail (17/11/2026) o con quello di prima.
S=/usr/local/etc/daemoxcp-mail; [ -d "$S" ] || S=/usr/local/etc/mail-panel
F=$S/panel-secrets.properties
R=$S/root-secrets.properties
C=/usr/local/www/roundcube/config/config.inc.php
# La password di root sta nel file di root dal passo 1 della separazione; prima stava nel file del pannello.
secret() { for x in "$R" "$F"; do [ -f "$x" ] && v=$(grep "^$1=" "$x" | cut -d= -f2- | sed 's/\\//g') && [ -n "$v" ] && { echo "$v"; return; }; done; }
W=$(mktemp -d /var/tmp/rcdb-fault.XXXXXX); trap 'rm -rf "$W"' EXIT
printf "[client]\nuser=root\npassword=\"%s\"\n" "$(secret mysql_root_password)" > "$W/root.cnf"
sql() { mysql --defaults-extra-file="$W/root.cnf" -N -B -e "$1"; }
case "$1:$2" in
  plant:password-policy)   # l'account non si crea: la politica vuole simboli, il pannello genera lettere e cifre
    sql "INSTALL COMPONENT 'file://component_validate_password'; SET GLOBAL validate_password.policy = MEDIUM;" ;;
  clear:password-policy)
    sql "UNINSTALL COMPONENT 'file://component_validate_password';" ;;
  plant:init-connect)      # roundcube non entra: init_connect legge mailserver, che roundcube non vede
    sql "SET GLOBAL init_connect = 'DO (SELECT COUNT(*) FROM mailserver.domains)';" ;;
  clear:init-connect)
    sql "SET GLOBAL init_connect = '';" ;;
  plant:session-trigger)   # la pagina d'accesso si vede, ma la sessione di roundcube non arriva nel database
    sql "CREATE TRIGGER roundcubemail.planted_fault_session BEFORE INSERT ON roundcubemail.session FOR EACH ROW SET NEW.sess_id = IF(SUBSTRING_INDEX(USER(), '@', 1) = 'roundcube', NULL, NEW.sess_id);" ;;
  clear:session-trigger)
    sql "DROP TRIGGER IF EXISTS roundcubemail.planted_fault_session;" ;;
  plant:users-trigger)     # la pagina e la sessione vanno, l'accesso vero no: roundcube non aggiorna users
    sql "CREATE TRIGGER roundcubemail.planted_fault_users BEFORE UPDATE ON roundcubemail.users FOR EACH ROW SET NEW.username = IF(SUBSTRING_INDEX(USER(), '@', 1) = 'roundcube', NULL, NEW.username);" ;;
  clear:users-trigger)
    sql "DROP TRIGGER IF EXISTS roundcubemail.planted_fault_users;" ;;
  plant:session-update)    # la pagina d'accesso fa solo INSERT in session; un accesso vero salva la sessione con UPDATE
    sql "CREATE TRIGGER roundcubemail.planted_fault_session_update BEFORE UPDATE ON roundcubemail.session FOR EACH ROW SET NEW.sess_id = IF(SUBSTRING_INDEX(USER(), '@', 1) = 'roundcube', NULL, NEW.sess_id);" ;;
  clear:session-update)
    sql "DROP TRIGGER IF EXISTS roundcubemail.planted_fault_session_update;" ;;
  plant:logged-in-session) # roundcube non salva la sessione di chi e' entrato (vars con user_id): la pagina d'accesso si', l'accesso vero no
    for op in INSERT UPDATE; do
      sql "CREATE TRIGGER roundcubemail.planted_fault_login_$op BEFORE $op ON roundcubemail.session FOR EACH ROW SET NEW.sess_id = IF(SUBSTRING_INDEX(USER(), '@', 1) = 'roundcube' AND FROM_BASE64(NEW.vars) LIKE '%user_id%', NULL, NEW.sess_id);"
    done ;;
  clear:logged-in-session)
    sql "DROP TRIGGER IF EXISTS roundcubemail.planted_fault_login_INSERT; DROP TRIGGER IF EXISTS roundcubemail.planted_fault_login_UPDATE;" ;;
  plant:panel-plugin)      # un plugin che entra come il pannello, senza DSN: si vede solo dopo la revoca
    d=/usr/local/www/roundcube/plugins/planted_fault
    mkdir -p "$d"
    cat > "$d/planted_fault.php" << EOP
<?php
class planted_fault extends rcube_plugin
{
    function init()
    {
        \$pdo = new PDO('mysql:host=127.0.0.1;dbname=roundcubemail', 'mailpanel', '$(secret mysql_password)');
        \$pdo->query('SELECT 1 FROM session LIMIT 1');
    }
}
EOP
    chown -R root:roundcube "$d"; chmod 750 "$d"; chmod 640 "$d/planted_fault.php"
    cp -p "$C" /root/rcdb/config-before-plugin.php
    sed -i '' "s/\$config\['plugins'\] = array('mailpanel_sso'/\$config['plugins'] = array('planted_fault', 'mailpanel_sso'/" "$C"
    grep -c planted_fault "$C" ;;
  clear:panel-plugin)
    sed -i '' "s/array('planted_fault', 'mailpanel_sso'/array('mailpanel_sso'/" "$C"
    rm -rf /usr/local/www/roundcube/plugins/planted_fault
    grep -c planted_fault "$C" ;;
  plant:fpm-reload)        # il reload di php-fpm fallisce (php-fpm -t rifiuta un pool), la webmail resta accesa
    printf "[planted]\nthis line is not php-fpm configuration\n" > /usr/local/etc/php-fpm.d/zz-planted-fault.conf ;;
  clear:fpm-reload)
    rm -f /usr/local/etc/php-fpm.d/zz-planted-fault.conf; service php_fpm reload >/dev/null 2>&1 ;;
  plant:webmail-down)      # la webmail non risponde gia' prima
    service php_fpm stop >/dev/null ;;
  clear:webmail-down)
    service php_fpm start >/dev/null ;;
  plant:existing-account)  # un account roundcube che la webmail non usa
    sql "CREATE USER 'roundcube'@'127.0.0.1' IDENTIFIED BY 'SomebodyElse0123456789x';" ;;
  clear:existing-account)
    sql "DROP USER IF EXISTS 'roundcube'@'127.0.0.1';" ;;
  plant:dsnr)              # db_dsnr che entra come il pannello
    cp -p "$C" /root/rcdb/config-before-dsnr.php
    printf "\$config['db_dsnr'] = 'mysql://mailpanel:%s@127.0.0.1/roundcubemail';\n" "$(secret mysql_password)" >> "$C"
    grep -c db_dsnr "$C" ;;
  clear:dsnr)
    cp -p /root/rcdb/config-before-dsnr.php "$C"; grep -c db_dsnr "$C" ;;
  *) echo "uso: roundcube-db-faults.sh plant|clear webmail-down|password-policy|init-connect|fpm-reload|session-trigger|logged-in-session|panel-plugin|existing-account|dsnr"; exit 2 ;;
esac
