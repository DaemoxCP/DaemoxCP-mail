#!/bin/sh
# The real faults of the test bench, one per check of RoundcubeDbUser (findings, point 124):
#   roundcube-db-faults.sh plant|clear NAME
# The copies of config.inc.php go in /root/rcdb, the folder of the test bench.
# Each one is planted before starting the panel and removed afterwards, by hand.
# The folder of the secrets with the name of DaemoxCP Mail (2026-11-17) or with the one from before.
S=/usr/local/etc/daemoxcp-mail; [ -d "$S" ] || S=/usr/local/etc/mail-panel
F=$S/panel-secrets.properties
R=$S/root-secrets.properties
C=/usr/local/www/roundcube/config/config.inc.php
# The root password is in root's file since step 1 of the separation; before, it was in the panel's file.
secret() { for x in "$R" "$F"; do [ -f "$x" ] && v=$(grep "^$1=" "$x" | cut -d= -f2- | sed 's/\\//g') && [ -n "$v" ] && { echo "$v"; return; }; done; }
W=$(mktemp -d /var/tmp/rcdb-fault.XXXXXX); trap 'rm -rf "$W"' EXIT
printf "[client]\nuser=root\npassword=\"%s\"\n" "$(secret mysql_root_password)" > "$W/root.cnf"
sql() { mysql --defaults-extra-file="$W/root.cnf" -N -B -e "$1"; }
case "$1:$2" in
  plant:password-policy)   # the account is not created: the policy wants symbols, the panel generates letters and digits
    sql "INSTALL COMPONENT 'file://component_validate_password'; SET GLOBAL validate_password.policy = MEDIUM;" ;;
  clear:password-policy)
    sql "UNINSTALL COMPONENT 'file://component_validate_password';" ;;
  plant:init-connect)      # roundcube does not get in: init_connect reads mailserver, which roundcube does not see
    sql "SET GLOBAL init_connect = 'DO (SELECT COUNT(*) FROM mailserver.domains)';" ;;
  clear:init-connect)
    sql "SET GLOBAL init_connect = '';" ;;
  plant:session-trigger)   # the login page shows, but the roundcube session does not reach the database
    sql "CREATE TRIGGER roundcubemail.planted_fault_session BEFORE INSERT ON roundcubemail.session FOR EACH ROW SET NEW.sess_id = IF(SUBSTRING_INDEX(USER(), '@', 1) = 'roundcube', NULL, NEW.sess_id);" ;;
  clear:session-trigger)
    sql "DROP TRIGGER IF EXISTS roundcubemail.planted_fault_session;" ;;
  plant:users-trigger)     # the page and the session work, the real login does not: roundcube does not update users
    sql "CREATE TRIGGER roundcubemail.planted_fault_users BEFORE UPDATE ON roundcubemail.users FOR EACH ROW SET NEW.username = IF(SUBSTRING_INDEX(USER(), '@', 1) = 'roundcube', NULL, NEW.username);" ;;
  clear:users-trigger)
    sql "DROP TRIGGER IF EXISTS roundcubemail.planted_fault_users;" ;;
  plant:session-update)    # the login page only does INSERT into session; a real login saves the session with UPDATE
    sql "CREATE TRIGGER roundcubemail.planted_fault_session_update BEFORE UPDATE ON roundcubemail.session FOR EACH ROW SET NEW.sess_id = IF(SUBSTRING_INDEX(USER(), '@', 1) = 'roundcube', NULL, NEW.sess_id);" ;;
  clear:session-update)
    sql "DROP TRIGGER IF EXISTS roundcubemail.planted_fault_session_update;" ;;
  plant:logged-in-session) # roundcube does not save the session of whoever logged in (vars with user_id): the login page does, the real login does not
    for op in INSERT UPDATE; do
      sql "CREATE TRIGGER roundcubemail.planted_fault_login_$op BEFORE $op ON roundcubemail.session FOR EACH ROW SET NEW.sess_id = IF(SUBSTRING_INDEX(USER(), '@', 1) = 'roundcube' AND FROM_BASE64(NEW.vars) LIKE '%user_id%', NULL, NEW.sess_id);"
    done ;;
  clear:logged-in-session)
    sql "DROP TRIGGER IF EXISTS roundcubemail.planted_fault_login_INSERT; DROP TRIGGER IF EXISTS roundcubemail.planted_fault_login_UPDATE;" ;;
  plant:panel-plugin)      # a plugin that connects as the panel, without DSN: it shows only after the revoke
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
  plant:fpm-reload)        # the php-fpm reload fails (php-fpm -t rejects a pool), the webmail stays up
    printf "[planted]\nthis line is not php-fpm configuration\n" > /usr/local/etc/php-fpm.d/zz-planted-fault.conf ;;
  clear:fpm-reload)
    rm -f /usr/local/etc/php-fpm.d/zz-planted-fault.conf; service php_fpm reload >/dev/null 2>&1 ;;
  plant:webmail-down)      # the webmail already does not answer before
    service php_fpm stop >/dev/null ;;
  clear:webmail-down)
    service php_fpm start >/dev/null ;;
  plant:existing-account)  # a roundcube account that the webmail does not use
    sql "CREATE USER 'roundcube'@'127.0.0.1' IDENTIFIED BY 'SomebodyElse0123456789x';" ;;
  clear:existing-account)
    sql "DROP USER IF EXISTS 'roundcube'@'127.0.0.1';" ;;
  plant:dsnr)              # db_dsnr that connects as the panel
    cp -p "$C" /root/rcdb/config-before-dsnr.php
    printf "\$config['db_dsnr'] = 'mysql://mailpanel:%s@127.0.0.1/roundcubemail';\n" "$(secret mysql_password)" >> "$C"
    grep -c db_dsnr "$C" ;;
  clear:dsnr)
    cp -p /root/rcdb/config-before-dsnr.php "$C"; grep -c db_dsnr "$C" ;;
  *) echo "usage: roundcube-db-faults.sh plant|clear webmail-down|password-policy|init-connect|fpm-reload|session-trigger|logged-in-session|panel-plugin|existing-account|dsnr"; exit 2 ;;
esac
