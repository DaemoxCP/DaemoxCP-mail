#!/bin/sh
# Prepares on the test VM the three old situations for SignedJobsE2ETest, and removes them.
#
#   sh tests/signed-jobs-setup.sh roundcube        Roundcube recorded one version behind
#   sh tests/signed-jobs-setup.sh python           py311-build installed and locked
#   sh tests/signed-jobs-setup.sh mysql84          MySQL 8.0 in place of 8.4, with the data loaded again
#   sh tests/signed-jobs-setup.sh restore-python   removes what the move added
#   sh tests/signed-jobs-setup.sh restore-mysql84  puts back the 8.4 datadir of before and the real dependencies
#   sh tests/signed-jobs-setup.sh cleanup          removes the boot environments the jobs created
#   sh tests/signed-jobs-setup.sh confirm          keeps the panel's most recent session confirmed for an hour
#   sh tests/signed-jobs-setup.sh confirm-stop     stops confirming it
#
# The fresh confirmation (reauth_at) is what the panel wants before starting a job, and it normally comes from a
# passkey or a code by email: on the VM it is written in MySQL, like confirm_session of separation-service-test.sh,
# for the session opened with the console code (signed-jobs-browser-test.js). Only on the test VM: on the real server
# it would be getting around it.
#
# Only on a test machine, as root. It never prints passwords or database contents: MySQL's root credentials go in an
# options file 0600 read by the clients, and the data goes from one file to another without being shown.
#
# What is real and what is built, so that the finding says it:
#  - roundcube: the real package stays the one installed; in pkg's database its version becomes the previous one of
#    the series, so pkg really updates it (downloads, reinstalls the files, runs the scripts). The webmail database's
#    schema is already the new one: updatedb.sh has nothing to do.
#  - python: all real. py311-build from the catalog, locked like the rest of the stack; hidapi and libevent, orphans
#    left by an old test, marked as installed on request for the duration, so that autoremove touches only the py311
#    family (with them the job skips it, and rightly).
#  - mysql84: real 8.0 server and client, from the catalog; a new 8.0 datadir, with 8.4's databases and accounts
#    loaded again (a logical dump, the accounts with their hash, never the password). 8.4's datadir is set aside. In
#    pkg's database, postfix-mysql and dovecot-mysql depend on the 8.0 client, as on a server installed with 8.0.
set -eu

W=/var/tmp/signed-jobs
mkdir -p "$W"
chmod 700 "$W"
mode="${1:-}"

# The boot environments of now, the first time: "cleanup" removes only those born after.
[ -f "$W/bes-before.txt" ] || bectl list -H | cut -f1 | sort > "$W/bes-before.txt"

root_cnf() {
    umask 077
    # The file is in the properties format: "\!" stands for "!", "\\" for "\".
    pw=$(sed -n 's/^mysql_root_password=//p' /usr/local/etc/daemoxcp-mail/root-secrets.properties | sed 's/\\\(.\)/\1/g')
    [ -n "$pw" ] || { echo "mysql_root_password is missing"; exit 1; }
    printf '[client]\nuser=root\npassword="%s"\nhost=localhost\n' "$pw" > "$W/root.cnf"
    unset pw
}

case "$mode" in
roundcube)
    pkg=$(pkg query %n | grep -E '^roundcube' | head -1)
    cur=$(pkg query %v "$pkg")
    avail=$(pkg rquery -U %v "$pkg")
    [ "$cur" = "$avail" ] || { echo "$pkg $cur is not the catalog's $avail: nothing to fake"; exit 1; }
    minor=$(echo "$cur" | sed -E 's/^1\.7\.([0-9]+),1$/\1/')
    [ "$minor" != "$cur" ] && [ "$minor" -gt 0 ] || { echo "unexpected version $cur"; exit 1; }
    older="1.7.$((minor - 1)),1"
    echo "UPDATE packages SET version = '$older' WHERE name = '$pkg';" | pkg shell
    echo "$pkg recorded as $(pkg query %v "$pkg"), catalog $avail, locked: $(pkg query %k "$pkg")"
    ;;
python)
    pkg query %n | sort > "$W/python-before.txt"
    pkg query '%n %a' hidapi libevent > "$W/python-automatic-before.txt"
    pkg install -y py311-build
    pkg lock -y py311-build
    pkg set -y -A 0 hidapi libevent
    echo "py311 now: $(pkg query %n | grep -E '^(py311-|python311$)' | tr '\n' ' ')"
    echo "autoremove would remove: $(pkg autoremove -n 2>/dev/null | sed -n 's/^	\([^:]*\):.*/\1/p' | tr '\n' ' ')"
    ;;
restore-python)
    # What the move added (py312-build and its new dependencies) goes; the flags of hidapi and libevent go back
    # to what they were.
    new=$(pkg query %n | sort | comm -13 "$W/python-before.txt" -)
    for n in $new; do pkg unlock -y "$n" >/dev/null 2>&1 || true; done
    [ -z "$new" ] || pkg delete -y $new
    while read -r n a; do pkg set -y -A "$a" "$n"; done < "$W/python-automatic-before.txt"
    missing=$(pkg query %n | sort | comm -23 "$W/python-before.txt" -)
    echo "removed: ${new:-none}; missing from before: ${missing:-none}"
    ;;
mysql84)
    root_cnf
    service postfix stop || true
    service dovecot stop || true
    # The databases and accounts of now.
    dbs=$(mysql --defaults-file="$W/root.cnf" -N -e "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('mysql','information_schema','performance_schema','sys')")
    echo "databases: $(echo $dbs | wc -w)"
    mysqldump --defaults-file="$W/root.cnf" --single-transaction --routines --triggers --events \
        --set-gtid-purged=OFF --databases $dbs > "$W/data.sql"
    : > "$W/grants.sql"
    users="FROM mysql.user WHERE user NOT IN ('mysql.infoschema','mysql.session','mysql.sys')"
    mysql --defaults-file="$W/root.cnf" -N -e "SELECT CONCAT(QUOTE(user),'@',QUOTE(host)) $users" > "$W/account-names.txt"
    # The accounts, written from mysql.user with the hash always in hexadecimal. SHOW CREATE USER writes the hash as a
    # quoted string when its bytes happen to be all printable, and such a string can break the file: on 23/11/2026 one
    # did, root's line after it was lost, and the new datadir kept root without its password (the preparation stopped
    # there, with Postfix and Dovecot down). Plugin, hash and lock are all the panel's accounts set; the rest is
    # MySQL's default. CREATE for the accounts the new datadir lacks, then ALTER for all, root included, who is
    # already there.
    auth="' IDENTIFIED WITH ', QUOTE(plugin), IF(authentication_string = '', '', CONCAT(' AS 0x', HEX(authentication_string)))"
    mysql --defaults-file="$W/root.cnf" -N -e "SELECT CONCAT('CREATE USER IF NOT EXISTS ', QUOTE(user), '@', QUOTE(host), $auth, IF(account_locked = 'Y', ' ACCOUNT LOCK', ''), ';') $users" > "$W/accounts.sql"
    mysql --defaults-file="$W/root.cnf" -N -e "SELECT CONCAT('ALTER USER ', QUOTE(user), '@', QUOTE(host), $auth, ';') $users" >> "$W/accounts.sql"
    while read -r a; do
        case "$a" in "'root'@"*) continue ;; esac
        mysql --defaults-file="$W/root.cnf" -N -e "SHOW GRANTS FOR $a" | sed 's/$/;/' >> "$W/grants.sql"
    done < "$W/account-names.txt"
    echo "accounts: $(wc -l < "$W/account-names.txt")"
    service mysql-server stop
    mv /var/db/mysql "$W/datadir-84"
    pkg unlock -y mysql84-server mysql84-client
    pkg delete -f -y mysql84-server mysql84-client
    pkg install -y -U mysql80-server mysql80-client
    # As on a server installed with 8.0: postfix-mysql and dovecot-mysql depend on its client.
    cat <<'EOF' | pkg shell
UPDATE deps SET name = 'mysql80-client', origin = 'databases/mysql80-client', version = (SELECT version FROM packages WHERE name = 'mysql80-client') WHERE name = 'mysql84-client';
EOF
    service mysql-server start
    for i in $(seq 1 60); do mysql -uroot -N -e 'SELECT 1' >/dev/null 2>&1 && break; sleep 2; done
    mysql -uroot --force < "$W/accounts.sql" 2> "$W/accounts.err" || true
    mysql --defaults-file="$W/root.cnf" < "$W/data.sql"
    mysql --defaults-file="$W/root.cnf" --force < "$W/grants.sql" 2> "$W/grants.err" || true
    mysql --defaults-file="$W/root.cnf" -e 'FLUSH PRIVILEGES'
    pkg lock -y mysql80-server mysql80-client
    service postfix start || true
    service dovecot start || true
    echo "MySQL now: $(mysql --defaults-file="$W/root.cnf" -N -e 'SELECT VERSION()')"
    echo "errors loading accounts: $(grep -c . "$W/accounts.err" || true), grants: $(grep -c . "$W/grants.err" || true)"
    echo "rdeps of mysql80-client: $(pkg query %rn mysql80-client | tr '\n' ' ')"
    ;;
restore-mysql84)
    # After the migration: the dependencies of postfix-mysql and dovecot-mysql go back to the 8.4 client, and the
    # 8.4 datadir of before goes back in its place (the one the job migrated is set aside, then removed).
    [ -d "$W/datadir-84" ] || { echo "no 8.4 datadir set aside"; exit 1; }
    pkg info -e mysql84-server || { echo "mysql84-server is not installed: the migration did not finish"; exit 1; }
    cat <<'EOF' | pkg shell
UPDATE deps SET name = 'mysql84-client', origin = 'databases/mysql84-client', version = (SELECT version FROM packages WHERE name = 'mysql84-client') WHERE name = 'mysql80-client';
EOF
    service postfix stop || true
    service dovecot stop || true
    service mysql-server stop
    mv /var/db/mysql "$W/datadir-migrated"
    mv "$W/datadir-84" /var/db/mysql
    service mysql-server start
    for i in $(seq 1 60); do service mysql-server status >/dev/null 2>&1 && break; sleep 2; done
    service postfix start || true
    service dovecot start || true
    rm -rf "$W/datadir-migrated" "$W/data.sql" "$W/accounts.sql" "$W/accounts2.sql" "$W/grants.sql" "$W/root.cnf"
    echo "rdeps of mysql84-client: $(pkg query %rn mysql84-client | tr '\n' ' ')"
    echo "missing dependencies: $(pkg check -d -n 2>&1 | grep -c 'has a missing dependency' || true)"
    ;;
confirm)
    if [ -f "$W/confirm.pid" ] && ps -o command= -p "$(cat "$W/confirm.pid")" 2>/dev/null | grep -q 'signed-jobs-confirm'; then
        kill "$(cat "$W/confirm.pid")" && echo "stopped the previous confirmation"
    fi
    root_cnf
    db=$(mysql --defaults-file="$W/root.cnf" -N -e "SELECT DISTINCT routine_schema FROM information_schema.routines WHERE routine_name = 'check_session'")
    id=$(mysql --defaults-file="$W/root.cnf" -N -e "SELECT id FROM $db.panel_sessions ORDER BY created_at DESC LIMIT 1")
    [ -n "$id" ] || { echo "no panel session in $db: sign in first (console code), then confirm"; rm -f "$W/root.cnf"; exit 1; }
    echo "confirming session $id of $db for an hour"
    nohup sh -c "end=\$((\$(date +%s) + 3600)); while [ \$(date +%s) -lt \$end ]; do mysql --defaults-file=$W/root.cnf -N -e 'UPDATE $db.panel_sessions SET reauth_at = UTC_TIMESTAMP() WHERE id = $id'; sleep 60; done # signed-jobs-confirm" \
        > "$W/confirm.out" 2>&1 &
    echo $! > "$W/confirm.pid"
    ;;
confirm-stop)
    if [ -f "$W/confirm.pid" ] && ps -o command= -p "$(cat "$W/confirm.pid")" 2>/dev/null | grep -q 'signed-jobs-confirm'; then
        kill "$(cat "$W/confirm.pid")" && echo "confirmation stopped"
    fi
    rm -f "$W/confirm.pid"
    ;;
cleanup)
    for be in $(bectl list -H | cut -f1 | sort | comm -13 "$W/bes-before.txt" -); do
        case "$be" in packages-before-*) bectl destroy -o "$be" && echo "destroyed $be" ;; *) echo "kept $be" ;; esac
    done
    ;;
*)
    echo "mode: roundcube | python | restore-python | mysql84 | restore-mysql84 | confirm | confirm-stop | cleanup"; exit 2 ;;
esac
