#!/bin/sh
# Prepara sulla VM di prova le tre situazioni vecchie per SignedJobsE2ETest, e le toglie.
#
#   sh tests/signed-jobs-setup.sh roundcube        Roundcube registrato una versione indietro
#   sh tests/signed-jobs-setup.sh python           py311-build installato e protetto
#   sh tests/signed-jobs-setup.sh mysql84          MySQL 8.0 al posto della 8.4, coi dati ricaricati
#   sh tests/signed-jobs-setup.sh restore-python   toglie cio' che il passaggio ha aggiunto
#   sh tests/signed-jobs-setup.sh restore-mysql84  rimette il datadir 8.4 di prima e le dipendenze vere
#   sh tests/signed-jobs-setup.sh cleanup          toglie i boot environment creati dai lavori
#   sh tests/signed-jobs-setup.sh confirm          tiene confermata per un'ora la sessione piu' recente del pannello
#   sh tests/signed-jobs-setup.sh confirm-stop     smette di confermarla
#
# La conferma recente (reauth_at) e' quella che il pannello vuole prima di avviare un lavoro, e che normalmente
# arriva da una passkey o da un codice via email: sulla VM la si scrive in MySQL, come confirm_session di
# separation-service-test.sh, per la sessione aperta col codice da console (signed-jobs-browser-test.js). Solo
# sulla VM di prova: sul server vero sarebbe aggirarla.
#
# Solo su una macchina di prova, come root. Non stampa mai password ne' contenuti del database:
# le credenziali di root di MySQL vanno in un file di opzioni 0600 letto dai client, e i dati
# passano da un file all'altro senza essere mostrati.
#
# Che cosa e' vero e che cosa e' costruito, perche' il reperto lo dica:
#  - roundcube: il pacchetto vero resta quello installato; nel database di pkg la sua versione
#    diventa quella precedente della serie, cosi' pkg lo aggiorna davvero (scarica, reinstalla i
#    file, esegue gli script). Lo schema del database della webmail e' gia' quello nuovo:
#    updatedb.sh non ha niente da fare.
#  - python: tutto vero. py311-build dal catalogo, protetto come il resto della pila; hidapi e
#    libevent, orfani rimasti da una prova vecchia, segnati per la durata come installati su
#    richiesta, perche' autoremove tocchi solo la famiglia py311 (con loro il lavoro lo salta, ed e'
#    giusto).
#  - mysql84: server e client 8.0 veri, dal catalogo; il datadir 8.0 nuovo, coi database e gli
#    account della 8.4 ricaricati (dump logico, account con l'hash, mai la password). Il datadir
#    della 8.4 resta da parte. Nel database di pkg, postfix-mysql e dovecot-mysql dipendono dal
#    client 8.0, come su un server installato con la 8.0.
set -eu

W=/var/tmp/signed-jobs
mkdir -p "$W"
chmod 700 "$W"
mode="${1:-}"

# I boot environment di adesso, la prima volta: "cleanup" toglie solo quelli nati dopo.
[ -f "$W/bes-before.txt" ] || bectl list -H | cut -f1 | sort > "$W/bes-before.txt"

root_cnf() {
    umask 077
    # Il file e' nel formato properties: "\!" vale "!", "\\" vale "\".
    pw=$(sed -n 's/^mysql_root_password=//p' /usr/local/etc/mail-panel/root-secrets.properties | sed 's/\\\(.\)/\1/g')
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
    # Cio' che il passaggio ha aggiunto (py312-build e le sue dipendenze nuove) se ne va; i flag
    # di hidapi e libevent tornano com'erano.
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
    # I database e gli account di adesso.
    dbs=$(mysql --defaults-file="$W/root.cnf" -N -e "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('mysql','information_schema','performance_schema','sys')")
    echo "databases: $(echo $dbs | wc -w)"
    mysqldump --defaults-file="$W/root.cnf" --single-transaction --routines --triggers --events \
        --set-gtid-purged=OFF --databases $dbs > "$W/data.sql"
    : > "$W/accounts.sql"; : > "$W/grants.sql"
    mysql --defaults-file="$W/root.cnf" -N -e "SELECT CONCAT(QUOTE(user),'@',QUOTE(host)) FROM mysql.user WHERE user NOT IN ('mysql.infoschema','mysql.session','mysql.sys')" > "$W/account-names.txt"
    while read -r a; do
        mysql --defaults-file="$W/root.cnf" -N -e "SET print_identified_with_as_hex = ON; SHOW CREATE USER $a" \
            | sed -E 's/^CREATE USER /CREATE USER IF NOT EXISTS /; s/$/;/' >> "$W/accounts.sql"
        # E la password anche per chi c'e' gia' (root, nel datadir nuovo): solo nome, plugin e hash.
        mysql --defaults-file="$W/root.cnf" -N -e "SET print_identified_with_as_hex = ON; SHOW CREATE USER $a" \
            | sed -nE "s/^CREATE USER (\`[^\`]*\`@\`[^\`]*\`) IDENTIFIED WITH ('[^']*') AS (0x[0-9A-Fa-f]+) .*/ALTER USER \1 IDENTIFIED WITH \2 AS \3;/p" >> "$W/accounts.sql"
        case "$a" in "'root'@"*) continue ;; esac
        mysql --defaults-file="$W/root.cnf" -N -e "SHOW GRANTS FOR $a" | sed 's/$/;/' >> "$W/grants.sql"
    done < "$W/account-names.txt"
    echo "accounts: $(wc -l < "$W/account-names.txt")"
    service mysql-server stop
    mv /var/db/mysql "$W/datadir-84"
    pkg unlock -y mysql84-server mysql84-client
    pkg delete -f -y mysql84-server mysql84-client
    pkg install -y -U mysql80-server mysql80-client
    # Come su un server installato con la 8.0: postfix-mysql e dovecot-mysql dipendono dal suo client.
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
    # Dopo la migrazione: le dipendenze di postfix-mysql e dovecot-mysql tornano sul client 8.4, e il
    # datadir della 8.4 di prima torna al suo posto (quello migrato dal lavoro va da parte e poi via).
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
