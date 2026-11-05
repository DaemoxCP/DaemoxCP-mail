#!/bin/sh
# Il passaggio del pannello di posta a un jar nuovo, su un server gia' avviato: lo stesso giro che e'
# stato provato sulla VM dal pannello dell'11/10 (reperti, punto 127). Si ferma al primo segnale
# storto, e da quel momento non tocca piu' niente: dice cosa ha visto e come tornare indietro.
#
# Uso, da root:
#   upgrade-panel.sh [-m CASELLA -p FILE] JAR_NUOVO SHA256_DEL_JAR
#
#   JAR_NUOVO       il jar da mettere al posto di quello che gira; non si tocca niente finche' la
#                   sua impronta non e' quella attesa
#   SHA256_DEL_JAR  l'impronta attesa, presa da dove il jar e' stato costruito, non dal jar stesso
#   -m CASELLA      una casella su cui provare, prima e dopo, accesso IMAP, consegna e webmail
#   -p FILE         il file con la sua password, una riga, solo per root (0600 o 0400)
#
# Cosa fa, in ordine:
#   1. i controlli: root, impronta, pannello acceso come servizio, boot environment, spazio, nessun
#      pkg in corso;
#   2. la fotografia dello stato (servizi, porte, configurazioni, MTA-STS, webmail, pacchetti
#      protetti, e la casella se c'e');
#   3. ferma il pannello (la posta resta accesa), crea il boot environment, copia la cartella del
#      pannello, che sta fuori dai boot environment, col jar di prima;
#   4. mette il jar nuovo e lo avvia; aspetta che le migrazioni finiscano e le legge nel log: devono
#      dire DONE, o niente;
#   5. lo stato, che deve essere uguale alla fotografia;
#   6. un secondo avvio, che non deve trovare piu' niente da fare;
#   7. di nuovo lo stato.
# Quello che vede lo scrive in una cartella accanto a quella del pannello (il nome lo stampa
# all'inizio), quindi fuori dal boot environment: resta anche tornando indietro.

set -u
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077

RC=/usr/local/etc/rc.d/mailpanel
BOOT_TIMEOUT=900      # secondi: AcmeUser puo' installare acme.sh dalla rete
STOP_TIMEOUT=60
MIN_FREE_KB=1048576   # 1 GiB liberi nel pool del boot environment

usage() {
    echo "uso: $0 [-m CASELLA -p FILE_PASSWORD] JAR_NUOVO SHA256_DEL_JAR" >&2
    echo "     $0 --check-log FILE first|second" >&2
    exit 64
}

# L'annuncio di LocalMtaRepair, scritto come avviso ma previsto sui server installati prima che
# Postfix fosse l'MTA locale (il server vero ha myorigin = il nome dell'host): dice cosa sta per
# cambiare, e subito dopo "Postfix is now the local MTA" dice che e' fatto. E' una migrazione, non
# un segnale storto; se non riesce, le righe dopo sono avvisi veri e fermano.
LOCAL_MTA_NOTICE='^WARNING: \[LocalMta\] (myorigin .* is not in mydestination: it becomes localhost first|sendmail\(8\) hands over to dma: )'

# Le righe che fermano: ogni avviso o errore, le eccezioni, e i nomi trovati due volte.
bad_lines() {
    grep -nE '^(WARNING|SEVERE):|Exception|Both .* exist|Could not rename|FAILED|failed:' "$1" \
        | grep -vE "^[0-9]+:${LOCAL_MTA_NOTICE#^}"
}

# Quello che le migrazioni hanno fatto: al primo avvio si leggono, al secondo non ce ne devono essere.
# Le righe dei controlli che passano ("Alias map OK", "already hands over") non contano.
migration_lines() {
    grep -nE "^(INFO|WARNING|SEVERE): (\[[A-Za-z0-9]+\] [A-Z_]+: |Renamed |\[CommentRepair\] comments repaired|\[LocalMta\] Postfix is now|\[PostfixAliases\] Auto-fix|Mail stack packages locked at startup)|${LOCAL_MTA_NOTICE}" "$1"
}

# Solo la lettura di un pezzo di log, con le regole del passaggio: per rileggere un avvio a mano, e
# per provare le regole su log costruiti apposta. "first": le migrazioni si elencano, gli avvisi
# fermano; "second": ferma anche una sola migrazione. Esce 1 se il log fermerebbe il passaggio.
if [ "${1:-}" = "--check-log" ]; then
    [ $# -eq 3 ] && [ -f "$2" ] || usage
    case $3 in first|second) ;; *) usage ;; esac
    m=$(migration_lines "$2"); b=$(bad_lines "$2")
    [ -n "$m" ] && printf 'migrazioni:\n%s\n' "$m"
    [ -n "$b" ] && printf 'righe che fermano:\n%s\n' "$b"
    [ -z "$b" ] && { [ "$3" = first ] || [ -z "$m" ]; } && { echo "esito: va"; exit 0; }
    echo "esito: FERMO"; exit 1
fi

MAILBOX=
PASSFILE=
while getopts m:p: o; do
    case $o in
        m) MAILBOX=$OPTARG ;;
        p) PASSFILE=$OPTARG ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 2 ] || usage
NEW_JAR=$1
EXPECTED=$(printf '%s' "$2" | tr 'A-F' 'a-f')

STAMP=$(date -u +%Y-%m-%d-%H%M%S)
BE=before-panel-upgrade-$STAMP
STEP="controlli"
SWAPPED=no

say() { printf '%s\n' "$*"; }

# Il valore che lo script di avvio usera': rc.conf se c'e', altrimenti il suo valore di default.
rc_setting() {
    v=$(sysrc -n "$1" 2>/dev/null)
    [ -n "$v" ] || v=$(sed -n 's/^: \${'"$1"':="\(.*\)"}$/\1/p' "$RC" 2>/dev/null | head -1)
    printf '%s\n' "$v"
}

# Come tornare indietro, detto con i nomi veri di questo passaggio.
rollback_help() {
    say ""
    say "Per tornare indietro:"
    if [ "$SWAPPED" = no ]; then
        say "  il jar non e' stato cambiato: niente da rimettere."
        say "  Se il pannello e' fermo: service mailpanel start"
        return
    fi
    say "  tutto com'era prima (consigliato se le migrazioni sono partite):"
    say "    sh $(dirname "$0")/rollback-panel.sh $WORK"
    say "    poi: shutdown -r now"
    say "  Rimette il boot environment $BE, la cartella del pannello"
    say "  com'era ($PANEL_DIR) e i nomi dei log fuori dal boot environment. I dati del server"
    say "  scritti dopo $STAMP (UTC) in MySQL tornano a quel momento; la posta in arrivo no."
}

fail() {
    say ""
    say "FERMO ($STEP): $*"
    [ -n "${WORK:-}" ] && [ -d "${WORK:-}" ] && { say "FERMO ($STEP): $*" >> "$WORK/summary.txt"; say "Quello che ho visto: $WORK"; }
    rollback_help
    exit 1
}

# --- 1. i controlli -----------------------------------------------------------------------------

[ "$(id -u)" = 0 ] || fail "va lanciato da root"
[ "$(uname -s)" = FreeBSD ] || fail "non e' FreeBSD"
[ -f "$NEW_JAR" ] || fail "il jar nuovo non c'e': $NEW_JAR"
printf '%s' "$EXPECTED" | grep -Eq '^[0-9a-f]{64}$' || fail "l'impronta attesa non e' uno sha256: $EXPECTED"
NEW_SHA=$(sha256 -q "$NEW_JAR")
[ "$NEW_SHA" = "$EXPECTED" ] || fail "l'impronta del jar nuovo e' $NEW_SHA, non $EXPECTED"
unzip -tq "$NEW_JAR" >/dev/null 2>&1 || fail "il jar nuovo non e' un archivio integro"

[ -f "$RC" ] || fail "manca lo script di avvio $RC: il pannello non e' installato come servizio"
[ "$(sysrc -n mailpanel_enable 2>/dev/null)" = YES ] || fail "mailpanel_enable non e' YES in rc.conf"
service mailpanel status >/dev/null 2>&1 || fail "il pannello non e' acceso: questo script passa da un pannello che gira"

JAR=$(rc_setting mailpanel_jar)
PANEL_DIR=$(rc_setting mailpanel_dir)
LOG_BEFORE=$(rc_setting mailpanel_log)
[ -f "$JAR" ] || fail "il jar che gira ($JAR, da $RC) non c'e'"
[ -d "$PANEL_DIR" ] || fail "la cartella del pannello ($PANEL_DIR) non c'e'"
OLD_SHA=$(sha256 -q "$JAR")
[ "$OLD_SHA" = "$NEW_SHA" ] && fail "gira gia' questo jar ($NEW_SHA)"

if [ -n "$MAILBOX$PASSFILE" ]; then
    [ -n "$MAILBOX" ] && [ -n "$PASSFILE" ] || fail "-m e -p vanno insieme"
    [ -f "$PASSFILE" ] || fail "il file della password non c'e': $PASSFILE"
    case $(stat -f %Lp "$PASSFILE") in 600|400) ;; *) fail "il file della password deve essere 0600 o 0400" ;; esac
    [ "$(stat -f %Su "$PASSFILE")" = root ] || fail "il file della password deve essere di root"
fi

command -v bectl >/dev/null 2>&1 || fail "manca bectl: senza boot environment non c'e' un ritorno indietro completo"
bectl check >/dev/null 2>&1 || fail "bectl check: il sistema non e' su un boot environment ZFS"
bectl list -H | awk '{print $1}' | grep -qxF "$BE" && fail "il boot environment $BE esiste gia'"
ROOT_DS=$(mount -p | awk '$2 == "/" {print $1}')
POOL=${ROOT_DS%%/*}
FREE_KB=$(( $(zfs get -Hp -o value available "$POOL") / 1024 ))
[ "$FREE_KB" -ge "$MIN_FREE_KB" ] || fail "nel pool $POOL restano $FREE_KB KiB, ne servono almeno $MIN_FREE_KB"
pgrep -x pkg >/dev/null 2>&1 && fail "c'e' un pkg in corso: aspettare che finisca"
pgrep -x pkg-static >/dev/null 2>&1 && fail "c'e' un pkg-static in corso: aspettare che finisca"

# La cartella del lavoro accanto a quella del pannello: sullo stesso dataset, fuori dal boot
# environment se il pannello sta in /home come sul server.
WORK=${PANEL_DIR%/*}/panel-upgrade-$STAMP
mkdir -m 700 "$WORK" || fail "non riesco a creare $WORK"
{
    say "passaggio del pannello $STAMP (UTC)"
    say "jar: $JAR"
    say "di prima: $OLD_SHA"
    say "nuovo:    $NEW_SHA"
    say "boot environment: $BE"
    say "cartella del pannello: $PANEL_DIR"
    say "log del pannello prima: $LOG_BEFORE"
} > "$WORK/summary.txt"
say "Passaggio del pannello: tutto quello che vedo va in $WORK"

# --- 2. la fotografia ---------------------------------------------------------------------------

# Lo stato che deve restare uguale dopo il passaggio, una riga per cosa. Niente password ne'
# contenuti: solo esiti.
state() {
    # In ordine di nome: service -e segue rcorder, che cambia quando un pacchetto si aggiunge.
    for s in $(service -e | sed -n 's#^/usr/local/etc/rc.d/##p' | grep -vx mailpanel | sort); do
        printf 'servizio %s: %s\n' "$s" "$(service "$s" status >/dev/null 2>&1 && echo acceso || echo SPENTO)"
    done
    printf 'mysqld: %s\n' "$(pgrep -q mysqld && echo acceso || echo SPENTO)"
    sockstat -46l -P tcp 2>/dev/null | awk 'NR > 1 {print "porta in ascolto: " $6}' | sort -u
    printf 'nginx -t: %s\n' "$(nginx -t >/dev/null 2>&1 && echo ok || echo ERRORE)"
    printf 'postfix check: %s\n' "$(postfix check >/dev/null 2>&1 && echo ok || echo ERRORE)"
    printf 'doveconf: %s\n' "$(doveconf -n >/dev/null 2>&1 && echo ok || echo ERRORE)"
    printf 'fail2ban: %s\n' "$(timeout -f 20 fail2ban-client ping >/dev/null 2>&1 && echo risponde || echo NON RISPONDE)"
    printf 'pannello sulla 2096: %s\n' "$(curl -sk -m 15 -o /dev/null -w '%{http_code}' https://127.0.0.1:2096/)"
    for h in $(grep -h "server_name" /usr/local/etc/nginx/conf.d/*.conf 2>/dev/null | tr -s ' ;' '\n' | grep '^mta-sts\.' | sort -u); do
        printf 'MTA-STS %s: %s\n' "$h" "$(curl -sk -m 15 --resolve "$h:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$h/.well-known/mta-sts.txt")"
    done
    wn=$(awk '/server_name/ && !/_;/ {gsub(";", "", $2); print $2; exit}' /usr/local/etc/nginx/nginx.conf 2>/dev/null)
    wp=$(awk '/listen/ && !/default_server/ {gsub(";", "", $2); print $2; exit}' /usr/local/etc/nginx/nginx.conf 2>/dev/null)
    if [ -n "$wn" ] && [ -n "$wp" ]; then
        printf 'pagina di accesso della webmail (%s:%s): %s\n' "$wn" "$wp" \
            "$(curl -sk -m 15 --resolve "$wn:$wp:127.0.0.1" "https://$wn:$wp/" | grep -c rcmloginuser)"
    fi
    [ -n "$MAILBOX" ] && mailbox_state "$wn" "$wp"
    return 0
}

# I pacchetti protetti, uno per riga. Si confrontano a parte: all'avvio il pannello nuovo protegge
# anche i pacchetti dello stack che non lo erano (UpdateManager.applyLockPolicy) e non ne sblocca
# nessuno, quindi l'elenco puo' crescere; quelli di prima devono restarci tutti.
locked() {
    pkg query -e '%k = 1' '%n' 2>/dev/null | sort
}

# Il confronto con la fotografia: lo stato uguale, e nessun pacchetto protetto perso.
compare() {
    state > "$WORK/state-after-$1.txt" 2>&1
    locked > "$WORK/locked-after-$1.txt"
    if ! diff -u "$WORK/state-before.txt" "$WORK/state-after-$1.txt" > "$WORK/state-diff-$1.txt"; then
        cat "$WORK/state-diff-$1.txt"
        fail "lo stato e' cambiato rispetto alla fotografia (sopra)"
    fi
    comm -23 "$WORK/locked-before.txt" "$WORK/locked-after-$1.txt" > "$WORK/locked-lost-$1.txt"
    if [ -s "$WORK/locked-lost-$1.txt" ]; then
        cat "$WORK/locked-lost-$1.txt"
        fail "questi pacchetti erano protetti e non lo sono piu'"
    fi
    comm -13 "$WORK/locked-before.txt" "$WORK/locked-after-$1.txt" > "$WORK/locked-new-$1.txt"
    [ -s "$WORK/locked-new-$1.txt" ] && say "Protetti in piu': $(tr '\n' ' ' < "$WORK/locked-new-$1.txt")"
    return 0
}

# Accesso IMAP, consegna e webmail con la casella data: la password non esce mai dal suo file.
mailbox_state() {
    printf 'accesso alla casella: %s\n' "$(timeout -f 20 doveadm auth test "$MAILBOX" < "$PASSFILE" >/dev/null 2>&1 && echo ok || echo RIFIUTATO)"
    token="panel-upgrade-$STAMP-$(date +%s)"
    # Il sendmail di Postfix, non /usr/sbin/sendmail: prima del passaggio quello puo' ancora andare a
    # dma (mailer.conf), che consegna fuori invece che in casella.
    printf 'Subject: %s\n\nprova del passaggio del pannello\n' "$token" | timeout -f 20 "$(postconf -h sendmail_path)" "$MAILBOX"
    i=0
    while [ $i -lt 60 ] && ! timeout -f 5 doveadm search -u "$MAILBOX" mailbox INBOX subject "$token" 2>/dev/null | grep -q .; do
        sleep 1; i=$((i + 1))
    done
    if timeout -f 5 doveadm search -u "$MAILBOX" mailbox INBOX subject "$token" 2>/dev/null | grep -q .; then
        say "consegna alla casella: ok"
        timeout -f 10 doveadm expunge -u "$MAILBOX" mailbox INBOX subject "$token" >/dev/null 2>&1
    else
        say "consegna alla casella: NON ARRIVATA in 60 s"
    fi
    [ -n "$1" ] || return 0
    t=$(mktemp -d /var/tmp/panel-upgrade.XXXXXX)
    curl -sk -m 15 --resolve "$1:$2:127.0.0.1" -c "$t/jar" -b "$t/jar" -o "$t/login.html" "https://$1:$2/"
    tok=$(grep -o 'name="_token" value="[^"]*"' "$t/login.html" | head -1 | sed 's/.*value="//; s/"$//')
    head -1 "$PASSFILE" | tr -d '\n' > "$t/pass"
    curl -sk -m 20 --resolve "$1:$2:127.0.0.1" -c "$t/jar" -b "$t/jar" -L -o "$t/after.html" \
        --data-urlencode "_task=login" --data-urlencode "_action=login" --data-urlencode "_timezone=UTC" \
        --data-urlencode "_token=$tok" --data-urlencode "_user=$MAILBOX" --data-urlencode "_pass@$t/pass" \
        "https://$1:$2/?_task=login"
    printf 'accesso alla webmail con mail e password: %s\n' "$(grep -q '_task=logout' "$t/after.html" && echo ok || echo RIFIUTATO)"
    rm -rf "$t"
}

STEP="fotografia"
state > "$WORK/state-before.txt" 2>&1
locked > "$WORK/locked-before.txt"
grep -E 'SPENTO|ERRORE|NON RISPONDE|RIFIUTATO|NON ARRIVATA' "$WORK/state-before.txt" > "$WORK/already-wrong.txt"
if [ -s "$WORK/already-wrong.txt" ]; then
    cat "$WORK/already-wrong.txt"
    fail "qualcosa non va gia' prima del passaggio (sopra): prima si sistema quello"
fi
say "Fotografia: $(wc -l < "$WORK/state-before.txt" | tr -d ' ') righe, tutto a posto; $(wc -l < "$WORK/locked-before.txt" | tr -d ' ') pacchetti protetti"

# --- 3. pannello fermo, boot environment, copie -------------------------------------------------

STEP="arresto del pannello"
service mailpanel stop >> "$WORK/service.txt" 2>&1
i=0
while [ $i -lt $STOP_TIMEOUT ] && pgrep -qf -- "-jar $JAR"; do sleep 1; i=$((i + 1)); done
pgrep -qf -- "-jar $JAR" && fail "il pannello non si e' fermato in $STOP_TIMEOUT s"

STEP="boot environment"
bectl create "$BE" >> "$WORK/service.txt" 2>&1 || { service mailpanel start >/dev/null 2>&1; fail "bectl create $BE non e' riuscito (pannello riacceso col jar di prima)"; }
say "Boot environment: $BE"

STEP="copia della cartella del pannello"
tar -cpf "$WORK/panel-dir.tar" -C "${PANEL_DIR%/*}" "${PANEL_DIR##*/}" 2>> "$WORK/service.txt" \
    || { service mailpanel start >/dev/null 2>&1; fail "la copia di $PANEL_DIR non e' riuscita (pannello riacceso col jar di prima)"; }
cp -p "$JAR" "$WORK/previous.jar"
ls -1 /var/log/nginx > "$WORK/nginx-logs-before.txt" 2>/dev/null
stat -f '%Su:%Sg %N' /var/log/php_errors.log > "$WORK/php-errors-owner-before.txt" 2>/dev/null
say "Copia della cartella del pannello: $WORK/panel-dir.tar"

# --- 4. il jar nuovo e il primo avvio -----------------------------------------------------------

STEP="jar nuovo"
cp "$NEW_JAR" "$JAR.new" && [ "$(sha256 -q "$JAR.new")" = "$NEW_SHA" ] \
    || { rm -f "$JAR.new"; service mailpanel start >/dev/null 2>&1; fail "la copia del jar nuovo non coincide (pannello riacceso col jar di prima)"; }
chown "$(stat -f %Su:%Sg "$JAR")" "$JAR.new"
chmod "$(stat -f %Lp "$JAR")" "$JAR.new"
mv -f "$JAR.new" "$JAR"
SWAPPED=yes
say "Jar nuovo al suo posto: $NEW_SHA"

# Il log dal segno in poi. Il file puo' cambiare nome durante l'avvio (PathMigration rinomina il log
# che daemon sta scrivendo, RcScriptRepair corregge lo script), e lo script di avvio lo mette da
# parte (.1) se supera 10 MB: si cerca il segno dappertutto.
segment() {
    for f in "$(rc_setting mailpanel_log)" "$LOG_BEFORE"; do
        if [ -f "$f" ] && grep -qF "$1" "$f"; then
            awk -v m="$1" 'found {print} index($0, m) {found = 1}' "$f"
            return
        fi
        if [ -f "$f.1" ] && grep -qF "$1" "$f.1"; then
            awk -v m="$1" 'found {print} index($0, m) {found = 1}' "$f.1"
            cat "$f"
            return
        fi
    done
}

# Avvia (o riavvia) e aspetta la fine dell'avvio: la riga del server partito arriva dopo le
# migrazioni del thread principale, quella dell'ACME dopo AcmeUser e ServiceUsers.
boot() {
    mark="=== upgrade-panel.sh $STAMP: $1 ==="
    printf '%s\n' "$mark" >> "$(rc_setting mailpanel_log)"
    service mailpanel "$2" >> "$WORK/service.txt" 2>&1
    i=0
    while [ $i -lt $BOOT_TIMEOUT ]; do
        segment "$mark" > "$WORK/$1.log"
        grep -q "Mail Panel server started on port" "$WORK/$1.log" \
            && grep -q "\[ACME\] Checking certificate status at startup" "$WORK/$1.log" && return 0
        if [ $i -ge 20 ] && ! service mailpanel status >/dev/null 2>&1; then
            fail "il pannello si e' spento durante l'avvio: $WORK/$1.log"
        fi
        sleep 5; i=$((i + 5))
    done
    fail "l'avvio non e' finito in $BOOT_TIMEOUT s: $WORK/$1.log"
}

STEP="primo avvio"
boot first-start start
migration_lines "$WORK/first-start.log" > "$WORK/first-start-migrations.txt"
say "Primo avvio finito. Le migrazioni:"
sed 's/^/  /' "$WORK/first-start-migrations.txt"
bad_lines "$WORK/first-start.log" > "$WORK/first-start-bad.txt"
if [ -s "$WORK/first-start-bad.txt" ]; then
    cat "$WORK/first-start-bad.txt"
    fail "il primo avvio ha scritto le righe qui sopra"
fi

# --- 5. lo stato dopo il primo avvio ------------------------------------------------------------

STEP="stato dopo il primo avvio"
compare first-start
say "Stato dopo il primo avvio: uguale alla fotografia"

# --- 6. il secondo avvio ------------------------------------------------------------------------

STEP="secondo avvio"
boot second-start restart
migration_lines "$WORK/second-start.log" > "$WORK/second-start-migrations.txt"
bad_lines "$WORK/second-start.log" > "$WORK/second-start-bad.txt"
if [ -s "$WORK/second-start-migrations.txt" ] || [ -s "$WORK/second-start-bad.txt" ]; then
    cat "$WORK/second-start-migrations.txt" "$WORK/second-start-bad.txt"
    fail "il secondo avvio doveva essere muto, e ha scritto le righe qui sopra"
fi

# --- 7. di nuovo lo stato -----------------------------------------------------------------------

STEP="stato dopo il secondo avvio"
compare second-start

{
    say "FATTO: primo avvio con le migrazioni qui sotto, secondo avvio muto, stato uguale alla fotografia."
    cat "$WORK/first-start-migrations.txt"
} >> "$WORK/summary.txt"
say ""
say "FATTO. Secondo avvio senza niente da fare, stato uguale alla fotografia."
say "Restano, per tornare indietro finche' servono:"
say "  il boot environment $BE (bectl destroy -o $BE quando non serve piu')"
say "  $WORK (la cartella del pannello di prima e quello che ho visto)"
exit 0
