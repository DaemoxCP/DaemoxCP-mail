#!/bin/sh
# Il passaggio del pannello di posta a un jar nuovo, su un server gia' avviato: lo stesso giro che e'
# stato provato sulla VM dal pannello dell'11/10 (reperti, punto 135). Si ferma al primo segnale
# storto, e da quel momento non tocca piu' niente: dice cosa ha visto e come tornare indietro.
#
# Uso, da root:
#   upgrade-panel.sh [-m MAILBOX -p PASSWORD_FILE] NEW_JAR JAR_SHA256
#
#   NEW_JAR         il jar da mettere al posto di quello che gira; non si tocca niente finche' la
#                   sua impronta non e' quella attesa
#   JAR_SHA256      l'impronta attesa, presa da dove il jar e' stato costruito, non dal jar stesso
#   -m MAILBOX      una casella su cui provare, prima e dopo, accesso IMAP, consegna e webmail
#   -p PASSWORD_FILE il file con la sua password, una riga, solo per root (0600 o 0400)
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

# Il servizio del pannello: daemoxcp_mail da DaemoxCP Mail (17/11/2026), mailpanel prima. Il primo avvio del jar
# nuovo lo rinomina da se' (PanelServiceRename) mentre questo script aspetta, quindi il nome si rilegge ogni volta.
service_name() {
    if [ -f /usr/local/etc/rc.d/daemoxcp_mail ]; then echo daemoxcp_mail; else echo mailpanel; fi
}
RC=/usr/local/etc/rc.d/$(service_name)
BOOT_TIMEOUT=900      # secondi: AcmeUser puo' installare acme.sh dalla rete
STOP_TIMEOUT=60
MIN_FREE_KB=1048576   # 1 GiB liberi nel pool del boot environment

usage() {
    echo "usage: $0 [-m MAILBOX -p PASSWORD_FILE] NEW_JAR JAR_SHA256" >&2
    echo "       $0 --check-log FILE first|second" >&2
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
    [ -n "$m" ] && printf 'migrations:\n%s\n' "$m"
    [ -n "$b" ] && printf 'lines that stop:\n%s\n' "$b"
    [ -z "$b" ] && { [ "$3" = first ] || [ -z "$m" ]; } && { echo "outcome: go"; exit 0; }
    echo "outcome: STOPPED"; exit 1
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
STEP="checks"
SWAPPED=no

say() { printf '%s\n' "$*"; }

# Il valore che lo script di avvio usera' (jar, dir, log...): rc.conf se c'e', altrimenti il suo valore di default.
# Col servizio di adesso, che durante il primo avvio cambia nome.
rc_setting() {
    s=$(service_name)
    v=$(sysrc -n "${s}_$1" 2>/dev/null)
    [ -n "$v" ] || v=$(sed -n 's/^: \${'"${s}_$1"':="\(.*\)"}$/\1/p' "/usr/local/etc/rc.d/$s" 2>/dev/null | head -1)
    printf '%s\n' "$v"
}

# Come tornare indietro, detto con i nomi veri di questo passaggio.
rollback_help() {
    say ""
    say "To go back:"
    if [ "$SWAPPED" = no ]; then
        say "  the jar was not changed: nothing to put back."
        say "  If the panel is stopped: service $(service_name) start"
        return
    fi
    say "  everything as it was before (recommended if the migrations started):"
    say "    sh $(dirname "$0")/rollback-panel.sh $WORK"
    say "    then: shutdown -r now"
    say "  It puts back the boot environment $BE, the panel folder as it was"
    say "  ($PANEL_DIR) and the names of the logs outside the boot environment. What the server"
    say "  wrote in MySQL after $STAMP (UTC) goes back to that moment; incoming mail does not."
}

fail() {
    say ""
    say "STOPPED ($STEP): $*"
    [ -n "${WORK:-}" ] && [ -d "${WORK:-}" ] && { say "STOPPED ($STEP): $*" >> "$WORK/summary.txt"; say "What I saw: $WORK"; }
    rollback_help
    exit 1
}

# --- 1. i controlli -----------------------------------------------------------------------------

[ "$(id -u)" = 0 ] || fail "it must be run as root"
[ "$(uname -s)" = FreeBSD ] || fail "this is not FreeBSD"
[ -f "$NEW_JAR" ] || fail "the new jar is not there: $NEW_JAR"
printf '%s' "$EXPECTED" | grep -Eq '^[0-9a-f]{64}$' || fail "the expected fingerprint is not a sha256: $EXPECTED"
NEW_SHA=$(sha256 -q "$NEW_JAR")
[ "$NEW_SHA" = "$EXPECTED" ] || fail "the new jar's fingerprint is $NEW_SHA, not $EXPECTED"
unzip -tq "$NEW_JAR" >/dev/null 2>&1 || fail "the new jar is not an intact archive"

[ -f "$RC" ] || fail "the start script $RC is missing: the panel is not installed as a service"
SVC=$(service_name)
[ "$(sysrc -n "${SVC}_enable" 2>/dev/null)" = YES ] || fail "${SVC}_enable is not YES in rc.conf"
service "$SVC" status >/dev/null 2>&1 || fail "the panel is not running: this script starts from a running panel"

JAR=$(rc_setting jar)
PANEL_DIR=$(rc_setting dir)
LOG_BEFORE=$(rc_setting log)
[ -f "$JAR" ] || fail "the running jar ($JAR, from $RC) is not there"
[ -d "$PANEL_DIR" ] || fail "the panel folder ($PANEL_DIR) is not there"
OLD_SHA=$(sha256 -q "$JAR")
[ "$OLD_SHA" = "$NEW_SHA" ] && fail "this jar is already running ($NEW_SHA)"

if [ -n "$MAILBOX$PASSFILE" ]; then
    [ -n "$MAILBOX" ] && [ -n "$PASSFILE" ] || fail "-m and -p go together"
    [ -f "$PASSFILE" ] || fail "the password file is not there: $PASSFILE"
    case $(stat -f %Lp "$PASSFILE") in 600|400) ;; *) fail "the password file must be 0600 or 0400" ;; esac
    [ "$(stat -f %Su "$PASSFILE")" = root ] || fail "the password file must belong to root"
fi

command -v bectl >/dev/null 2>&1 || fail "bectl is missing: without a boot environment there is no complete way back"
bectl check >/dev/null 2>&1 || fail "bectl check: the system is not on a ZFS boot environment"
bectl list -H | awk '{print $1}' | grep -qxF "$BE" && fail "the boot environment $BE already exists"
ROOT_DS=$(mount -p | awk '$2 == "/" {print $1}')
POOL=${ROOT_DS%%/*}
FREE_KB=$(( $(zfs get -Hp -o value available "$POOL") / 1024 ))
[ "$FREE_KB" -ge "$MIN_FREE_KB" ] || fail "the pool $POOL has $FREE_KB KiB left, at least $MIN_FREE_KB are needed"
pgrep -x pkg >/dev/null 2>&1 && fail "a pkg is running: wait for it to finish"
pgrep -x pkg-static >/dev/null 2>&1 && fail "a pkg-static is running: wait for it to finish"

# La cartella del lavoro accanto a quella del pannello: sullo stesso dataset, fuori dal boot
# environment se il pannello sta in /home come sul server.
WORK=${PANEL_DIR%/*}/panel-upgrade-$STAMP
mkdir -m 700 "$WORK" || fail "cannot create $WORK"
{
    say "panel upgrade $STAMP (UTC)"
    say "jar: $JAR"
    say "before: $OLD_SHA"
    say "new:    $NEW_SHA"
    say "boot environment: $BE"
    say "panel folder: $PANEL_DIR"
    say "panel log before: $LOG_BEFORE"
} > "$WORK/summary.txt"
say "Panel upgrade: everything I see goes into $WORK"

# --- 2. la fotografia ---------------------------------------------------------------------------

# Lo stato che deve restare uguale dopo il passaggio, una riga per cosa. Niente password ne'
# contenuti: solo esiti.
state() {
    # In ordine di nome: service -e segue rcorder, che cambia quando un pacchetto si aggiunge.
    # Il pannello no, con tutti e due i nomi: il primo avvio lo rinomina.
    for s in $(service -e | sed -n 's#^/usr/local/etc/rc.d/##p' | grep -vxE 'mailpanel|daemoxcp_mail' | sort); do
        printf 'service %s: %s\n' "$s" "$(service "$s" status >/dev/null 2>&1 && echo up || echo DOWN)"
    done
    printf 'mysqld: %s\n' "$(pgrep -q mysqld && echo up || echo DOWN)"
    # Le porte di MySQL: la 33060 (protocollo X) e l'indirizzo della 3306 li chiude il pannello stesso
    # al primo avvio (MysqlListen, che lo verifica e se non va rimette com'era). Qui contano come una
    # riga sola, cosi' chiuderle non sembra un guasto; che MySQL sia acceso lo dice la riga mysqld.
    # Lo stesso per POP3 (110, 995): il pannello lo accende o lo spegne come ha scelto l'amministratore,
    # spento finche' non sceglie (Pop3, che verifica che IMAP risponda ancora e se no rimette com'era);
    # IMAP resta nella fotografia.
    # E la 24 e la 6379, su 127.0.0.1 e ::1: le chiude il pannello al primo avvio, quando Postfix consegna a Dovecot dal
    # socket nella sua coda (LmtpSocket, reperto 234) e rspamd parla con redis dal socket (RedisSocket, 235). Tutti e due
    # provano una consegna e una scansione prima e dopo, e se non va rimettono la porta.
    sockstat -46l -P tcp 2>/dev/null | awk 'NR > 1 {a = $6; if (a ~ /:(33060|110|995)$/) next; if (a ~ /^(127\.0\.0\.1|\[::1\]):(24|6379)$/) next; if (a ~ /:3306$/) a = "MySQL 3306"; print "listening port: " a}' | sort -u
    printf 'nginx -t: %s\n' "$(nginx -t >/dev/null 2>&1 && echo ok || echo ERROR)"
    printf 'postfix check: %s\n' "$(postfix check >/dev/null 2>&1 && echo ok || echo ERROR)"
    printf 'doveconf: %s\n' "$(doveconf -n >/dev/null 2>&1 && echo ok || echo ERROR)"
    printf 'fail2ban: %s\n' "$(timeout -f 20 fail2ban-client ping >/dev/null 2>&1 && echo answers || echo NOT ANSWERING)"
    printf 'panel on 2096: %s\n' "$(curl -sk -m 15 -o /dev/null -w '%{http_code}' https://127.0.0.1:2096/)"
    # MTA-STS: dai file di nginx che servono la politica, chiesta a ogni loro nome. Sul server (e sul
    # banco) la 443 e' il sito predefinito, "server_name _": risponde a qualunque nome, quindi si
    # chiede all'indirizzo locale. Senza nessun file lo si dice, cosi' anche una sparizione cambia
    # lo stato (la prima versione cercava "mta-sts." fra i nomi e non controllava niente).
    confs=$(grep -l 'mta-sts\.txt' /usr/local/etc/nginx/conf.d/*.conf 2>/dev/null)
    [ -n "$confs" ] || say "MTA-STS on 443: no nginx file serves it"
    for c in $confs; do
        for h in $(awk '/^[[:space:]]*server_name/ {for (i = 2; i <= NF; i++) {gsub(";", "", $i); print $i}}' "$c" | sort -u); do
            [ "$h" = "_" ] && h=127.0.0.1
            t=$(mktemp /var/tmp/panel-upgrade-mta-sts.XXXXXX)
            code=$(curl -sk -m 15 --resolve "$h:443:127.0.0.1" -o "$t" -w '%{http_code}' "https://$h/.well-known/mta-sts.txt")
            printf 'MTA-STS on 443 (%s): %s %s\n' "$h" "$code" "$(head -1 "$t" | tr -cd '[:print:]')"
            rm -f "$t"
        done
    done
    wn=$(awk '/server_name/ && !/_;/ {gsub(";", "", $2); print $2; exit}' /usr/local/etc/nginx/nginx.conf 2>/dev/null)
    wp=$(awk '/listen/ && !/default_server/ {gsub(";", "", $2); print $2; exit}' /usr/local/etc/nginx/nginx.conf 2>/dev/null)
    if [ -n "$wn" ] && [ -n "$wp" ]; then
        printf 'webmail login page (%s:%s): %s\n' "$wn" "$wp" \
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
        fail "the state changed from the snapshot (above)"
    fi
    comm -23 "$WORK/locked-before.txt" "$WORK/locked-after-$1.txt" > "$WORK/locked-lost-$1.txt"
    if [ -s "$WORK/locked-lost-$1.txt" ]; then
        cat "$WORK/locked-lost-$1.txt"
        fail "these packages were locked and are not any more"
    fi
    comm -13 "$WORK/locked-before.txt" "$WORK/locked-after-$1.txt" > "$WORK/locked-new-$1.txt"
    [ -s "$WORK/locked-new-$1.txt" ] && say "Newly locked: $(tr '\n' ' ' < "$WORK/locked-new-$1.txt")"
    return 0
}

# Accesso IMAP, consegna e webmail con la casella data: la password non esce mai dal suo file.
mailbox_state() {
    printf 'mailbox login: %s\n' "$(timeout -f 20 doveadm auth test "$MAILBOX" < "$PASSFILE" >/dev/null 2>&1 && echo ok || echo REFUSED)"
    token="panel-upgrade-$STAMP-$(date +%s)"
    # Il sendmail di Postfix, non /usr/sbin/sendmail: prima del passaggio quello puo' ancora andare a
    # dma (mailer.conf), che consegna fuori invece che in casella.
    printf 'Subject: %s\n\npanel upgrade test\n' "$token" | timeout -f 20 "$(postconf -h sendmail_path)" "$MAILBOX"
    i=0
    while [ $i -lt 60 ] && ! timeout -f 5 doveadm search -u "$MAILBOX" mailbox INBOX subject "$token" 2>/dev/null | grep -q .; do
        sleep 1; i=$((i + 1))
    done
    if timeout -f 5 doveadm search -u "$MAILBOX" mailbox INBOX subject "$token" 2>/dev/null | grep -q .; then
        say "delivery to the mailbox: ok"
        timeout -f 10 doveadm expunge -u "$MAILBOX" mailbox INBOX subject "$token" >/dev/null 2>&1
    else
        say "delivery to the mailbox: NOT ARRIVED within 60 s"
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
    printf 'webmail login with address and password: %s\n' "$(grep -q '_task=logout' "$t/after.html" && echo ok || echo REFUSED)"
    rm -rf "$t"
}

STEP="snapshot"
state > "$WORK/state-before.txt" 2>&1
locked > "$WORK/locked-before.txt"
# Solo in fondo alla riga: la prima riga di una pagina (MTA-STS) puo' contenere qualunque parola.
grep -E ': (DOWN|ERROR|NOT ANSWERING|REFUSED)$|: NOT ARRIVED within' "$WORK/state-before.txt" > "$WORK/already-wrong.txt"
if [ -s "$WORK/already-wrong.txt" ]; then
    cat "$WORK/already-wrong.txt"
    fail "something is already wrong before the upgrade (above): fix that first"
fi
say "Snapshot: $(wc -l < "$WORK/state-before.txt" | tr -d ' ') lines, all fine; $(wc -l < "$WORK/locked-before.txt" | tr -d ' ') locked packages"

# --- 3. pannello fermo, boot environment, copie -------------------------------------------------

STEP="stopping the panel"
service "$SVC" stop >> "$WORK/service.txt" 2>&1
i=0
while [ $i -lt $STOP_TIMEOUT ] && pgrep -qf -- "-jar $JAR"; do sleep 1; i=$((i + 1)); done
pgrep -qf -- "-jar $JAR" && fail "the panel did not stop within $STOP_TIMEOUT s"

STEP="boot environment"
bectl create "$BE" >> "$WORK/service.txt" 2>&1 || { service "$SVC" start >/dev/null 2>&1; fail "bectl create $BE failed (panel started again with the previous jar)"; }
say "Boot environment: $BE"

STEP="copy of the panel folder"
tar -cpf "$WORK/panel-dir.tar" -C "${PANEL_DIR%/*}" "${PANEL_DIR##*/}" 2>> "$WORK/service.txt" \
    || { service "$SVC" start >/dev/null 2>&1; fail "the copy of $PANEL_DIR failed (panel started again with the previous jar)"; }
cp -p "$JAR" "$WORK/previous.jar"
ls -1 /var/log/nginx > "$WORK/nginx-logs-before.txt" 2>/dev/null
stat -f '%Su:%Sg %N' /var/log/php_errors.log > "$WORK/php-errors-owner-before.txt" 2>/dev/null
# Il registro degli accessi al pannello col suo nome di adesso o di prima (AuthJailRename lo rinomina), e cosa c'e'
# in /var/log: sta fuori dai boot environment, e rollback-panel.sh rimette i nomi di prima.
for f in /var/log/daemoxcp-mail-auth.log /var/log/mail-panel-auth.log; do
    [ -f "$f" ] && stat -f '%Su:%Sg %N' "$f" > "$WORK/auth-log-owner-before.txt" && break
done
ls -1 /var/log > "$WORK/var-log-before.txt" 2>/dev/null
say "Copy of the panel folder: $WORK/panel-dir.tar"

# --- 4. il jar nuovo e il primo avvio -----------------------------------------------------------

STEP="new jar"
cp "$NEW_JAR" "$JAR.new" && [ "$(sha256 -q "$JAR.new")" = "$NEW_SHA" ] \
    || { rm -f "$JAR.new"; service "$SVC" start >/dev/null 2>&1; fail "the copy of the new jar does not match (panel started again with the previous jar)"; }
chown "$(stat -f %Su:%Sg "$JAR")" "$JAR.new"
chmod "$(stat -f %Lp "$JAR")" "$JAR.new"
mv -f "$JAR.new" "$JAR"
SWAPPED=yes
say "New jar in place: $NEW_SHA"

# Il log dal segno in poi. Il file si cerca prima per inode, perche' daemon(8) scrive sempre lo
# stesso file anche se cambia nome: il pannello nuovo puo' rinominarlo (PathMigration) senza che lo
# script di avvio lo sappia, ed e' proprio il difetto che la #89 ha corretto. Se lo script di avvio
# l'ha messo da parte (.1, oltre 10 MB), il resto sta nel file nuovo.
segment() {
    # La cartella del registro di prima, e quella dove la sposta il primo avvio (DataFolderRename): stesso inode.
    for f in $(find "$LOG_DIR" /var/db/daemoxcp-mail /var/db/mailpanel -maxdepth 1 -type f -inum "$LOG_INODE" 2>/dev/null) \
             "$(rc_setting log)" "$LOG_BEFORE"; do
        [ -f "$f" ] && grep -qF "$1" "$f" || continue
        awk -v m="$1" 'found {print} index($0, m) {found = 1}' "$f"
        case $f in *.1) [ -f "${f%.1}" ] && cat "${f%.1}" ;; esac
        return
    done
}

# Avvia (o riavvia) e aspetta la fine dell'avvio: la riga del server partito arriva dopo le
# migrazioni del thread principale, quella dell'ACME dopo AcmeUser e ServiceUsers. Col pannello
# separato (PanelSeparation) la riga e' quella della parte root pronta: la porta la tiene la web.
boot() {
    mark="=== upgrade-panel.sh $STAMP: $1 ==="
    f=$(rc_setting log)
    printf '%s\n' "$mark" >> "$f"
    LOG_DIR=${f%/*}
    LOG_INODE=$(stat -f %i "$f")
    service "$(service_name)" "$2" >> "$WORK/service.txt" 2>&1
    i=0
    while [ $i -lt $BOOT_TIMEOUT ]; do
        segment "$mark" > "$WORK/$1.log"
        grep -qE "(DaemoxCP Mail|Mail Panel) (server started on port|root part ready)" "$WORK/$1.log" \
            && grep -q "\[ACME\] Checking certificate status at startup" "$WORK/$1.log" && return 0
        if [ $i -ge 20 ] && ! service "$(service_name)" status >/dev/null 2>&1; then
            fail "the panel stopped during the start: $WORK/$1.log"
        fi
        sleep 5; i=$((i + 5))
    done
    fail "the start did not finish within $BOOT_TIMEOUT s: $WORK/$1.log"
}

STEP="first start"
boot first-start start
migration_lines "$WORK/first-start.log" > "$WORK/first-start-migrations.txt"
say "First start finished. The migrations:"
sed 's/^/  /' "$WORK/first-start-migrations.txt"
bad_lines "$WORK/first-start.log" > "$WORK/first-start-bad.txt"
if [ -s "$WORK/first-start-bad.txt" ]; then
    cat "$WORK/first-start-bad.txt"
    fail "the first start wrote the lines above"
fi

# --- 5. lo stato dopo il primo avvio ------------------------------------------------------------

STEP="state after the first start"
compare first-start
say "State after the first start: same as the snapshot"

# --- 6. il secondo avvio ------------------------------------------------------------------------

STEP="second start"
boot second-start restart
migration_lines "$WORK/second-start.log" > "$WORK/second-start-migrations.txt"
bad_lines "$WORK/second-start.log" > "$WORK/second-start-bad.txt"
if [ -s "$WORK/second-start-migrations.txt" ] || [ -s "$WORK/second-start-bad.txt" ]; then
    cat "$WORK/second-start-migrations.txt" "$WORK/second-start-bad.txt"
    fail "the second start had to be silent, and wrote the lines above"
fi

# --- 7. di nuovo lo stato -----------------------------------------------------------------------

STEP="state after the second start"
compare second-start

{
    say "DONE: first start with the migrations below, silent second start, state same as the snapshot."
    cat "$WORK/first-start-migrations.txt"
} >> "$WORK/summary.txt"
say ""
say "DONE. Second start with nothing to do, state same as the snapshot."
say "Left, to go back while they are needed:"
say "  the boot environment $BE (bectl destroy -o $BE when it is no longer needed)"
say "  $WORK (the panel folder from before, and what I saw)"
exit 0
