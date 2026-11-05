#!/bin/sh
# Il ritorno indietro completo dopo upgrade-panel.sh: il boot environment di prima, la cartella del
# pannello com'era e le poche cose che le migrazioni cambiano FUORI dal boot environment. Non
# riavvia: alla fine dice di farlo (shutdown -r now), cosi' chi lo lancia sceglie il momento.
#
# Uso, da root:
#   rollback-panel.sh CARTELLA_DEL_PASSAGGIO
# dove CARTELLA_DEL_PASSAGGIO e' quella che upgrade-panel.sh ha stampato all'inizio
# (per esempio /home/panel-upgrade-2026-11-05-180000).
#
# Cosa rimette:
#   - il boot environment creato prima del passaggio (bectl activate): sistema, pacchetti,
#     configurazioni, /var/db (MySQL compreso) tornano a quel momento;
#   - la cartella del pannello, che sta fuori dai boot environment, dalla sua copia; quella di dopo
#     resta accanto, rinominata;
#   - i log di nginx della superficie pubblica col nome di prima, se il primo avvio li aveva
#     rinominati: /var/log sta fuori dai boot environment, e due nomi insieme fermerebbero il
#     prossimo passaggio (BOTH_NAMES);
#   - il proprietario di /var/log/php_errors.log, che RoundcubeUser da' all'utente della webmail.
# La posta NON torna indietro: /var/vmail sta DENTRO il boot environment (sul server vero come sulla
# VM), quindi prima di attivarlo ci si copia la posta di adesso, e quella di prima resta li' accanto
# (/var/vmail.before-rollback-...). MySQL invece torna al momento del passaggio: caselle, domini e
# alias creati dopo vanno rifatti.

set -u
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH

fail() { printf 'FERMO: %s\n' "$*"; exit 1; }
[ $# -eq 1 ] || { echo "uso: $0 CARTELLA_DEL_PASSAGGIO" >&2; exit 64; }
WORK=${1%/}
[ "$(id -u)" = 0 ] || fail "va lanciato da root"
[ -f "$WORK/summary.txt" ] || fail "$WORK non e' una cartella di upgrade-panel.sh (manca summary.txt)"
[ -f "$WORK/panel-dir.tar" ] || fail "manca la copia della cartella del pannello: $WORK/panel-dir.tar"

value() { sed -n "s/^$1: //p" "$WORK/summary.txt" | head -1; }
BE=$(value "boot environment")
PANEL_DIR=$(value "cartella del pannello")
STAMP=${WORK##*/panel-upgrade-}
[ -n "$BE" ] && [ -n "$PANEL_DIR" ] || fail "summary.txt non dice boot environment e cartella del pannello"
bectl list -H | awk '{print $1}' | grep -qxF "$BE" || fail "il boot environment $BE non c'e' piu'"

echo "Ritorno a prima del passaggio $STAMP"
if service mailpanel status >/dev/null 2>&1; then
    service mailpanel stop || fail "il pannello non si ferma"
fi

# La posta di adesso nel boot environment di prima, coi servizi di posta fermi perche' non cambi
# mentre si copia. Si riaccendono subito se qualcosa non va: fino a bectl activate niente e' cambiato.
VMAIL=/var/vmail
queued=$(postqueue -j 2>/dev/null | wc -l | tr -d ' ')
[ "$queued" = 0 ] || echo "ATTENZIONE: $queued messaggi nella coda di Postfix: la coda sta nel boot environment e torna a quella di prima"
MNT=$(mktemp -d /tmp/panel-rollback.XXXXXX)
bectl mount "$BE" "$MNT" >/dev/null || fail "bectl mount $BE non e' riuscito: niente e' stato cambiato"
service postfix stop >/dev/null 2>&1
service dovecot stop >/dev/null 2>&1
restart_mail() { service dovecot start >/dev/null 2>&1; service postfix start >/dev/null 2>&1; }
if [ -d "$VMAIL" ]; then
    if [ -e "$MNT$VMAIL" ]; then
        mv "$MNT$VMAIL" "$MNT$VMAIL.before-rollback-$STAMP" || { bectl umount "$BE"; restart_mail; fail "non riesco a mettere da parte la posta di prima nel boot environment"; }
    fi
    tar -cpf - -C "${VMAIL%/*}" "${VMAIL##*/}" | tar -xpf - -C "$MNT${VMAIL%/*}" \
        || { bectl umount "$BE"; restart_mail; fail "la copia della posta nel boot environment non e' riuscita: niente e' stato attivato"; }
    echo "Posta di adesso copiata nel boot environment di prima (quella di prima: $VMAIL.before-rollback-$STAMP)"
fi
bectl umount "$BE" || { restart_mail; fail "bectl umount $BE non e' riuscito"; }
rmdir "$MNT" 2>/dev/null

bectl activate "$BE" || { restart_mail; fail "bectl activate $BE non e' riuscito: niente e' stato attivato"; }
echo "Boot environment al prossimo avvio: $BE (posta ferma fino al riavvio)"

if [ -d "$PANEL_DIR" ]; then
    mv "$PANEL_DIR" "$PANEL_DIR.after-upgrade-$STAMP" || fail "non riesco a mettere da parte $PANEL_DIR (il boot environment e' gia' attivato: rimettere a mano)"
fi
tar -xpf "$WORK/panel-dir.tar" -C "${PANEL_DIR%/*}" || fail "la copia di $PANEL_DIR non si estrae (quella di dopo e' in $PANEL_DIR.after-upgrade-$STAMP)"
echo "Cartella del pannello com'era: $PANEL_DIR (quella di dopo: $PANEL_DIR.after-upgrade-$STAMP)"

# I log di nginx: quelli che c'erano prima e adesso mancano, se c'e' il loro nome nuovo.
if [ -f "$WORK/nginx-logs-before.txt" ]; then
    while read -r old; do
        [ -e "/var/log/nginx/$old" ] && continue
        new=$(printf '%s' "$old" | sed 's/mailpanel-pubblico/mailpanel-public/')
        [ "$new" != "$old" ] && [ -e "/var/log/nginx/$new" ] || continue
        mv "/var/log/nginx/$new" "/var/log/nginx/$old" && echo "log di nginx: $new -> $old"
    done < "$WORK/nginx-logs-before.txt"
fi

if [ -s "$WORK/php-errors-owner-before.txt" ] && [ -f /var/log/php_errors.log ]; then
    owner=$(awk '{print $1}' "$WORK/php-errors-owner-before.txt")
    chown "$owner" /var/log/php_errors.log && echo "proprietario di /var/log/php_errors.log: $owner"
fi

echo ""
echo "Pronto. Al riavvio parte $BE col pannello di prima: shutdown -r now"
