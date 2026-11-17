#!/bin/sh
# Il ritorno indietro completo dopo upgrade-panel.sh: il boot environment di prima, la cartella del
# pannello com'era e le poche cose che le migrazioni cambiano FUORI dal boot environment. Non
# riavvia: alla fine dice di farlo (shutdown -r now), cosi' chi lo lancia sceglie il momento.
#
# Uso, da root:
#   rollback-panel.sh UPGRADE_FOLDER
# dove UPGRADE_FOLDER e' quella che upgrade-panel.sh ha stampato all'inizio
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
#   - il proprietario di /var/log/php_errors.log, che RoundcubeUser da' all'utente della webmail;
#   - il proprietario del registro degli accessi al pannello, che col pannello separato e' dell'utente
#     della parte web (PanelSeparation): nel boot environment di prima quell'utente non c'e';
#   - i nomi di prima in /var/log, se il primo avvio li aveva cambiati col nome del prodotto (DaemoxCP Mail,
#     17/11/2026): il registro degli accessi con le sue copie e la cartella delle reinstallazioni.
# La posta NON torna indietro: /var/vmail sta DENTRO il boot environment (sul server vero come sulla
# VM), quindi prima di attivarlo ci si copia la posta di adesso, e quella di prima resta li' accanto
# (/var/vmail.before-rollback-...). MySQL invece torna al momento del passaggio: caselle, domini e
# alias creati dopo vanno rifatti.

set -u
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH

fail() { printf 'STOPPED: %s\n' "$*"; exit 1; }
[ $# -eq 1 ] || { echo "usage: $0 UPGRADE_FOLDER" >&2; exit 64; }
WORK=${1%/}
[ "$(id -u)" = 0 ] || fail "it must be run as root"
[ -f "$WORK/summary.txt" ] || fail "$WORK is not a folder of upgrade-panel.sh (summary.txt is missing)"
[ -f "$WORK/panel-dir.tar" ] || fail "the copy of the panel folder is missing: $WORK/panel-dir.tar"

value() { sed -n "s/^$1: //p" "$WORK/summary.txt" | head -1; }
BE=$(value "boot environment")
PANEL_DIR=$(value "panel folder")
# Le cartelle scritte dalle versioni di prima, coi nomi in italiano
[ -n "$PANEL_DIR" ] || PANEL_DIR=$(value "cartella del pannello")
STAMP=${WORK##*/panel-upgrade-}
[ -n "$BE" ] && [ -n "$PANEL_DIR" ] || fail "summary.txt does not give the boot environment and the panel folder"
bectl list -H | awk '{print $1}' | grep -qxF "$BE" || fail "the boot environment $BE is no longer there"

echo "Going back to before the upgrade $STAMP"
# Il servizio col nome di adesso o con quello di prima: il primo avvio del pannello nuovo lo rinomina.
for svc in daemoxcp_mail mailpanel; do
    [ -f "/usr/local/etc/rc.d/$svc" ] || continue
    if service "$svc" status >/dev/null 2>&1; then
        service "$svc" stop || fail "the panel does not stop"
    fi
done

# La posta di adesso nel boot environment di prima, coi servizi di posta fermi perche' non cambi
# mentre si copia. Si riaccendono subito se qualcosa non va: fino a bectl activate niente e' cambiato.
VMAIL=/var/vmail
queued=$(postqueue -j 2>/dev/null | wc -l | tr -d ' ')
[ "$queued" = 0 ] || echo "WARNING: $queued messages in Postfix's queue: the queue is inside the boot environment and goes back to the previous one"
MNT=$(mktemp -d /tmp/panel-rollback.XXXXXX)
bectl mount "$BE" "$MNT" >/dev/null || fail "bectl mount $BE failed: nothing was changed"
service postfix stop >/dev/null 2>&1
service dovecot stop >/dev/null 2>&1
restart_mail() { service dovecot start >/dev/null 2>&1; service postfix start >/dev/null 2>&1; }
if [ -d "$VMAIL" ]; then
    if [ -e "$MNT$VMAIL" ]; then
        mv "$MNT$VMAIL" "$MNT$VMAIL.before-rollback-$STAMP" || { bectl umount "$BE"; restart_mail; fail "cannot set aside the previous mail in the boot environment"; }
    fi
    tar -cpf - -C "${VMAIL%/*}" "${VMAIL##*/}" | tar -xpf - -C "$MNT${VMAIL%/*}" \
        || { bectl umount "$BE"; restart_mail; fail "copying the mail into the boot environment failed: nothing was activated"; }
    echo "Current mail copied into the previous boot environment (the previous mail: $VMAIL.before-rollback-$STAMP)"
fi
# La casella di sistema della parte web: PanelUserRename l'ha portata col nome nuovo, e nel boot environment
# di prima l'utente ha ancora quello vecchio. Stesso uid: torna col suo nome di prima.
if [ -f /var/mail/daemoxcp_mail ] && [ ! -e /var/mail/mailpanel ] && grep -q "^mailpanel:" "$MNT/etc/passwd" \
        && ! grep -q "^daemoxcp_mail:" "$MNT/etc/passwd"; then
    mv /var/mail/daemoxcp_mail /var/mail/mailpanel && echo "the system mailbox of the web part has its previous name again: /var/mail/mailpanel"
fi
# Le caselle di sistema vuote che pw useradd crea in /var/mail (fuori dai boot environment) per gli
# utenti nati col passaggio (roundcube, acme): nel boot environment di prima quegli utenti non ci sono.
for f in /var/mail/*; do
    u=${f##*/}
    [ -f "$f" ] && [ ! -s "$f" ] && ! grep -q "^$u:" "$MNT/etc/passwd" && rm -f "$f" && echo "removed the empty mailbox $f (the user $u does not exist before the upgrade)"
done
bectl umount "$BE" || { restart_mail; fail "bectl umount $BE failed"; }
rmdir "$MNT" 2>/dev/null

bectl activate "$BE" || { restart_mail; fail "bectl activate $BE failed: nothing was activated"; }
echo "Boot environment at the next start: $BE (mail stopped until the restart)"

if [ -d "$PANEL_DIR" ]; then
    mv "$PANEL_DIR" "$PANEL_DIR.after-upgrade-$STAMP" || fail "cannot set aside $PANEL_DIR (the boot environment is already activated: put it back by hand)"
fi
tar -xpf "$WORK/panel-dir.tar" -C "${PANEL_DIR%/*}" || fail "the copy of $PANEL_DIR does not extract (the one from after is in $PANEL_DIR.after-upgrade-$STAMP)"
echo "Panel folder as it was: $PANEL_DIR (the one from after: $PANEL_DIR.after-upgrade-$STAMP)"

# I log di nginx: quelli che c'erano prima e adesso mancano, se c'e' il loro nome nuovo.
if [ -f "$WORK/nginx-logs-before.txt" ]; then
    while read -r old; do
        [ -e "/var/log/nginx/$old" ] && continue
        # Dall'italiano all'inglese (30/10/2026), poi al nome del prodotto (17/11/2026).
        for new in $(printf '%s' "$old" | sed 's/mailpanel-pubblico/mailpanel-public/') \
                   $(printf '%s' "$old" | sed 's/mailpanel-pubblico/daemoxcp-mail-public/; s/mailpanel-public/daemoxcp-mail-public/'); do
            [ "$new" != "$old" ] && [ -e "/var/log/nginx/$new" ] || continue
            mv "/var/log/nginx/$new" "/var/log/nginx/$old" && echo "nginx log: $new -> $old"
            break
        done
    done < "$WORK/nginx-logs-before.txt"
fi

if [ -s "$WORK/php-errors-owner-before.txt" ] && [ -f /var/log/php_errors.log ]; then
    owner=$(awk '{print $1}' "$WORK/php-errors-owner-before.txt")
    chown "$owner" /var/log/php_errors.log && echo "owner of /var/log/php_errors.log: $owner"
fi

# /var/log col nome di prima del prodotto: quello che c'era prima e adesso manca, se c'e' il suo nome nuovo.
if [ -f "$WORK/var-log-before.txt" ]; then
    while read -r old; do
        [ -e "/var/log/$old" ] && continue
        new=$(printf '%s' "$old" | sed 's/^mail-panel-auth/daemoxcp-mail-auth/; s/^mailpanel$/daemoxcp-mail/')
        [ "$new" != "$old" ] && [ -e "/var/log/$new" ] || continue
        mv "/var/log/$new" "/var/log/$old" && echo "/var/log: $new -> $old"
    done < "$WORK/var-log-before.txt"
fi

if [ -s "$WORK/auth-log-owner-before.txt" ]; then
    owner=$(awk '{print $1}' "$WORK/auth-log-owner-before.txt")
    file=$(awk '{print $2}' "$WORK/auth-log-owner-before.txt")
    [ -f "$file" ] && chown "$owner" "$file" && echo "owner of $file: $owner"
fi

echo ""
echo "Ready. At the restart $BE starts with the previous panel: shutdown -r now"
