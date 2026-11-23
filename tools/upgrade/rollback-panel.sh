#!/bin/sh
# The complete way back after upgrade-panel.sh: the boot environment from before, the folder of the
# panel as it was and the few things that the migrations change OUTSIDE the boot environment. It does
# not restart: at the end it says to do it (shutdown -r now), so whoever runs it chooses the moment.
#
# Usage, as root:
#   rollback-panel.sh UPGRADE_FOLDER
# where UPGRADE_FOLDER is the one that upgrade-panel.sh printed at the start
# (for example /home/panel-upgrade-2026-11-05-180000).
#
# What it puts back:
#   - the boot environment created before the upgrade (bectl activate): system, packages,
#     configurations, /var/db (MySQL included) go back to that moment;
#   - the folder of the panel, which is outside the boot environments, from its copy; the one from
#     after stays beside it, renamed;
#   - the nginx logs of the public surface with the name from before, if the first start had
#     renamed them: /var/log is outside the boot environments, and two names together would stop the
#     next upgrade (BOTH_NAMES);
#   - the owner of /var/log/php_errors.log, which RoundcubeUser gives to the webmail user;
#   - the owner of the access log of the panel, which with the separated panel belongs to the user
#     of the web part (PanelSeparation): in the boot environment from before that user does not exist;
#   - the names from before in /var/log, if the first start had changed them with the product name
#     (DaemoxCP Mail, 2026-11-17): the access log with its copies and the folder of the reinstallations.
# The mail does NOT go back: /var/vmail is INSIDE the boot environment (on the production server as on
# the VM), so before activating it the current mail is copied into it, and the mail from before stays
# there beside it (/var/vmail.before-rollback-...). MySQL instead goes back to the moment of the
# upgrade: mailboxes, domains and aliases created afterwards must be made again.

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
# The folders written by the earlier versions, with the names in Italian
[ -n "$PANEL_DIR" ] || PANEL_DIR=$(value "cartella del pannello")
STAMP=${WORK##*/panel-upgrade-}
[ -n "$BE" ] && [ -n "$PANEL_DIR" ] || fail "summary.txt does not give the boot environment and the panel folder"
bectl list -H | awk '{print $1}' | grep -qxF "$BE" || fail "the boot environment $BE is no longer there"

echo "Going back to before the upgrade $STAMP"
# The service with the current name or with the one from before: the first start of the new panel renames it.
for svc in daemoxcp_mail mailpanel; do
    [ -f "/usr/local/etc/rc.d/$svc" ] || continue
    if service "$svc" status >/dev/null 2>&1; then
        service "$svc" stop || fail "the panel does not stop"
    fi
done

# The current mail into the boot environment from before, with the mail services stopped so that it does not
# change while it is copied. They are started again right away if something goes wrong: until bectl activate
# nothing has changed.
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
# The system mailbox of the web part: PanelUserRename moved it to the new name, and in the boot environment
# from before the user still has the old one. Same uid: it goes back to its name from before.
if [ -f /var/mail/daemoxcp_mail ] && [ ! -e /var/mail/mailpanel ] && grep -q "^mailpanel:" "$MNT/etc/passwd" \
        && ! grep -q "^daemoxcp_mail:" "$MNT/etc/passwd"; then
    mv /var/mail/daemoxcp_mail /var/mail/mailpanel && echo "the system mailbox of the web part has its previous name again: /var/mail/mailpanel"
fi
# The empty system mailboxes that pw useradd creates in /var/mail (outside the boot environments) for the
# users born with the upgrade (roundcube, acme): in the boot environment from before those users do not exist.
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

# The nginx logs: those that were there before and are now missing, if their new name is there.
if [ -f "$WORK/nginx-logs-before.txt" ]; then
    while read -r old; do
        [ -e "/var/log/nginx/$old" ] && continue
        # From Italian to English (2026-10-30), then to the product name (2026-11-17).
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

# /var/log with the name from before the product: what was there before and is now missing, if its new name is there.
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
