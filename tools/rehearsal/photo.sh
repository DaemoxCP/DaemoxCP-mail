#!/bin/sh
# La fotografia del banco: un boot environment, con dentro le copie delle due cartelle che stanno
# FUORI dai boot environment e che il passaggio tocca (/home/panel e /var/log). Senza quelle copie
# un clone riparte col jar e coi log di nginx dell'ultima prova, non con quelli della fotografia
# (reperti, punti 112 e 135).
#
# Uso, da root sulla VM:
#   photo.sh take NOME             le copie in /root/rehearsal-photo, poi bectl create NOME
#   photo.sh restore NOME CLONE    clone di NOME attivato al prossimo avvio, /home/panel e /var/log
#                                  rimessi dalle copie del clone; poi: shutdown -r now
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
COPIES=/root/rehearsal-photo

case "${1:-}" in
take)
    NAME=$2
    rm -rf "$COPIES"; mkdir -p "$COPIES"
    tar -cpf "$COPIES/home-panel.tar" -C /home panel
    tar -cpf "$COPIES/var-log.tar" -C /var log
    bectl create "$NAME"
    echo "snapshot $NAME: boot environment plus $COPIES (home-panel.tar, var-log.tar)"
    ;;
restore)
    NAME=$2; CLONE=$3
    bectl create -e "$NAME" "$CLONE"
    MNT=$(mktemp -d /tmp/photo.XXXXXX)
    bectl mount "$CLONE" "$MNT" >/dev/null
    cp -p "$MNT$COPIES/home-panel.tar" "$MNT$COPIES/var-log.tar" /var/tmp/
    bectl umount "$CLONE"; rmdir "$MNT"
    for svc in daemoxcp_mail mailpanel; do [ -f /usr/local/etc/rc.d/$svc ] && service $svc stop >/dev/null 2>&1; done; true
    rm -rf /home/panel
    tar -xpf /var/tmp/home-panel.tar -C /home
    # /var/log come nella fotografia, anche senza i file nati dopo: un log col nome nuovo rimasto
    # da una prova ferma la rinomina della superficie pubblica (BOTH_NAMES).
    find /var/log -mindepth 1 -delete
    tar -xpf /var/tmp/var-log.tar -C /var
    rm -f /var/tmp/home-panel.tar /var/tmp/var-log.tar
    bectl activate "$CLONE"
    echo "ready: $CLONE at the next boot. Now: shutdown -r now"
    ;;
*)
    echo "usage: $0 take NAME | restore NAME CLONE" >&2; exit 64 ;;
esac
