#!/bin/sh
# The snapshot of the test bench: a boot environment, with inside it the copies of the two folders that are
# OUTSIDE the boot environments and that the upgrade touches (/home/panel and /var/log). Without those copies
# a clone restarts with the jar and the nginx logs of the last test, not with those of the snapshot
# (findings, points 112 and 135).
#
# Usage, as root on the VM:
#   photo.sh take NAME             the copies in /root/rehearsal-photo, then bectl create NAME
#   photo.sh restore NAME CLONE    clone of NAME activated at the next boot, /home/panel and /var/log
#                                  put back from the copies of the clone; then: shutdown -r now
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
    # /var/log as in the snapshot, even without the files born afterwards: a log with the new name left over
    # from a test stops the rename of the public surface (BOTH_NAMES).
    find /var/log -mindepth 1 -delete
    tar -xpf /var/tmp/var-log.tar -C /var
    rm -f /var/tmp/home-panel.tar /var/tmp/var-log.tar
    bectl activate "$CLONE"
    echo "ready: $CLONE at the next boot. Now: shutdown -r now"
    ;;
*)
    echo "usage: $0 take NAME | restore NAME CLONE" >&2; exit 64 ;;
esac
