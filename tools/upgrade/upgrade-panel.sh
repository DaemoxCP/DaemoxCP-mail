#!/bin/sh
# The upgrade of the mail panel to a new jar, on a server already running: the same round that was
# tested on the VM from the panel of 11 October (findings, point 135). It stops at the first wrong
# sign, and from that moment on it no longer touches anything: it says what it saw and how to go back.
#
# Usage, as root:
#   upgrade-panel.sh [-m MAILBOX -p PASSWORD_FILE] NEW_JAR JAR_SHA256
#
#   NEW_JAR         the jar to put in place of the one that is running; nothing is touched until its
#                   fingerprint is the expected one
#   JAR_SHA256      the expected fingerprint, taken from where the jar was built, not from the jar itself
#   -m MAILBOX      a mailbox on which to test, before and after, IMAP login, delivery and webmail
#   -p PASSWORD_FILE the file with its password, one line, for root only (0600 or 0400)
#
# What it does, in order:
#   1. the checks: root, fingerprint, panel running as a service, boot environment, space, no
#      pkg in progress;
#   2. the snapshot of the state (services, ports, configurations, MTA-STS, webmail, locked
#      packages, and the mailbox if there is one);
#   3. stops the panel (the mail stays up), creates the boot environment, copies the folder of the
#      panel, which is outside the boot environments, with the jar from before;
#   4. puts the new jar in place and starts it; waits for the migrations to finish and reads them in
#      the log: they must say DONE, or nothing;
#   5. the state, which must be equal to the snapshot;
#   6. a second start, which must not find anything more to do;
#   7. the state again.
# What it sees it writes into a folder next to the one of the panel (it prints the name at the
# start), so outside the boot environment: it stays there even when going back.

set -u
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077

# The service of the panel: daemoxcp_mail since DaemoxCP Mail (2026-11-17), mailpanel before. The first start of
# the new jar renames it by itself (PanelServiceRename) while this script waits, so the name is read again every time.
service_name() {
    if [ -f /usr/local/etc/rc.d/daemoxcp_mail ]; then echo daemoxcp_mail; else echo mailpanel; fi
}
RC=/usr/local/etc/rc.d/$(service_name)
BOOT_TIMEOUT=900      # seconds: AcmeUser can install acme.sh from the network
STOP_TIMEOUT=60
MIN_FREE_KB=1048576   # 1 GiB free in the boot environment's pool

usage() {
    echo "usage: $0 [-m MAILBOX -p PASSWORD_FILE] NEW_JAR JAR_SHA256" >&2
    echo "       $0 --check-log FILE first|second" >&2
    exit 64
}

# The announcement of LocalMtaRepair, written as a warning but expected on the servers installed before
# Postfix was the local MTA (the production server has myorigin = the host name): it says what is about to
# change, and right after it "Postfix is now the local MTA" says that it is done. It is a migration, not
# a wrong sign; if it does not succeed, the lines after it are real warnings and they stop.
LOCAL_MTA_NOTICE='^WARNING: \[LocalMta\] (myorigin .* is not in mydestination: it becomes localhost first|sendmail\(8\) hands over to dma: )'

# The lines that stop: every warning or error, the exceptions, and the names found twice.
bad_lines() {
    grep -nE '^(WARNING|SEVERE):|Exception|Both .* exist|Could not rename|FAILED|failed:' "$1" \
        | grep -vE "^[0-9]+:${LOCAL_MTA_NOTICE#^}"
}

# What the migrations did: at the first start they are read, at the second there must be none.
# The lines of the checks that pass ("Alias map OK", "already hands over") do not count.
migration_lines() {
    grep -nE "^(INFO|WARNING|SEVERE): (\[[A-Za-z0-9]+\] [A-Z_]+: |Renamed |\[CommentRepair\] comments repaired|\[LocalMta\] Postfix is now|\[PostfixAliases\] Auto-fix|Mail stack packages locked at startup)|${LOCAL_MTA_NOTICE}" "$1"
}

# Only the reading of a piece of log, with the rules of the upgrade: to read a start again by hand, and
# to test the rules on logs built on purpose. "first": the migrations are listed, the warnings
# stop; "second": even a single migration stops. Exits 1 if the log would stop the upgrade.
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

# The value that the start script will use (jar, dir, log...): rc.conf if it is there, otherwise its default value.
# With the current service, which changes name during the first start.
rc_setting() {
    s=$(service_name)
    v=$(sysrc -n "${s}_$1" 2>/dev/null)
    [ -n "$v" ] || v=$(sed -n 's/^: \${'"${s}_$1"':="\(.*\)"}$/\1/p' "/usr/local/etc/rc.d/$s" 2>/dev/null | head -1)
    printf '%s\n' "$v"
}

# How to go back, said with the real names of this upgrade.
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

# --- 1. the checks ------------------------------------------------------------------------------

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

# The folder of the job next to the one of the panel: on the same dataset, outside the boot
# environment if the panel is in /home as on the server.
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

# --- 2. the snapshot ----------------------------------------------------------------------------

# The state that must stay the same after the upgrade, one line per thing. No passwords and no
# contents: only outcomes.
# The services of the packages enabled in rc.conf: those of "service -e", with the same computation (name,
# rcvar, load_rc_config_var of rc.subr), but without checkyesno. For the scripts that give the default value
# only inside themselves (sentinel of redis, pkg_triggers, mysqlrouter, clamav_milter) checkyesno writes
# "WARNING: $..._enable is not set properly" in the system log at every call, even with 2>/dev/null: 4 lines
# per snapshot, 12 per update (measured on 2026-11-20; same list as service -e, tested on the VM).
enabled_local() (
    . /etc/rc.subr
    for file in /usr/local/etc/rc.d/*; do
        [ -f "$file" ] && grep -q '^rcvar' "$file" || continue
        name=; rcvar=
        eval "$(grep '^name=' "$file")"
        eval "$(grep '^rcvar' "$file")"
        [ -n "$rcvar" ] || continue
        load_rc_config_var "$name" "$rcvar"
        eval "v=\${$rcvar:-}"
        case "$v" in [Yy][Ee][Ss]|[Tt][Rr][Uu][Ee]|[Oo][Nn]|1) echo "${file##*/}" ;; esac
    done
)

state() {
    # In order of name: service -e follows rcorder, which changes when a package is added.
    # Not the panel, with both names: the first start renames it.
    for s in $(enabled_local | grep -vxE 'mailpanel|daemoxcp_mail' | sort); do
        printf 'service %s: %s\n' "$s" "$(service "$s" status >/dev/null 2>&1 && echo up || echo DOWN)"
    done
    printf 'mysqld: %s\n' "$(pgrep -q mysqld && echo up || echo DOWN)"
    # The MySQL ports: 33060 (X protocol) and the address of 3306 are closed by the panel itself
    # at the first start (MysqlListen, which verifies it and if it does not work puts it back as it was).
    # Here they count as a single line, so that closing them does not look like a fault; that MySQL is
    # running is said by the mysqld line.
    # The same for POP3 (110, 995): the panel turns it on or off as the administrator chose, off
    # until they choose (Pop3, which verifies that IMAP still answers and if not puts it back as it
    # was); IMAP stays in the snapshot.
    # And 24 and 6379, on 127.0.0.1 and ::1: the panel closes them at the first start, when Postfix
    # delivers to Dovecot from the socket in its queue (LmtpSocket, finding 234) and rspamd talks to
    # redis over the socket (RedisSocket, 235). Both test a delivery and a scan before and after, and
    # if it does not work they put the port back.
    # 4190 (ManageSieve) counts for its name and not for the address: the first start moves it from all
    # the interfaces to 127.0.0.1, where the webmail uses it (ManageSieveLocal, which after the restart
    # of Dovecot verifies authentication, IMAP and the ManageSieve greeting, and if not puts it back as
    # it was). If Dovecot stopped listening on it, the line would disappear.
    sockstat -46l -P tcp 2>/dev/null | awk 'NR > 1 {a = $6; if (a ~ /:(33060|110|995)$/) next; if (a ~ /^(127\.0\.0\.1|\[::1\]):(24|6379)$/) next; if (a ~ /:3306$/) a = "MySQL 3306"; if (a ~ /:4190$/) a = "ManageSieve 4190"; print "listening port: " a}' | sort -u
    printf 'nginx -t: %s\n' "$(nginx -t >/dev/null 2>&1 && echo ok || echo ERROR)"
    printf 'postfix check: %s\n' "$(postfix check >/dev/null 2>&1 && echo ok || echo ERROR)"
    printf 'doveconf: %s\n' "$(doveconf -n >/dev/null 2>&1 && echo ok || echo ERROR)"
    printf 'fail2ban: %s\n' "$(timeout -f 20 fail2ban-client ping >/dev/null 2>&1 && echo answers || echo NOT ANSWERING)"
    printf 'panel on 2096: %s\n' "$(curl -sk -m 15 -o /dev/null -w '%{http_code}' https://127.0.0.1:2096/)"
    # MTA-STS: from the nginx files that serve the policy, requested at each of their names. On the
    # server (and on the test bench) 443 is the default site, "server_name _": it answers to any name,
    # so it is requested at the local address. Without any file it says so, so that a disappearance too
    # changes the state (the first version looked for "mta-sts." among the names and checked nothing).
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

# The locked packages, one per line. They are compared separately: at startup the new panel also locks
# the packages of the stack that were not locked (UpdateManager.applyLockPolicy) and unlocks none of
# them, so the list can grow; the ones from before must all stay in it.
locked() {
    pkg query -e '%k = 1' '%n' 2>/dev/null | sort
}

# The comparison with the snapshot: the state the same, and no locked package lost.
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

# IMAP login, delivery and webmail with the given mailbox: the password never leaves its file.
mailbox_state() {
    printf 'mailbox login: %s\n' "$(timeout -f 20 doveadm auth test "$MAILBOX" < "$PASSFILE" >/dev/null 2>&1 && echo ok || echo REFUSED)"
    token="panel-upgrade-$STAMP-$(date +%s)"
    # The sendmail of Postfix, not /usr/sbin/sendmail: before the upgrade that one can still go to
    # dma (mailer.conf), which delivers outside instead of into the mailbox.
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
# Only at the end of the line: the first line of a page (MTA-STS) can contain any word.
grep -E ': (DOWN|ERROR|NOT ANSWERING|REFUSED)$|: NOT ARRIVED within' "$WORK/state-before.txt" > "$WORK/already-wrong.txt"
if [ -s "$WORK/already-wrong.txt" ]; then
    cat "$WORK/already-wrong.txt"
    fail "something is already wrong before the upgrade (above): fix that first"
fi
say "Snapshot: $(wc -l < "$WORK/state-before.txt" | tr -d ' ') lines, all fine; $(wc -l < "$WORK/locked-before.txt" | tr -d ' ') locked packages"

# --- 3. panel stopped, boot environment, copies -------------------------------------------------

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
# The access log of the panel with its current name or the one from before (AuthJailRename renames it), and
# what is in /var/log: it is outside the boot environments, and rollback-panel.sh puts back the old names.
for f in /var/log/daemoxcp-mail-auth.log /var/log/mail-panel-auth.log; do
    # With the numbers, not with the names: the first start renames the user of the web part, and before the
    # reboot into the boot environment from before chown would no longer know the old name (seen on the VM on
    # 2026-11-17).
    [ -f "$f" ] && stat -f '%u:%g %N' "$f" > "$WORK/auth-log-owner-before.txt" && break
done
ls -1 /var/log > "$WORK/var-log-before.txt" 2>/dev/null
say "Copy of the panel folder: $WORK/panel-dir.tar"

# --- 4. the new jar and the first start ---------------------------------------------------------

STEP="new jar"
cp "$NEW_JAR" "$JAR.new" && [ "$(sha256 -q "$JAR.new")" = "$NEW_SHA" ] \
    || { rm -f "$JAR.new"; service "$SVC" start >/dev/null 2>&1; fail "the copy of the new jar does not match (panel started again with the previous jar)"; }
chown "$(stat -f %Su:%Sg "$JAR")" "$JAR.new"
chmod "$(stat -f %Lp "$JAR")" "$JAR.new"
mv -f "$JAR.new" "$JAR"
SWAPPED=yes
say "New jar in place: $NEW_SHA"

# The log from the mark onwards. The file is looked up by inode first, because daemon(8) always writes
# the same file even if it changes name: the new panel can rename it (PathMigration) without the start
# script knowing, and that is exactly the defect that #89 fixed. If the start script set it aside
# (.1, over 10 MB), the rest is in the new file.
segment() {
    # The folder of the log from before, and the one where the first start moves it (DataFolderRename): same inode.
    for f in $(find "$LOG_DIR" /var/db/daemoxcp-mail /var/db/mailpanel -maxdepth 1 -type f -inum "$LOG_INODE" 2>/dev/null) \
             "$(rc_setting log)" "$LOG_BEFORE"; do
        [ -f "$f" ] && grep -qF "$1" "$f" || continue
        awk -v m="$1" 'found {print} index($0, m) {found = 1}' "$f"
        case $f in *.1) [ -f "${f%.1}" ] && cat "${f%.1}" ;; esac
        return
    done
}

# Starts (or restarts) and waits for the end of the startup: the line of the started server arrives after
# the migrations of the main thread, the ACME one after AcmeUser and ServiceUsers. With the separated panel
# (PanelSeparation) the line is the one of the root part being ready: the port is held by the web part.
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

# --- 5. the state after the first start ---------------------------------------------------------

STEP="state after the first start"
compare first-start
say "State after the first start: same as the snapshot"

# --- 6. the second start ------------------------------------------------------------------------

STEP="second start"
boot second-start restart
migration_lines "$WORK/second-start.log" > "$WORK/second-start-migrations.txt"
bad_lines "$WORK/second-start.log" > "$WORK/second-start-bad.txt"
if [ -s "$WORK/second-start-migrations.txt" ] || [ -s "$WORK/second-start-bad.txt" ]; then
    cat "$WORK/second-start-migrations.txt" "$WORK/second-start-bad.txt"
    fail "the second start had to be silent, and wrote the lines above"
fi

# --- 7. the state again -------------------------------------------------------------------------

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
