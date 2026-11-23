#!/bin/sh
# A real login on the mail server just installed: IMAP on 993 and SMTP on 587.
#
# Why it exists: on 2026-10-24 an installation from scratch put in a Dovecot without MySQL support,
# and no check noticed. All services showed as running, `doveconf -n` accepted the configuration,
# the ports were listening; the fault showed only at somebody's first connection, in the log:
#     auth: Fatal: Support not compiled in for passdb driver 'sql'
#     imap-login: Disconnected: Auth process broken
# "The service runs" says nothing about "a mailbox gets in". This probe really asks.
#
# What it does, and what it leaves:
#  - it creates a test domain and mailbox (login-probe.test, which nobody can own: .test is
#    reserved) in the mail database, with a random password;
#  - it tries `doveadm auth test`, an IMAP LOGIN on 993 and an AUTH PLAIN on 587 after STARTTLS,
#    that is the two ways into the mailboxes (587 goes through Dovecot's authentication:
#    smtpd_sasl_type = dovecot);
#  - a real Roundcube login on the webmail's nginx site, then the mailbox page, which opens only if Roundcube
#    decrypts the IMAP password from its session (finding 239), then the logout;
#  - Sieve (finding 214): a script of the mailbox's own through ManageSieve on 4190 (PUTSCRIPT,
#    SETACTIVE), a rule of the panel written as the panel writes it (root, /var/mail/sieve, sievec),
#    then a real delivery through Postfix: the panel's rule must run first and the mailbox's own
#    script after it, each filing a copy into its folder; `doveadm sieve list` must open the
#    mailbox's scripts, and no "dovecot.sieve" may show up among the mail folders; the script's
#    "duplicate" test writes Dovecot's duplicate database (.dovecot.lda-dupes, as autoreplies and
#    forwards do), and with the home in the mail root that showed up as folders too (finding 217);
#    then (finding 216) a panel's rule that moves, with no keep at the end as the panel writes it now:
#    the message only in the panel's folder, not in INBOX, and the mailbox's own script does not run on it;
#  - it shows the lines of /var/log/maillog written meanwhile;
#  - at the end it removes mailbox, domain, the mail folder created by the login and the rule.
#
# The test password goes on the command line of doveadm and openssl: it is a throwaway credential
# the probe creates and deletes, on a test machine. Do not use it on a server with real users.
#
# Usage, as root, on the installed machine:
#   sh tests/mail-login-probe.sh [database]          (default: daemoxcp_mail)
# The MySQL root password is taken from ./installed-mysql-root-password (InstallFromScratch writes
# it) or, if it is not there, from the panel's secrets file.
# Exit code: 0 if all four get in (doveadm, IMAP, SMTP, the webmail) and Sieve works, 1 otherwise.

DB="${1:-daemoxcp_mail}"
DOMAIN="login-probe.test"
MAILBOX="probe@$DOMAIN"

case "$DB" in
    *[!A-Za-z0-9_]*|"") echo "database name not valid: $DB"; exit 2 ;;
esac
if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root"; exit 2
fi

WORK=$(mktemp -d /var/tmp/mail-login-probe.XXXXXXXX) || exit 2
cleanup() {
    if [ -f "$WORK/root.cnf" ]; then
        mysql --defaults-extra-file="$WORK/root.cnf" "$DB" -e \
            "DELETE FROM mailboxes WHERE email='$MAILBOX'; DELETE FROM domains WHERE domain='$DOMAIN';" \
            >/dev/null 2>&1
        # The webmail login leaves Roundcube's row for the mailbox (its identities go with it).
        mysql --defaults-extra-file="$WORK/root.cnf" roundcubemail -e "DELETE FROM users WHERE username='$MAILBOX';" \
            >/dev/null 2>&1
    fi
    rm -rf "/var/vmail/$DOMAIN" "/var/mail/sieve/$DOMAIN"
    rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

ROOT_PW=""
if [ -f ./installed-mysql-root-password ]; then
    ROOT_PW=$(cat ./installed-mysql-root-password)
else
    # The panel writes the file with java.util.Properties, which escapes ! # = : with a backslash:
    # read as it is, the password would be wrong. The generator's alphabet has no backslash, so
    # dropping the escapes gives the password back.
    # Since the panel split its secrets the root password is in
    # root-secrets.properties; on a server not split yet it is still in panel-secrets.properties.
    for f in /usr/local/etc/daemoxcp-mail/root-secrets.properties /usr/local/etc/daemoxcp-mail/panel-secrets.properties; do
        [ -f "$f" ] || continue
        ROOT_PW=$(sed -n 's/^mysql_root_password=//p' "$f" | sed 's/\\\(.\)/\1/g')
        [ -n "$ROOT_PW" ] && break
    done
fi
if [ -z "$ROOT_PW" ]; then
    echo "MySQL root password not found"; exit 2
fi
cat > "$WORK/root.cnf" << EOCNF
[client]
user=root
password="$ROOT_PW"
EOCNF

echo "== the packages =="
pkg query -g '%n-%v' 'dovecot*' 2>/dev/null | sed 's/^/  /'

PW=$(openssl rand -hex 16)
HASH=$(doveadm pw -s BLF-CRYPT -p "$PW" 2>/dev/null)
case "$HASH" in
    "{BLF-CRYPT}"*) ;;
    *) echo "doveadm pw did not give a BLF-CRYPT hash"; exit 2 ;;
esac

if ! mysql --defaults-extra-file="$WORK/root.cnf" "$DB" << EOSQL
DELETE FROM mailboxes WHERE email='$MAILBOX';
DELETE FROM domains WHERE domain='$DOMAIN';
INSERT INTO domains (domain, active) VALUES ('$DOMAIN', 1);
INSERT INTO mailboxes (domain_id, email, password, name, active)
    SELECT id, '$MAILBOX', '$HASH', 'login probe', 1 FROM domains WHERE domain='$DOMAIN';
EOSQL
then
    echo "cannot create the probe mailbox in $DB"; exit 2
fi
echo "== probe mailbox $MAILBOX created =="

LOG_BEFORE=$(wc -l < /var/log/maillog 2>/dev/null | tr -d ' ')
failed=0

echo ""
echo "== doveadm auth test =="
timeout 40 doveadm auth test "$MAILBOX" "$PW" > "$WORK/auth.out" 2>&1
sed 's/^/  /' "$WORK/auth.out"
if grep -q "auth succeeded" "$WORK/auth.out"; then
    echo "  RESULT: OK"
else
    echo "  RESULT: FAILED"; failed=1
fi

echo ""
echo "== IMAP LOGIN on 993 =="
{ sleep 2; printf 'a LOGIN "%s" "%s"\r\n' "$MAILBOX" "$PW"; sleep 15; printf 'b LOGOUT\r\n'; sleep 2; } \
    | timeout 40 openssl s_client -connect 127.0.0.1:993 -quiet -ign_eof > "$WORK/imap.out" 2>/dev/null
tr -d '\r' < "$WORK/imap.out" | sed 's/^/  /'
if tr -d '\r' < "$WORK/imap.out" | grep -q '^a OK'; then
    echo "  RESULT: OK"
else
    echo "  RESULT: FAILED"; failed=1
fi

echo ""
echo "== SMTP AUTH PLAIN on 587, after STARTTLS =="
B64=$(printf '\000%s\000%s' "$MAILBOX" "$PW" | openssl base64 -A)
{ sleep 2; printf 'EHLO login-probe\r\n'; sleep 2; printf 'AUTH PLAIN %s\r\n' "$B64"; sleep 15; printf 'QUIT\r\n'; sleep 2; } \
    | timeout 40 openssl s_client -starttls smtp -connect 127.0.0.1:587 -quiet -ign_eof > "$WORK/smtp.out" 2>/dev/null
tr -d '\r' < "$WORK/smtp.out" | grep -v '^250-' | sed 's/^/  /'
if tr -d '\r' < "$WORK/smtp.out" | grep -q '^235'; then
    echo "  RESULT: OK"
else
    echo "  RESULT: FAILED"; failed=1
fi

echo ""
echo "== Webmail: a real Roundcube login, then the mailbox =="
# Roundcube keeps the IMAP password in its session, encrypted with des_key and cipher_method (finding 239): the
# mailbox page opens only if Roundcube decrypts it and logs into IMAP with it on that request. The site is the nginx
# server whose root is Roundcube's; the password goes in a file, not on curl's command line.
WM=$(nginx -T 2>/dev/null | awk '
    /^[ \t]*server[ \t]*\{/ { name = ""; port = ""; rc = 0 }
    /^[ \t]*listen[ \t]/ && port == "" { p = $2; sub(/;$/, "", p); n = split(p, a, ":"); port = a[n] }
    /^[ \t]*server_name[ \t]/ && name == "" { name = $2; sub(/;$/, "", name) }
    /^[ \t]*root[ \t]+\/usr\/local\/www\/roundcube(\/public_html)?\/?;/ { rc = 1 }
    rc && name != "" && port != "" { print name ":" port; exit }')
if [ -z "$WM" ]; then
    echo "  no nginx server serves Roundcube"
    echo "  RESULT: FAILED"; failed=1
else
    WM_HOST=${WM%:*}; WM_PORT=${WM##*:}
    WM_URL="https://$WM_HOST:$WM_PORT/"
    wm() { curl -sk -m 30 --resolve "$WM_HOST:$WM_PORT:127.0.0.1" -c "$WORK/wm.cookies" -b "$WORK/wm.cookies" "$@"; }
    wm -o "$WORK/wm1.html" "$WM_URL"
    WM_TOKEN=$(sed -n 's/.*name="_token" value="\([A-Za-z0-9]*\)".*/\1/p' "$WORK/wm1.html" | head -1)
    printf '_token=%s&_task=login&_action=login&_timezone=UTC&_url=&_user=%s&_pass=%s' \
        "$WM_TOKEN" "$(printf '%s' "$MAILBOX" | sed 's/@/%40/')" "$PW" > "$WORK/wm.post"
    WM_CODE=$(wm -o "$WORK/wm2.html" -w '%{http_code}' --data-binary @"$WORK/wm.post" "${WM_URL}?_task=login")
    wm -L -o "$WORK/wm3.html" "${WM_URL}?_task=mail&_mbox=INBOX"
    echo "  $WM_HOST:$WM_PORT, login page token: $([ -n "$WM_TOKEN" ] && echo yes || echo no), login answered $WM_CODE"
    # The folder list comes from IMAP: with IMAP refused Roundcube still draws the mail page, with an error and no
    # folders (measured on the VM with des_key changed after the login: "task":"mail" and the logout link were there).
    if grep -q '"mailboxes":{"INBOX"' "$WORK/wm3.html" && ! grep -q 'rcmloginuser' "$WORK/wm3.html"; then
        echo "  the mailbox opened, with its folders from IMAP"
        echo "  RESULT: OK"
        WM_REQ=$(sed -n 's/.*"request_token":"\([A-Za-z0-9]*\)".*/\1/p' "$WORK/wm3.html" | head -1)
        [ -n "$WM_REQ" ] && wm -o /dev/null "${WM_URL}?_task=logout&_token=$WM_REQ"
    else
        echo "  the mailbox did not open (login form: $(grep -c rcmloginuser "$WORK/wm3.html"), IMAP error: $(grep -c 'display_message(' "$WORK/wm3.html"))"
        echo "  RESULT: FAILED"; failed=1
    fi
fi

echo ""
echo "== Sieve: the mailbox's own script through ManageSieve, the panel's rule before it =="
USERDIR=$(printf '%s' "$MAILBOX" | cut -d@ -f1)
# "duplicate" writes Dovecot's duplicate database in the home, as autoreplies and forwards do (finding 217).
printf 'require ["fileinto","mailbox","duplicate"];\r\nif header :contains "subject" "sieve-probe" { if not duplicate { fileinto :create "SieveProbeOwn"; } }\r\n' > "$WORK/own.sieve"
LEN=$(wc -c < "$WORK/own.sieve" | tr -d ' ')
{ sleep 2; printf 'AUTHENTICATE "PLAIN" "%s"\r\n' "$B64"; sleep 2
  printf 'PUTSCRIPT "probe" {%s+}\r\n' "$LEN"; cat "$WORK/own.sieve"; printf '\r\n'; sleep 2
  printf 'SETACTIVE "probe"\r\n'; sleep 1; printf 'LISTSCRIPTS\r\n'; sleep 1; printf 'LOGOUT\r\n'; sleep 1; } \
    | timeout 40 nc 127.0.0.1 4190 > "$WORK/sieve.out" 2>&1
tr -d '\r' < "$WORK/sieve.out" | grep -v '^"' | sed 's/^/  /'
tr -d '\r' < "$WORK/sieve.out" | grep '^"probe"' | sed 's/^/  /'
# The panel's rule, as SieveGenerator writes it: root, under /var/mail/sieve, compiled with sievec.
mkdir -p "/var/mail/sieve/$DOMAIN/$USERDIR"
printf 'require ["fileinto","copy","mailbox"];\nif header :contains "subject" "sieve-probe" { fileinto :copy :create "SieveProbePanel"; }\n' \
    > "/var/mail/sieve/$DOMAIN/$USERDIR/.dovecot.sieve"
sievec "/var/mail/sieve/$DOMAIN/$USERDIR/.dovecot.sieve" >/dev/null 2>&1
SIEVE_LOG=$(wc -l < /var/log/maillog 2>/dev/null | tr -d ' ')
printf 'From: root@%s\nTo: %s\nSubject: sieve-probe %s\n\nSieve probe\n' "$DOMAIN" "$MAILBOX" "$(date +%s)" > "$WORK/msg.eml"
sendmail -f "root@$DOMAIN" "$MAILBOX" < "$WORK/msg.eml"
for i in $(seq 1 30); do
    [ "$(tail -n +"$((SIEVE_LOG + 1))" /var/log/maillog | grep -c "lmtp($MAILBOX).*stored mail into mailbox")" -ge 2 ] && break
    sleep 1
done
tail -n +"$((SIEVE_LOG + 1))" /var/log/maillog | grep "lmtp($MAILBOX)" | sed 's/^.*: sieve: /  sieve: /; s/^.*lmtp(/  lmtp(/'
LISTED=$(doveadm sieve list -u "$MAILBOX" 2>&1)
FOLDERS=$(doveadm mailbox list -u "$MAILBOX" 2>&1 | tr '\n' ' ')
echo "  doveadm sieve list: $LISTED"
echo "  folders: $FOLDERS"
if tr -d '\r' < "$WORK/sieve.out" | grep -q '^"probe" ACTIVE' \
    && [ "$(doveadm search -u "$MAILBOX" mailbox SieveProbePanel subject sieve-probe 2>/dev/null | wc -l | tr -d ' ')" -eq 1 ] \
    && [ "$(doveadm search -u "$MAILBOX" mailbox SieveProbeOwn subject sieve-probe 2>/dev/null | wc -l | tr -d ' ')" -eq 1 ] \
    && printf '%s' "$LISTED" | grep -q '^probe ACTIVE' && ! printf '%s' "$FOLDERS" | grep -q 'dovecot'; then
    echo "  RESULT: OK"
else
    echo "  RESULT: FAILED"; failed=1
fi

echo ""
echo "== Sieve: a panel's rule that moves, as the panel writes it (no keep at the end) =="
# Finding 216: a move in the panel's rule must take the message out of INBOX, and then the mailbox's own script does
# not run on it (Pigeonhole runs the next script only while a keep is in effect). The own script above would file it
# too: its subject contains "sieve-probe".
printf 'require ["fileinto","mailbox"];\nif header :contains "subject" "sieve-move" { fileinto :create "SieveProbePanel"; }\n' \
    > "/var/mail/sieve/$DOMAIN/$USERDIR/.dovecot.sieve"
sievec "/var/mail/sieve/$DOMAIN/$USERDIR/.dovecot.sieve" >/dev/null 2>&1
MOVE_LOG=$(wc -l < /var/log/maillog 2>/dev/null | tr -d ' ')
printf 'From: root@%s\nTo: %s\nSubject: sieve-probe sieve-move %s\n\nSieve probe\n' "$DOMAIN" "$MAILBOX" "$(date +%s)" > "$WORK/move.eml"
sendmail -f "root@$DOMAIN" "$MAILBOX" < "$WORK/move.eml"
for i in $(seq 1 30); do
    [ "$(tail -n +"$((MOVE_LOG + 1))" /var/log/maillog | grep -c "lmtp($MAILBOX).*stored mail into mailbox")" -ge 1 ] && break
    sleep 1
done
sleep 1
tail -n +"$((MOVE_LOG + 1))" /var/log/maillog | grep "lmtp($MAILBOX)" | sed 's/^.*: sieve: /  sieve: /; s/^.*lmtp(/  lmtp(/'
MOVED=$(doveadm search -u "$MAILBOX" mailbox SieveProbePanel subject sieve-move 2>/dev/null | wc -l | tr -d ' ')
OWN=$(doveadm search -u "$MAILBOX" mailbox SieveProbeOwn subject sieve-move 2>/dev/null | wc -l | tr -d ' ')
INBOX=$(doveadm search -u "$MAILBOX" mailbox INBOX subject sieve-move 2>/dev/null | wc -l | tr -d ' ')
echo "  in the panel's folder: $MOVED, in the own script's folder: $OWN, in INBOX: $INBOX"
if [ "$MOVED" -eq 1 ] && [ "$OWN" -eq 0 ] && [ "$INBOX" -eq 0 ]; then
    echo "  RESULT: OK"
else
    echo "  RESULT: FAILED"; failed=1
fi

echo ""
echo "== /var/log/maillog, the lines written meanwhile =="
tail -n +"$((LOG_BEFORE + 1))" /var/log/maillog 2>/dev/null | grep -E 'auth|imap|submission|sasl|Fatal|Error' | sed 's/^/  /'

echo ""
if [ "$failed" -eq 0 ]; then
    echo "== all four logins succeeded, and Sieve works =="
else
    echo "== AT LEAST ONE CHECK FAILED =="
fi
exit "$failed"
