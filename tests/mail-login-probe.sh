#!/bin/sh
# A real login on the mail server just installed: IMAP on 993 and SMTP on 587.
#
# Why it exists: on 24/10/2026 an installation from scratch put in a Dovecot without MySQL support,
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
#  - it shows the lines of /var/log/maillog written meanwhile;
#  - at the end it removes mailbox, domain and the mail folder created by the login.
#
# The test password goes on the command line of doveadm and openssl: it is a throwaway credential
# the probe creates and deletes, on a test machine. Do not use it on a server with real users.
#
# Usage, as root, on the installed machine:
#   sh tests/mail-login-probe.sh [database]          (default: mailserver)
# The MySQL root password is taken from ./installed-mysql-root-password (InstallFromScratch writes
# it) or, if it is not there, from the panel's secrets file.
# Exit code: 0 if all three get in, 1 otherwise.

DB="${1:-mailserver}"
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
    fi
    rm -rf "/var/vmail/$DOMAIN"
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
    for f in /usr/local/etc/mail-panel/root-secrets.properties /usr/local/etc/mail-panel/panel-secrets.properties; do
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
echo "== /var/log/maillog, the lines written meanwhile =="
tail -n +"$((LOG_BEFORE + 1))" /var/log/maillog 2>/dev/null | grep -E 'auth|imap|submission|sasl|Fatal|Error' | sed 's/^/  /'

echo ""
if [ "$failed" -eq 0 ]; then
    echo "== all three logins succeeded =="
else
    echo "== AT LEAST ONE LOGIN FAILED =="
fi
exit "$failed"
