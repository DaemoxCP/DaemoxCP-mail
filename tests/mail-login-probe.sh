#!/bin/sh
# Un login vero sul server di posta appena installato: IMAP sulla 993 e SMTP sulla 587.
#
# Perche' esiste: il 24/10/2026 un'installazione da zero ha messo un Dovecot senza supporto
# MySQL, e nessun controllo se n'e' accorto. Tutti i servizi risultavano attivi, `doveconf -n`
# accettava la configurazione, le porte erano in ascolto; il guasto compariva solo alla prima
# connessione di qualcuno, nel registro:
#     auth: Fatal: Support not compiled in for passdb driver 'sql'
#     imap-login: Disconnected: Auth process broken
# «Il servizio gira» non dice niente su «una casella entra». Questa sonda lo chiede davvero.
#
# Che cosa fa, e che cosa lascia:
#  - crea un dominio e una casella di prova (login-probe.test, che nessuno puo' possedere:
#    .test e' riservato) nel database della posta, con una password casuale;
#  - prova `doveadm auth test`, un LOGIN IMAP sulla 993 e un AUTH PLAIN sulla 587 dopo
#    STARTTLS, cioe' i due ingressi delle caselle (la 587 passa per l'autenticazione di
#    Dovecot: smtpd_sasl_type = dovecot);
#  - mostra le righe di /var/log/maillog scritte nel frattempo;
#  - alla fine toglie casella, dominio e la cartella di posta creata dal login.
#
# La password di prova passa sulla riga di comando di doveadm e openssl: e' una credenziale
# usa e getta che la sonda crea e cancella, su una macchina di prova. Non usarla su un server
# con utenti veri.
#
# Uso, da root, sulla macchina installata:
#   sh tests/mail-login-probe.sh [database]          (predefinito: mailserver)
# La password di root di MySQL si prende da ./installed-mysql-root-password (la scrive
# InstallFromScratch) o, se non c'e', dal file dei segreti del pannello.
# Codice d'uscita: 0 se entrano tutti e tre, 1 altrimenti.

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
elif [ -f /usr/local/etc/mail-panel/panel-secrets.properties ]; then
    ROOT_PW=$(grep '^mysql_root_password=' /usr/local/etc/mail-panel/panel-secrets.properties | cut -d= -f2-)
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
