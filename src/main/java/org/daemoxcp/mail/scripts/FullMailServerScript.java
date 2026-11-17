package org.daemoxcp.mail.scripts;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║              Complete Mail Server Installation Script for FreeBSD            ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  This script installs and configures the complete mail server stack:         ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  COMPONENTS INSTALLED                                                   │ ║
 * ║  ├─────────────────────────────────────────────────────────────────────────┤ ║
 * ║  │  1. Postfix (SMTP)        - ports 25/587/465                            │ ║
 * ║  │     • Virtual users via MySQL                                           │ ║
 * ║  │     • SASL auth via Dovecot                                             │ ║
 * ║  │     • Config: /usr/local/etc/postfix/                                   │ ║
 * ║  │                                                                         │ ║
 * ║  │  2. Dovecot (IMAP)        - ports 143/993                               │ ║
 * ║  │     • LMTP via private/dovecot-lmtp                                     │ ║
 * ║  │     • SASL authentication for Postfix                                   │ ║
 * ║  │     • Mailboxes in /var/vmail/{domain}/{user}                           │ ║
 * ║  │                                                                         │ ║
 * ║  │  3. Rspamd (Anti-Spam)    - port 11332 (milter)                         │ ║
 * ║  │     • Integrated with Postfix via milter                                │ ║
 * ║  │                                                                         │ ║
 * ║  │  4. ClamAV (Antivirus)    - integrated with Rspamd                      │ ║
 * ║  │                                                                         │ ║
 * ║  │  5. Redis                 - Unix socket only, cache for Rspamd          │ ║
 * ║  │                                                                         │ ║
 * ║  │  6. MySQL 8.0             - port 3306, mail database                    │ ║
 * ║  │                                                                         │ ║
 * ║  │  7. Self-signed SSL       - temporary, replace with Let's Encrypt       │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
public class FullMailServerScript {

    public boolean writed = false;
    private static final String SCRIPT_PATH = "./install_scripts/install_mail_server.sh";

    private final String data = """
#!/bin/sh
# =============================================================================
# FreeBSD Mail Server - Complete Installation Script (Postfix Edition)
# =============================================================================
# Installs: Postfix, Dovecot, Rspamd, ClamAV, Roundcube, MySQL, SSL
# =============================================================================

MYSQL_HOST="$1"
MYSQL_PORT="$2"
MYSQL_USER="$3"
MYSQL_DATABASE="$4"
MAIL_HOSTNAME="$5"
ROUNDCUBE_DOMAIN="$6"
ROUNDCUBE_PORT="$7"
ROUNDCUBE_SSL_CERT="$8"
ROUNDCUBE_SSL_KEY="$9"
ROUNDCUBE_SSL_CHAIN="${10}"

# Le due password NON sono argomenti: arrivano dall'ambiente, perche' la riga di comando
# di un processo la legge chiunque con "ps" per tutto il tempo che l'installazione dura.
#   MYSQL_PASSWORD        quella dell'utente del pannello
#   MYSQL_ROOT_PASSWORD   quella di root, generata dal pannello e tenuta nel file dei segreti
# Chi lancia questo script a mano deve esportarle.
# Dall'ambiente arriva anche ROUNDCUBE_DB_PASSWORD, quella dell'utente MySQL della webmail
# (roundcube), anche lei nel file dei segreti: la webmail non entra piu' come il pannello.

# Colors. Con printf, non fra apici: l'echo di /bin/sh su FreeBSD non interpreta \\033, e il log
# dell'installazione mostrava "\\033[1;33m[PHASE 6/10]" scritto a lettere (33 righe, misurato).
RED=$(printf '\\033[0;31m')
GREEN=$(printf '\\033[0;32m')
YELLOW=$(printf '\\033[1;33m')
CYAN=$(printf '\\033[0;36m')
NC=$(printf '\\033[0m')

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "${RED}Error: Must run as root${NC}"
    exit 1
fi

# =============================================================================
# Il turno dei lavori sui pacchetti: lo stesso del pannello
# =============================================================================
# Questo script toglie e rimette pacchetti mentre la posta e' spenta. Se intanto il pannello
# aggiorna o protegge pacchetti (una manutenzione dalla pagina Aggiornamenti, o la regola dei
# blocchi a un suo avvio), i due si tolgono le protezioni a vicenda e pkg si ferma a meta'. Il
# pannello lo evita col turno: chi lavora sui pacchetti tiene un lock su PACKAGE_TURN_LOCK
# (PackageQueue.TURN_LOCK_PATH), e dentro scrive chi e'.
#  - Lanciato dal menu del pannello (DAEMOXCP_MAIL_PACKAGE_TURN = pid del pannello): il turno lo
#    tiene gia' il pannello, che e' il processo padre. Non lo si crede: si controlla che il lock
#    sia preso e che dentro ci sia scritto quel pid.
#  - Lanciato a mano: si prende il turno rilanciandosi sotto lockf(1). Se lo tiene qualcun
#    altro ci si ferma qui, prima di fermare qualunque cosa.
# Misurato il 06/11/2026 sulla VM FreeBSD 15.1 (reperto 153): il lock di lockf (flock) e quello
# del pannello (fcntl, FileChannel.tryLock) si escludono in tutte e due le direzioni. Due modi
# di usare lockf invece non vanno: senza -k cancella il file alla fine (e un pannello che lo
# tiene aperto non escluderebbe piu' chi ne crea uno nuovo); e "exec 9>>file; lockf 9" fa
# ereditare il lock a ogni figlio della shell, cioe' anche ai servizi che lo script avvia, che
# lo terrebbero per sempre. Con "lockf -k file comando" il comando non eredita il descrittore.
PACKAGE_TURN_LOCK=/var/db/daemoxcp-mail/package-turn.lock

# Vero se qualcuno tiene il turno. lockf esce 75 (EX_TEMPFAIL) se il lock e' gia' preso; se lo
# prende, lo rilascia subito. Ogni altro codice (il file non si apre) non e' "preso".
turn_is_held() {
    lockf -k -s -t 0 "$PACKAGE_TURN_LOCK" true
    [ $? -eq 75 ]
}

if [ -n "${DAEMOXCP_MAIL_PACKAGE_TURN:-}" ]; then
    TURN_HOLDER=$(head -n 1 "$PACKAGE_TURN_LOCK" 2>/dev/null)
    if [ "$DAEMOXCP_MAIL_PACKAGE_TURN" != "$PPID" ] || ! turn_is_held || [ "${TURN_HOLDER#pid $PPID,}" = "$TURN_HOLDER" ]; then
        echo "${RED}STOPPED: started as the installation of DaemoxCP Mail, but the panel does not hold the package turn.${NC}"
        echo "Turn lock $PACKAGE_TURN_LOCK says: ${TURN_HOLDER:-nothing}"
        echo "Nothing was stopped and nothing was changed."
        exit 1
    fi
elif [ "${DAEMOXCP_MAIL_TURN_BY_LOCKF:-}" = "1" ]; then
    # Il rilancio sotto lockf: il turno lo tiene lockf, il processo padre.
    if [ "$(ps -o comm= -p "$PPID")" != "lockf" ] || ! turn_is_held; then
        echo "${RED}STOPPED: DAEMOXCP_MAIL_TURN_BY_LOCKF is set, but this script is not running under lockf holding the package turn.${NC}"
        echo "Nothing was stopped and nothing was changed."
        exit 1
    fi
    echo "pid $$, complete mail server installation, install_mail_server.sh started by hand ($(date -u +%Y-%m-%dT%H:%M:%SZ))" > "$PACKAGE_TURN_LOCK"
else
    if [ ! -f "$0" ]; then
        echo "${RED}Error: run this script by its path (sh /path/to/install_mail_server.sh), not from standard input.${NC}"
        exit 1
    fi
    mkdir -p "$(dirname "$PACKAGE_TURN_LOCK")"
    if turn_is_held; then
        echo "${RED}STOPPED: another job is working on the packages:${NC}"
        sed 's/^/  /' "$PACKAGE_TURN_LOCK"
        echo "Nothing was stopped and nothing was changed. Wait for it to finish, then run this script again."
        exit 1
    fi
    export DAEMOXCP_MAIL_TURN_BY_LOCKF=1
    exec lockf -k -t 0 "$PACKAGE_TURN_LOCK" /bin/sh "$0" "$@"
    echo "${RED}Error: cannot start lockf.${NC}"
    exit 1
fi

echo ""
echo "${CYAN}=============================================================================${NC}"
echo "${CYAN}           FreeBSD Mail Server - Complete Installation (Postfix)${NC}"
echo "${CYAN}=============================================================================${NC}"
echo ""

# Validate parameters
if [ -z "$MYSQL_PASSWORD" ]; then
    echo "${RED}Error: MYSQL_PASSWORD not in the environment${NC}"
    exit 1
fi

if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
    echo "${RED}Error: MYSQL_ROOT_PASSWORD not in the environment${NC}"
    exit 1
fi

if [ -z "$ROUNDCUBE_DB_PASSWORD" ]; then
    echo "${RED}Error: ROUNDCUBE_DB_PASSWORD not in the environment${NC}"
    exit 1
fi

if [ -z "$MAIL_HOSTNAME" ]; then
    MAIL_HOSTNAME="mail.$(hostname)"
    echo "${YELLOW}Warning: Mail hostname not provided, using: $MAIL_HOSTNAME${NC}"
fi

# Roundcube is REQUIRED
if [ -z "$ROUNDCUBE_DOMAIN" ]; then
    echo ""
    echo "${RED}=============================================================================${NC}"
    echo "${RED}  ERROR: Roundcube domain not configured!${NC}"
    echo "${RED}=============================================================================${NC}"
    echo ""
    echo "Please configure Roundcube first from the panel menu."
    exit 1
fi

if [ -z "$ROUNDCUBE_PORT" ]; then
    ROUNDCUBE_PORT="8443"
fi

echo "Configuration:"
echo "  MySQL Host:     $MYSQL_HOST"
echo "  MySQL Port:     $MYSQL_PORT"
echo "  MySQL User:     $MYSQL_USER"
echo "  MySQL Database: $MYSQL_DATABASE"
echo "  Mail Hostname:  $MAIL_HOSTNAME"
echo "  Roundcube:      https://$ROUNDCUBE_DOMAIN:$ROUNDCUBE_PORT"
echo ""

# =============================================================================
# Prima di fermare qualunque cosa: i pacchetti protetti
# =============================================================================
# Misurato il 05/11/2026 sulla VM FreeBSD 15.1 (reperto 126): dove il pannello e' gia' partito,
# i pacchetti dello stack sono protetti con pkg lock (39 su quella macchina). La fase 1 fermava
# i servizi e ne cancellava le configurazioni, la fase 2 si fermava su «mysql84-server-8.4.11_4
# is locked and may not be modified», lo script usciva 1 e la posta restava spenta.
# Un pacchetto protetto qualunque puo' fermare pkg install, anche una dipendenza: ci si ferma se
# ce n'e' anche uno solo, e PRIMA della fase 1. La voce del menu del pannello li sblocca da se'
# (con l'elenco salvato) e li riprotegge alla fine; chi lancia lo script a mano li sblocca lui.
# Si legge con pkg query e non con "pkg lock -l -q", che senza nessun protetto esce con 1 come
# per un errore (misurato lo stesso giorno). Se pkg non risponde ci si ferma lo stesso: la fase 2
# fallirebbe uguale, ma a servizi spenti.
if true; then
    if ! LOCKED_PACKAGES=$(pkg query -e '%k = 1' '%n-%v' 2>/dev/null); then
        echo "${RED}Error: pkg cannot say which packages are locked:${NC}"
        pkg query -e '%k = 1' '%n-%v'
        echo "Nothing was stopped and nothing was changed."
        exit 1
    fi
    if [ -n "$LOCKED_PACKAGES" ]; then
        echo "${RED}=============================================================================${NC}"
        echo "${RED}  STOPPED: some packages are locked (pkg lock). pkg would refuse to change${NC}"
        echo "${RED}  them halfway through, with the mail services already stopped.${NC}"
        echo "${RED}=============================================================================${NC}"
        echo "Locked now:"
        echo "$LOCKED_PACKAGES" | sed 's/^/  /'
        echo ""
        echo "Nothing was stopped and nothing was changed."
        echo "DaemoxCP Mail locks the mail stack packages when it starts. Its menu entry"
        echo "'Install/Reinstall Complete Mail Server' unlocks them before this script and"
        echo "locks them again after it. Running this script by hand: unlock them first"
        echo "(pkg unlock -a -y); the panel locks the mail stack again at its next start."
        exit 1
    fi
fi

# =============================================================================
# PHASE 1: CLEANUP
# =============================================================================
echo "${YELLOW}[PHASE 1/10] Cleaning up existing installation...${NC}"

# Stop all services
service postfix stop 2>/dev/null || true
service dovecot stop 2>/dev/null || true
service rspamd stop 2>/dev/null || true
service clamav_clamd stop 2>/dev/null || true
service clamav_freshclam stop 2>/dev/null || true
service redis stop 2>/dev/null || true
service nginx stop 2>/dev/null || true
service php_fpm stop 2>/dev/null || true

pkill -9 master 2>/dev/null || true
pkill -9 postfix 2>/dev/null || true
pkill -9 dovecot 2>/dev/null || true
pkill -9 nginx 2>/dev/null || true
pkill -9 php-fpm 2>/dev/null || true
sleep 2

# Remove old configs
rm -rf /usr/local/etc/postfix/*.cf 2>/dev/null || true
rm -rf /usr/local/etc/postfix/mysql-*.cf 2>/dev/null || true
rm -rf /usr/local/etc/dovecot/* 2>/dev/null || true
rm -rf /usr/local/etc/rspamd/local.d/* 2>/dev/null || true
rm -rf /usr/local/etc/ssl/mail/* 2>/dev/null || true

# Remove mailbox data
rm -rf /var/vmail/* 2>/dev/null || true

echo "${GREEN}  Cleanup complete${NC}"

# =============================================================================
# PHASE 2: INSTALL PACKAGES
# =============================================================================
# Ogni pacchetto passa da install_packages, mai da "pkg install" nudo: pkg puo' togliere
# un pacchetto chiesto ed uscire con 0, e qui sotto lo ha fatto davvero (Dovecot).
"""
            + PackageInstall.shellFunction() + """

echo ""
echo "${YELLOW}[PHASE 2/10] Installing packages...${NC}"

# MySQL
install_packages mysql84-server mysql84-client

# Postfix with MySQL support (postfix-mysql replaces postfix)
install_packages postfix-mysql

# Dovecot con il supporto MySQL, e il Sieve COSTRUITO PER QUEL Dovecot.
# Il port mail/dovecot ha dei sapori che si escludono a vicenda (dovecot, dovecot-mysql,
# dovecot-pgsql: stessi file, compresi /usr/local/bin/doveadm), e anche Pigeonhole ce li
# ha: dovecot-pigeonhole dipende da "dovecot", dovecot-pigeonhole-mysql da dovecot-mysql.
# Chiedere dovecot-mysql insieme a dovecot-pigeonhole e' chiedere due Dovecot: misurato il
# 24/10/2026, pkg ha risolto il conflitto togliendo in silenzio dovecot-mysql, e il server
# installato rispondeva «auth: Fatal: Support not compiled in for passdb driver 'sql'» a
# ogni login IMAP e chiudeva la 587 («no SASL authentication mechanisms»).
# Dove il catalogo offre la 2.4 (ramo latest) si installa quella (DovecotConfig.packagesShell, reperto 215).
"""
            + DovecotConfig.packagesShell() + """
install_packages $DOVECOT_PACKAGES

# Anti-spam and antivirus
install_packages rspamd redis clamav

# Fail2ban. Quindici file del pannello lo usano -- Fail2banManager, Fail2banAutoSetup,
# BanActionRepair, WebProtection, la pagina Firewall -- e nessuno lo installava: dopo
# un'installazione completa "pkg info | grep fail2ban" non trovava niente, e le jail che il
# pannello scrive al proprio avvio finivano in una cartella che non esiste.
# Si nomina per ORIGINE: il nome del pacchetto porta davanti la versione di Python
# ("py312-fail2ban" oggi) e cambia da sola.
install_packages security/py-fail2ban
sysrc fail2ban_enable="YES"

# dig. Il pannello lo chiama in sei file -- i record DNS, DKIM, le liste nere, MTA-STS,
# autoconfig, i controlli di Unbound -- e il sistema base non ce l'ha (solo drill e host):
# misurato il 29/10/2026 su una macchina appena installata, "which dig" non trovava niente.
# E il codice tratta l'errore come una risposta vuota (digRecord in SSLMailServer restituisce
# ""), cioe' come un record che non c'e': letto nel codice, non misurato dalla pagina.
install_packages dns/bind-tools

# SSL: NON si installa il port security/openssl.
# Il predefinito dei port FreeBSD e' ssl=base, cioe' i pacchetti binari sono costruiti contro
# l'OpenSSL del sistema, che sta in /usr/lib e non e' un pacchetto. Installare anche il port
# aggiunge una seconda copia in /usr/local/lib che nessuno usa: verificato il 31/08/2026 su
# questo server con tre misure indipendenti (nessun pacchetto la dichiarava, nessuno dei 12
# processi con TLS l'aveva aperta, e il comando "openssl" nel PATH risolveva gia' a
# /usr/bin/openssl del base). In piu' il port era fermo alla 3.0, che esce dal supporto il
# 07/09/2026, mentre il base e' sulla 3.5 LTS supportata fino all'08/04/2030.
# Fonte: https://openssl-library.org/policies/releasestrat/

# Roundcube
install_packages nginx php84 php84-extensions
install_packages roundcube-php84
# Prima questa riga finiva con "2>/dev/null || true": se UN nome non fosse stato nel
# catalogo, pkg avrebbe rifiutato l'intera riga e Roundcube sarebbe rimasto senza mysqli o
# pdo_mysql, in silenzio. Tutti e tredici esistono (installati sulla VM FreeBSD 15.1 di
# prova il 24/10/2026): se un giorno uno sparisce dal catalogo, l'installazione deve dirlo.
install_packages php84-mysqli php84-mbstring php84-intl php84-xml php84-zip php84-pdo php84-pdo_mysql php84-session php84-fileinfo php84-dom php84-iconv php84-curl php84-gd

# Create vmail user
pw groupadd vmail -g 5000 2>/dev/null || true
pw useradd vmail -u 5000 -g vmail -d /var/vmail -s /usr/sbin/nologin -c "Virtual Mail" 2>/dev/null || true
mkdir -p /var/vmail
"""
            // Le cartelle della posta a vmail senza dargli file di altri: niente hard link, niente collegamenti (reperto 252)
            + org.daemoxcp.mail.security.SafeOwnership.shell("/var/vmail", "vmail", "vmail") + """
chmod 770 /var/vmail

echo "${GREEN}  Packages installed${NC}"

# =============================================================================
# pf, il firewall: senza, i blocchi di fail2ban non fermano niente
# =============================================================================
# Misurato su una FreeBSD 15.1 appena installata: /etc/pf.conf NON esiste, il modulo pf non
# e' caricato e pf_enable non e' impostato. La jail del pannello ha "action = pf[...]", quindi
# fail2ban scrive le sue regole nell'anchor "f2b/*" e, senza niente di tutto questo,
# fail2ban-client dichiara bloccato un indirizzo mentre in pf non c'e' nulla. "Blocca e dice
# di aver bloccato" e' il caso peggiore: non lascia tracce da cui accorgersi.
#
# Qui si puo' fare perche' installare un server di posta e' un'azione esplicita. Il pannello
# all'AVVIO non lo fa: quello ricorre a ogni riavvio, su una macchina che intanto puo' aver
# cambiato configurazione per mano d'altri, e li' si limita a dirlo.
echo ""
echo "${YELLOW}Setting up pf, so that a ban actually blocks...${NC}"

if [ "$(sysctl -n security.jail.jailed 2>/dev/null)" = 1 ]; then
    # Dentro una jail i moduli non si caricano e il firewall e' dell'host: non e' un guasto.
    echo "${YELLOW}  Inside a FreeBSD jail: pf belongs to the host, leaving it alone.${NC}"
elif kldstat 2>/dev/null | grep -q ipfw.ko; then
    # Questa macchina ha gia' un firewall. Accenderne un secondo non si fa a sorpresa.
    echo "${YELLOW}  ipfw is loaded: this machine already has a firewall, leaving pf alone.${NC}"
    echo "  To use fail2ban's bans, add an ipfw rule for its table, or switch to pf."
else
    if ! kldstat 2>/dev/null | grep -q pf.ko; then
        # Senza il modulo, pfctl non parla col kernel: nemmeno la prova di sintassi parte
        # ("pfctl: /dev/pf: No such file or directory").
        kldload pf 2>/dev/null || true
    fi
    if ! kldstat 2>/dev/null | grep -q pf.ko; then
        echo "${RED}  WARNING: cannot load the pf kernel module. Fail2ban will record bans"
        echo "  that block nothing. Check 'kldload pf' by hand.${NC}"
    elif [ -f /etc/pf.conf ]; then
        # C'e' gia': quelle regole le ha scritte qualcun altro e non si riscrivono, e pf NON
        # si accende, perche' non si sa che cosa bloccherebbero. Il pannello al proprio avvio
        # aggiunge l'anchor con una prova di sintassi e una copia di sicurezza.
        echo "${YELLOW}  /etc/pf.conf already exists: left untouched, and pf NOT enabled.${NC}"
        echo "  The panel adds 'anchor \\"f2b/*\\"' to it at startup; enable pf yourself when"
        echo "  you have checked those rules: sysrc pf_enable=YES && service pf start"
    else
        # Il file minimo: non blocca NESSUN servizio, quindi accendere pf non chiude fuori
        # nessuno. L'unico blocco arriva dall'anchor, cioe' dagli indirizzi che fail2ban
        # mette in tabella, e dalla tabella <permaban> del pannello.
        cat > /etc/pf.conf << 'PFCONF'
# /etc/pf.conf, scritto dall'installazione di DaemoxCP Mail.
#
# Configurazione MINIMA e SICURA per fail2ban + pf:
#  - nessun servizio viene bloccato, quindi accendere pf non chiude fuori nessuno;
#  - l'unico blocco arriva dagli indirizzi che fail2ban mette nel suo anchor e dalla
#    tabella <permaban> del pannello.
#
# Per personalizzarla: si modifica questo file e poi 'pfctl -f /etc/pf.conf'.

# Il loopback non si filtra.
set skip on lo

# La lista dei blocchi permanenti del pannello.
table <permaban> persist file "/var/db/daemoxcp-mail/permaban.list"
block in quick from <permaban>

# L'anchor di fail2ban: ci mette le sue "block in quick" l'azione pf della jail.
# Deve venire PRIMA del pass, e le sue regole hanno "quick".
anchor "f2b/*"

# Predefinito: passa tutto. Niente e' bloccato a parte quanto sopra.
pass
PFCONF
        chmod 644 /etc/pf.conf
        mkdir -p /var/db/daemoxcp-mail
        [ -f /var/db/daemoxcp-mail/permaban.list ] || : > /var/db/daemoxcp-mail/permaban.list
        chmod 640 /var/db/daemoxcp-mail/permaban.list
        # Prova di sintassi prima di accendere: un pf.conf rifiutato lascia pf spento, non
        # a meta'.
        if pfctl -nf /etc/pf.conf 2>&1; then
            sysrc pf_enable="YES" >/dev/null
            service pf start 2>/dev/null || pfctl -e -f /etc/pf.conf 2>/dev/null || true
            if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
                echo "${GREEN}  pf is on, with a ruleset that blocks nothing by itself.${NC}"
            else
                echo "${RED}  WARNING: pf did not come up. Fail2ban will record bans that block"
                echo "  nothing. Check 'service pf start' by hand.${NC}"
            fi
        else
            echo "${RED}  WARNING: the generated /etc/pf.conf was refused by pfctl: pf left off.${NC}"
        fi
    fi
fi

# =============================================================================
# PHASE 3: CONFIGURE MySQL
# =============================================================================
echo ""
echo "${YELLOW}[PHASE 3/10] Configuring MySQL...${NC}"

sysrc mysql_enable="YES"
service mysql-server start 2>/dev/null || service mysql-server restart 2>/dev/null || true

# Il server deve rispondere davvero, non basta avere lanciato il comando di avvio.
# Senza questo controllo le fasi 3, 9 e 10 fallivano una per una e l'installazione
# si dichiarava comunque riuscita, lasciando un sistema senza database.
mysql_ready=no
attempt=0
while [ $attempt -lt 30 ]; do
    if mysqladmin ping >/dev/null 2>&1; then
        mysql_ready=yes
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
if [ "$mysql_ready" != yes ]; then
    echo "${RED}  ERROR: the MySQL server is not answering.${NC}"
    echo "  Postfix, Dovecot and Roundcube all need the database: stopping here."
    echo "  Check that the server package is installed: pkg info | grep mysql"
    exit 1
fi

# Una cartella privata per i due file che contengono un segreto: il file di credenziali di
# root e lo script SQL. mktemp -d la crea 700 qualunque sia la maschera, quindi nessun altro
# utente ci entra, e il contenuto e' al riparo dal momento in cui nasce. Prima lo script SQL
# stava in /tmp e veniva portato a 600 DOPO essere stato scritto: in mezzo c'era una finestra
# in cui chiunque poteva leggerlo. Non si tocca la maschera globale: piu' avanti lo script
# scrive file che devono restare leggibili da roundcube e da postfix.
MYSQL_WORK=$(mktemp -d /var/tmp/daemoxcp-mail-mysql.XXXXXXXX) || {
    echo "${RED}Error: cannot create the temporary folder${NC}"; exit 1; }
trap 'rm -rf "$MYSQL_WORK"' EXIT HUP INT TERM
MYSQL_ROOT_CNF="$MYSQL_WORK/root.cnf"
MYSQL_SETUP_SQL="$MYSQL_WORK/setup.sql"

# La password di root. Un MySQL appena installato su FreeBSD lascia root SENZA password, e
# finche' resta cosi' qualunque utente locale -- roundcube compreso, che fa girare la webmail -- ha
# i pieni poteri sul database. Prima nessuno la impostava: lo script faceva "mysql -u root"
# e, se falliva, "mysql -u root --password=".
#
# Se si entra senza password, questo MySQL e' nuovo e la password si imposta adesso. Se non
# si entra, una password c'e' gia' e deve essere quella del pannello: non si va a indovinare.
if mysql -u root --password= -e "SELECT 1" >/dev/null 2>&1; then
    echo "  Fresh MySQL: setting the root password"
    # Here-document NON quotato: $MYSQL_ROOT_PASSWORD si espande una volta sola, quindi un
    # dollaro DENTRO la password non viene riespanso. L'alfabeto del generatore non ha
    # apice, virgolette, barra rovescia ne' accento grave, che qui spezzerebbero la riga.
    if ! mysql -u root --password= << EOROOT
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
FLUSH PRIVILEGES;
EOROOT
    then
        echo "${RED}  ERROR: cannot set the MySQL root password.${NC}"
        exit 1
    fi
fi

# Da qui in poi root si usa SEMPRE cosi': la password in un file 600 letto da mysql, mai
# in "-p..." sulla riga di comando, che "ps" mostra a tutti. Le virgolette intorno al
# valore servono perche' nei file di opzioni di MySQL un '#' non quotato apre un commento.
cat > "$MYSQL_ROOT_CNF" << EOCNF
[client]
user=root
password="$MYSQL_ROOT_PASSWORD"
EOCNF

if ! mysql --defaults-extra-file="$MYSQL_ROOT_CNF" -e "SELECT 1" >/dev/null 2>&1; then
    echo "${RED}  ERROR: the MySQL root password does not work.${NC}"
    echo "  MySQL was already here with a root password that the panel does not know."
    echo "  Set it to the one in the panel secrets file, or let the panel install MySQL."
    exit 1
fi

# Create database and tables
cat > "$MYSQL_SETUP_SQL" << EOSQL
CREATE DATABASE IF NOT EXISTS $MYSQL_DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$MYSQL_USER'@'localhost' IDENTIFIED BY '$MYSQL_PASSWORD';
CREATE USER IF NOT EXISTS '$MYSQL_USER'@'127.0.0.1' IDENTIFIED BY '$MYSQL_PASSWORD';
ALTER USER '$MYSQL_USER'@'localhost' IDENTIFIED BY '$MYSQL_PASSWORD';
ALTER USER '$MYSQL_USER'@'127.0.0.1' IDENTIFIED BY '$MYSQL_PASSWORD';
GRANT ALL PRIVILEGES ON $MYSQL_DATABASE.* TO '$MYSQL_USER'@'localhost';
GRANT ALL PRIVILEGES ON $MYSQL_DATABASE.* TO '$MYSQL_USER'@'127.0.0.1';
FLUSH PRIVILEGES;
USE $MYSQL_DATABASE;

SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS audit_log, rspamd_training, email_statistics, roundcube_tokens;
DROP TABLE IF EXISTS auto_responders, sieve_filters, forwarding_rules, rate_limits;
DROP TABLE IF EXISTS admin_passkeys, panel_sessions, login_code_email, login_code_console, stepup_code, email_change_code;
DROP TABLE IF EXISTS panel_settings, panel_admin, installed_components;
DROP TABLE IF EXISTS aliases, mailboxes, domains;
SET FOREIGN_KEY_CHECKS = 1;

-- Domains
CREATE TABLE domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    dkim_selector VARCHAR(50) DEFAULT 'mail',
    dkim_private_key TEXT,
    dkim_public_key TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Mailboxes
CREATE TABLE mailboxes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    quota_mb INT DEFAULT 1024,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Aliases
CREATE TABLE aliases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    source VARCHAR(255) NOT NULL,
    destination VARCHAR(255) NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    UNIQUE KEY unique_alias (source, destination)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Panel admin
-- No password: passkeys and email codes. The panel adds its login tables when it starts.
CREATE TABLE panel_admin (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email_enc VARCHAR(512) NULL,
    email_index CHAR(64) CHARACTER SET ascii NULL,
    user_handle VARCHAR(64) CHARACTER SET ascii NULL,
    created_at DATETIME NULL,
    last_login DATETIME NULL,
    active BOOLEAN DEFAULT TRUE,
    role ENUM('superadmin', 'admin', 'operator', 'viewer') DEFAULT 'admin',
    theme VARCHAR(10) DEFAULT 'auto',
    language VARCHAR(5) NULL,
    UNIQUE KEY uq_admin_email_index (email_index),
    UNIQUE KEY uq_admin_user_handle (user_handle)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Panel settings
CREATE TABLE panel_settings (
    setting_key VARCHAR(64) PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Rate limits
CREATE TABLE rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_type ENUM('global', 'domain', 'mailbox') NOT NULL,
    target_id INT NULL,
    max_per_hour INT DEFAULT 100,
    max_per_day INT DEFAULT 1000,
    max_recipients INT DEFAULT 50,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_target (target_type, target_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Auto-responders
CREATE TABLE auto_responders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mailbox_id INT NOT NULL UNIQUE,
    enabled BOOLEAN DEFAULT FALSE,
    subject VARCHAR(255) NOT NULL DEFAULT 'Out of Office',
    body TEXT NOT NULL,
    start_date DATE NULL,
    end_date DATE NULL,
    interval_hours INT DEFAULT 24,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Forwarding rules
CREATE TABLE forwarding_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mailbox_id INT NOT NULL,
    destination VARCHAR(255) NOT NULL,
    keep_copy BOOLEAN DEFAULT TRUE,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Installed components
CREATE TABLE installed_components (
    id INT AUTO_INCREMENT PRIMARY KEY,
    component_name VARCHAR(50) NOT NULL UNIQUE,
    version VARCHAR(20),
    installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('installed', 'uninstalled', 'failed') DEFAULT 'installed'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sieve filters
CREATE TABLE sieve_filters (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mailbox_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    priority INT DEFAULT 0,
    enabled BOOLEAN DEFAULT TRUE,
    conditions JSON NOT NULL,
    actions JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Roundcube tokens
CREATE TABLE roundcube_tokens (
    token VARCHAR(64) PRIMARY KEY,
    mailbox_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Email statistics
CREATE TABLE email_statistics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    stat_date DATE NOT NULL,
    mailbox_id INT NULL,
    domain_id INT NULL,
    sent_count INT DEFAULT 0,
    received_count INT DEFAULT 0,
    spam_count INT DEFAULT 0,
    virus_count INT DEFAULT 0,
    bounced_count INT DEFAULT 0,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    UNIQUE KEY unique_daily_stat (stat_date, mailbox_id, domain_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Rspamd training
CREATE TABLE rspamd_training (
    id INT AUTO_INCREMENT PRIMARY KEY,
    message_id VARCHAR(255) NOT NULL,
    trained_as ENUM('spam', 'ham') NOT NULL,
    trained_by INT NOT NULL,
    trained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (trained_by) REFERENCES panel_admin(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Audit log
CREATE TABLE audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    username VARCHAR(255),
    ip_address VARCHAR(45) NOT NULL,
    details TEXT,
    user_agent VARCHAR(512),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_action (action),
    INDEX idx_username (username),
    INDEX idx_ip (ip_address),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
EOSQL

# "-p''" collassava a "-p" nudo e faceva chiedere la password all'operatore, con il
# messaggio di errore nascosto da 2>/dev/null. Adesso root ha una password e la si passa
# dal file di credenziali, quindi non c'e' piu' niente da indovinare e niente da nascondere.
# E niente "|| true": se il database non si crea non c'e' nulla su cui appoggiarsi.
if ! mysql --defaults-extra-file="$MYSQL_ROOT_CNF" < "$MYSQL_SETUP_SQL"; then
    echo "${RED}  ERROR: cannot create the database and its tables.${NC}"
    exit 1
fi
rm -f "$MYSQL_SETUP_SQL"

echo "${GREEN}  MySQL configured${NC}"

# =============================================================================
# PHASE 4: CREATE DIRECTORIES
# =============================================================================
echo ""
echo "${YELLOW}[PHASE 4/10] Creating directories...${NC}"

mkdir -p /usr/local/etc/ssl/mail
mkdir -p /usr/local/etc/postfix
mkdir -p /var/vmail
mkdir -p /var/run/dovecot
mkdir -p /var/db/daemoxcp-mail

"""
            // Le cartelle della posta a vmail senza dargli file di altri: niente hard link, niente collegamenti (reperto 252)
            + org.daemoxcp.mail.security.SafeOwnership.shell("/var/vmail", "vmail", "vmail") + """
chmod 770 /var/vmail
chown root:dovecot /var/run/dovecot
chmod 755 /var/run/dovecot

echo "${GREEN}  Directories created${NC}"

# =============================================================================
# PHASE 5: GENERATE SSL CERTIFICATE
# =============================================================================
echo ""
echo "${YELLOW}[PHASE 5/10] Generating self-signed SSL certificate...${NC}"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
    -keyout /usr/local/etc/ssl/mail/privkey.pem \\
    -out /usr/local/etc/ssl/mail/fullchain.pem \\
    -subj "/C=IT/ST=Italy/L=Rome/O=Mail Server/CN=$MAIL_HOSTNAME"

chmod 600 /usr/local/etc/ssl/mail/privkey.pem
chmod 644 /usr/local/etc/ssl/mail/fullchain.pem

echo "${GREEN}  SSL certificate generated${NC}"

# =============================================================================
# PHASE 6: CONFIGURE POSTFIX
# =============================================================================
echo ""
echo "${YELLOW}[PHASE 6/10] Configuring Postfix...${NC}"

# Disable sendmail
sysrc sendmail_enable="NO"
sysrc sendmail_submit_enable="NO"
sysrc sendmail_outbound_enable="NO"
sysrc sendmail_msp_queue_enable="NO"

# myorigin = localhost: gli indirizzi senza dominio -- root, postmaster, cioe' la posta di
# cron e di periodic -- restano su questa macchina. Diventano @localhost, che e' in
# mydestination, e Postfix li consegna in /var/mail come faceva dma. Con myorigin = $mydomain
# diventavano @$MAIL_HOSTNAME, che non e' locale: misurato sulla VM il 23/10/2026, Postfix li
# spediva via SMTP a se stesso e li rimbalzava ("loops back to myself").
# L'altra strada, $myhostname in mydestination, e' quella dei manuali, ed e' stata scartata
# per due motivi. Apre a Internet gli account di sistema: misurato dal Mac, fuori da
# mynetworks, "RCPT TO:<root@$MAIL_HOSTNAME>" passava da 454 Relay access denied a 250, e un
# utente inesistente dava 550 "User unknown in local recipient table", cioe' l'elenco degli
# account si ricava dall'SMTP. E se il nome del server coincidesse con un dominio gestito dal
# pannello, tutta la posta di quel dominio verrebbe consegnata agli utenti di sistema invece
# che alle caselle. Con localhost, da fuori, non cambia niente: root@localhost resta 504 per
# reject_non_fqdn_recipient.
# Il prezzo di localhost, chiuso con smtp_generic_maps: la posta di sistema che esce dalla
# macchina (root inoltrato dal pannello a un indirizzo esterno, un MAILTO di cron) avrebbe
# avuto il mittente root@localhost, che i server altrui rifiutano. Nel client SMTP, e solo
# li', @localhost diventa @$myhostname: la consegna locale resta com'e', e il nome si legge a
# ogni uso, quindi segue quello che il pannello riscrive in myhostname.

# main.cf
cat > /usr/local/etc/postfix/main.cf << POSTFIX_MAIN
# Postfix - DaemoxCP Mail
# Generated automatically

# Basic settings
myhostname = $MAIL_HOSTNAME
mydomain = $MAIL_HOSTNAME
# Indirizzi senza dominio (root, postmaster) consegnati qui: vedi lo script di installazione
myorigin = localhost
mydestination = localhost
# In uscita root@localhost diventa root@<nome del server>: vedi lo script di installazione
smtp_generic_maps = inline:{ @localhost=@\\$myhostname }
mynetworks = 127.0.0.0/8 [::1]/128
# In chiaro: senza, lo script di ogni aggiornamento di postfix scrive inet_protocols = ipv4 (reperto 207)
inet_protocols = all

# Virtual mailbox settings
virtual_mailbox_domains = mysql:/usr/local/etc/postfix/mysql-virtual-domains.cf
virtual_mailbox_maps = mysql:/usr/local/etc/postfix/mysql-virtual-mailboxes.cf
virtual_alias_maps = mysql:/usr/local/etc/postfix/mysql-virtual-aliases.cf
virtual_transport = lmtp:unix:private/dovecot-lmtp

# TLS settings
smtpd_tls_cert_file = /usr/local/etc/ssl/mail/fullchain.pem
smtpd_tls_key_file = /usr/local/etc/ssl/mail/privkey.pem
smtpd_tls_security_level = may
smtpd_tls_auth_only = yes
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_loglevel = 1

smtp_tls_security_level = may
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_loglevel = 1

# SASL authentication via Dovecot
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \\$myhostname
broken_sasl_auth_clients = yes

# Restrictions
smtpd_helo_required = yes
smtpd_helo_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_invalid_helo_hostname,
    reject_non_fqdn_helo_hostname

smtpd_sender_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain

smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain

# Milter (Rspamd)
smtpd_milters = inet:127.0.0.1:11332
non_smtpd_milters = inet:127.0.0.1:11332
milter_protocol = 6
milter_default_action = accept

# Limits
message_size_limit = 52428800
mailbox_size_limit = 0
virtual_mailbox_limit = 0

# Queue
maximal_queue_lifetime = 5d
bounce_queue_lifetime = 5d

# Misc
biff = no
append_dot_mydomain = no
recipient_delimiter = +
compatibility_level = 3.6
POSTFIX_MAIN

# master.cf
cat > /usr/local/etc/postfix/master.cf << 'POSTFIX_MASTER'
# Postfix master process configuration

# SMTP (port 25)
smtp      inet  n       -       n       -       -       smtpd

# Submission (port 587)
submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# SMTPS (port 465)
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# Local services
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
POSTFIX_MASTER

# MySQL virtual domains
cat > /usr/local/etc/postfix/mysql-virtual-domains.cf << MYSQL_DOMAINS
user = $MYSQL_USER
password = $MYSQL_PASSWORD
hosts = 127.0.0.1
dbname = $MYSQL_DATABASE
query = SELECT domain FROM domains WHERE domain='%s' AND active=1
MYSQL_DOMAINS

# MySQL virtual mailboxes
cat > /usr/local/etc/postfix/mysql-virtual-mailboxes.cf << MYSQL_MAILBOXES
user = $MYSQL_USER
password = $MYSQL_PASSWORD
hosts = 127.0.0.1
dbname = $MYSQL_DATABASE
query = SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM mailboxes WHERE email='%s' AND active=1 AND receive_enabled=1
MYSQL_MAILBOXES

# MySQL virtual aliases
cat > /usr/local/etc/postfix/mysql-virtual-aliases.cf << MYSQL_ALIASES
user = $MYSQL_USER
password = $MYSQL_PASSWORD
hosts = 127.0.0.1
dbname = $MYSQL_DATABASE
query = SELECT destination FROM aliases WHERE source='%s' AND active=1
MYSQL_ALIASES

# Set permissions
chmod 640 /usr/local/etc/postfix/mysql-*.cf
chown root:postfix /usr/local/etc/postfix/mysql-*.cf

# Create Postfix spool directory for Dovecot SASL socket
# This is CRITICAL - Dovecot needs this directory to create the auth socket
mkdir -p /var/spool/postfix/private
chown postfix:postfix /var/spool/postfix/private
chmod 710 /var/spool/postfix/private

sysrc postfix_enable="YES"

"""
            // Postfix come MTA locale: senza, la posta di sistema esce da dma. Lo stesso pezzo
            // e' in PostfixScript e FullMailStackScript.
            + LocalMtaScript.SHELL
            // Il livello di compatibilita' che chiede il Postfix installato, se esaminato (reperto 251). Lo stesso pezzo
            // e' in PostfixScript e FullMailStackScript, dopo main.cf.
            + PostfixLevelScript.shell() + """

echo "${GREEN}  Postfix configured${NC}"

# =============================================================================
# PHASE 7: CONFIGURE DOVECOT
# =============================================================================
echo ""
echo "${YELLOW}[PHASE 7/10] Configuring Dovecot...${NC}"

# La configurazione Dovecot viene scritta piu' avanti, in un blocco solo.

"""
            // L'utente master di Dovecot per «Apri webmail»: lo stesso pezzo e' in FullMailStackScript
            // e DovecotScript. Passa di qui prima di dovecot.conf, e per questo usa "doveadm -O".
            + org.daemoxcp.mail.system.DovecotMasterUser.shell() + """

# SQL config
"""
            // Sorgente UNICA della configurazione Dovecot, scritta DOPO master-users
            // perche' auth-master.conf.ext lo referenzia. Prima questo script aveva
            // la sua copia della configurazione, divergente dalle altre due.
            + DovecotConfig.fromPanelConfig().scriptFragment() + """

sysrc dovecot_enable="YES"

echo "${GREEN}  Dovecot configured${NC}"

# =============================================================================
# PHASE 8: CONFIGURE RSPAMD + CLAMAV + REDIS
# =============================================================================
echo ""
echo "${YELLOW}[PHASE 8/10] Configuring Rspamd, ClamAV, Redis...${NC}"

"""
            // Il risolutore ricorsivo locale, prima che rspamd parta (fase 10): senza, le liste
            // di Spamhaus non rispondono. Lo stesso pezzo e' in RspamdScript e FullMailStackScript.
            + LocalResolverScript.SHELL + """

# Redis solo sul socket Unix, 0770 del gruppo redis, e rspamd in quel gruppo: il redis.conf del pacchetto
# ascolta su 127.0.0.1:6379 e ::1 senza password, e tutta la macchina leggeva e scriveva i dati di rspamd.
# Le righe sono quelle di RedisSocket.java (reperto 235), che fa lo stesso sui server installati prima.
if ! grep -qF 'reperto 235' /usr/local/etc/redis.conf 2>/dev/null; then
    cat >> /usr/local/etc/redis.conf << 'REDIS_SOCKET'

""" + org.daemoxcp.mail.system.RedisSocket.FINAL + """
REDIS_SOCKET
fi
pw groupmod redis -m rspamd
sysrc redis_enable="YES"
service redis start 2>/dev/null || true

# ClamAV
mkdir -p /var/run/clamav
chown clamav:clamav /var/run/clamav

# Il socket di clamd solo del gruppo clamav, 0660, e rspamd in quel gruppo: il clamd.conf del pacchetto lo lascia
# a tutti (0666). Le righe sono quelle di ClamdSocket.java (reperto 237).
if ! grep -qF 'reperto 237' /usr/local/etc/clamd.conf 2>/dev/null; then
    cat >> /usr/local/etc/clamd.conf << 'CLAMD_SOCKET'

""" + org.daemoxcp.mail.system.ClamdSocket.BLOCK + """
CLAMD_SOCKET
fi
pw groupmod clamav -m rspamd

if [ -f /usr/local/etc/rc.d/clamav_clamd ]; then
    sysrc clamav_clamd_enable="YES"
    sysrc clamav_freshclam_enable="YES"
fi

freshclam 2>/dev/null || true

# Rspamd
mkdir -p /usr/local/etc/rspamd/local.d
mkdir -p /usr/local/etc/rspamd/override.d
mkdir -p /var/log/rspamd
mkdir -p /var/run/rspamd
chown rspamd:rspamd /var/log/rspamd /var/run/rspamd

cat > /usr/local/etc/rspamd/local.d/worker-proxy.inc << 'RSPAMD_PROXY'
bind_socket = "127.0.0.1:11332";
milter = yes;
timeout = 120s;
upstream "local" {
  default = yes;
  self_scan = yes;
}
RSPAMD_PROXY

cat > /usr/local/etc/rspamd/local.d/worker-normal.inc << 'RSPAMD_WORKER'
bind_socket = "127.0.0.1:11333";
RSPAMD_WORKER

cat > /usr/local/etc/rspamd/local.d/redis.conf << 'RSPAMD_REDIS'
servers = "/var/run/redis/redis.sock";
RSPAMD_REDIS

# Il controller (11334) del pacchetto lascia entrare 127.0.0.1 e ::1 senza password: la password la genera il
# pannello al primo avvio e la tiene nei segreti di root (RspamdController.java, reperto 236).

cat > /usr/local/etc/rspamd/local.d/antivirus.conf << 'RSPAMD_AV'
clamav {
  action = "reject";
  symbol = "CLAM_VIRUS";
  type = "clamav";
  servers = "/var/run/clamav/clamd.sock";
}
RSPAMD_AV

sysrc rspamd_enable="YES"

echo "${GREEN}  Rspamd configured${NC}"

# =============================================================================
# PHASE 9: CONFIGURE ROUNDCUBE
# =============================================================================
echo ""
echo "${YELLOW}[PHASE 9/10] Configuring Roundcube...${NC}"

# Il database di Roundcube, e il suo utente MySQL: roundcube, coi privilegi su roundcubemail e
# basta. Prima la webmail entrava come l'utente del pannello, che ha anche il database della
# posta (caselle, hash delle password, amministratori): chi prendeva la webmail leggeva la
# password in config.inc.php e con quella tutto il resto. Su una reinstallazione l'utente del
# pannello perde i privilegi su roundcubemail che gli aveva dato la versione di prima.
if ! mysql --defaults-extra-file="$MYSQL_ROOT_CNF" << ROUNDCUBE_DB
CREATE DATABASE IF NOT EXISTS roundcubemail CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
""" + org.daemoxcp.mail.scripts.RoundcubeDbAccountScript.sql("$ROUNDCUBE_DB_PASSWORD", "$MYSQL_USER") + """
FLUSH PRIVILEGES;
ROUNDCUBE_DB
then
    echo "${RED}  ERROR: cannot create the webmail database or its MySQL user.${NC}"
    exit 1
fi

if [ -f /usr/local/www/roundcube/SQL/mysql.initial.sql ]; then
    # Le tabelle di Roundcube le fa root, dal file di credenziali: "-p$MYSQL_PASSWORD"
    # metteva anche questa password nella riga di comando, dove la legge chiunque con "ps".
    mysql --defaults-extra-file="$MYSQL_ROOT_CNF" roundcubemail \
        < /usr/local/www/roundcube/SQL/mysql.initial.sql 2>/dev/null || true
fi

# 32 caratteri per AES-256-CBC (RoundcubeCipher.java, reperto 239): DES-EDE3-CBC, il predefinito di Roundcube, c'e'
# solo per compatibilita'.
ROUNDCUBE_DES_KEY=$(openssl rand -base64 48 | tr -d '/+=' | head -c 32)

cat > /usr/local/www/roundcube/config/config.inc.php << ROUNDCUBE_CONFIG
<?php
\\$config['db_dsnw'] = 'mysql://roundcube:$ROUNDCUBE_DB_PASSWORD@127.0.0.1/roundcubemail';
\\$config['imap_host'] = 'ssl://127.0.0.1:993';
\\$config['imap_auth_type'] = 'LOGIN';
\\$config['imap_conn_options'] = array(
    'ssl' => array('verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true)
);
\\$config['smtp_host'] = 'tls://127.0.0.1:587';
\\$config['smtp_user'] = '%u';
\\$config['smtp_pass'] = '%p';
\\$config['smtp_auth_type'] = 'LOGIN';
\\$config['smtp_conn_options'] = array(
    'ssl' => array('verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true)
);
\\$config['product_name'] = 'FreeBSD Webmail';
\\$config['des_key'] = '$ROUNDCUBE_DES_KEY';
\\$config['cipher_method'] = 'AES-256-CBC';
\\$config['skin'] = 'elastic';
\\$config['language'] = 'it_IT';
\\$config['enable_installer'] = false;
\\$config['default_charset'] = 'UTF-8';
\\$config['create_default_folders'] = true;
\\$config['plugins'] = array('archive', 'zipdownload');
ROUNDCUBE_CONFIG

# Chi puo' leggere config.inc.php (la password del database, la des_key), temp e logs lo decide
# piu' avanti il pezzo di RoundcubeUser, dopo il pool: root:roundcube 640, non piu' root:www.
chmod 600 /usr/local/www/roundcube/config/config.inc.php

# Generate SSO key. La legge solo il pannello: il plugin ha il segreto nella sua configurazione.
if [ ! -f /var/db/daemoxcp-mail/roundcube_sso.key ]; then
    openssl rand 32 > /var/db/daemoxcp-mail/roundcube_sso.key
fi
chmod 600 /var/db/daemoxcp-mail/roundcube_sso.key
chown root:wheel /var/db/daemoxcp-mail/roundcube_sso.key

# php.ini
#
# Il pacchetto php84 NON lo installa: in /usr/local/etc ci sono solo i campioni
# php.ini-production e php.ini-development, e senza php.ini PHP parte sui valori
# predefiniti compilati dentro. Verificato dopo un'installazione completa: il file non
# c'era e php-fpm girava lo stesso. Quei predefiniti sono il motivo per cui un allegato
# di 3 MB non si poteva spedire (upload_max_filesize = 2M) e PHP non sapeva in che fuso
# fosse.
#
# I limiti di caricamento sono tarati su message_size_limit di Postfix (50 MB, definito
# sopra in questo stesso script): il tetto vero resta quello, PHP non deve essere il
# collo di bottiglia che lo nasconde. post_max_size sta sopra upload_max_filesize perche'
# nella stessa richiesta viaggia anche il resto del modulo.
cat > /usr/local/etc/php.ini << 'PHPINIEOF'
""" + org.daemoxcp.mail.system.PhpHardening.INI + """
PHPINIEOF

if [ ! -f /usr/local/etc/php.ini ]; then
    echo "${RED}  ERROR: cannot write /usr/local/etc/php.ini${NC}"
    exit 1
fi
chmod 644 /usr/local/etc/php.ini

# La cartella delle sessioni di Roundcube e il registro degli errori di PHP.
# Sono di roundcube, che ci scrive: proprietario e permessi li mette il pezzo di RoundcubeUser,
# dopo il pool. (La riga qui sopra resta com'e': CommentRepair la usa come forma giusta.)
mkdir -p /var/db/daemoxcp-mail/php_sessions
chmod 700 /var/db/daemoxcp-mail/php_sessions
touch /var/log/php_errors.log
chmod 640 /var/log/php_errors.log

# La rotazione, altrimenti quel registro cresce senza fine. La cartella si crea: su una
# FreeBSD appena installata non c'e', ma /etc/newsyslog.conf la include gia'.
mkdir -p /usr/local/etc/newsyslog.conf.d
cat > /usr/local/etc/newsyslog.conf.d/php-errors.conf << 'PHPLOGEOF'
# Registro degli errori di PHP (scritto dall'installazione di DaemoxCP Mail)
/var/log/php_errors.log    roundcube:roundcube    640    7    1024    *    JC
PHPLOGEOF

echo "${GREEN}  php.ini written${NC}"

# PHP-FPM: il pool di Roundcube, col suo utente (prima era il pool www, l'utente di nginx).
"""
            + org.daemoxcp.mail.system.RoundcubeUser.shellPool() + """

# Determine SSL for Roundcube
if [ -n "$ROUNDCUBE_SSL_CERT" ] && [ -f "$ROUNDCUBE_SSL_CERT" ]; then
    RC_SSL_CERT="$ROUNDCUBE_SSL_CERT"
    RC_SSL_KEY="$ROUNDCUBE_SSL_KEY"
else
    RC_SSL_CERT="/usr/local/etc/ssl/mail/fullchain.pem"
    RC_SSL_KEY="/usr/local/etc/ssl/mail/privkey.pem"
fi

# Nginx
mkdir -p /usr/local/etc/nginx /var/log/nginx
cat > /usr/local/etc/nginx/nginx.conf << NGINX_CONF
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    client_max_body_size 50M;

    server {
        listen $ROUNDCUBE_PORT ssl;
        server_name $ROUNDCUBE_DOMAIN;
        root /usr/local/www/roundcube;
        index index.php;

        ssl_certificate $RC_SSL_CERT;
        ssl_certificate_key $RC_SSL_KEY;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
            try_files \\$uri \\$uri/ /index.php?\\$args;
        }

        # Roundcube 1.7 serve gli asset come /static.php/percorso/al/file.css: uno script PHP
        # con un percorso attaccato. Un location che chiede .php in fondo all'URI non lo prende,
        # e il foglio di stile torna come pagina HTML: la webmail si apre senza grafica.
        # Configurazione dal wiki ufficiale di Roundcube (pagina Installation). La riga
        location ~ \\\\.php {
            include fastcgi_params;
            fastcgi_index index.php;
            fastcgi_split_path_info ^(.+\\\\.php)(/.+)\\$;
            fastcgi_param SCRIPT_FILENAME \\$document_root\\$fastcgi_script_name;
            fastcgi_param PATH_INFO \\$fastcgi_path_info;
            fastcgi_pass unix:/var/run/php-fpm-roundcube.sock;
        }

        location ~ /\\\\. { deny all; }
    }
}
NGINX_CONF

# Dalla 1.7 Roundcube non serve piu' i file dalla radice dell'applicazione ma dalla
# sottocartella public_html: e' una protezione voluta, e con la radice vecchia la webmail
# risponde 404 su tutto. Non lo si deduce dal numero di versione, si guarda se la cartella
# c'e': cosi' la stessa riga vale per la 1.6 e per la 1.7 senza doverle distinguere.
if [ -d /usr/local/www/roundcube/public_html ]; then
    sed -i '' 's#root /usr/local/www/roundcube;#root /usr/local/www/roundcube/public_html;#' /usr/local/etc/nginx/nginx.conf
    echo "  Roundcube 1.7 or later: nginx root set to public_html"
fi

sysrc nginx_enable="YES"
sysrc php_fpm_enable="YES"
"""
            + org.daemoxcp.mail.system.RoundcubeUser.shellOwnership() + """
echo "${GREEN}  Roundcube configured${NC}"

# =============================================================================
# PHASE 10: START SERVICES
# =============================================================================
echo ""
echo "${YELLOW}[PHASE 10/10] Starting services...${NC}"

service mysql-server start 2>/dev/null || true
sleep 2
service redis start 2>/dev/null || true
service clamav_freshclam start 2>/dev/null || true
service clamav_clamd start 2>/dev/null || true
service rspamd start 2>/dev/null || true
sleep 2
service dovecot start 2>/dev/null || true
sleep 1
service postfix start 2>/dev/null || true
service php_fpm start 2>/dev/null || true
service nginx start 2>/dev/null || true
# Fail2ban parte ora, anche se la jail del pannello non c'e' ancora: la scrive il pannello
# al proprio avvio e poi fa "fail2ban-client reload". Le jail della posta invece stanno
# gia' in jail.d.
#
# RESTART, non start, e il motivo e' misurato: l'azione pf di una jail crea la propria
# regola in "actionstart", una volta sola, quando la jail parte. Se quella volta pf non
# c'era, fail2ban scrive nel suo registro
#   ERROR stderr: 'pfctl: /dev/pf: No such file or directory'
#   ERROR Error starting action Jail('daemoxcp-mail-auth')/pf
# e NON la riprova mai: ne' un reload, ne' un "service start" su un servizio gia' in
# esecuzione. Da li' in avanti "actionban" sembra riuscire -- crea la tabella da se' -- e
# in pf resta una tabella SENZA la regola che la legge, cioe' niente. Misurato: con
# l'azione fallita, "pfctl -a f2b/daemoxcp-mail-auth -s rules" e' vuoto mentre
# fail2ban-client dice "Banned IP list: 203.0.113.77"; dopo un restart la regola c'e'.
# Succede a ogni REINSTALLAZIONE, perche' li' fail2ban e' gia' in esecuzione da prima.
service fail2ban restart 2>/dev/null || service fail2ban start 2>/dev/null || true

sleep 3

echo ""
echo "Verifying services..."

SERVICES_OK=true

if service postfix status >/dev/null 2>&1; then
    echo "  ${GREEN}[OK]${NC} Postfix is running"
else
    echo "  ${RED}[FAIL]${NC} Postfix is NOT running"
    SERVICES_OK=false
fi

if service dovecot status >/dev/null 2>&1; then
    echo "  ${GREEN}[OK]${NC} Dovecot is running"
else
    echo "  ${RED}[FAIL]${NC} Dovecot is NOT running"
    SERVICES_OK=false
fi

if service rspamd status >/dev/null 2>&1; then
    echo "  ${GREEN}[OK]${NC} Rspamd is running"
else
    echo "  ${RED}[FAIL]${NC} Rspamd is NOT running"
    SERVICES_OK=false
fi

if service nginx status >/dev/null 2>&1; then
    echo "  ${GREEN}[OK]${NC} Nginx is running"
else
    echo "  ${RED}[FAIL]${NC} Nginx is NOT running"
    SERVICES_OK=false
fi

# Non e' un servizio, ma senza questo la posta di sistema esce da dma (LocalMtaScript.java).
if grep -Eq '^sendmail[[:space:]]+/usr/local/sbin/sendmail([[:space:]]|$)' /usr/local/etc/mail/mailer.conf 2>/dev/null; then
    echo "  ${GREEN}[OK]${NC} sendmail(8) hands over to Postfix"
else
    echo "  ${RED}[FAIL]${NC} sendmail(8) does NOT hand over to Postfix (dma)"
    SERVICES_OK=false
fi

# Il risolutore locale per rspamd (LocalResolverScript.java): che risponda, e da ricorsivo.
# Qualche tentativo: a cache fredda la prima domanda a Spamhaus puo' fallire (misurato).
DNS_RESOLVER_OK=no
for attempt in 1 2 3 4 5; do
    if drill @127.0.0.1 2.0.0.127.zen.spamhaus.org A 2>/dev/null | grep -Eq "IN[[:space:]]+A[[:space:]]+127[.]0[.]0[.][0-9]+"; then DNS_RESOLVER_OK=yes; break; fi
    sleep 2
done
if [ "$DNS_RESOLVER_OK" = "yes" ]; then
    echo "  ${GREEN}[OK]${NC} Local DNS resolver answers, Spamhaus included"
else
    echo "  ${RED}[FAIL]${NC} Local DNS resolver does NOT answer for Spamhaus (DNS blocklists will not work)"
    SERVICES_OK=false
fi

echo ""
echo "${GREEN}=============================================================================${NC}"
echo "${GREEN}           Mail Server Installation Complete! (Postfix)${NC}"
echo "${GREEN}=============================================================================${NC}"
echo ""
echo "Services:"
echo "  Postfix (SMTP)      - ports 25, 587, 465"
echo "  Dovecot (IMAP) - ports 143, 993"
echo "  Rspamd (Anti-Spam)  - port 11332"
echo "  Roundcube           - https://$ROUNDCUBE_DOMAIN:$ROUNDCUBE_PORT"
echo ""
echo "Mail hostname: $MAIL_HOSTNAME"
echo ""

exit 0
        """;

    /** Sempre, tutto o niente, con l'impronta del jar (InstallScripts): mai uno script di una versione di prima. */
    public void write_file() {
        this.writed = InstallScripts.write(SCRIPT_PATH, this.data);
    }

    public String getScriptContent() {
        return this.data;
    }
}
