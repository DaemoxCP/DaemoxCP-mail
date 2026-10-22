package org.mail_panel.scripts;

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
 * ║  │  2. Dovecot (IMAP/POP3)   - ports 143/993/110/995                       │ ║
 * ║  │     • LMTP delivery on localhost:24                                     │ ║
 * ║  │     • SASL authentication for Postfix                                   │ ║
 * ║  │     • Mailboxes in /var/vmail/{domain}/{user}                           │ ║
 * ║  │                                                                         │ ║
 * ║  │  3. Rspamd (Anti-Spam)    - port 11332 (milter)                         │ ║
 * ║  │     • Integrated with Postfix via milter                                │ ║
 * ║  │                                                                         │ ║
 * ║  │  4. ClamAV (Antivirus)    - integrated with Rspamd                      │ ║
 * ║  │                                                                         │ ║
 * ║  │  5. Redis                 - port 6379, cache for Rspamd                 │ ║
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

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
CYAN='\\033[0;36m'
NC='\\033[0m'

echo ""
echo "${CYAN}=============================================================================${NC}"
echo "${CYAN}           FreeBSD Mail Server - Complete Installation (Postfix)${NC}"
echo "${CYAN}=============================================================================${NC}"
echo ""

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "${RED}Error: Must run as root${NC}"
    exit 1
fi

# Validate parameters
if [ -z "$MYSQL_PASSWORD" ]; then
    echo "${RED}Error: MYSQL_PASSWORD not in the environment${NC}"
    exit 1
fi

if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
    echo "${RED}Error: MYSQL_ROOT_PASSWORD not in the environment${NC}"
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
echo ""
echo "${YELLOW}[PHASE 2/10] Installing packages...${NC}"

# MySQL
pkg install -y mysql84-server mysql84-client

# Postfix with MySQL support (postfix-mysql replaces postfix)
pkg install -y postfix-mysql

# Dovecot with MySQL (dovecot-mysql replaces dovecot)
pkg install -y dovecot-mysql dovecot-pigeonhole

# Anti-spam and antivirus
pkg install -y rspamd redis clamav

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
pkg install -y nginx php84 php84-extensions
pkg install -y roundcube-php84
pkg install -y php84-mysqli php84-mbstring php84-intl php84-xml php84-zip php84-pdo php84-pdo_mysql php84-session php84-fileinfo php84-dom php84-iconv php84-curl php84-gd 2>/dev/null || true

# Create vmail user
pw groupadd vmail -g 5000 2>/dev/null || true
pw useradd vmail -u 5000 -g vmail -d /var/vmail -s /usr/sbin/nologin -c "Virtual Mail" 2>/dev/null || true
mkdir -p /var/vmail
chown -R vmail:vmail /var/vmail
chmod 770 /var/vmail

echo "${GREEN}  Packages installed${NC}"

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
# scrive file che devono restare leggibili da www e da postfix.
MYSQL_WORK=$(mktemp -d /var/tmp/mailpanel-mysql.XXXXXXXX) || {
    echo "${RED}Error: cannot create the temporary folder${NC}"; exit 1; }
trap 'rm -rf "$MYSQL_WORK"' EXIT HUP INT TERM
MYSQL_ROOT_CNF="$MYSQL_WORK/root.cnf"
MYSQL_SETUP_SQL="$MYSQL_WORK/setup.sql"

# La password di root. Un MySQL appena installato su FreeBSD lascia root SENZA password, e
# finche' resta cosi' qualunque utente locale -- www compreso, che fa girare Roundcube -- ha
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
mkdir -p /var/db/mailpanel

chown -R vmail:vmail /var/vmail
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

# main.cf
cat > /usr/local/etc/postfix/main.cf << POSTFIX_MAIN
# Postfix - FreeBSD Mail Panel
# Generated automatically

# Basic settings
myhostname = $MAIL_HOSTNAME
mydomain = $MAIL_HOSTNAME
myorigin = \\$mydomain
mydestination = localhost
mynetworks = 127.0.0.0/8 [::1]/128

# Virtual mailbox settings
virtual_mailbox_domains = mysql:/usr/local/etc/postfix/mysql-virtual-domains.cf
virtual_mailbox_maps = mysql:/usr/local/etc/postfix/mysql-virtual-mailboxes.cf
virtual_alias_maps = mysql:/usr/local/etc/postfix/mysql-virtual-aliases.cf
virtual_transport = lmtp:inet:127.0.0.1:24

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

echo "${GREEN}  Postfix configured${NC}"

# =============================================================================
# PHASE 7: CONFIGURE DOVECOT
# =============================================================================
echo ""
echo "${YELLOW}[PHASE 7/10] Configuring Dovecot...${NC}"

# La configurazione Dovecot viene scritta piu' avanti, in un blocco solo.

# Generate master password
MASTER_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)
mkdir -p /var/db/mailpanel
echo "$MASTER_PASSWORD" > /var/db/mailpanel/dovecot_master.key
chmod 600 /var/db/mailpanel/dovecot_master.key

if command -v doveadm >/dev/null 2>&1; then
    MASTER_PASSWORD_HASH=$(doveadm pw -s BLF-CRYPT -p "$MASTER_PASSWORD" 2>/dev/null)
else
    MASTER_PASSWORD_HASH='{PLAIN}'$MASTER_PASSWORD
fi

cat > /usr/local/etc/dovecot/master-users << MASTER_EOF
admin:$MASTER_PASSWORD_HASH
MASTER_EOF

chmod 640 /usr/local/etc/dovecot/master-users
chown root:dovecot /usr/local/etc/dovecot/master-users

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

# Redis
sysrc redis_enable="YES"
service redis start 2>/dev/null || true

# ClamAV
mkdir -p /var/run/clamav
chown clamav:clamav /var/run/clamav

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
servers = "127.0.0.1";
RSPAMD_REDIS

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

# Create Roundcube database
mysql --defaults-extra-file="$MYSQL_ROOT_CNF" << ROUNDCUBE_DB
CREATE DATABASE IF NOT EXISTS roundcubemail CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON roundcubemail.* TO '$MYSQL_USER'@'localhost';
GRANT ALL PRIVILEGES ON roundcubemail.* TO '$MYSQL_USER'@'127.0.0.1';
FLUSH PRIVILEGES;
ROUNDCUBE_DB

if [ -f /usr/local/www/roundcube/SQL/mysql.initial.sql ]; then
    # Le tabelle di Roundcube le fa root, dal file di credenziali: "-p$MYSQL_PASSWORD"
    # metteva anche questa password nella riga di comando, dove la legge chiunque con "ps".
    mysql --defaults-extra-file="$MYSQL_ROOT_CNF" roundcubemail \
        < /usr/local/www/roundcube/SQL/mysql.initial.sql 2>/dev/null || true
fi

ROUNDCUBE_DES_KEY=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)

cat > /usr/local/www/roundcube/config/config.inc.php << ROUNDCUBE_CONFIG
<?php
\\$config['db_dsnw'] = 'mysql://$MYSQL_USER:$MYSQL_PASSWORD@127.0.0.1/roundcubemail';
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
\\$config['skin'] = 'elastic';
\\$config['language'] = 'it_IT';
\\$config['enable_installer'] = false;
\\$config['default_charset'] = 'UTF-8';
\\$config['create_default_folders'] = true;
\\$config['plugins'] = array('archive', 'zipdownload');
ROUNDCUBE_CONFIG

chown -R www:www /usr/local/www/roundcube/temp /usr/local/www/roundcube/logs
chmod 640 /usr/local/www/roundcube/config/config.inc.php
chown root:www /usr/local/www/roundcube/config/config.inc.php

# Generate SSO key
if [ ! -f /var/db/mailpanel/roundcube_sso.key ]; then
    openssl rand 32 > /var/db/mailpanel/roundcube_sso.key
fi
chmod 640 /var/db/mailpanel/roundcube_sso.key
chown root:www /var/db/mailpanel/roundcube_sso.key

# PHP-FPM
cat > /usr/local/etc/php-fpm.d/www.conf << 'PHPFPM_CONF'
[www]
user = www
group = www
listen = /var/run/php-fpm.sock
listen.owner = www
listen.group = www
listen.mode = 0660
pm = dynamic
pm.max_children = 10
pm.start_servers = 3
pm.min_spare_servers = 2
pm.max_spare_servers = 5
PHPFPM_CONF

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
            fastcgi_pass unix:/var/run/php-fpm.sock;
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
    echo "  Roundcube 1.7 o successiva: radice di nginx impostata su public_html"
fi

sysrc nginx_enable="YES"
sysrc php_fpm_enable="YES"

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

echo ""
echo "${GREEN}=============================================================================${NC}"
echo "${GREEN}           Mail Server Installation Complete! (Postfix)${NC}"
echo "${GREEN}=============================================================================${NC}"
echo ""
echo "Services:"
echo "  Postfix (SMTP)      - ports 25, 587, 465"
echo "  Dovecot (IMAP/POP3) - ports 143, 993, 110, 995"
echo "  Rspamd (Anti-Spam)  - port 11332"
echo "  Roundcube           - https://$ROUNDCUBE_DOMAIN:$ROUNDCUBE_PORT"
echo ""
echo "Mail hostname: $MAIL_HOSTNAME"
echo ""

exit 0
        """;

    public void write_file() {
        File scriptFile = new File(SCRIPT_PATH);
        if (scriptFile.exists()) {
            scriptFile.delete();
        }

        try (FileWriter writer = new FileWriter(SCRIPT_PATH)) {
            writer.write(this.data);
            scriptFile.setExecutable(true);
            this.writed = true;
        } catch (IOException e) {
            System.out.println("Error writing script: " + e.getMessage());
        }
    }

    public String getScriptContent() {
        return this.data;
    }
}
