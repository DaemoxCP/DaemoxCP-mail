# FreeBSD Mail Panel

**Native mail server control panel for FreeBSD 15+**

Similar to Mailcow but **100% native** - NO Docker required.

**Created by Pietro Giuseppe D'Amico**

---

## Table of Contents

- [Overview](#overview)
- [Mail Server Stack](#mail-server-stack)
- [System Requirements](#system-requirements)
- [Dependencies](#dependencies)
- [Directory Structure](#directory-structure)
- [Configuration Files](#configuration-files)
- [Database Schema](#database-schema)
- [Ports Reference](#ports-reference)
- [Package Locks](#package-locks)
- [Service Commands](#service-commands)
- [Installation](#installation)
- [Web Panel](#web-panel)
- [SSL Certificates](#ssl-certificates)
- [Cloudflare Integration](#cloudflare-integration)
- [Security Features](#security-features)
- [Troubleshooting](#troubleshooting)

---

## Overview

FreeBSD Mail Panel is a complete mail server solution that installs and manages:

```
┌─────────────────────────────────────────────────────────────────┐
│                     FreeBSD Mail Panel                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│   │   Postfix   │    │   Dovecot   │    │   Rspamd    │        │
│   │    SMTP     │───▶│  IMAP/POP3  │    │  Anti-Spam  │        │
│   │  Port 25    │    │  Port 993   │    │ Port 11332  │        │
│   └─────────────┘    └─────────────┘    └─────────────┘        │
│          │                  │                  │                │
│          ▼                  ▼                  ▼                │
│   ┌─────────────────────────────────────────────────┐          │
│   │                   MySQL 8.0                      │          │
│   │       domains, mailboxes, aliases, panel_admin   │          │
│   └─────────────────────────────────────────────────┘          │
│                                                                 │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│   │   ClamAV    │    │    Redis    │    │  Roundcube  │        │
│   │  Antivirus  │    │    Cache    │    │   Webmail   │        │
│   └─────────────┘    └─────────────┘    └─────────────┘        │
│                                                                 │
│   ┌─────────────────────────────────────────────────┐          │
│   │              Web Panel (Port 2096)               │          │
│   └─────────────────────────────────────────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Mail Server Stack

### SMTP Server: Postfix

| Property | Value |
|----------|-------|
| **Package** | `postfix-mysql` |
| **Service** | `postfix` |
| **Config** | `/usr/local/etc/postfix/main.cf` |
| **Port 25** | Incoming mail (STARTTLS) |
| **Port 587** | Submission (STARTTLS + Auth) |
| **Port 465** | Submission SSL (SMTPS + Auth) |

MySQL lookup tables:
- `/usr/local/etc/postfix/mysql-virtual-domains.cf`
- `/usr/local/etc/postfix/mysql-virtual-mailboxes.cf`
- `/usr/local/etc/postfix/mysql-virtual-aliases.cf`

Postfix delivers mail to Dovecot via LMTP on port 24.

### IMAP/POP3 Server: Dovecot

| Property | Value |
|----------|-------|
| **Package** | `dovecot-mysql`, `dovecot-pigeonhole` |
| **Service** | `dovecot` |
| **Config** | `/usr/local/etc/dovecot/` |
| **Port 143** | IMAP (STARTTLS) |
| **Port 993** | IMAPS (implicit SSL) |
| **Port 110** | POP3 (STARTTLS) |
| **Port 995** | POP3S (implicit SSL) |
| **LMTP Port** | 24 (localhost only) |
| **Mailboxes** | `/var/vmail/{domain}/{user}` |

### Anti-Spam: Rspamd

| Property | Value |
|----------|-------|
| **Package** | `rspamd` |
| **Service** | `rspamd` |
| **Config** | `/usr/local/etc/rspamd/` |
| **Port 11332** | Milter (for Postfix) |
| **Port 11333** | Normal worker |
| **Port 11334** | Web UI/Controller |

Integration with Postfix via milter protocol.

### Antivirus: ClamAV

| Property | Value |
|----------|-------|
| **Package** | `clamav` |
| **Services** | `clamav_clamd`, `clamav_freshclam` |
| **Socket** | `/var/run/clamav/clamd.sock` |

Integrated with Rspamd for email scanning.

### Cache: Redis

| Property | Value |
|----------|-------|
| **Package** | `redis` |
| **Service** | `redis` |
| **Port** | 6379 |

Used by Rspamd for caching.

### Database: MySQL 8.0

| Property | Value |
|----------|-------|
| **Package** | `mysql80-server`, `mysql80-client` |
| **Service** | `mysql-server` |
| **Port** | 3306 |
| **Database** | `mailserver` (configurable) |

### Webmail: Roundcube

| Property | Value |
|----------|-------|
| **Package** | `roundcube-php84` |
| **Web Server** | nginx + php-fpm |
| **Port** | 8443 (configurable) |
| **Database** | `roundcubemail` |

---

## System Requirements

- **OS**: FreeBSD 15.0 or later
- **RAM**: 2GB minimum, 4GB recommended
- **Disk**: 20GB minimum
- **Java**: JDK 24 (for panel)
- **Root access**: Required for installation

---

## Dependencies

### Java Dependencies (pom.xml)

| Dependency | Version | Purpose |
|------------|---------|---------|
| `mysql-connector-j` | 9.1.0 | MySQL database connection |
| `lanterna` | 3.1.2 | Terminal GUI |
| `sqlite-jdbc` | 3.47.1.0 | SQLite for panel config |
| `slf4j-nop` | 2.0.16 | Logging |
| `json` | 20241224 | JSON parsing |
| `jbcrypt` | 0.4 | Mailbox password hashing |
| `webauthn-server-core` | 2.5.0 | WebAuthn/Passkey support |
| `yubico-util` | 2.5.0 | Yubico utilities |

### FreeBSD Packages (installed automatically)

```
postfix-mysql dovecot-mysql dovecot-pigeonhole
rspamd redis clamav
mysql80-server mysql80-client
nginx php84 php84-extensions roundcube-php84
openssl
```

---

## Directory Structure

```
/usr/local/etc/
├── postfix/
│   ├── main.cf                 # Postfix main config
│   ├── master.cf               # Postfix master config
│   ├── mysql-virtual-domains.cf
│   ├── mysql-virtual-mailboxes.cf
│   └── mysql-virtual-aliases.cf
├── dovecot/
│   ├── dovecot.conf            # Main config
│   ├── dovecot-sql.conf        # SQL auth config
│   └── conf.d/                 # Config fragments
├── rspamd/
│   ├── rspamd.conf             # Main config
│   ├── local.d/                # Local overrides
│   └── override.d/             # Override configs
├── nginx/
│   └── nginx.conf              # Roundcube web server
└── ssl/
    └── mail/
        ├── fullchain.pem       # SSL certificate + chain
        └── privkey.pem         # Private key

/var/
├── vmail/                      # Virtual mailboxes
│   └── {domain}/
│       └── {user}/
│           └── Maildir/
├── spool/postfix/
│   └── private/
│       └── auth                # Dovecot SASL socket
├── run/
│   ├── dovecot/
│   │   └── lmtp                # LMTP socket
│   ├── clamav/
│   │   └── clamd.sock          # ClamAV socket
│   └── rspamd/
├── db/mailpanel/
│   ├── dovecot_master.key      # Dovecot master password
│   └── roundcube_sso.key       # SSO encryption key
└── log/
    ├── maillog
    ├── dovecot.log
    └── rspamd/

./database/                     # Panel SQLite database
    └── mailpanel.db

./install_scripts/              # Generated install scripts
    ├── install_mail_server.sh
    └── setup_timezone_and_dns.sh
```

---

## Configuration Files

### Postfix (`/usr/local/etc/postfix/main.cf`)

```conf
# Postfix - FreeBSD Mail Panel

# Basic settings
myhostname = mail.example.com
mydomain = mail.example.com
myorigin = $mydomain
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

# SASL authentication via Dovecot
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes

# Milter (Rspamd)
smtpd_milters = inet:127.0.0.1:11332
non_smtpd_milters = inet:127.0.0.1:11332
milter_protocol = 6
milter_default_action = accept
```

### Dovecot SQL Auth (`/usr/local/etc/dovecot/dovecot-sql.conf`)

```conf
driver = mysql
connect = host=127.0.0.1 dbname=mailserver user=mailpanel password=YOUR_PASSWORD
default_pass_scheme = BLF-CRYPT
password_query = SELECT email as user, password FROM mailboxes WHERE email='%u' AND active=1
```

---

## Database Schema

### SQLite (Panel Configuration)

File: `./database/mailpanel.db`

```sql
CREATE TABLE config (
    id INTEGER PRIMARY KEY,
    mail_panel_host TEXT,           -- Web panel host (0.0.0.0)
    mail_panel_port TEXT,           -- Web panel port (2096)
    mail_panel_ssl_cert TEXT,       -- SSL certificate (PEM)
    mail_panel_ssl_cert_key TEXT,   -- empty: the key is in the panel secrets file
    mail_panel_ssl_chain TEXT,      -- SSL chain (PEM)
    mail_panel_sessions_prefix TEXT,-- Session cookie prefix
    mysql_host TEXT,                -- MySQL host
    mysql_port TEXT,                -- MySQL port
    mysql_user TEXT,                -- MySQL username
    mysql_password TEXT,            -- empty: the password is in the panel secrets file
    mysql_database TEXT,            -- MySQL database name
    mail_hostname TEXT,             -- Mail server hostname
    postfix_installed INTEGER,      -- Postfix status
    dovecot_installed INTEGER,      -- Dovecot status
    rspamd_installed INTEGER,       -- Rspamd status
    clamav_installed INTEGER,       -- ClamAV status
    roundcube_installed INTEGER,    -- Roundcube status
    roundcube_domain TEXT,          -- Roundcube domain
    roundcube_port TEXT,            -- Roundcube port
    roundcube_ssl_cert TEXT,        -- Roundcube SSL cert path
    roundcube_ssl_key TEXT          -- Roundcube SSL key path
);
```

### MySQL (Mail Data)

Database: `mailserver` (configurable)

```sql
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
);

-- Mailboxes
CREATE TABLE mailboxes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,       -- BLF-CRYPT hash
    name VARCHAR(255),
    quota_mb INT DEFAULT 1024,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
);

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
);

-- Panel administrators: no password. They sign in with a passkey or a one-time code.
CREATE TABLE panel_admin (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email_enc VARCHAR(512) NULL,          -- AES-256-GCM, random nonce
    email_index CHAR(64) NULL UNIQUE,     -- blind index, HMAC-SHA256
    user_handle VARCHAR(64) NULL UNIQUE,  -- WebAuthn user handle
    created_at DATETIME NULL,             -- UTC
    last_login DATETIME NULL,             -- UTC
    active BOOLEAN DEFAULT TRUE,
    role ENUM('superadmin', 'admin', 'operator', 'viewer') DEFAULT 'admin',
    theme VARCHAR(10) DEFAULT 'auto',
    language VARCHAR(5) NULL
);
-- Also: admin_passkeys, panel_sessions (only the SHA-256 of the session token), and one table
-- per one-time code flow (login_code_email, login_code_console, stepup_code, email_change_code)
-- holding only the HMAC of the code.

-- Panel settings
CREATE TABLE panel_settings (
    setting_key VARCHAR(64) PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Rate limits
CREATE TABLE rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_type ENUM('global', 'domain', 'mailbox') NOT NULL,
    target_id INT NULL,
    max_per_hour INT DEFAULT 100,
    max_per_day INT DEFAULT 1000,
    max_recipients INT DEFAULT 50,
    enabled BOOLEAN DEFAULT TRUE
);

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
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
);

-- Forwarding rules
CREATE TABLE forwarding_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mailbox_id INT NOT NULL,
    destination VARCHAR(255) NOT NULL,
    keep_copy BOOLEAN DEFAULT TRUE,
    enabled BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
);

-- Sieve filters
CREATE TABLE sieve_filters (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mailbox_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    priority INT DEFAULT 0,
    enabled BOOLEAN DEFAULT TRUE,
    conditions JSON NOT NULL,
    actions JSON NOT NULL,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
);

-- Roundcube SSO tokens
CREATE TABLE roundcube_tokens (
    token VARCHAR(64) PRIMARY KEY,
    mailbox_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
);

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
    bytes_received BIGINT DEFAULT 0
);

-- Audit log
CREATE TABLE audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    username VARCHAR(255),
    ip_address VARCHAR(45) NOT NULL,
    details TEXT,
    user_agent VARCHAR(512),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## Ports Reference

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| Postfix | 25 | TCP | SMTP (incoming mail) |
| Postfix | 587 | TCP | Submission (STARTTLS) |
| Postfix | 465 | TCP | SMTPS (implicit SSL) |
| Dovecot | 143 | TCP | IMAP (STARTTLS) |
| Dovecot | 993 | TCP | IMAPS (implicit SSL) |
| Dovecot | 110 | TCP | POP3 (STARTTLS) |
| Dovecot | 995 | TCP | POP3S (implicit SSL) |
| Dovecot | 24 | TCP | LMTP (localhost only) |
| Rspamd | 11332 | TCP | Milter interface |
| Rspamd | 11333 | TCP | Normal worker |
| Rspamd | 11334 | TCP | Web UI/Controller |
| MySQL | 3306 | TCP | Database |
| Redis | 6379 | TCP | Cache |
| Roundcube | 8443 | TCP | Webmail (HTTPS) |
| **Web Panel** | **2096** | TCP | HTTPS admin panel |

---

## Package Locks

At startup the panel runs `pkg lock` on every installed package of the mail stack (Postfix,
Dovecot, Rspamd, ClamAV, Redis, MySQL, nginx, PHP and its extensions, Roundcube, fail2ban,
the panel's own JDK). On a full installation that is around 40 packages.

**Why.** The panel generates the configuration of these services. A new major version may
refuse that configuration instead of degrading — Dovecot 2.4 does not start on a 2.3
configuration — so a plain `pkg upgrade` could stop the mail server, and no version number
would say so. The lock makes that impossible until the panel's guided update has checked the
live configuration, the vulnerability ranges and the services that must restart.

**How to update a locked package.** From the panel: *Updates*. It shows, per package, the
catalog version, whether it closes a vulnerability and which services will restart; then it
unlocks, updates, re-locks and restarts, verifying each step. An administrator can also
unlock a single package from that page, and the panel remembers that choice and does not
lock it again.

**What `pkg upgrade` does meanwhile.** It skips the locked packages, names them in a line
that scrolls past, leaves them out of the summary and **exits 0**:

```
nginx-1.30.5_2,3 is locked and may not be modified
postfix-mysql-3.11.7_1,1 is locked and may not be modified
The following 3 package(s) will be affected (of 0 checked):
...
Number of packages to be upgraded: 3
```

So from the outside it looks like there was nothing to do. The panel's periodic report says
how many updates the lock is holding back, and marks the vulnerable ones.

**If the panel is removed, or stops starting.** The locks stay: nothing removes them at
shutdown, by design. Those packages then stop receiving updates, **including security
fixes**, silently. The panel leaves the explanation on the machine:

- `/var/db/mailpanel/locked-packages.txt` — why they are locked, the list, and the commands
  to release them. Rewritten at every startup and at every lock change.
- each locked package carries a `mail_panel_lock` annotation in pkg's own database, visible
  with `pkg info -A <name>`, pointing at that file.
- removing the panel's rc script from the panel says how many packages stay locked and how
  to release them.

To release everything by hand:

```bash
pkg unlock -a -y
```

One package only: `pkg unlock -y <name>`. The real state is always `pkg lock -l`.

**A way back before every package job.** Before the guided update, the maintenance, the update
of unprotected packages, Roundcube, Python, MySQL 8.4, the relinking and the removal of a
package, the panel creates a ZFS boot environment named `packages-before-<UTC time>-<job>`, and
the job log says how to go back (`bectl activate <name> && shutdown -r now`). If the system has
boot environments and the creation fails, the job does not start. If no package changed in the
end, that boot environment is removed; otherwise the panel keeps the last three and removes the
older ones (never the active one). Careful: when `/var/vmail` or `/var/db/mysql` live inside the
boot environment, going back also brings back the mail and the databases as they were: the log
says so, and `tools/upgrade/rollback-panel.sh` shows how to copy the newer mail first.

**One package job at a time, across processes.** The package turn is also an `fcntl` lock on
`/var/db/mailpanel/package-turn.lock` (the file says who holds it). A second panel process —
the terminal menu opened while the web panel is updating — cannot start a job and does not
touch the running job's list at startup. The lock disappears with the process that held it.

**If a job is interrupted** (the panel killed, restarted or crashed, a power loss), the next
start protects the listed packages again; if `pkg` is still working, it retries every 30
seconds until it can, instead of waiting for the next restart. It also writes
`/var/db/mailpanel/package-job-interrupted.json`: which job, when, and what to check by hand.
The notice stays at the top of *Updates* and in the periodic report until an administrator
marks it as checked (recorded in the audit log). The report also names packages still
unprotected, and mail stack packages that nobody unlocked from the panel.

**`pkg` is never killed halfway.** A `pkg install/upgrade/delete` or `freebsd-update install`
that runs past its time limit is not stopped: an installation stopped halfway leaves packages
half-installed. The job log says it is still working and keeps waiting. Other commands are
stopped together with all their subprocesses.

---

## Service Commands

### Postfix (SMTP)

```bash
# Start/Stop/Restart
service postfix start
service postfix stop
service postfix restart

# Reload configuration (no downtime)
service postfix reload

# Check configuration syntax
postfix check

# View mail queue
postqueue -p

# Flush mail queue
postqueue -f

# Delete all queued mail
postsuper -d ALL

# Enable at boot
sysrc postfix_enable="YES"
```

### Dovecot (IMAP/POP3)

```bash
service dovecot start
service dovecot stop
service dovecot restart
service dovecot reload

# Check configuration
doveconf -n

# Enable at boot
sysrc dovecot_enable="YES"
```

### Rspamd (Anti-Spam)

```bash
service rspamd start
service rspamd stop
service rspamd restart
service rspamd reload

# Check configuration
rspamadm configtest

# Enable at boot
sysrc rspamd_enable="YES"
```

### ClamAV (Antivirus)

```bash
# Daemon
service clamav_clamd start
service clamav_clamd stop

# Signature updates
service clamav_freshclam start
service clamav_freshclam stop

# Manual update
freshclam

# Enable at boot
sysrc clamav_clamd_enable="YES"
sysrc clamav_freshclam_enable="YES"
```

### Redis (Cache)

```bash
service redis start
service redis stop
service redis restart

sysrc redis_enable="YES"
```

### MySQL

```bash
service mysql-server start
service mysql-server stop
service mysql-server restart

sysrc mysql_enable="YES"
```

### Nginx + PHP-FPM (Roundcube)

```bash
service nginx start
service nginx stop
service nginx restart

service php_fpm start
service php_fpm stop
service php_fpm restart

sysrc nginx_enable="YES"
sysrc php_fpm_enable="YES"
```

---

## Installation

### 1. Build the Panel

```bash
# Requires Java 25 and Maven
tools/build-jar.sh
```

`tools/build-jar.sh` runs `mvn package` with the build number and the commit written into the jar
(the dashboard shows them behind the eye button) and prints the jar's SHA-256. Extra options go to
Maven, for example `-o` to build offline. A plain `mvn clean package` works too: the dashboard then
says the build was not recorded.

### 2. Run the Panel

```bash
java -jar target/freebsd-mail-panel-1.0.jar
```

Al primo avvio il pannello scrive accanto al jar un `run.sh` che rispecchia esattamente
il comando con cui e' partito. Non e' un file da distribuire e non serve al funzionamento:
e' solo una scorciatoia. Se esiste gia', il pannello non lo tocca.

Due modi di avviarlo:

| Comando | Cosa fa |
|---|---|
| `java -jar target/freebsd-mail-panel-1.0.jar` | menu a schermo; il server web parte dalla voce 100 |
| `java -jar target/freebsd-mail-panel-1.0.jar --web` | **solo** il server web: nessun menu, nessun terminale richiesto |

La modalita' `--web` esiste perche' il pannello deve poter tornare su da solo dopo essersi
spento per aggiornare la propria JVM, dove un terminale non c'e'. Il comando di riavvio non
viene letto da `run.sh`: il pannello lo ricostruisce dal processo vivo, quindi riparte
esattamente com'era partito.

### 3. Terminal Menu

```
╔═══════════════════════════════════════════════════════════════╗
║            FreeBSD Mail Panel v1.0 - Select an option         ║
╠═══════════════════════════════════════════════════════════════╣
║  1) Set TimeZone and CloudFlare DNS                           ║
║  2) Edit Panel Configuration                                  ║
║  3) Edit Roundcube Configuration                              ║
║  4) Install/Reinstall Mail Server                             ║
║  5) Emergency access code                                     ║
║  >>> Start Mail Panel WebServer <<<                           ║
║  Exit                                                         ║
╚═══════════════════════════════════════════════════════════════╝
```

### 4. Configure Roundcube First (Option 3)

Before installing the mail server, configure Roundcube:
- Domain name
- Port (default: 8443)
- SSL certificate paths (optional, will use panel's SSL if not set)

### 5. Install Mail Server (Option 4)

This will:
1. Stop existing services
2. Remove old configurations
3. Install packages (Postfix, Dovecot, Rspamd, ClamAV, Redis, Roundcube)
4. Configure MySQL database
5. Create virtual mail user (vmail:5000)
6. Generate self-signed SSL certificate
7. Configure all services
8. Start all services

### 6. Start Web Panel

Select "Start Mail Panel WebServer" to start the HTTPS panel on port 2096.

---

## Web Panel

### Access

```
https://your-server:2096/
```

### First Administrator

The first administrator is never created from the web page: whoever reached it first would
become the administrator. Until there is one, the panel shows `/setup` with the command to run
on the server, from the panel folder:

```bash
java -jar freebsd-mail-panel-1.0.jar --create-admin <name> <email>
```

It creates a superadmin with no password and prints a one-time 8-digit code, valid for 15
minutes: on the login page choose "Code from the server console", then register a passkey in
Settings. It refuses when an active administrator already exists; the others are added from the
Administrators page.

### Signing In

There are no passwords. An administrator signs in with:

- a **passkey** (WebAuthn): no username to type;
- a **6-digit code** sent to the sign-in email by this server's Postfix, valid for 10 minutes;
- an **8-digit code** from the server console, when the email does not arrive:

```bash
java -jar freebsd-mail-panel-1.0.jar --access-code [name]
```

The same one-time code comes from the terminal menu, option **5) Emergency access code**: it is
always available from the server, for any active administrator, when passkey and email are not
enough (and it creates the first administrator if there is none yet).

The panel keys (data encryption, blind index, code HMAC, CSRF, webmail key) and the panel's
MySQL password and TLS private key are in `/usr/local/etc/mail-panel/panel-secrets.properties`
(mode 600, folder 700), never in the database. On a server that is already running, the first
start of this version moves the MySQL password and the TLS key out of `database/mail_panel.db`
by itself and empties those columns; `database/` becomes 700 and `mail_panel.db` 600.

**Mailbox passwords can always be seen and copied** (Mailboxes → Edit → Reveal): each one is
stored as the bcrypt hash Dovecot reads and as an AES-256-GCM copy (key in
`/usr/local/etc/mail-panel/master.key`). If the copy cannot be written, the password is not saved
at all. Reveal shows the copy only while it matches the hash. Password changes from the webmail
go through the panel (Roundcube password plugin, `httpapi` driver, to
`https://127.0.0.1:<panel port>/api/internal/mailbox-password`, loopback only, with the webmail
key): the panel checks the current password and writes hash and copy together. The panel writes
these settings in a block at the end of Roundcube's `config.inc.php` at every start, replacing the
old `sql` driver lines (which stored the new password in clear text, so Dovecot refused it). Rows
left in clear text by that bug are rewritten as hash + copy at startup. Mailboxes created before
the vault get their copy the next time someone signs in to the webmail with them.

### Features

- Domain management (add, edit, delete)
- Mailbox management (create, modify, quota)
- Alias management
- DKIM key generation (RSA 2048-bit)
- DNS record generator (SPF, DKIM, DMARC)
- Service status monitoring
- Mail queue management
- SSL certificate management
- Roundcube SSO integration
- Audit logging
- Passwordless sign-in: passkeys (WebAuthn) and one-time codes by email or from the console

---

## SSL Certificates

### Certificate Location

```
/usr/local/etc/ssl/mail/
├── fullchain.pem    # Certificate + chain
└── privkey.pem      # Private key
```

### Self-Signed (Default)

Generated automatically during installation. **Replace with a real certificate for production!**

### Let's Encrypt

```bash
# Install certbot
pkg install -y py311-certbot

# Generate certificate (requires port 80 accessible)
certbot certonly --standalone -d mail.example.com

# Copy to mail directory
cp /usr/local/etc/letsencrypt/live/mail.example.com/fullchain.pem /usr/local/etc/ssl/mail/
cp /usr/local/etc/letsencrypt/live/mail.example.com/privkey.pem /usr/local/etc/ssl/mail/

# Restart services
service postfix reload
service dovecot reload
```

### Cloudflare Origin Certificate

1. Generate Origin Certificate in Cloudflare dashboard
2. Copy certificate to `/usr/local/etc/ssl/mail/fullchain.pem`
3. Copy private key to `/usr/local/etc/ssl/mail/privkey.pem`
4. Configure in web panel under "Edit Panel Configuration"

---

## Cloudflare Integration

### Proxy Support

The panel supports Cloudflare proxy with:
- `CF-Connecting-IP` header for real client IP
- `SameSite=Lax` cookies for compatibility

### DNS Records Required

| Type | Name | Value | Proxy |
|------|------|-------|-------|
| A | mail | YOUR_IP | DNS only (gray cloud) |
| MX | @ | mail.example.com | - |
| TXT | @ | v=spf1 mx ~all | - |
| TXT | _dmarc | v=DMARC1; p=none | - |
| TXT | mail._domainkey | (DKIM key from panel) | - |

**Important**: Mail records (A for mail, MX) should NOT be proxied through Cloudflare.

---

## Security Features

### Authentication
- **Panel administrators**: no password; passkeys (WebAuthn, user verification required) or
  one-time codes (only their HMAC is stored; 5 attempts; rate limits per IP, subnet and recipient)
- **Same answer for every address**: asking for a code never tells whether an account exists
- **Sessions**: in MySQL, only the SHA-256 of the token; `__Host-` cookie; 30 minutes idle, 12 hours at most; revocable
- **Admin emails**: AES-256-GCM with a blind index; keys outside the database
- **Mailbox passwords**: BLF-CRYPT (Blowfish)

### Protection
- CSRF protection on all forms
- Session management with secure cookies
- IP binding on Roundcube SSO tokens
- AES-256-GCM for SSO token encryption
- Fail2ban integration ready
- Rate limiting support

### Audit
- All admin actions logged
- IP address tracking
- User agent logging

---

## Troubleshooting

### Postfix won't start

```bash
# Check configuration
postfix check

# Check logs
tail -f /var/log/maillog

# Common issues:
# - SSL certificate missing/invalid
# - Port already in use
# - MySQL not accessible
```

### Dovecot authentication failing

```bash
# Check SQL config
cat /usr/local/etc/dovecot/dovecot-sql.conf

# Test MySQL connection
mysql -u mailpanel -p mailserver -e "SELECT * FROM mailboxes;"

# Check logs
tail -f /var/log/dovecot.log
```

### Rspamd not filtering

```bash
# Check if running
sockstat -l | grep 11332

# Check config
rspamadm configtest

# Check logs
tail -f /var/log/rspamd/rspamd.log
```

### Mail not delivered

```bash
# Check Postfix queue
postqueue -p

# Check LMTP connection
telnet 127.0.0.1 24

# Check mailbox permissions
ls -la /var/vmail/
```

### Web panel login issues

1. Clear browser cookies
2. Check if using Cloudflare proxy
3. Verify MySQL connection in panel config
4. Check `./database/mailpanel.db` exists

---

## Architecture

```
FreeBSD Mail Panel (Java 24)
├── Main.java                 # Entry point, terminal GUI
├── webserver/
│   ├── SSLMailServer.java    # HTTPS server
│   ├── WebSessions.java      # Session management
│   └── SecurityUtils.java    # Security utilities
├── database/
│   └── MailDatabase.java     # MySQL for mail data
├── sqli/
│   ├── dataBaseManager.java  # SQLite manager
│   └── database.java         # SQLite connection
├── security/
│   ├── TotpManager.java      # 2FA TOTP
│   ├── PasskeyManager.java   # WebAuthn support
│   ├── DkimManager.java      # DKIM key generation
│   ├── DnsRecordsGenerator.java
│   ├── AcmeManager.java      # Let's Encrypt
│   └── Fail2banManager.java
├── integration/
│   ├── RoundcubeSsoManager.java  # SSO with Roundcube
│   ├── RspamdManager.java        # Rspamd API
│   └── SieveGenerator.java       # Mail filters
├── monitoring/
│   ├── MailQueueManager.java # Postfix queue
│   └── LogManager.java       # Log parsing
├── gui/
│   ├── Chooser.java          # Main menu
│   ├── ModifyData.java       # Config editor
│   ├── RoundcubeConfig.java  # Roundcube setup
│   └── Welcome.java          # Info dialogs
├── scripts/
│   ├── FullMailServerScript.java  # Complete installation
│   ├── PostfixScript.java         # SMTP setup
│   ├── DovecotScript.java         # IMAP/POP3 setup
│   ├── RspamdScript.java          # Anti-spam setup
│   ├── ClamAVScript.java          # Antivirus setup
│   ├── RoundcubeScript.java       # Webmail setup
│   ├── RedisScript.java           # Cache setup
│   ├── MySQLMailScript.java       # Database setup
│   ├── LetsEncryptScript.java     # SSL certificates
│   └── SetTimeOnSystemScript.java # Timezone/DNS
└── content/
    └── MailPanelContent.java # HTML/CSS/JS generator
```

---

## Password Hashing

- **Mailbox passwords**: BLF-CRYPT (Blowfish) - for Dovecot compatibility
- **Panel administrators**: no password (passkeys and one-time codes)

---

## User and Group

Virtual mail is handled by:
- **User**: vmail (UID 5000)
- **Group**: vmail (GID 5000)
- **Home**: /var/vmail

---

## License

MIT License

---

&copy; 2025 FreeBSD Mail Panel - Created by Pietro Giuseppe D'Amico
