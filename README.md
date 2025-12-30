# FreeBSD Mail Panel

**Native mail server control panel for FreeBSD 15+**

Similar to Mailcow but **100% native** - NO Docker required.

**Created by Pietro Giuseppe D'Amico**

---

## Table of Contents

- [Overview](#overview)
- [Mail Server Stack](#mail-server-stack)
- [System Requirements](#system-requirements)
- [Directory Structure](#directory-structure)
- [Configuration Files](#configuration-files)
- [Database Schema](#database-schema)
- [Ports Reference](#ports-reference)
- [Service Commands](#service-commands)
- [Installation](#installation)
- [Web Panel](#web-panel)
- [SSL Certificates](#ssl-certificates)
- [Cloudflare Integration](#cloudflare-integration)
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
│   │  OpenSMTPD  │    │   Dovecot   │    │   Rspamd    │        │
│   │    SMTP     │───▶│  IMAP/POP3  │    │  Anti-Spam  │        │
│   │  Port 25    │    │  Port 993   │    │ Port 11332  │        │
│   └─────────────┘    └─────────────┘    └─────────────┘        │
│          │                  │                  │                │
│          ▼                  ▼                  ▼                │
│   ┌─────────────────────────────────────────────────┐          │
│   │                   MySQL 8.0                      │          │
│   │     virtual_domains, virtual_users, aliases      │          │
│   └─────────────────────────────────────────────────┘          │
│                                                                 │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│   │   ClamAV    │    │    Redis    │    │  Web Panel  │        │
│   │  Antivirus  │    │    Cache    │    │  Port 2096  │        │
│   └─────────────┘    └─────────────┘    └─────────────┘        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Mail Server Stack

> **IMPORTANT: We use OpenSMTPD, NOT Postfix!**
>
> OpenSMTPD is the native FreeBSD mail transfer agent.

### SMTP Server: OpenSMTPD

| Property | Value |
|----------|-------|
| **Package** | `opensmtpd`, `opensmtpd-extras` |
| **Service** | `smtpd` |
| **Config** | `/usr/local/etc/mail/smtpd.conf` |
| **Port 25** | Incoming mail (STARTTLS) |
| **Port 587** | Submission (STARTTLS + Auth) |
| **Port 465** | Submission SSL (SMTPS + Auth) |

MySQL lookup tables:
- `/usr/local/etc/mail/mysql-domains.cf`
- `/usr/local/etc/mail/mysql-users.cf`
- `/usr/local/etc/mail/mysql-aliases.cf`
- `/usr/local/etc/mail/mysql-credentials.cf`

### IMAP/POP3 Server: Dovecot

| Property | Value |
|----------|-------|
| **Package** | `dovecot`, `dovecot-pigeonhole` |
| **Service** | `dovecot` |
| **Config** | `/usr/local/etc/dovecot/` |
| **Port 143** | IMAP (STARTTLS) |
| **Port 993** | IMAPS (implicit SSL) |
| **Port 110** | POP3 (STARTTLS) |
| **Port 995** | POP3S (implicit SSL) |
| **LMTP Socket** | `/var/run/dovecot/lmtp` |
| **Mailboxes** | `/var/vmail/{domain}/{user}` |

### Anti-Spam: Rspamd

| Property | Value |
|----------|-------|
| **Package** | `rspamd` |
| **Service** | `rspamd` |
| **Config** | `/usr/local/etc/rspamd/` |
| **Port 11332** | Milter (for OpenSMTPD filter) |
| **Port 11333** | Normal worker |
| **Port 11334** | Web UI/Controller |

Integration with OpenSMTPD via `filter-rspamd`.

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

---

## System Requirements

- **OS**: FreeBSD 15.0 or later
- **RAM**: 2GB minimum, 4GB recommended
- **Disk**: 20GB minimum
- **Java**: JDK 17+ (for panel)
- **Root access**: Required for installation

---

## Directory Structure

```
/usr/local/etc/
├── mail/
│   ├── smtpd.conf              # OpenSMTPD main config
│   ├── mysql-domains.cf        # Domain lookup
│   ├── mysql-users.cf          # User lookup
│   ├── mysql-aliases.cf        # Alias lookup
│   └── mysql-credentials.cf    # Auth credentials
├── dovecot/
│   ├── dovecot.conf            # Main config
│   ├── dovecot-sql.conf        # SQL auth config
│   └── conf.d/                 # Config fragments
├── rspamd/
│   ├── rspamd.conf             # Main config
│   ├── local.d/                # Local overrides
│   └── override.d/             # Override configs
└── ssl/
    └── mail/
        ├── fullchain.pem       # SSL certificate + chain
        └── privkey.pem         # Private key

/var/
├── vmail/                      # Virtual mailboxes
│   └── {domain}/
│       └── {user}/
│           └── Maildir/
├── run/
│   ├── dovecot/
│   │   └── lmtp                # LMTP socket
│   ├── clamav/
│   │   └── clamd.sock          # ClamAV socket
│   └── rspamd/
│       └── rspamd.pid
└── log/
    ├── dovecot.log
    ├── rspamd/
    └── maillog

./database/                     # Panel SQLite database
    └── mailpanel.db

./install_scripts/              # Generated install scripts
    ├── install_mail_server.sh
    └── setup_timezone_and_dns.sh
```

---

## Configuration Files

### OpenSMTPD (`/usr/local/etc/mail/smtpd.conf`)

```conf
# OpenSMTPD - FreeBSD Mail Panel

# PKI (SSL/TLS)
pki mail.example.com cert "/usr/local/etc/ssl/mail/fullchain.pem"
pki mail.example.com key "/usr/local/etc/ssl/mail/privkey.pem"

# MySQL Tables
table domains mysql:/usr/local/etc/mail/mysql-domains.cf
table users mysql:/usr/local/etc/mail/mysql-users.cf
table aliases mysql:/usr/local/etc/mail/mysql-aliases.cf
table credentials mysql:/usr/local/etc/mail/mysql-credentials.cf

# Filters
filter rspamd proc-exec "filter-rspamd"

# Listen directives
listen on lo0
listen on egress port 25 tls pki mail.example.com filter "rspamd"
listen on egress port 587 tls-require pki mail.example.com auth <credentials> filter "rspamd"
listen on egress port 465 smtps pki mail.example.com auth <credentials> filter "rspamd"

# Actions
action "local_mail" mbox alias <aliases>
action "virtual_mail" lmtp "/var/run/dovecot/lmtp" virtual <users>
action "relay_out" relay

# Matching rules
match from any for domain <domains> action "virtual_mail"
match from local for local action "local_mail"
match auth from any for any action "relay_out"
```

### Dovecot SQL Auth (`/usr/local/etc/dovecot/dovecot-sql.conf`)

```conf
driver = mysql
connect = host=127.0.0.1 dbname=mailserver user=mailpanel password=YOUR_PASSWORD
default_pass_scheme = BLF-CRYPT
password_query = SELECT email as user, password FROM virtual_users WHERE email='%u' AND active=1
```

---

## Database Schema

### SQLite (Panel Configuration)

File: `./database/mailpanel.db`

```sql
-- Panel configuration table
CREATE TABLE config (
    id INTEGER PRIMARY KEY,
    mail_panel_host TEXT,           -- Web panel host (0.0.0.0)
    mail_panel_port TEXT,           -- Web panel port (2096)
    mail_panel_ssl_cert TEXT,       -- SSL certificate (PEM)
    mail_panel_ssl_cert_key TEXT,   -- SSL private key (PEM)
    mail_panel_ssl_chain TEXT,      -- SSL chain (PEM)
    mail_panel_sessions_prefix TEXT,-- Session cookie prefix
    mysql_host TEXT,                -- MySQL host
    mysql_port TEXT,                -- MySQL port
    mysql_user TEXT,                -- MySQL username
    mysql_password TEXT,            -- MySQL password
    mysql_database TEXT,            -- MySQL database name
    mail_hostname TEXT,             -- Mail server hostname
    opensmtpd_installed INTEGER,    -- OpenSMTPD status (NOT postfix!)
    dovecot_installed INTEGER,      -- Dovecot status
    rspamd_installed INTEGER,       -- Rspamd status
    clamav_installed INTEGER,       -- ClamAV status
    roundcube_installed INTEGER     -- Roundcube status
);
```

### MySQL (Mail Data)

Database: `mailserver` (configurable)

```sql
-- Virtual domains
CREATE TABLE virtual_domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,  -- e.g., "example.com"
    active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Virtual users (mailboxes)
CREATE TABLE virtual_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,  -- e.g., "user@example.com"
    password VARCHAR(255) NOT NULL,       -- BLF-CRYPT hash
    quota BIGINT DEFAULT 0,
    active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
);

-- Virtual aliases
CREATE TABLE virtual_aliases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    source VARCHAR(255) NOT NULL,        -- e.g., "info@example.com"
    destination VARCHAR(255) NOT NULL,   -- e.g., "user@example.com"
    active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
);

-- Panel administrators
CREATE TABLE panel_admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,       -- BCrypt hash
    email VARCHAR(255),
    role VARCHAR(50) DEFAULT 'admin',
    totp_secret VARCHAR(255),             -- 2FA secret
    totp_enabled TINYINT(1) DEFAULT 0,
    active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Settings
CREATE TABLE settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(255) NOT NULL UNIQUE,
    setting_value TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

---

## Ports Reference

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| OpenSMTPD | 25 | TCP | SMTP (incoming mail) |
| OpenSMTPD | 587 | TCP | Submission (STARTTLS) |
| OpenSMTPD | 465 | TCP | SMTPS (implicit SSL) |
| Dovecot | 143 | TCP | IMAP (STARTTLS) |
| Dovecot | 993 | TCP | IMAPS (implicit SSL) |
| Dovecot | 110 | TCP | POP3 (STARTTLS) |
| Dovecot | 995 | TCP | POP3S (implicit SSL) |
| Rspamd | 11332 | TCP | Milter interface |
| Rspamd | 11333 | TCP | Normal worker |
| Rspamd | 11334 | TCP | Web UI/Controller |
| MySQL | 3306 | TCP | Database |
| Redis | 6379 | TCP | Cache |
| **Web Panel** | **2096** | TCP | HTTPS admin panel |

---

## Service Commands

### OpenSMTPD (SMTP)

```bash
# Start/Stop/Restart
service smtpd start
service smtpd stop
service smtpd restart

# Reload configuration (no downtime)
service smtpd reload

# Check configuration syntax
smtpd -n

# View mail queue
smtpctl show queue

# Enable at boot
sysrc smtpd_enable="YES"
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

---

## Installation

### 1. Build the Panel

```bash
# Requires Java 17+ and Maven
mvn clean package
```

### 2. Run the Panel

```bash
java -jar target/freebsd-mail-panel-1.0.jar
```

### 3. Terminal Menu

```
╔═══════════════════════════════════════════════════════════╗
║            FreeBSD Mail Panel - Select an option           ║
╠═══════════════════════════════════════════════════════════╣
║  1) Set TimeZone and CloudFlare DNS                        ║
║  2) Edit Panel Configuration                               ║
║  3) Install/Reinstall Mail Server                          ║
║  >>> Start Mail Panel WebServer <<<                        ║
║  Exit                                                      ║
╚═══════════════════════════════════════════════════════════╝
```

### 4. Install Mail Server (Option 3)

This will:
1. Stop existing services
2. Remove old configurations
3. Install packages (OpenSMTPD, Dovecot, Rspamd, ClamAV, Redis)
4. Configure MySQL database
5. Create virtual mail user (vmail:5000)
6. Generate self-signed SSL certificate
7. Configure all services
8. Start all services

### 5. Start Web Panel

Opens HTTPS panel on port 2096.

---

## Web Panel

### Access

```
https://your-server:2096/
```

### First Setup

1. Navigate to `/setup`
2. Create admin account
3. Set mail hostname

### Features

- Domain management
- Mailbox management
- Alias management
- Service status monitoring
- SSL certificate management
- DKIM key generation
- DNS record generator

---

## SSL Certificates

### Certificate Location

```
/usr/local/etc/ssl/mail/
├── fullchain.pem    # Certificate + chain
└── privkey.pem      # Private key
```

### Self-Signed (Default)

Generated automatically during installation. **Replace with real certificate!**

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
service smtpd reload
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
| TXT | default._domainkey | (DKIM key) | - |

**Important**: Mail records (A for mail, MX) should NOT be proxied through Cloudflare.

---

## Troubleshooting

### OpenSMTPD won't start

```bash
# Check configuration
smtpd -n

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
mysql -u mailpanel -p mailserver -e "SELECT * FROM virtual_users;"

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
# Check queue
smtpctl show queue

# Check LMTP socket
ls -la /var/run/dovecot/lmtp

# Check mailbox permissions
ls -la /var/vmail/
```

### Web panel login issues

1. Clear browser cookies
2. Check if using Cloudflare proxy
3. Verify MySQL connection in panel config
4. Check `./database/mailpanel.db` exists

---

## Important Notes

### OpenSMTPD vs Postfix

> **This project uses OpenSMTPD, NOT Postfix!**
>
> OpenSMTPD is the native FreeBSD mail transfer agent. All service commands use `smtpd`:
> ```bash
> service smtpd start
> service smtpd stop
> service smtpd reload
> ```

### User and Group

Virtual mail is handled by:
- **User**: vmail (UID 5000)
- **Group**: vmail (GID 5000)
- **Home**: /var/vmail

### Password Hashing

- **Mailbox passwords**: BLF-CRYPT (Blowfish)
- **Panel admin passwords**: BCrypt

---

## Architecture

```
FreeBSD Mail Panel (Java)
├── Main.java                 # Entry point, terminal GUI
├── SSLMailServer.java        # HTTPS server + REST API
├── dataBaseManager.java      # SQLite for panel state
├── MailDatabase.java         # MySQL for mail data
├── MailPanelContent.java     # HTML/CSS/JS generator
└── Scripts/
    ├── FullMailServerScript  # Complete installation
    ├── OpenSMTPDScript       # SMTP installation
    ├── DovecotScript         # IMAP/POP3 installation
    ├── RspamdScript          # Anti-spam installation
    ├── ClamAVScript          # Antivirus installation
    └── LetsEncryptScript     # SSL certificate
```

---

## License

MIT License

---

&copy; 2025 FreeBSD Mail Panel - Created by Pietro Giuseppe D'Amico
