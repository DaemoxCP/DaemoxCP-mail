# DaemoxCP Mail

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

DaemoxCP Mail (formerly FreeBSD Mail Panel) is a complete mail server solution that installs and manages:

```
┌─────────────────────────────────────────────────────────────────┐
│                          DaemoxCP Mail                          │
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
│   │                   MySQL 8.4                      │          │
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

Postfix delivers mail to Dovecot via LMTP on the socket `/var/spool/postfix/private/dovecot-lmtp`
(0600, postfix): no TCP port.

### IMAP/POP3 Server: Dovecot

| Property | Value |
|----------|-------|
| **Package** | `dovecot24-mysql` and `dovecot24-pigeonhole-mysql` (Dovecot 2.4) on new installations; `dovecot-mysql` and `dovecot-pigeonhole-mysql` (2.3) on older ones, which move to 2.4 from *Updates* |
| **Service** | `dovecot` |
| **Config** | `/usr/local/etc/dovecot/` |
| **Port 143** | IMAP (STARTTLS) |
| **Port 993** | IMAPS (implicit SSL) |
| **Port 110** | POP3 (STARTTLS), only if POP3 is on (*Settings*) |
| **Port 995** | POP3S (implicit SSL), only if POP3 is on |
| **LMTP** | socket `/var/spool/postfix/private/dovecot-lmtp`, for Postfix only |
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
| **Socket** | `/var/run/redis/redis.sock` (0770, group `redis`; no TCP port) |

Used by Rspamd for caching. Only rspamd (in the `redis` group) and root can reach it.

### Database: MySQL 8.4

| Property | Value |
|----------|-------|
| **Package** | `mysql84-server`, `mysql84-client` |
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

- **OS**: FreeBSD 15.x, amd64 or arm64
- **RAM**: 4 GB. Measured on a running server: ClamAV 1-1.3 GB, the panel's two Java processes about
  0.5 GB, MySQL 0.1-0.5 GB, all processes together 2.5-3 GB
- **Disk**: 20 GB at least, plus the space of the mail
- **Java**: OpenJDK 25 (`pkg install openjdk25`, with procfs on `/proc`)
- **Root access** over SSH
- **Cloudflare** for the panel's and the webmail's names (see [Installation](#installation))

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
postfix-mysql dovecot24-mysql dovecot24-pigeonhole-mysql
rspamd redis clamav security/py-fail2ban dns/bind-tools
mysql84-server mysql84-client
nginx php84 php84-extensions roundcube-php84
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
│   │   └── lmtp                # Dovecot's own LMTP socket (root only)
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
    └── mail_panel.db

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
virtual_transport = lmtp:unix:private/dovecot-lmtp

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

File: `./database/mail_panel.db`

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

What listens, and from where it should be reached. The panel's own firewall on the server (pf) blocks everything
else and lets in, from any address, the ports that are not "this server" (POP3 only when it is on). The narrower
sources, "your IP only" and "Cloudflare only", are set in your provider's firewall (see
[Step 1](#step-1-at-your-provider-example-hetzner-cloud)).

| Service | Port | Open to | Description |
|---------|------|---------|-------------|
| sshd | 22 | your IP only | SSH; the panel never changes it |
| Postfix | 25 | everyone | SMTP, incoming mail |
| the panel | 80 | everyone | Let's Encrypt's HTTP challenge: opened by the panel only while it runs |
| Dovecot | 143 | everyone | IMAP with STARTTLS |
| nginx | 443 | everyone | MTA-STS policy and autoconfig |
| Postfix | 465 | everyone | submission with implicit TLS |
| Postfix | 587 | everyone | submission with STARTTLS |
| Dovecot | 993 | everyone | IMAP with implicit TLS |
| Dovecot | 110, 995 | everyone, only if POP3 is on | POP3 (off by default; *Settings*) |
| **Web panel** | **2096** | **Cloudflare only** | this panel, HTTPS |
| nginx (Roundcube) | 8443 | Cloudflare only | the webmail, HTTPS |
| Dovecot | 4190 | this server | ManageSieve, for the webmail |
| MySQL | 3306 | this server (127.0.0.1) | the mail database; X protocol off |
| Rspamd | 11332, 11333, 11334 | this server | milter, worker, controller (with a password) |
| Dovecot LMTP | socket | this server | `/var/spool/postfix/private/dovecot-lmtp`, Postfix only; no port 24 |
| Redis | socket | this server | `/var/run/redis/redis.sock`, rspamd only; no port 6379 |
| ClamAV | socket | this server | `/var/run/clamav/clamd.sock`, rspamd only |

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

This is the whole installation, from a FreeBSD server that has just been created to a mail server
whose panel comes back by itself after a reboot. Do the steps in this order: each one relies on the
ones before. The examples use `example.com`, `203.0.113.10` and `2001:db8::10`: put your own names
and addresses in their place.

### What you need before you start

- **A server** with FreeBSD 15.x (amd64 or arm64), a public IPv4 address (an IPv6 address is a
  plus), **4 GB of RAM** and at least 20 GB of disk. Measured on a running server: ClamAV takes
  1-1.3 GB, the panel's two Java processes about 0.5 GB, MySQL 0.1-0.5 GB; everything together
  2.5-3 GB.
- **Root access over SSH with a key.** The panel never changes the SSH configuration.
- **Your domains on Cloudflare** (their DNS is managed by Cloudflare).
- **Three host names**, each with a precise role:

  | Name (example) | What it is | In Cloudflare |
  |---|---|---|
  | `mail.example.com` | the mail server: MX, SMTP, IMAP, the server's reverse DNS | **DNS only** (grey cloud) |
  | `webmail.example.com` | the webmail (Roundcube), on port **8443** | **Proxied** (orange cloud) |
  | `panel.example.com` | this panel, on port **2096** | **Proxied** (orange cloud) |

  The webmail and the panel are two different names because each has its own certificate, its own
  configuration in the menu (options 3 and 2) and its own port. They can be in the same domain or in
  two different domains, as long as both domains are on Cloudflare. The mail name must be different
  from both: mail (ports 25, 465, 587, 993) does not go through Cloudflare's proxy, the two web names
  do. Cloudflare proxies HTTPS on 443, 2053, 2083, 2087, **2096** and **8443**: that is why the panel
  and the webmail use those two ports.

### Step 1: at your provider (example: Hetzner Cloud)

1. **Reverse DNS.** Set the reverse DNS (PTR) of the server's IPv4 address, and of the IPv6 one if
   you use it, to the mail name (`mail.example.com`). On Hetzner Cloud: the server, *Networking*,
   the edit button next to the address. Big mail providers refuse or mark as spam mail from an
   address whose reverse DNS does not match.
2. **Outgoing ports 25 and 465.** Many providers close them on new accounts. Hetzner Cloud closes
   both, and opens them on request once the first invoice is paid, deciding case by case: open a
   support request saying that the server is a mail server. Incoming mail works without this,
   outgoing mail stays in the queue. The panel checks it for you: *Diagnostics*, *Check everything*,
   "Outgoing mail (port 25)".
3. **The provider's firewall.** Create a firewall with these **inbound** rules and attach it to the
   server. Leave outbound traffic as it is.

   | Rule | Protocol | Ports | Sources |
   |---|---|---|---|
   | SSH | TCP | 22 (or the port your sshd uses) | **only your own IP address**: your IPv4 as `/32` and, if you have one, your IPv6 as `/128` |
   | Mail | TCP | 25, 80, 143, 443, 465, 587, 993 | any IPv4, any IPv6 |
   | POP3, only if you turn it on later in *Settings* | TCP | 110, 995 | any IPv4, any IPv6 |
   | Panel and webmail | TCP | 2096, 8443 | **only Cloudflare's addresses** |

   Cloudflare's addresses are published at <https://www.cloudflare.com/ips-v4> and
   <https://www.cloudflare.com/ips-v6>. Once the panel is running, its *Firewall* page has the card
   "Your provider's firewall" with the list ready to paste (on Hetzner Cloud: into the *Sources*
   field of the rule, comma separated) and the same rules computed from the server's real ports.

   No other inbound rule is needed: in particular **no rule for 53 (DNS) and none for 123 (NTP)**.
   The Hetzner Cloud firewall is stateful, so the answers to the queries the server makes come back
   on their own, and an open 123 would only expose the clock service to the internet.

   **Cloudflare's list changes from time to time, and you update it by hand.** Hetzner Cloud does
   have an API for firewalls, but its tokens are "Read" or "Read & Write" on the whole project: a
   token that can change the firewall can also delete the server, and it does not belong on the
   mail server. So the panel does the next best thing: when you have put the list in the firewall,
   press "I have put this list in my provider's firewall"; the panel remembers it and, when Cloudflare
   changes its list, the card and *Diagnostics* tell you to update the rule.

   Other providers: the same rules, in their firewall. Hetzner's dedicated servers (Robot) have a
   different firewall, which is **not** stateful: there you also need Hetzner's rule that lets in the
   answers to the server's own connections (TCP, ports 32768-65535, with the ACK flag).

### Step 2: at Cloudflare

1. **DNS records** (in each zone):

   | Type | Name | Content | Proxy status |
   |---|---|---|---|
   | A | `mail` | `203.0.113.10` (the server's IPv4) | **DNS only** |
   | AAAA | `mail` | `2001:db8::10`, if the server has IPv6 | **DNS only** |
   | MX | `@` | `mail.example.com`, priority 10 | - |
   | A | `webmail` | `203.0.113.10` | **Proxied** |
   | A | `panel` | `203.0.113.10` | **Proxied** |

   Repeat the MX record in every domain whose mail this server receives (all pointing to the same
   `mail.example.com`). SPF, DKIM, DMARC, MTA-STS, autoconfig and the SRV records are written later
   by the panel itself ("Set up everything", step 7): you do not type them.
2. **SSL/TLS encryption mode: Full (strict).** Cloudflare then talks to the server over HTTPS and
   checks its certificate.
3. **Origin certificates.** *SSL/TLS*, *Origin Server*, *Create Certificate*: key type RSA (2048),
   the host names (for example `panel.example.com` and `webmail.example.com`, or `*.example.com`
   and `example.com`), validity up to 15 years. Cloudflare shows the certificate and the private key
   once: save them as two files, for example `panel-origin.pem` and `panel-origin.key`. An origin
   certificate covers names of one zone only: if the panel and the webmail are in two different
   domains, create one in each. These certificates are trusted by Cloudflare only, which is exactly
   what is needed behind the proxy; a browser that reaches the server directly would warn.
4. **An API token for the panel.** *My Profile*, *API Tokens*, *Create Token*, template *Edit zone
   DNS*, with the permissions **Zone > DNS > Edit** and **Zone > Zone > Read**, and *Zone Resources*
   *Include > Specific zone* for each mail domain. Never the Global API Key. You enter it in the panel
   in step 7.

### Step 3: the base system

Log in as root and bring the system and the package catalog up to date:

```bash
freebsd-update fetch install
pkg update
pkg upgrade
```

The first time `pkg` runs it offers to install itself: answer yes. Before installing,
`freebsd-update` keeps the system as it was in a boot environment (`bectl list` shows it), and it may
restart `sshd`: the SSH session you are in stays open. If it installed a new kernel, reboot
(`shutdown -r now`) before going on.

### Step 4: Java

The panel is a Java 25 program. Install OpenJDK 25 from the packages:

```bash
pkg install openjdk25
```

OpenJDK on FreeBSD wants `procfs` mounted on `/proc`. Add it to `/etc/fstab`, so that it is there
after every reboot too, and mount it now:

```bash
grep -q '^proc' /etc/fstab || echo 'proc /proc procfs rw 0 0' >> /etc/fstab
mount /proc
java -version
```

`java -version` must say `25`.

### Step 5: the panel and the certificates on the server

1. **Build the panel's jar**, on any computer with Java 25 and Maven, from this repository:

   ```bash
   tools/build-jar.sh
   ```

   It writes `target/freebsd-mail-panel-1.0.jar` with the build number and the commit inside, and
   prints the jar's SHA-256. (On the server itself: `pkg install git maven`, clone the repository,
   then the same command.)
2. **Put it in `/home/panel`**, not in `/root`. The panel's web part runs as its own user,
   `mailpanel`, which must be able to read the jar; `/root` is closed to other users, and from there
   the panel would run entirely as root.

   ```bash
   install -d -m 755 /home/panel
   ```

   Then, from your computer:

   ```bash
   scp target/freebsd-mail-panel-1.0.jar root@203.0.113.10:/home/panel/
   ```
3. **Copy the origin certificates.** The panel's pair can go anywhere: the panel reads it once and
   keeps it. The webmail's pair must stay where you put it, because nginx reads it from there: use
   `/usr/local/etc/ssl/webmail/`, never `/usr/local/etc/ssl/mail/`, which the installation empties.

   ```bash
   install -d -m 700 /root/certs /usr/local/etc/ssl/webmail
   ```

   From your computer:

   ```bash
   scp panel-origin.pem panel-origin.key root@203.0.113.10:/root/certs/
   ```

   ```bash
   scp webmail-origin.pem webmail-origin.key root@203.0.113.10:/usr/local/etc/ssl/webmail/
   ```

   On the server, keep the private keys readable by root only:

   ```bash
   chmod 600 /root/certs/*.key /usr/local/etc/ssl/webmail/*.key
   ```

### Step 6: the terminal menu

Open the menu from the panel's folder, in a terminal of at least 120 x 40 characters (from your
computer: `ssh -t root@203.0.113.10`):

```bash
cd /home/panel
java -jar freebsd-mail-panel-1.0.jar
```

Use the arrows to move, Enter to choose, Tab to go from a field to the next. Every option asks for
a confirmation first; in the confirmations *Cancel* is selected, press Tab to reach *OK*. Go through
the options in this order:

1. **1) Time zone, clock (NTP) and DNS resolver.** Write the server's time zone as an IANA name (for
   example `Europe/Rome` or `UTC`): the panel refuses names that do not exist. It also turns on NTP.
2. **2) Edit Panel Configuration.**
   - *PANEL PORT*: `2096`;
   - *PANEL HOST*: the panel's name, `panel.example.com` (not an IP address: passkeys and Cloudflare
     need a name);
   - *SSL CERTIFICATE* and *SSL PRIVATE KEY*: the paths of the files, `/root/certs/panel-origin.pem`
     and `/root/certs/panel-origin.key` (pasting the PEM text works too).
   Before saving, the panel checks that the certificate is readable, valid now, covers the panel's
   name and that the key is its own, and shows what it covers and when it expires.
3. **3) Edit Roundcube Configuration.**
   - *DOMAIN*: the webmail's name, `webmail.example.com`;
   - *PORT*: `8443`;
   - *SSL CERT PATH* and *SSL KEY PATH*: `/usr/local/etc/ssl/webmail/webmail-origin.pem` and
     `/usr/local/etc/ssl/webmail/webmail-origin.key`.
   The same checks as for the panel, on the webmail's name.
4. **4) Install/Reinstall Mail Server.** It asks for the mail name: `mail.example.com`. Before
   starting it checks the three names (the webmail's must be set, mail and web must be different
   names). It installs and configures MySQL, Postfix, Dovecot, Rspamd, ClamAV, Redis, nginx, PHP
   and Roundcube, fail2ban and the firewall, and takes several minutes; it goes on even if the
   terminal closes, and its log is in `/var/log/mailpanel/`. **It erases any existing mail
   configuration, mailboxes and panel accounts**: on a new server there is nothing to lose.
5. **5) Emergency access code.** There is no administrator yet: it asks for a name and an email and
   creates the first administrator, then shows an **8-digit code**, valid for 15 minutes.
6. **>>> Start Mail Panel WebServer <<<.** The panel starts; leave the terminal open for now.

### Step 7: the first login, and the panel set up

1. Open `https://panel.example.com:2096` in the browser. On the login page choose **Code from the
   server console** and type the 8-digit code.
2. **Passkeys.** In *Account*, register a passkey (fingerprint, face, device PIN or a hardware key),
   better two on two different devices. There are no passwords: from now on you sign in with a
   passkey, or with a 6-digit code sent to your email.
3. **Start at boot.** *Diagnostics*, card *Operating system*, **Start at boot**, then **Install and
   enable**. It writes `/usr/local/etc/rc.d/mailpanel` and turns it on, without starting a second
   copy of the panel.
4. Back in the terminal, press **Enter**: the panel started from the menu stops. Start it as a
   service, the way it will run from now on:

   ```bash
   service mailpanel start
   service mailpanel status
   ```

   From now on the panel starts by itself at every boot. Try it: `shutdown -r now`, and after a
   minute or two the panel answers again.
5. **Cloudflare.** On the *Cloudflare* page add the account with the token of step 2 (**Test token**
   first: if Cloudflare does not accept it, the page says so, and the usual cause is a token copied
   only in part or with a space), then choose it for the mail server's certificate.
6. **Let's Encrypt.** On the *SSL certificates* page, the card "Let's Encrypt is not ready": write
   the email for the Let's Encrypt account (an address you read: Let's Encrypt writes there only about
   the account) and press **Install acme.sh**. It installs the FreeBSD package `security/acme.sh`,
   which runs as its own user `acme`, and creates the account. If Let's Encrypt refuses the address,
   the card says why and stays: correct it and press again.
7. **Domains.** On the *Domains* page **Add domain** for each mail domain. Then on the *DNS* page
   choose the domain (*Change domain*, at the top): the card **Create the records on Cloudflare**
   shows what its zone already has. Press **Set up everything**: DKIM, SPF, DMARC, autoconfig, the
   SRV records and MTA-STS, with a Let's Encrypt certificate for the mail name and the MTA-STS names.
   It never overwrites a record that is already there.
   - The domain needs a Cloudflare account whose token sees its zone. If only one account of the
     panel sees it, *Set up everything* links it to the domain by itself; if more than one does,
     choose it on the same page, card *Cloudflare accounts*, *Domains → account*. If none does, it
     changes nothing and says what to check.
   - Under the card, every step gets a line with its outcome. If some are not in order, the card
     says how many, and the lines marked FAILED say what each one needs; press again after fixing it.
8. **The provider's firewall.** *Firewall* page, card **Your provider's firewall**: check that its
   rules are the ones you created in step 1, copy Cloudflare's list into the panel and webmail rule if
   you have not done it yet, then press **I have put this list in my provider's firewall**.
9. **Check everything.** *Diagnostics*, **Check everything**: what needs a look comes first, each
   with its next step. If *Outgoing mail (port 25)* is a problem, your provider still blocks port 25
   (step 1). Then create the mailboxes (*Mailboxes*, **Add mailbox**) and send and receive a test
   message, for example from the webmail.

### Keeping it up to date

- **The system and the mail software:** the *Updates* page, which says what is new and does every
  step with its checks.
- **The panel itself:** build the new jar and run `tools/upgrade/upgrade-panel.sh` on the server
  (`tools/upgrade/README.md`): it keeps a way back, starts the new panel twice and stops at the first
  sign that something is wrong or different. When it stops it shows the difference and how to go
  back; a difference the new version is meant to make (a page that now answers) is not a fault.
- **Cloudflare's addresses:** when *Diagnostics* says that Cloudflare changed its list, update the
  panel and webmail rule in your provider's firewall and confirm it on the *Firewall* page.

### Starting the panel by hand

| Command, from `/home/panel` | What it does |
|---|---|
| `java -jar freebsd-mail-panel-1.0.jar` | the terminal menu; the web server starts from its last entry |
| `java -jar freebsd-mail-panel-1.0.jar --web` | **only** the web server: no menu, no terminal needed (what the service runs) |
| `java -jar freebsd-mail-panel-1.0.jar --access-code [name]` | a one-time 8-digit sign-in code for an administrator |
| `java -jar freebsd-mail-panel-1.0.jar --create-admin <name> <email>` | the first administrator, when there is none |

With the service running, use `service mailpanel stop|start|restart|status`. The console commands
must be run from `/home/panel`: the panel's database is in `database/` next to the jar. At its first
start the panel writes next to the jar a `run.sh` with the exact command it was started with: a
shortcut, nothing depends on it.

### The terminal menu

```
╔═══════════════════════════════════════════════════════════════╗
║             DaemoxCP Mail v1.0 - Select an option             ║
╠═══════════════════════════════════════════════════════════════╣
║  1) Time zone, clock (NTP) and DNS resolver                   ║
║  2) Edit Panel Configuration                                  ║
║  3) Edit Roundcube Configuration                              ║
║  4) Install/Reinstall Mail Server                             ║
║  5) Emergency access code                                     ║
║  6) Go back to the server before the last reinstallation      ║
║  >>> Start Mail Panel WebServer <<<                           ║
║  Exit                                                         ║
╚═══════════════════════════════════════════════════════════════╝
```

Option 6 brings back the boot environment taken before the last installation (ZFS only) and
reboots after asking.

---

## Web Panel

### Access

```
https://panel.example.com:2096/
```

The panel answers only to its own name, the one written with menu option 2 (and through Cloudflare's proxy).
Reached with another name or with the bare IP address it answers `421 Misdirected Request`.

### First Administrator

The first administrator is never created from the web page: whoever reached it first would
become the administrator. Until there is one, the panel shows `/setup` with the command to run
on the server, from the panel folder:

```bash
java -jar freebsd-mail-panel-1.0.jar --create-admin <name> <email>
```

It creates a superadmin with no password and prints a one-time 8-digit code, valid for 15
minutes: on the login page choose "Code from the server console", then register a passkey in
Account. It refuses when an active administrator already exists; the others are added from the
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

Three certificates, one per name:

| Name | Certificate | Where it is set | Renewal |
|---|---|---|---|
| the panel (`panel.example.com`, 2096) | Cloudflare Origin Certificate | menu option 2 (file path or pasted PEM); the panel keeps it | none needed (up to 15 years) |
| the webmail (`webmail.example.com`, 8443) | Cloudflare Origin Certificate | menu option 3 (file paths: the files stay there, nginx reads them) or *Settings* | none needed |
| the mail server (`mail.example.com`, plus `mta-sts.` and `autoconfig.` of each domain) | Let's Encrypt, through acme.sh | *SSL certificates* page and "Set up everything" on the *DNS* page | automatic, checked every day |

Menu options 2 and 3 check a certificate before saving it: readable, valid now, covering the name, and with its own key.

The mail server's certificate is in `/usr/local/etc/ssl/mail/` (`fullchain.pem`, `privkey.pem`), used by Postfix,
Dovecot and nginx on 443. Until Let's Encrypt issues one, the installation's self-signed certificate is there: mail
clients warn about it. acme.sh is the FreeBSD package `security/acme.sh` and runs as its own user `acme`, with its
files in `/var/db/acme`; it is installed from the *SSL certificates* page together with the Let's Encrypt account. The
challenge is DNS-01 through Cloudflare (the account chosen on the *Cloudflare* page: renews by itself), or HTTP-01 on
port 80, which the panel opens only for the time of the challenge, or DNS-01 by hand (a TXT record; it cannot renew by
itself). A certificate obtained elsewhere can be uploaded on the same page.

## Cloudflare Integration

### The two web names behind the proxy

The panel (port 2096) and the webmail (port 8443) are reached through Cloudflare's proxy, which serves HTTPS on those
ports; the mail name is "DNS only", because mail does not go through the proxy. Cloudflare connects to the server in
"Full (strict)" mode and checks the origin certificates. Behind the proxy the panel reads the visitor's address from
`CF-Connecting-IP`, and only when the request really comes from one of Cloudflare's address ranges (the list the panel
trusts is on the *Diagnostics* page, with a comparison against Cloudflare's official one). Its session cookie is
`__Host-MailPanel`, `Secure`, `HttpOnly`, `SameSite=Strict`.

### The API token

Entered on the *Cloudflare* page, with the permissions **Zone > DNS > Edit** and **Zone > Zone > Read**, limited to
the mail domains' zones (never the Global API Key). The panel uses it for:

- the records of each mail domain, written by "Set up everything" on the *DNS* page and never overwriting an existing
  one: DKIM (`<selector>._domainkey`), SPF (`v=spf1 ip4:<server IP> mx -all`), DMARC (`v=DMARC1; p=none;
  rua=mailto:dmarc@<domain>`, monitoring mode), the CNAMEs `autoconfig` and `mta-sts` (DNS only), the SRV records
  `_imaps._tcp` and `_submission._tcp`, and the MTA-STS TXT `_mta-sts` once the policy answers;
- the DNS-01 challenge of the mail server's Let's Encrypt certificate.

It does **not** create the A, AAAA and MX records, nor the reverse DNS (at your provider), nor the panel's and the
webmail's records: those are created by hand, once, as in [Step 2](#step-2-at-cloudflare). The *DNS* page checks them
all (A, MX, PTR with forward confirmation, SPF, DKIM, DMARC, MTA-STS, autoconfig, SRV) and lists the values to enter
by hand when a domain's DNS is not on Cloudflare.

### Cloudflare's addresses and your provider's firewall

Ports 2096 and 8443 must be open only to Cloudflare's address ranges, in your provider's firewall. The ranges change
from time to time and the provider's firewall is updated by hand (on Hetzner Cloud an API exists, but a token able to
change the firewall can also delete the server, so it does not belong on the mail server). The *Firewall* page, card
"Your provider's firewall", shows the official list ready to paste and remembers the one you confirmed; *Diagnostics*
warns when Cloudflare changes it.

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

# Postfix delivers to Dovecot through this socket (no port 24)
postconf -h virtual_transport
ls -l /var/spool/postfix/private/dovecot-lmtp

# Check mailbox permissions
ls -la /var/vmail/
```

### Web panel login issues

1. Clear browser cookies
2. Check if using Cloudflare proxy
3. Verify MySQL connection in panel config
4. Check `./database/mail_panel.db` exists (in the panel's folder, `/home/panel`)

---

## Architecture

```
DaemoxCP Mail (Java 25)
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
    └── PanelContent.java     # HTML/CSS/JS generator
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

&copy; 2025 DaemoxCP Mail - Created by Pietro Giuseppe D'Amico
