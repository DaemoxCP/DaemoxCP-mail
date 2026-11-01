package org.mail_panel.scripts;

/**
 * Full Mail Stack Installation - Installs everything at once
 * On reinstall: stops all services, removes everything, then reinstalls fresh
 *
 * Uses Postfix for SMTP with MySQL virtual users
 */
public class FullMailStackScript {

    private final String data;

    public FullMailStackScript() {
        this.data = """
            #!/bin/sh
            # Full Mail Stack Installation for FreeBSD 15
            # Installs: MySQL, Redis, Postfix, Dovecot, Rspamd, ClamAV, Roundcube
            #
            # REINSTALL MODE: If components exist, they are completely removed first

            echo "=============================================="
            echo "  FreeBSD Mail Server - Full Installation"
            echo "=============================================="
            echo ""

            # Check root
            if [ "$(id -u)" -ne 0 ]; then
                echo "Error: Must run as root"
                exit 1
            fi

            #############################################
            # PHASE 1: COMPLETE CLEANUP (if reinstalling)
            #############################################

            echo "[CLEANUP] Stopping all mail services..."

            # Stop all services (ignore errors if not running)
            service nginx stop 2>/dev/null || true
            service php_fpm stop 2>/dev/null || true
            service roundcube stop 2>/dev/null || true
            service rspamd stop 2>/dev/null || true
            service clamav_clamd stop 2>/dev/null || true
            service clamav_freshclam stop 2>/dev/null || true
            service dovecot stop 2>/dev/null || true
            service postfix stop 2>/dev/null || true
            service redis stop 2>/dev/null || true
            service mysql-server stop 2>/dev/null || true

            # Kill any remaining processes
            pkill -9 nginx 2>/dev/null || true
            pkill -9 php-fpm 2>/dev/null || true
            pkill -9 rspamd 2>/dev/null || true
            pkill -9 clamd 2>/dev/null || true
            pkill -9 freshclam 2>/dev/null || true
            pkill -9 dovecot 2>/dev/null || true
            pkill -9 master 2>/dev/null || true
            pkill -9 postfix 2>/dev/null || true
            pkill -9 redis-server 2>/dev/null || true
            pkill -9 mysqld 2>/dev/null || true

            sleep 3

            # Flush Redis data (Rspamd uses Redis for some stats)
            redis-cli FLUSHALL 2>/dev/null || true

            echo "[CLEANUP] Removing packages..."

            # Remove packages (ignore errors if not installed)
            pkg delete -fy roundcube-php84 roundcube-php82 roundcube 2>/dev/null || true
            pkg delete -fy nginx 2>/dev/null || true
            pkg delete -fy php84-fpm php84 php82-fpm php82 2>/dev/null || true
            pkg delete -fy rspamd 2>/dev/null || true
            pkg delete -fy clamav 2>/dev/null || true
            pkg delete -fy dovecot dovecot-pigeonhole 2>/dev/null || true
            pkg delete -fy postfix postfix-mysql 2>/dev/null || true
            pkg delete -fy redis 2>/dev/null || true
            pkg delete -fy mysql80-server mysql80-client 2>/dev/null || true

            # Autoremove orphaned dependencies
            pkg autoremove -fy 2>/dev/null || true

            echo "[CLEANUP] Removing all data directories..."

            # MySQL data
            rm -rf /var/db/mysql 2>/dev/null || true
            rm -rf /var/run/mysql 2>/dev/null || true

            # Redis data
            rm -rf /var/db/redis 2>/dev/null || true
            rm -rf /var/run/redis 2>/dev/null || true

            # Mail data
            rm -rf /var/vmail 2>/dev/null || true
            rm -rf /var/spool/postfix 2>/dev/null || true
            rm -rf /var/run/dovecot 2>/dev/null || true

            # ClamAV data
            rm -rf /var/db/clamav 2>/dev/null || true
            rm -rf /var/run/clamav 2>/dev/null || true
            rm -rf /var/log/clamav 2>/dev/null || true

            # Rspamd data
            rm -rf /var/db/rspamd 2>/dev/null || true
            rm -rf /var/run/rspamd 2>/dev/null || true
            rm -rf /var/log/rspamd 2>/dev/null || true

            # Roundcube/Nginx
            rm -rf /var/db/roundcube 2>/dev/null || true
            rm -rf /var/log/nginx 2>/dev/null || true
            rm -rf /var/run/nginx 2>/dev/null || true
            rm -rf /usr/local/www/roundcube 2>/dev/null || true

            echo "[CLEANUP] Removing configuration files..."

            # Configuration directories
            rm -rf /usr/local/etc/postfix 2>/dev/null || true
            rm -rf /usr/local/etc/dovecot 2>/dev/null || true
            rm -rf /usr/local/etc/rspamd 2>/dev/null || true
            rm -rf /usr/local/etc/clamav 2>/dev/null || true
            rm -rf /usr/local/etc/nginx 2>/dev/null || true
            rm -rf /usr/local/etc/php-fpm.d 2>/dev/null || true
            rm -rf /usr/local/etc/mysql 2>/dev/null || true
            rm -rf /usr/local/etc/redis.conf 2>/dev/null || true

            # Log files
            rm -f /var/log/dovecot.log 2>/dev/null || true
            rm -f /var/log/maillog 2>/dev/null || true

            echo "[CLEANUP] Removing system users..."

            # Remove users (but keep vmail for later recreation)
            pw userdel clamav 2>/dev/null || true
            pw userdel redis 2>/dev/null || true
            pw userdel mysql 2>/dev/null || true
            pw userdel vmail 2>/dev/null || true
            pw userdel rspamd 2>/dev/null || true
            pw userdel www 2>/dev/null || true

            # Remove groups
            pw groupdel clamav 2>/dev/null || true
            pw groupdel redis 2>/dev/null || true
            pw groupdel mysql 2>/dev/null || true
            pw groupdel vmail 2>/dev/null || true
            pw groupdel rspamd 2>/dev/null || true

            # Clean rc.conf entries
            sysrc -x mysql_enable 2>/dev/null || true
            sysrc -x redis_enable 2>/dev/null || true
            sysrc -x postfix_enable 2>/dev/null || true
            sysrc -x sendmail_enable 2>/dev/null || true
            sysrc -x dovecot_enable 2>/dev/null || true
            sysrc -x rspamd_enable 2>/dev/null || true
            sysrc -x clamav_clamd_enable 2>/dev/null || true
            sysrc -x clamav_freshclam_enable 2>/dev/null || true
            sysrc -x nginx_enable 2>/dev/null || true
            sysrc -x php_fpm_enable 2>/dev/null || true

            echo ""
            echo "[CLEANUP] Complete! Starting fresh installation..."
            echo ""

            #############################################
            # PHASE 2: FRESH INSTALLATION
            #############################################

            # Create mail directories
            echo "[0/8] Preparing directories..."
            mkdir -p /var/vmail
            mkdir -p /usr/local/etc/ssl/mail
            mkdir -p /usr/local/etc/postfix

            # Create vmail user
            pw groupadd vmail -g 5000 2>/dev/null || true
            pw useradd vmail -c "Virtual Mail" -d /var/vmail -s /usr/sbin/nologin -u 5000 -g 5000 2>/dev/null || true
            chown -R vmail:vmail /var/vmail

            # ============ 1. MySQL ============
            echo ""
            echo "[1/8] Installing MySQL 8.0..."
            pkg install -y mysql80-server mysql80-client

            mkdir -p /var/db/mysql
            chown mysql:mysql /var/db/mysql

            sysrc mysql_enable="YES"
            service mysql-server start

            echo "Waiting for MySQL to be ready..."
            for i in $(seq 1 30); do
                if mysqladmin ping -h 127.0.0.1 2>/dev/null; then
                    echo "MySQL is ready!"
                    break
                fi
                echo "  Waiting... ($i/30)"
                sleep 2
            done

            MAILSERVER_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)

            mysql -u root << SQLEOF
            CREATE DATABASE IF NOT EXISTS mailpanel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
            CREATE USER IF NOT EXISTS 'mailpanel'@'localhost' IDENTIFIED BY '${MAILSERVER_PASS}';
            CREATE USER IF NOT EXISTS 'mailpanel'@'127.0.0.1' IDENTIFIED BY '${MAILSERVER_PASS}';
            GRANT ALL PRIVILEGES ON mailpanel.* TO 'mailpanel'@'localhost';
            GRANT ALL PRIVILEGES ON mailpanel.* TO 'mailpanel'@'127.0.0.1';

            USE mailpanel;

            -- Domains with DKIM support
            CREATE TABLE IF NOT EXISTS domains (
                id INT AUTO_INCREMENT PRIMARY KEY,
                domain VARCHAR(255) NOT NULL UNIQUE,
                description TEXT,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                dkim_selector VARCHAR(50) DEFAULT 'mail',
                dkim_private_key TEXT,
                dkim_public_key TEXT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            -- Mailboxes (quota_mb: 0 = unlimited, receive_enabled: false = no-reply)
            CREATE TABLE IF NOT EXISTS mailboxes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                domain_id INT NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255),
                quota_mb INT DEFAULT 1024,
                active BOOLEAN DEFAULT TRUE,
                receive_enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            -- Aliases
            CREATE TABLE IF NOT EXISTS aliases (
                id INT AUTO_INCREMENT PRIMARY KEY,
                domain_id INT NOT NULL,
                source VARCHAR(255) NOT NULL,
                destination VARCHAR(255) NOT NULL,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
                UNIQUE KEY unique_alias (source, destination)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            -- Panel admin users
            -- No password: passkeys and email codes. The panel adds its login tables when it starts.
            CREATE TABLE IF NOT EXISTS panel_admin (
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
            CREATE TABLE IF NOT EXISTS panel_settings (
                setting_key VARCHAR(64) PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            -- Installed components
            CREATE TABLE IF NOT EXISTS installed_components (
                id INT AUTO_INCREMENT PRIMARY KEY,
                component_name VARCHAR(50) NOT NULL UNIQUE,
                version VARCHAR(20),
                installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status ENUM('installed', 'uninstalled', 'failed') DEFAULT 'installed'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            -- Roundcube auto-login tokens
            CREATE TABLE IF NOT EXISTS roundcube_tokens (
                token VARCHAR(64) PRIMARY KEY,
                mailbox_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            CREATE DATABASE IF NOT EXISTS roundcubemail CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
            CREATE USER IF NOT EXISTS 'roundcube'@'127.0.0.1' IDENTIFIED BY '${MAILSERVER_PASS}';
            GRANT ALL PRIVILEGES ON roundcubemail.* TO 'roundcube'@'127.0.0.1';

            FLUSH PRIVILEGES;
            SQLEOF

            mkdir -p /usr/local/etc/mail
            echo "${MAILSERVER_PASS}" > /usr/local/etc/mail/mysql_password
            chmod 600 /usr/local/etc/mail/mysql_password

            # ============ 2. Redis ============
            echo ""
            echo "[2/8] Installing Redis..."
            pkg install -y redis

            mkdir -p /var/db/redis
            chown redis:redis /var/db/redis

            cat > /usr/local/etc/redis.conf << 'REDISCONF'
bind 127.0.0.1
port 6379
daemonize yes
pidfile /var/run/redis/redis.pid
logfile /var/log/redis.log
dir /var/db/redis
maxmemory 256mb
maxmemory-policy allkeys-lru
REDISCONF

            sysrc redis_enable="YES"
            service redis start

            # ============ 3. Postfix ============
            echo ""
            echo "[3/8] Installing Postfix..."
            # postfix-mysql replaces postfix and adds MySQL support
            pkg install -y postfix-mysql

            # Disable sendmail
            sysrc sendmail_enable="NO"
            sysrc sendmail_submit_enable="NO"
            sysrc sendmail_outbound_enable="NO"
            sysrc sendmail_msp_queue_enable="NO"
            service sendmail stop 2>/dev/null || true

            """
            // Postfix come MTA locale: senza, la posta di sistema esce da dma. Lo stesso pezzo
            // e' in FullMailServerScript e PostfixScript.
            + LocalMtaScript.SHELL + """

            mkdir -p /usr/local/etc/postfix
            mkdir -p /var/spool/postfix/private
            chown postfix:postfix /var/spool/postfix/private
            chmod 710 /var/spool/postfix/private

            cat > /usr/local/etc/postfix/main.cf << 'POSTFIXCONF'
# Postfix - Managed by FreeBSD Mail Panel
myhostname = mail.localhost
mydomain = localhost
inet_interfaces = all
inet_protocols = all

# Consegna locale solo per localhost: ci arrivano gli indirizzi senza dominio (root,
# postmaster: cron e periodic), che ora passano da Postfix e non da dma. Spenta del tutto,
# com'era, quella posta rimbalzava. myorigin esplicito perche' il pannello riscrive mydomain
# con il nome vero del server. Il perche' misurato e' in FullMailServerScript.
myorigin = localhost
mydestination = localhost
# In uscita root@localhost diventa root@<nome del server>: vedi FullMailServerScript.
smtp_generic_maps = inline:{ @localhost=@$myhostname }

# Solo questa macchina spedisce senza autenticarsi. Senza compatibility_level Postfix usa il
# livello 0, dove mynetworks_style = subnet: tutta la rete del server diventava fidata, cioe'
# un relay aperto (misurato con postconf -c: mynetworks = 192.168.64.0/24 ...). Gli stessi
# valori dell'installazione completa.
compatibility_level = 3.6
mynetworks = 127.0.0.0/8 [::1]/128

# Virtual mailbox settings
virtual_mailbox_domains = mysql:/usr/local/etc/postfix/mysql-virtual-domains.cf
virtual_mailbox_maps = mysql:/usr/local/etc/postfix/mysql-virtual-mailboxes.cf
virtual_alias_maps = mysql:/usr/local/etc/postfix/mysql-virtual-aliases.cf
virtual_transport = lmtp:inet:127.0.0.1:24
virtual_mailbox_base = /var/vmail
virtual_minimum_uid = 5000
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

# TLS settings (will be updated with real certs)
smtpd_tls_cert_file = /usr/local/etc/ssl/mail/fullchain.pem
smtpd_tls_key_file = /usr/local/etc/ssl/mail/privkey.pem
smtpd_tls_security_level = may
smtp_tls_security_level = may

# SASL authentication via Dovecot
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $myhostname

# Restrictions. reject_non_fqdn_recipient tiene fuori da Internet root@localhost, che con la
# consegna locale accesa per localhost reject_unauth_destination lascerebbe passare.
smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination, reject_non_fqdn_recipient

# Rspamd milter
smtpd_milters = inet:127.0.0.1:11332
non_smtpd_milters = inet:127.0.0.1:11332
milter_protocol = 6
milter_default_action = accept

# Limits
message_size_limit = 52428800
virtual_mailbox_limit = 2147483648
POSTFIXCONF

            cat > /usr/local/etc/postfix/mysql-virtual-domains.cf << MYSQLCONF
user = mailpanel
password = ${MAILSERVER_PASS}
hosts = 127.0.0.1
dbname = mailpanel
query = SELECT domain FROM domains WHERE domain='%s' AND active=1
MYSQLCONF

            cat > /usr/local/etc/postfix/mysql-virtual-mailboxes.cf << MYSQLCONF
user = mailpanel
password = ${MAILSERVER_PASS}
hosts = 127.0.0.1
dbname = mailpanel
query = SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM mailboxes WHERE email='%s' AND active=1 AND receive_enabled=1
MYSQLCONF

            cat > /usr/local/etc/postfix/mysql-virtual-aliases.cf << MYSQLCONF
user = mailpanel
password = ${MAILSERVER_PASS}
hosts = 127.0.0.1
dbname = mailpanel
query = SELECT destination FROM aliases WHERE source='%s' AND active=1
MYSQLCONF

            chmod 640 /usr/local/etc/postfix/mysql-*.cf
            chown root:postfix /usr/local/etc/postfix/mysql-*.cf

            # Configure master.cf for submission
            cat > /usr/local/etc/postfix/master.cf << 'MASTERCONF'
smtp      inet  n       -       n       -       -       smtpd
submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
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
MASTERCONF

            sysrc postfix_enable="YES"

            # Create /etc/aliases.db (required by Postfix)
            if [ ! -f /etc/aliases ]; then
                echo "# Postfix aliases" > /etc/aliases
                echo "postmaster: root" >> /etc/aliases
                echo "root: root" >> /etc/aliases
            fi
            newaliases 2>/dev/null || postalias /etc/aliases 2>/dev/null || true

            # ============ 4. Dovecot ============
            echo ""
            echo "[4/8] Installing Dovecot..."
            # dovecot-pigeonhole-mysql, non dovecot-pigeonhole: quest'ultimo dipende da
            # "dovecot" senza MySQL, e pkg risolve il conflitto togliendo dovecot-mysql in
            # silenzio (misurato il 24/10/2026, vedi PackageInstall e FullMailServerScript).
            pkg install -y dovecot-mysql dovecot-pigeonhole-mysql

            """
            // Sorgente UNICA della configurazione Dovecot. Prima scriveva dbname=mailpanel, cablato e diverso da quello configurato.
            + DovecotConfig.fromPanelConfig().scriptFragment() + """

            # Generate master user password for SSO
            echo "Configuring master user for SSO..."
            MASTER_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)
            mkdir -p /var/db/mailpanel
            echo "$MASTER_PASSWORD" > /var/db/mailpanel/dovecot_master.key
            chmod 600 /var/db/mailpanel/dovecot_master.key

            # Create master-users file with hashed password
            if command -v doveadm >/dev/null 2>&1; then
                MASTER_PASSWORD_HASH=$(doveadm pw -s BLF-CRYPT -p "$MASTER_PASSWORD" 2>/dev/null)
            else
                MASTER_PASSWORD_HASH='{PLAIN}'$MASTER_PASSWORD
            fi

            cat > /usr/local/etc/dovecot/master-users << MASTER_EOF
admin:$MASTER_PASSWORD_HASH
MASTER_EOF

            chmod 640 /usr/local/etc/dovecot/master-users
            chown root:wheel /usr/local/etc/dovecot/master-users

            # Generate self-signed SSL cert
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
                -keyout /usr/local/etc/ssl/mail/privkey.pem \\
                -out /usr/local/etc/ssl/mail/fullchain.pem \\
                -subj "/CN=mail.localhost/O=FreeBSD Mail Panel"
            chmod 600 /usr/local/etc/ssl/mail/privkey.pem

            sysrc dovecot_enable="YES"

            # ============ 5. Rspamd ============
            echo ""
            echo "[5/8] Installing Rspamd..."
            pkg install -y rspamd

            mkdir -p /usr/local/etc/rspamd/local.d
            mkdir -p /var/db/rspamd /var/run/rspamd /var/log/rspamd
            chown rspamd:rspamd /var/db/rspamd /var/run/rspamd /var/log/rspamd

            echo 'bind_socket = "127.0.0.1:11333";' > /usr/local/etc/rspamd/local.d/worker-normal.inc

            cat > /usr/local/etc/rspamd/local.d/worker-proxy.inc << 'EOF'
bind_socket = "127.0.0.1:11332";
milter = yes;
timeout = 120s;
upstream "local" {
    default = yes;
    self_scan = yes;
}
EOF

            echo 'bind_socket = "127.0.0.1:11334";' > /usr/local/etc/rspamd/local.d/worker-controller.inc
            echo 'servers = "127.0.0.1:6379";' > /usr/local/etc/rspamd/local.d/redis.conf

            cat > /usr/local/etc/rspamd/local.d/classifier-bayes.conf << 'EOF'
backend = "redis";
autolearn = true;
EOF

            """
            // Il risolutore ricorsivo locale, prima che rspamd parta: senza, le liste di Spamhaus
            // non rispondono. Lo stesso pezzo e' in FullMailServerScript e RspamdScript.
            + LocalResolverScript.SHELL + """

            # dig: il pannello lo usa per i controlli DNS e il sistema base non ce l'ha
            # (vedi FullMailServerScript).
            pkg install -y dns/bind-tools

            sysrc rspamd_enable="YES"

            # ============ 6. ClamAV ============
            echo ""
            echo "[6/8] Installing ClamAV..."
            pkg install -y clamav

            mkdir -p /var/run/clamav /var/log/clamav /var/db/clamav
            chown clamav:clamav /var/run/clamav /var/log/clamav /var/db/clamav

            cat > /usr/local/etc/clamd.conf << 'CLAMCONF'
LocalSocket /var/run/clamav/clamd.sock
TCPSocket 3310
TCPAddr 127.0.0.1
MaxFileSize 25M
MaxScanSize 100M
User clamav
LogFile /var/log/clamav/clamd.log
DatabaseDirectory /var/db/clamav
CLAMCONF

            cat > /usr/local/etc/freshclam.conf << 'FRESHCONF'
DatabaseDirectory /var/db/clamav
UpdateLogFile /var/log/clamav/freshclam.log
DatabaseMirror database.clamav.net
NotifyClamd /usr/local/etc/clamd.conf
Checks 24
FRESHCONF

            sysrc clamav_clamd_enable="YES"
            sysrc clamav_freshclam_enable="YES"

            # Download initial virus databases (required before clamd can start)
            echo "Downloading ClamAV virus databases (this may take a few minutes)..."
            freshclam --foreground --stdout || echo "Warning: freshclam failed, will retry on service start"

            # ============ 7. Nginx + PHP-FPM ============
            echo ""
            echo "[7/8] Installing Nginx + PHP-FPM..."
            pkg install -y nginx php84 php84-fpm php84-mysqli php84-mbstring php84-xml php84-zip php84-gd php84-intl php84-session php84-pdo php84-pdo_mysql php84-iconv php84-dom php84-fileinfo

            mkdir -p /var/log/nginx /var/run/nginx /usr/local/www/roundcube

            cat > /usr/local/etc/nginx/nginx.conf << 'NGINXCONF'
worker_processes auto;
events { worker_connections 1024; }

http {
    include mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;

    server {
        listen 80;
        server_name _;
        root /usr/local/www/roundcube;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$query_string;
        }

        # Roundcube 1.7 serve gli asset come /static.php/percorso/al/file.css: uno script PHP
        # con un percorso attaccato. Un location che chiede .php in fondo all'URI non lo prende,
        # e il foglio di stile torna come pagina HTML: la webmail si apre senza grafica.
        # Configurazione dal wiki ufficiale di Roundcube (pagina Installation). La riga
        location ~ \\.php {
            include fastcgi_params;
            fastcgi_index index.php;
            fastcgi_split_path_info ^(.+\\.php)(/.+)$;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param PATH_INFO $fastcgi_path_info;
            fastcgi_pass unix:/var/run/php-fpm-roundcube.sock;
        }

        location ~ /\\. { deny all; }
    }
}
NGINXCONF

            # Dalla 1.7 Roundcube non serve piu' i file dalla radice dell'applicazione ma dalla
            # sottocartella public_html: e' una protezione voluta, e con la radice vecchia la webmail
            # risponde 404 su tutto. Non lo si deduce dal numero di versione, si guarda se la cartella
            # c'e': cosi' la stessa riga vale per la 1.6 e per la 1.7 senza doverle distinguere.
            if [ -d /usr/local/www/roundcube/public_html ]; then
                sed -i '' 's#root /usr/local/www/roundcube;#root /usr/local/www/roundcube/public_html;#' /usr/local/etc/nginx/nginx.conf
                echo "  Roundcube 1.7 or later: nginx root set to public_html"
            fi

            # Il pool di Roundcube col suo utente e il suo socket, non il pool www sulla 9000
""" + org.mail_panel.system.RoundcubeUser.shellPool() + """

            sysrc nginx_enable="YES"
            sysrc php_fpm_enable="YES"

            # ============ 8. Roundcube ============
            echo ""
            echo "[8/8] Installing Roundcube..."
            pkg install -y roundcube-php84

            if [ -d /usr/local/www/roundcube-php84 ]; then
                cp -R /usr/local/www/roundcube-php84/* /usr/local/www/roundcube/
            fi

            cat > /usr/local/www/roundcube/config/config.inc.php << RCCONF
<?php
\\$config['db_dsnw'] = 'mysql://roundcube:${MAILSERVER_PASS}@127.0.0.1/roundcubemail';
\\$config['default_host'] = 'ssl://127.0.0.1';
\\$config['default_port'] = 993;
\\$config['smtp_server'] = 'tls://127.0.0.1';
\\$config['smtp_port'] = 587;
\\$config['smtp_user'] = '%u';
\\$config['smtp_pass'] = '%p';
\\$config['support_url'] = '';
\\$config['product_name'] = 'FreeBSD Mail Panel Webmail';
\\$config['des_key'] = '$(openssl rand -base64 24)';
\\$config['plugins'] = array('archive', 'zipdownload', 'managesieve', 'password');
\\$config['skin'] = 'elastic';
\\$config['language'] = 'it_IT';

// Password plugin (change password from webmail): the settings are added by the mail panel at
// startup, in the "mail-panel: webmail password changes" block at the end of this file. The change
// goes through the panel, which writes the bcrypt hash and the encrypted copy it can show again.

// Managesieve plugin (Dovecot Sieve filters)
\\$config['managesieve_host'] = '127.0.0.1';
\\$config['managesieve_port'] = 4190;
RCCONF

            # Prima tutta la webmail, codice compreso, era di www: scrivibile da nginx.
""" + org.mail_panel.system.RoundcubeUser.shellOwnership() + """
            mysql -u root roundcubemail < /usr/local/www/roundcube/SQL/mysql.initial.sql 2>/dev/null || true

            # ============ Start All Services ============
            echo ""
            echo "Starting all services..."

            # 1. Database and cache first
            service mysql-server start || true
            sleep 2
            service redis start || true
            sleep 1

            # 2. Antivirus (needed by Rspamd)
            # Check if ClamAV databases exist before starting clamd
            if [ -f /var/db/clamav/main.cvd ] || [ -f /var/db/clamav/main.cld ]; then
                service clamav_freshclam start || true
                service clamav_clamd start || true
            else
                echo "ClamAV databases not found, running freshclam..."
                freshclam --foreground --stdout || true
                service clamav_freshclam start || true
                service clamav_clamd start || true
            fi
            sleep 2

            # 3. Anti-spam (needs Redis and ClamAV)
            service rspamd start || true
            sleep 1

            # 4. Mail services (Dovecot first for SASL auth)
            service dovecot start || true
            sleep 1
            service postfix start || true

            # 5. Web services
            service php_fpm start || true
            service nginx start || true

            echo ""
            echo "=============================================="
            echo "  Installation Complete!"
            echo "=============================================="
            echo ""
            echo "MySQL/Panel password: ${MAILSERVER_PASS}"
            echo "(Also saved to /usr/local/etc/mail/mysql_password)"
            echo ""
            echo "Services installed:"
            echo "  - MySQL 8.0 (database)"
            echo "  - Redis (caching)"
            echo "  - Postfix (SMTP - ports 25, 587, 465)"
            echo "  - Dovecot (IMAP/POP3 - ports 143, 993, 110, 995)"
            echo "  - Rspamd (anti-spam - port 11334)"
            echo "  - ClamAV (antivirus)"
            echo "  - Roundcube (webmail - port 80)"
            echo ""
            echo "IMPORTANT: Use this password to configure the panel!"
            echo ""
            """;
    }

    public String getScriptContent() {
        return this.data;
    }
}
