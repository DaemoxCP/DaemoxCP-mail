package org.mail_panel.scripts;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Roundcube Webmail Installation Script for FreeBSD 15
 * On reinstall: completely removes Roundcube and reinstalls fresh
 *
 * Roundcube is a modern webmail client with auto-login support.
 */
public class RoundcubeScript {

    public boolean writed = false;
    private static final String SCRIPT_PATH = "./install_scripts/install_roundcube.sh";
    private final String data;

    public RoundcubeScript() {
        this.data = """
            #!/bin/sh
            # Roundcube Webmail Installation for FreeBSD 15
            # REINSTALL MODE: Completely removes Roundcube before reinstalling

            echo "=== Roundcube Webmail Installation ==="
            echo ""

            # Check root
            if [ "$(id -u)" -ne 0 ]; then
                echo "Error: Must run as root"
                exit 1
            fi

            #############################################
            # PHASE 1: COMPLETE CLEANUP
            #############################################

            echo "[CLEANUP] Stopping PHP-FPM..."
            service php_fpm stop 2>/dev/null || true
            pkill -9 php-fpm 2>/dev/null || true

            echo "[CLEANUP] Removing Roundcube packages..."
            pkg delete -fy roundcube-php84 roundcube-php82 php84-extensions php82-extensions 2>/dev/null || true
            pkg delete -fy php84 php84-session php84-pdo_mysql php84-mbstring php84-iconv 2>/dev/null || true
            pkg delete -fy php84-dom php84-openssl php84-xml php84-zip php84-intl 2>/dev/null || true
            pkg delete -fy php82 php82-session php82-pdo_mysql php82-mbstring php82-iconv 2>/dev/null || true
            pkg autoremove -fy 2>/dev/null || true

            echo "[CLEANUP] Removing Roundcube data and config..."
            rm -rf /usr/local/www/roundcube 2>/dev/null || true
            rm -rf /usr/local/etc/php 2>/dev/null || true
            rm -f /usr/local/etc/php-fpm.conf 2>/dev/null || true
            rm -rf /usr/local/etc/php-fpm.d 2>/dev/null || true
            rm -f /usr/local/etc/nginx/sites-enabled/roundcube.conf 2>/dev/null || true

            echo "[CLEANUP] Dropping Roundcube database..."
            if [ -f /usr/local/etc/mail/mysql_password ]; then
                MAILPANEL_PASS=$(cat /usr/local/etc/mail/mysql_password)
                mysql -u mailpanel -p"${MAILPANEL_PASS}" -h 127.0.0.1 -e "DROP DATABASE IF EXISTS roundcubemail;" 2>/dev/null || true
            fi

            echo "[CLEANUP] Removing rc.conf entries..."
            sysrc -x php_fpm_enable 2>/dev/null || true

            echo ""
            echo "[CLEANUP] Complete! Starting fresh installation..."
            echo ""

            #############################################
            # PHASE 2: FRESH INSTALLATION
            #############################################

            # Install Roundcube and dependencies
            echo "[1/5] Installing Roundcube..."
            pkg install -y roundcube-php84 php84-extensions

            # Enable PHP extensions
            echo "[2/5] Configuring PHP..."
            sysrc php_fpm_enable="YES"
            mkdir -p /usr/local/etc/php
            mkdir -p /usr/local/etc/php-fpm.d

            # Configure PHP-FPM to use socket (matching nginx config)
            cat > /usr/local/etc/php-fpm.d/www.conf << 'PHPFPMCONF'
[www]
user = www
group = www
listen = /var/run/php-fpm.sock
listen.owner = www
listen.group = www
listen.mode = 0660
pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 5
PHPFPMCONF

            # Configure PHP for Roundcube
            cat > /usr/local/etc/php/ext-30-roundcube.ini << 'PHPINI'
extension=pdo_mysql.so
extension=mbstring.so
extension=iconv.so
extension=dom.so
extension=json.so
extension=openssl.so
extension=session.so
extension=xml.so
extension=zip.so
extension=intl.so
PHPINI

            # Create Roundcube database
            echo "[3/5] Creating Roundcube database..."
            if [ -f /usr/local/etc/mail/mysql_password ]; then
                MAILPANEL_PASS=$(cat /usr/local/etc/mail/mysql_password)
                mysql -u root -h 127.0.0.1 << SQLEOF || true
CREATE DATABASE IF NOT EXISTS roundcubemail CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON roundcubemail.* TO 'roundcube'@'127.0.0.1' IDENTIFIED BY '${MAILPANEL_PASS}';
FLUSH PRIVILEGES;
SQLEOF
                # Import Roundcube schema
                mysql -u roundcube -p"${MAILPANEL_PASS}" -h 127.0.0.1 roundcubemail < /usr/local/www/roundcube/SQL/mysql.initial.sql 2>/dev/null || true
            fi

            # Generate random DES key
            RANDOM_KEY=$(openssl rand -hex 12)

            # Configure Roundcube
            echo "[4/5] Configuring Roundcube..."
            cat > /usr/local/www/roundcube/config/config.inc.php << RCCONFIG
<?php
// Roundcube Configuration
// Managed by FreeBSD Mail Panel

\\$config = [];

// Database
\\$config['db_dsnw'] = 'mysql://roundcube:${MAILPANEL_PASS}@127.0.0.1/roundcubemail';

// IMAP
\\$config['default_host'] = 'ssl://127.0.0.1';
\\$config['default_port'] = 993;
\\$config['imap_auth_type'] = 'LOGIN';
\\$config['imap_conn_options'] = [
    'ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false,
    ],
];

// SMTP
\\$config['smtp_server'] = 'tls://127.0.0.1';
\\$config['smtp_port'] = 587;
\\$config['smtp_user'] = '%u';
\\$config['smtp_pass'] = '%p';
\\$config['smtp_conn_options'] = [
    'ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false,
    ],
];

// Interface
\\$config['product_name'] = 'FreeBSD Webmail';
\\$config['skin'] = 'elastic';
\\$config['language'] = 'en_US';
\\$config['timezone'] = 'auto';

// Security
\\$config['des_key'] = '${RANDOM_KEY}';
\\$config['enable_installer'] = false;
\\$config['support_url'] = '';

// Logging (richiesto da Fail2ban per la jail roundcube-auth)
\\$config['log_driver'] = 'file';
\\$config['log_dir'] = '/usr/local/www/roundcube/logs/';
\\$config['log_logins'] = true;

// Plugins (mailpanel_sso is installed separately by the panel)
\\$config['plugins'] = [
    'archive',
    'zipdownload',
    'managesieve',
    'password',
];

// Password plugin (change password from webmail)
// NOTE: Uses mailpanel database where mailboxes table resides
\\$config['password_driver'] = 'sql';
\\$config['password_db_dsn'] = 'mysql://mailpanel:${MAILPANEL_PASS}@127.0.0.1/mailpanel';
\\$config['password_query'] = 'UPDATE mailboxes SET password=%P WHERE email=%u';
\\$config['password_crypt_hash'] = 'blowfish';

// Managesieve (Dovecot Sieve)
\\$config['managesieve_host'] = '127.0.0.1';
\\$config['managesieve_port'] = 4190;
RCCONFIG

            # SSO plugin is installed separately by the panel via RoundcubeSsoManager
            # No need to create autologin plugin here

            # Configure Nginx for Roundcube
            echo "[5/5] Configuring web server..."
            mkdir -p /usr/local/etc/nginx/sites-enabled

            cat > /usr/local/etc/nginx/sites-enabled/roundcube.conf << 'NGINXCONF'
server {
    listen 443 ssl;
    server_name webmail.* mail.*;

    ssl_certificate /usr/local/etc/ssl/mail/fullchain.pem;
    ssl_certificate_key /usr/local/etc/ssl/mail/privkey.pem;

    root /usr/local/www/roundcube;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \\.php$ {
        fastcgi_pass unix:/var/run/php-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\\. {
        deny all;
    }

    location ~ ^/(config|temp|logs)/ {
        deny all;
    }
}
NGINXCONF

            # Set permissions
            chown -R www:www /usr/local/www/roundcube/temp
            chown -R www:www /usr/local/www/roundcube/logs
            chmod 700 /usr/local/www/roundcube/temp
            chmod 700 /usr/local/www/roundcube/logs

            # Restart services
            service php_fpm restart || service php_fpm start
            service nginx reload 2>/dev/null || true

            echo ""
            echo "=== Roundcube Installation Complete ==="
            echo ""
            echo "Webmail URL: https://webmail.yourdomain.com/"
            echo ""
            echo "Auto-login from panel is enabled."
            echo "Click on a mailbox in the panel to open webmail."
            echo ""
            """;
    }

    public String getScriptContent() {
        return this.data;
    }

    public void write_file() {
        File scriptFile = new File(SCRIPT_PATH);
        if (scriptFile.exists()) {
            return;
        }

        try (FileWriter writer = new FileWriter(SCRIPT_PATH)) {
            writer.write(this.data);
            scriptFile.setExecutable(true);
            this.writed = true;
        } catch (IOException e) {
            System.out.println("Error writing script: " + e.getMessage());
        }
    }
}
