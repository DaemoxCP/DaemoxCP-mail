package org.daemoxcp.mail.scripts;

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

            # The password of the webmail's MySQL user (roundcube) is passed by the panel
            # in the environment, from its secrets file. Before, the script took it from
            # /usr/local/etc/mail/mysql_password, the password of the panel's user, which
            # the panel no longer writes: without the file it created neither the database nor the user.
            if [ -z "${ROUNDCUBE_DB_PASSWORD}" ]; then
                echo "Error: ROUNDCUBE_DB_PASSWORD not in the environment"
                exit 1
            fi

            # MySQL as root: with the password the panel passes in the environment (MYSQL_ROOT_PASSWORD,
            # when the panel installed MySQL) in an options file in a 700 folder, never
            # on the command line; without it, through the socket like a freshly installed MySQL.
            MYSQL_WORK=$(mktemp -d /var/tmp/daemoxcp-mail-roundcube.XXXXXXXX) || exit 1
            trap 'rm -rf "$MYSQL_WORK"' EXIT HUP INT TERM
            if [ -n "${MYSQL_ROOT_PASSWORD}" ]; then
                cat > "$MYSQL_WORK/root.cnf" << EOCNF
[client]
user=root
password="${MYSQL_ROOT_PASSWORD}"
EOCNF
                mysql_root() { mysql --defaults-extra-file="$MYSQL_WORK/root.cnf" "$@"; }
            else
                mysql_root() { mysql -u root "$@"; }
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
            mysql_root -e "DROP DATABASE IF EXISTS roundcubemail;" 2>/dev/null || true

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

            # PHP-FPM: Roundcube's pool with its own user and its own socket (the same as nginx's below)
""" + org.daemoxcp.mail.system.RoundcubeUser.shellPool() + """

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
            # The roundcube user has privileges on the webmail's database only. Before, the GRANT
            # had "IDENTIFIED BY", which MySQL 8 refuses: the user was not created at all.
            if ! mysql_root << SQLEOF
CREATE DATABASE IF NOT EXISTS roundcubemail CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
""" + org.daemoxcp.mail.scripts.RoundcubeDbAccountScript.sql("${ROUNDCUBE_DB_PASSWORD}", "daemoxcp_mail") + """
FLUSH PRIVILEGES;
SQLEOF
            then
                echo "Error: cannot create the webmail database or its MySQL user"
                exit 1
            fi
            # root creates the tables: roundcube's password does not go on the command line
            mysql_root roundcubemail < /usr/local/www/roundcube/SQL/mysql.initial.sql 2>/dev/null || true

            # Generate random DES key
            RANDOM_KEY=$(openssl rand -hex 12)

            # Configure Roundcube
            echo "[4/5] Configuring Roundcube..."
            cat > /usr/local/www/roundcube/config/config.inc.php << RCCONFIG
<?php
// Roundcube Configuration
// Managed by DaemoxCP Mail

\\$config = [];

// Database
\\$config['db_dsnw'] = 'mysql://roundcube:${ROUNDCUBE_DB_PASSWORD}@127.0.0.1/roundcubemail';

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

// Logging (required by Fail2ban for the roundcube-auth jail)
\\$config['log_driver'] = 'file';
\\$config['log_dir'] = '/usr/local/www/roundcube/logs/';
\\$config['log_logins'] = true;

// Plugins (daemoxcp_mail_sso is installed separately by the panel)
\\$config['plugins'] = [
    'archive',
    'zipdownload',
    'managesieve',
    'password',
];

// Password plugin (change password from webmail): the settings are added by DaemoxCP Mail at
// startup, in the "daemoxcp-mail: webmail password changes" block at the end of this file. The change
// goes through the panel, which writes the bcrypt hash and the encrypted copy it can show again.

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

    # Roundcube 1.7 serves its assets as /static.php/path/to/file.css: a PHP script
    # with a path attached. A location that wants .php at the end of the URI does not catch it,
    # and the style sheet comes back as an HTML page: the webmail opens without its look.
    # Configuration from Roundcube's official wiki (Installation page).
    location ~ \\.php {
        include fastcgi_params;
        fastcgi_index index.php;
        fastcgi_split_path_info ^(.+\\.php)(/.+)$;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_pass unix:/var/run/php-fpm-roundcube.sock;
    }

    location ~ /\\. {
        deny all;
    }

    location ~ ^/(config|temp|logs)/ {
        deny all;
    }
}
NGINXCONF

            # From 1.7 Roundcube no longer serves the files from the application's root but from the
            # public_html subfolder: it is a deliberate protection, and with the old root the webmail
            # answers 404 to everything. It is not inferred from the version number, it looks whether the folder
            # is there: so the same line works for 1.6 and 1.7 without telling them apart.
            if [ -d /usr/local/www/roundcube/public_html ]; then
                sed -i '' 's#root /usr/local/www/roundcube;#root /usr/local/www/roundcube/public_html;#' /usr/local/etc/nginx/sites-enabled/roundcube.conf
                echo "  Roundcube 1.7 or later: nginx root set to public_html"
            fi

            # Set permissions: the webmail's files belong to roundcube, not to nginx's user
""" + org.daemoxcp.mail.system.RoundcubeUser.shellOwnership() + """

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

    /** Always, all or nothing, with the jar's fingerprint (InstallScripts): never a script from an earlier version. */
    public void write_file() {
        this.writed = InstallScripts.write(SCRIPT_PATH, this.data);
    }
}
