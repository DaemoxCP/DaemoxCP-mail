package org.mail_panel.scripts;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Dovecot Installation Script for FreeBSD 15
 * On reinstall: completely removes Dovecot and reinstalls fresh
 *
 * Dovecot is an open source IMAP and POP3 email server.
 * Integrates with Postfix for mail delivery via LMTP.
 */
public class DovecotScript {

    public boolean writed = false;
    private static final String SCRIPT_PATH = "./install_scripts/install_dovecot.sh";
    private final String data;

    public DovecotScript() {
        this.data = """
            #!/bin/sh
            # Dovecot Installation for FreeBSD 15
            # REINSTALL MODE: Completely removes Dovecot before reinstalling

            echo "=== Dovecot Installation ==="
            echo ""

            # Check root
            if [ "$(id -u)" -ne 0 ]; then
                echo "Error: Must run as root"
                exit 1
            fi

            #############################################
            # PHASE 1: COMPLETE CLEANUP
            #############################################

            echo "[CLEANUP] Stopping Dovecot..."
            service dovecot stop 2>/dev/null || true
            pkill -9 dovecot 2>/dev/null || true
            sleep 2

            echo "[CLEANUP] Removing Dovecot packages..."
            pkg delete -fy dovecot dovecot-pigeonhole 2>/dev/null || true
            pkg autoremove -fy 2>/dev/null || true

            echo "[CLEANUP] Removing Dovecot data and config..."
            rm -rf /usr/local/etc/dovecot 2>/dev/null || true
            rm -rf /var/run/dovecot 2>/dev/null || true
            rm -rf /var/log/dovecot* 2>/dev/null || true
            rm -rf /var/run/dovecot/lmtp 2>/dev/null || true

            echo "[CLEANUP] Removing dovecot user..."
            pw userdel dovecot 2>/dev/null || true
            pw userdel dovenull 2>/dev/null || true
            pw groupdel dovecot 2>/dev/null || true
            pw groupdel dovenull 2>/dev/null || true

            echo "[CLEANUP] Removing rc.conf entry..."
            sysrc -x dovecot_enable 2>/dev/null || true

            echo ""
            echo "[CLEANUP] Complete! Starting fresh installation..."
            echo ""

            #############################################
            # PHASE 2: FRESH INSTALLATION
            #############################################

            # Install Dovecot with MySQL and Sieve support
            echo "[1/7] Installing Dovecot..."
            pkg install -y dovecot-mysql dovecot-pigeonhole-mysql

            # Create vmail user if not exists
            echo "[2/7] Creating vmail user..."
            pw user show vmail >/dev/null 2>&1 || pw useradd vmail -c "Virtual Mail" -d /var/vmail -s /usr/sbin/nologin -u 5000
            pw group show vmail >/dev/null 2>&1 || pw groupadd vmail -g 5000

            mkdir -p /var/vmail
            chown -R vmail:vmail /var/vmail
            chmod 700 /var/vmail

            # Configure Dovecot
            echo "[3/7] Configuring Dovecot..."
            mkdir -p /usr/local/etc/dovecot

            # Main configuration
            cat > /usr/local/etc/dovecot/dovecot.conf << 'DOVECOTCONF'
# Dovecot Configuration
# Managed by FreeBSD Mail Panel

protocols = imap pop3 lmtp sieve
listen = *, ::
mail_privileged_group = mail
first_valid_uid = 5000
first_valid_gid = 5000

# Use Postfix for sending vacation responses (not dma)
sendmail_path = /usr/local/sbin/sendmail

!include conf.d/*.conf

DOVECOTCONF

            # Create conf.d directory
            mkdir -p /usr/local/etc/dovecot/conf.d

            # 10-mail.conf
            cat > /usr/local/etc/dovecot/conf.d/10-mail.conf << 'DOVECOT_MAIL'
mail_location = maildir:/var/vmail/%d/%n
mail_uid = vmail
mail_gid = vmail
DOVECOT_MAIL

            # 10-auth.conf - includes master user support for SSO
            cat > /usr/local/etc/dovecot/conf.d/10-auth.conf << 'DOVECOT_AUTH'
disable_plaintext_auth = yes
auth_mechanisms = plain login

# Master user for admin SSO access
auth_master_user_separator = *
!include auth-master.conf.ext
!include auth-sql.conf.ext
DOVECOT_AUTH

            # 10-ssl.conf
            cat > /usr/local/etc/dovecot/conf.d/10-ssl.conf << 'DOVECOT_SSL'
ssl = required
ssl_cert = </usr/local/etc/ssl/mail/fullchain.pem
ssl_key = </usr/local/etc/ssl/mail/privkey.pem
ssl_min_protocol = TLSv1.2
DOVECOT_SSL

            # 10-master.conf - includes LMTP on port 24 for Postfix
            cat > /usr/local/etc/dovecot/conf.d/10-master.conf << 'DOVECOT_MASTER'
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

service lmtp {
  unix_listener lmtp {
    mode = 0666
    user = vmail
    group = vmail
  }
  # LMTP on port 24 for Postfix (virtual_transport = lmtp:inet:127.0.0.1:24)
  inet_listener lmtp {
    address = 127.0.0.1
    port = 24
  }
}

service auth {
  # For Postfix SASL authentication
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }

  unix_listener auth-userdb {
    mode = 0600
    user = vmail
    group = vmail
  }
}

# ManageSieve for mail filtering
service managesieve-login {
  inet_listener sieve {
    port = 4190
  }
}

service managesieve {
}

# Sieve plugin
protocol lmtp {
  mail_plugins = sieve
}

plugin {
  # Sieve script path - matches SieveGenerator output
  sieve = /var/mail/sieve/%d/%n/.dovecot.sieve
  sieve_dir = /var/mail/sieve/%d/%n/
  sieve_global_dir = /var/mail/sieve/global/

  # Enable all required extensions (date is needed for vacation with date range)
  sieve_extensions = +fileinto +reject +envelope +vacation +copy +imap4flags +regex +relational +comparator-i;ascii-numeric +date +variables
}
DOVECOT_MASTER

            # auth-sql.conf.ext
            cat > /usr/local/etc/dovecot/conf.d/auth-sql.conf.ext << 'DOVECOT_AUTH_SQL'
passdb {
  driver = sql
  args = /usr/local/etc/dovecot/dovecot-sql.conf
}
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/vmail/%d/%n
}
DOVECOT_AUTH_SQL

            # auth-master.conf.ext - Master user for SSO
            cat > /usr/local/etc/dovecot/conf.d/auth-master.conf.ext << 'DOVECOT_MASTER_AUTH'
passdb {
  driver = passwd-file
  master = yes
  args = /usr/local/etc/dovecot/master-users
  result_success = continue
}
DOVECOT_MASTER_AUTH

            # SQL configuration for virtual users
            echo "[4/7] Configuring SQL authentication..."
            # Read MySQL password and configure SQL
            if [ -f /usr/local/etc/mail/mysql_password ]; then
                MAILPANEL_PASS=$(cat /usr/local/etc/mail/mysql_password)
            else
                MAILPANEL_PASS="MAILPANEL_PASSWORD"
            fi

            cat > /usr/local/etc/dovecot/dovecot-sql.conf << SQLCONF
driver = mysql
connect = host=127.0.0.1 dbname=mailpanel user=mailpanel password=${MAILPANEL_PASS}
default_pass_scheme = BLF-CRYPT
password_query = SELECT email as user, password FROM mailboxes WHERE email='%u' AND active=1
SQLCONF

            chmod 600 /usr/local/etc/dovecot/dovecot-sql.conf
            chown root:dovecot /usr/local/etc/dovecot/dovecot-sql.conf

            # Generate master user password for SSO
            echo "[5/7] Configuring master user for SSO..."
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
            chown root:dovecot /usr/local/etc/dovecot/master-users

            # Create SSL directory
            echo "[6/7] Creating SSL directory..."
            mkdir -p /usr/local/etc/ssl/mail
            chmod 755 /usr/local/etc/ssl/mail

            # Generate self-signed cert (temporary)
            if [ ! -f /usr/local/etc/ssl/mail/fullchain.pem ]; then
                echo "Generating temporary self-signed certificate..."
                openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
                    -keyout /usr/local/etc/ssl/mail/privkey.pem \\
                    -out /usr/local/etc/ssl/mail/fullchain.pem \\
                    -subj "/CN=mail.localhost/O=FreeBSD Mail Panel"
                chmod 600 /usr/local/etc/ssl/mail/privkey.pem
            fi

            # Create run directory
            mkdir -p /var/run/dovecot
            chown root:dovecot /var/run/dovecot

            # Create Sieve directory for auto-responders and filters
            mkdir -p /var/mail/sieve/global
            chown -R vmail:vmail /var/mail/sieve
            chmod -R 755 /var/mail/sieve

            # Create Postfix spool directory for SASL socket
            mkdir -p /var/spool/postfix/private
            chown postfix:postfix /var/spool/postfix/private
            chmod 710 /var/spool/postfix/private

            # Enable and start
            echo "[7/7] Enabling service..."
            sysrc dovecot_enable="YES"
            service dovecot start || echo "Warning: Configure MySQL connection first"

            echo ""
            echo "=== Dovecot Installation Complete ==="
            echo ""
            echo "Configuration: /usr/local/etc/dovecot/dovecot.conf"
            echo "SQL Config:    /usr/local/etc/dovecot/dovecot-sql.conf"
            echo "SSL Certs:     /usr/local/etc/ssl/mail/"
            echo ""
            echo "Ports:"
            echo "  IMAP:  143 (STARTTLS), 993 (SSL)"
            echo "  POP3:  110 (STARTTLS), 995 (SSL)"
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
