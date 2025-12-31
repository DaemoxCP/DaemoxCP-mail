package org.mail_panel.scripts;

/**
 * Postfix Installation Script for FreeBSD 15
 * On reinstall: completely removes Postfix and reinstalls fresh
 *
 * Postfix is a free and open-source mail transfer agent (MTA).
 * It's fast, secure, and easy to administer.
 */
public class PostfixScript {

    private final String data;

    public PostfixScript() {
        this.data = """
            #!/bin/sh
            # Postfix Installation for FreeBSD 15
            # REINSTALL MODE: Completely removes Postfix before reinstalling

            echo "=== Postfix Installation ==="
            echo ""

            # Check root
            if [ "$(id -u)" -ne 0 ]; then
                echo "Error: Must run as root"
                exit 1
            fi

            #############################################
            # PHASE 1: COMPLETE CLEANUP
            #############################################

            echo "[CLEANUP] Stopping Postfix..."
            service postfix stop 2>/dev/null || true
            pkill -9 postfix 2>/dev/null || true
            pkill -9 master 2>/dev/null || true
            sleep 2

            echo "[CLEANUP] Removing Postfix packages..."
            pkg delete -fy postfix postfix-mysql 2>/dev/null || true
            pkg autoremove -fy 2>/dev/null || true

            echo "[CLEANUP] Removing Postfix data and config..."
            rm -rf /var/spool/postfix 2>/dev/null || true
            rm -rf /usr/local/etc/postfix 2>/dev/null || true

            echo "[CLEANUP] Removing rc.conf entries..."
            sysrc -x postfix_enable 2>/dev/null || true
            sysrc -x sendmail_enable 2>/dev/null || true
            sysrc -x sendmail_submit_enable 2>/dev/null || true
            sysrc -x sendmail_outbound_enable 2>/dev/null || true
            sysrc -x sendmail_msp_queue_enable 2>/dev/null || true

            echo ""
            echo "[CLEANUP] Complete! Starting fresh installation..."
            echo ""

            #############################################
            # PHASE 2: FRESH INSTALLATION
            #############################################

            # Install Postfix with MySQL support (postfix-mysql replaces postfix)
            echo "[1/6] Installing Postfix..."
            pkg install -y postfix-mysql

            # Disable sendmail completely
            echo "[2/6] Disabling sendmail..."
            sysrc sendmail_enable="NO"
            sysrc sendmail_submit_enable="NO"
            sysrc sendmail_outbound_enable="NO"
            sysrc sendmail_msp_queue_enable="NO"
            service sendmail stop 2>/dev/null || true

            # Create mail directories
            echo "[3/6] Creating mail directories..."
            mkdir -p /var/vmail
            mkdir -p /usr/local/etc/postfix

            # Create vmail user if not exists
            pw user show vmail >/dev/null 2>&1 || pw useradd vmail -c "Virtual Mail" -d /var/vmail -s /usr/sbin/nologin -u 5000
            pw group show vmail >/dev/null 2>&1 || pw groupadd vmail -g 5000

            chown vmail:vmail /var/vmail
            chmod 700 /var/vmail

            # Create spool directories
            echo "[4/6] Creating Postfix spool directories..."
            mkdir -p /var/spool/postfix/private
            chown postfix:postfix /var/spool/postfix/private
            chmod 710 /var/spool/postfix/private

            # Basic configuration (will be updated by panel/full install)
            echo "[5/6] Creating base configuration..."
            cat > /usr/local/etc/postfix/main.cf << 'MAINCONF'
# Postfix Configuration
# Managed by FreeBSD Mail Panel - Basic Setup
# Full configuration is done by FullMailServerScript

# Basic settings
myhostname = localhost
mydomain = localhost
myorigin = $mydomain
inet_interfaces = all
inet_protocols = all

# Virtual mailbox settings (will be configured by panel)
virtual_mailbox_base = /var/vmail
virtual_minimum_uid = 5000
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

# TLS settings (will be configured with certificates)
smtpd_tls_security_level = none

# Mailbox size limits
message_size_limit = 52428800
virtual_mailbox_limit = 2147483648

MAINCONF

            # Create /etc/aliases.db (required by Postfix)
            if [ ! -f /etc/aliases ]; then
                echo "# Postfix aliases" > /etc/aliases
                echo "postmaster: root" >> /etc/aliases
                echo "root: root" >> /etc/aliases
            fi
            newaliases 2>/dev/null || postalias /etc/aliases 2>/dev/null || true

            # Enable and start
            echo "[6/6] Enabling Postfix service..."
            sysrc postfix_enable="YES"
            service postfix start || echo "Warning: Could not start Postfix (configure domains first)"

            echo ""
            echo "=== Postfix Installation Complete ==="
            echo ""
            echo "Configuration: /usr/local/etc/postfix/main.cf"
            echo "Virtual mail:  /var/vmail/"
            echo ""
            echo "Next steps:"
            echo "1. Run full mail server installation for complete setup"
            echo "2. Or manually configure MySQL virtual users"
            echo ""
            """;
    }

    public String getScriptContent() {
        return this.data;
    }
}
