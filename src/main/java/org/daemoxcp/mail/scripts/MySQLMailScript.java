package org.daemoxcp.mail.scripts;

/**
 * MySQL Installation Script for Mail Panel
 * On reinstall: drops all databases, removes MySQL, reinstalls fresh
 */
public class MySQLMailScript {

    private final String data;

    public MySQLMailScript() {
        this.data = """
            #!/bin/sh
            # MySQL Installation for DaemoxCP Mail
            # FULLY AUTOMATIC: Generates and sets all passwords automatically

            echo "=== MySQL installation for DaemoxCP Mail ==="
            echo ""

            # Check root
            if [ "$(id -u)" -ne 0 ]; then
                echo "Error: Must run as root"
                exit 1
            fi

            #############################################
            # PHASE 1: COMPLETE CLEANUP
            #############################################

            echo "[CLEANUP] Stopping MySQL..."
            service mysql-server stop 2>/dev/null || true
            pkill -9 mysqld 2>/dev/null || true
            sleep 2

            echo "[CLEANUP] Removing MySQL packages..."
            pkg delete -fy mysql80-server mysql80-client 2>/dev/null || true
            pkg autoremove -fy 2>/dev/null || true

            echo "[CLEANUP] Removing MySQL data and config..."
            rm -rf /var/db/mysql 2>/dev/null || true
            rm -rf /var/run/mysql 2>/dev/null || true
            rm -rf /usr/local/etc/mysql 2>/dev/null || true
            rm -f /root/.my.cnf 2>/dev/null || true

            echo "[CLEANUP] Removing MySQL user..."
            pw userdel mysql 2>/dev/null || true
            pw groupdel mysql 2>/dev/null || true

            echo "[CLEANUP] Removing rc.conf entry..."
            sysrc -x mysql_enable 2>/dev/null || true

            # Remove old config
            rm -f /usr/local/etc/daemoxcp-mail/mysql.json 2>/dev/null || true

            echo ""
            echo "[CLEANUP] Complete! Starting fresh installation..."
            echo ""

            #############################################
            # PHASE 2: FRESH INSTALLATION
            #############################################

            echo "[1/5] Installing MySQL 8.0..."
            pkg install -y mysql80-server mysql80-client

            # Create data directory
            mkdir -p /var/db/mysql
            chown mysql:mysql /var/db/mysql

            # Enable and start
            echo "[2/5] Starting MySQL..."
            sysrc mysql_enable="YES"
            service mysql-server start

            # Wait for MySQL to be ready
            echo "Waiting for MySQL to be ready..."
            for i in $(seq 1 30); do
                if mysqladmin ping -h 127.0.0.1 2>/dev/null; then
                    echo "MySQL is ready!"
                    break
                fi
                echo "  Waiting... ($i/30)"
                sleep 2
            done

            #############################################
            # PHASE 3: GENERATE AND SET PASSWORDS
            #############################################

            echo "[3/5] Generating secure passwords..."

            # Generate random passwords (24 chars, alphanumeric)
            MYSQL_ROOT_PASS=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 24)
            DAEMOXCP_MAIL_PASS=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 24)
            ROUNDCUBE_PASS=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 24)

            # Set MySQL root password (fresh install has no password)
            echo "Setting MySQL root password..."
            mysqladmin -u root password "${MYSQL_ROOT_PASS}"

            if [ $? -ne 0 ]; then
                echo "Warning: Could not set root password (may already be set)"
                # Try without password change
                MYSQL_ROOT_PASS=""
            fi

            echo "[4/5] Creating databases and users..."

            # Use root password for all operations
            if [ -n "${MYSQL_ROOT_PASS}" ]; then
                MYSQL_CMD="mysql -u root -p${MYSQL_ROOT_PASS}"
            else
                MYSQL_CMD="mysql -u root"
            fi

            ${MYSQL_CMD} << SQLEOF
            -- Create daemoxcp_mail database
            CREATE DATABASE IF NOT EXISTS daemoxcp_mail CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

            -- Create daemoxcp_mail user (used by Dovecot and Postfix)
            CREATE USER IF NOT EXISTS 'daemoxcp_mail'@'127.0.0.1' IDENTIFIED BY '${DAEMOXCP_MAIL_PASS}';
            GRANT ALL PRIVILEGES ON daemoxcp_mail.* TO 'daemoxcp_mail'@'127.0.0.1';

            -- Create Roundcube database
            CREATE DATABASE IF NOT EXISTS roundcubemail CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
            CREATE USER IF NOT EXISTS 'roundcube'@'127.0.0.1' IDENTIFIED BY '${ROUNDCUBE_PASS}';
            GRANT ALL PRIVILEGES ON roundcubemail.* TO 'roundcube'@'127.0.0.1';

            FLUSH PRIVILEGES;
            SQLEOF

            #############################################
            # PHASE 4: SAVE CONFIGURATION
            #############################################

            echo "[5/5] Saving configuration..."

            # The folder is the panel's secrets folder (0750 root:daemoxcp_mail once the panel runs): create it
            # root-only when missing, never change it when it is there
            [ -d /usr/local/etc/daemoxcp-mail ] || install -d -m 0700 /usr/local/etc/daemoxcp-mail

            # Save all passwords as JSON (readable by Java)
            cat > /usr/local/etc/daemoxcp-mail/mysql.json << JSONEOF
{
    "mysql_root_password": "${MYSQL_ROOT_PASS}",
    "daemoxcp_mail_password": "${DAEMOXCP_MAIL_PASS}",
    "roundcube_password": "${ROUNDCUBE_PASS}",
    "host": "127.0.0.1",
    "port": 3306,
    "installed_at": "$(date -Iseconds)"
}
JSONEOF

            chmod 600 /usr/local/etc/daemoxcp-mail/mysql.json

            echo ""
            echo "=== MySQL Installation Complete ==="
            echo ""
            echo "All passwords have been automatically generated and saved to:"
            echo "  /usr/local/etc/daemoxcp-mail/mysql.json"
            echo ""
            echo "DaemoxCP Mail reads this file automatically."
            echo "No manual configuration required!"
            echo ""
            """;
    }

    public String getScriptContent() {
        return this.data;
    }
}
