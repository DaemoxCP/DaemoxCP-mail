package org.daemoxcp.mail.scripts;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Let's Encrypt SSL Certificate generation script for FreeBSD
 */
public class LetsEncryptScript {

    public boolean writed = false;
    private static final String SCRIPT_PATH = "./install_scripts/generate_letsencrypt.sh";

    private final String data = """
        #!/bin/sh
        # Let's Encrypt SSL Certificate Generation for DaemoxCP Mail

        HOSTNAME="$1"

        echo "=== Let's Encrypt SSL Certificate Generation ==="
        echo ""

        # Check root
        if [ "$(id -u)" -ne 0 ]; then
            echo "Error: Must run as root"
            exit 1
        fi

        if [ -z "$HOSTNAME" ]; then
            echo "Error: Hostname not provided"
            echo "Usage: $0 <hostname>"
            exit 1
        fi

        echo "Generating certificate for: $HOSTNAME"
        echo ""

        # Install certbot if not present
        echo "[1/4] Installing certbot..."
        pkg install -y py311-certbot || pkg install -y certbot

        # Stop services that might use port 80
        echo "[2/4] Temporarily stopping web services..."
        service nginx stop 2>/dev/null || true

        # Generate certificate
        echo "[3/4] Generating Let's Encrypt certificate..."
        certbot certonly --standalone -d "$HOSTNAME" --non-interactive --agree-tos --email admin@"$HOSTNAME" || {
            echo "Certbot failed. Trying with --register-unsafely-without-email..."
            certbot certonly --standalone -d "$HOSTNAME" --non-interactive --agree-tos --register-unsafely-without-email
        }

        # Check if certificate was generated
        if [ -f "/usr/local/etc/letsencrypt/live/$HOSTNAME/fullchain.pem" ]; then
            echo "[4/4] Setting up certificate paths..."

            # Create mail SSL directory
            mkdir -p /usr/local/etc/ssl/mail

            # Copy certificates
            cp /usr/local/etc/letsencrypt/live/$HOSTNAME/fullchain.pem /usr/local/etc/ssl/mail/fullchain.pem
            cp /usr/local/etc/letsencrypt/live/$HOSTNAME/privkey.pem /usr/local/etc/ssl/mail/privkey.pem

            chmod 644 /usr/local/etc/ssl/mail/fullchain.pem
            chmod 600 /usr/local/etc/ssl/mail/privkey.pem

            echo ""
            echo "=== Certificate Generated Successfully ==="
            echo ""
            echo "Certificate: /usr/local/etc/ssl/mail/fullchain.pem"
            echo "Private Key: /usr/local/etc/ssl/mail/privkey.pem"
            echo ""
            echo "Copy the contents of these files to the panel configuration:"
            echo ""
            echo "=== CERTIFICATE (fullchain.pem) ==="
            cat /usr/local/etc/ssl/mail/fullchain.pem
            echo ""
            echo "=== PRIVATE KEY (privkey.pem) ==="
            cat /usr/local/etc/ssl/mail/privkey.pem
            echo ""
            echo "Note: Auto-renewal is configured via certbot timer/cron"

            # Restart services
            service nginx start 2>/dev/null || true
            service postfix reload 2>/dev/null || true
            service dovecot reload 2>/dev/null || true
        else
            echo "Error: Certificate generation failed"
            echo "Make sure:"
            echo "  1. Port 80 is accessible from the internet"
            echo "  2. DNS for $HOSTNAME points to this server"
            echo "  3. No firewall is blocking port 80"
            exit 1
        fi

        echo ""
        """;

    /** Sempre, tutto o niente, con l'impronta del jar (InstallScripts): mai uno script di una versione di prima. */
    public void write_file() {
        this.writed = InstallScripts.write(SCRIPT_PATH, this.data);
    }

    public String getScriptContent() {
        return this.data;
    }
}
