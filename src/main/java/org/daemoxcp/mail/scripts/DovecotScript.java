package org.daemoxcp.mail.scripts;

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

    /**
     * The folder of the panel's Sieve rules (auto-reply, forward, filters:
     * /var/mail/sieve/domain/name/.dovecot.sieve) and that of the global scripts of sieve_global_dir: owned by root,
     * and nobody but root writes in them (finding 220).
     *
     * <p>Before, this script gave everything to vmail (chown -R vmail:vmail /var/mail/sieve). Since finding 214 the
     * panel's rules belong to root on purpose: vmail, which delivers, reads and runs them but must not be able to
     * rewrite them. With the folder owned by vmail, however, it was enough to rename a domain's folder (owned by
     * root) and make one's own next to it, with one's own rules: measured on the VM on 2026-11-10, "mv" and "mkdir"
     * as vmail succeeded. Pigeonhole 2.3's documentation (Sieve Usage) says the same of the global scripts: they
     * must not be writable by the user, and the administrator precompiles them with sievec (since finding 218 the
     * sievec user, then root puts them in place).
     *
     * <p>root:mail as the panel creates them: /var/mail is root:mail, and on FreeBSD a new folder takes the group
     * of the one that contains it. -R without -H does not follow links (those of ManageSieve stay as they were), and
     * go-w removes only writing: the script stays 0644, the folders 0755, and vmail reads them as before.
     *
     * <p>Nobody runs this class's script today: the /api/install route has not existed since the first commit
     * (2025-12-30), and install_dovecot.sh is among the scripts set aside (InstallScripts.RETIRED). The chown to
     * vmail arrived on 2025-12-31: no server ever ran it, so no boot migration.
     */
    static final String PANEL_SIEVE_FOLDER = """
            # The panel's Sieve rules: root's, and only root writes there (vmail reads and runs them)
            mkdir -p /var/mail/sieve/global
            chown -R root:mail /var/mail/sieve
            chmod -R go-w /var/mail/sieve
            chmod 755 /var/mail/sieve /var/mail/sieve/global
            """;

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
            pkg delete -fy dovecot dovecot-pigeonhole dovecot24 dovecot24-pigeonhole 2>/dev/null || true
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
            # Where the catalog offers 2.4 (latest branch) that one is installed (DovecotConfig.packagesShell, finding 215).
            """
            + DovecotConfig.packagesShell() + """
            pkg install -y $DOVECOT_PACKAGES

            # Create vmail user if not exists
            echo "[2/7] Creating vmail user..."
            pw user show vmail >/dev/null 2>&1 || pw useradd vmail -c "Virtual Mail" -d /var/vmail -s /usr/sbin/nologin -u 5000
            pw group show vmail >/dev/null 2>&1 || pw groupadd vmail -g 5000

            mkdir -p /var/vmail
            """
            // The mail folders to vmail without giving it other people's files: no hard links, no symbolic links
            // (finding 252)
            + org.daemoxcp.mail.security.SafeOwnership.shell("/var/vmail", "vmail", "vmail") + """
            chmod 700 /var/vmail

            # Configure Dovecot
            echo "[3/7] Configuring Dovecot..."
            """
            // SINGLE source of the configuration: before, every script had its own copy,
            // and two of the three wrote a hard-coded and wrong database name.
            + DovecotConfig.fromPanelConfig().scriptFragment() + """

            # Generate master user password for SSO
            echo "[5/7] Configuring master user for SSO..."
            """
            // The same piece as in FullMailServerScript and FullMailStackScript.
            + org.daemoxcp.mail.system.DovecotMasterUser.shell() + """

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
                    -subj "/CN=mail.localhost/O=DaemoxCP Mail"
                chmod 600 /usr/local/etc/ssl/mail/privkey.pem
            fi

            # Create run directory
            mkdir -p /var/run/dovecot
            chown root:dovecot /var/run/dovecot

            """ + PANEL_SIEVE_FOLDER + """

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
            echo ""
            """;
    }

    public String getScriptContent() {
        return this.data;
    }

    /** Always, all or nothing, with the jar's fingerprint (InstallScripts): never a script from a previous version. */
    public void write_file() {
        this.writed = InstallScripts.write(SCRIPT_PATH, this.data);
    }
}
