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

    /**
     * La cartella delle regole Sieve del pannello (risposta automatica, inoltro, filtri:
     * /var/mail/sieve/dominio/nome/.dovecot.sieve) e quella degli script globali di sieve_global_dir: di root, e
     * nessuno oltre root ci scrive (reperto 220).
     *
     * <p>Prima questo script dava tutto a vmail (chown -R vmail:vmail /var/mail/sieve). Dal reperto 214 le regole del
     * pannello sono di root apposta: vmail, che consegna, le legge e le esegue ma non le deve poter riscrivere. Con la
     * cartella di vmail pero' bastava rinominare quella di un dominio (di root) e farne una propria accanto, con regole
     * proprie: misurato sulla VM il 10/11/2026, «mv» e «mkdir» da vmail riusciti. La documentazione di Pigeonhole 2.3
     * (Sieve Usage) dice lo stesso degli script globali: non devono essere scrivibili dall'utente, e li precompila
     * l'amministratore con sievec (dal reperto 218 l'utente sievec, poi root li mette a posto).
     *
     * <p>root:mail come le crea il pannello: /var/mail e' root:mail, e su FreeBSD una cartella nuova prende il gruppo
     * di quella che la contiene. -R senza -H non segue i collegamenti (quelli di ManageSieve restano com'erano), e
     * go-w toglie solo la scrittura: lo script resta 0644, le cartelle 0755, e vmail li legge come prima.
     *
     * <p>Lo script di questa classe oggi non lo lancia nessuno: la rotta /api/install non c'e' dal primo commit
     * (30/12/2025), e install_dovecot.sh e' fra gli script messi da parte (InstallScripts.RETIRED). Il chown a vmail e'
     * arrivato il 31/12/2025: nessun server l'ha mai eseguito, quindi nessuna migrazione all'avvio.
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
            # Dove il catalogo offre la 2.4 (ramo latest) si installa quella (DovecotConfig.packagesShell, reperto 215).
            """
            + DovecotConfig.packagesShell() + """
            pkg install -y $DOVECOT_PACKAGES

            # Create vmail user if not exists
            echo "[2/7] Creating vmail user..."
            pw user show vmail >/dev/null 2>&1 || pw useradd vmail -c "Virtual Mail" -d /var/vmail -s /usr/sbin/nologin -u 5000
            pw group show vmail >/dev/null 2>&1 || pw groupadd vmail -g 5000

            mkdir -p /var/vmail
            chown -R vmail:vmail /var/vmail
            chmod 700 /var/vmail

            # Configure Dovecot
            echo "[3/7] Configuring Dovecot..."
            """
            // Sorgente UNICA della configurazione: prima ogni script aveva la sua copia,
            // e due delle tre scrivevano un nome di database cablato e sbagliato.
            + DovecotConfig.fromPanelConfig().scriptFragment() + """

            # Generate master user password for SSO
            echo "[5/7] Configuring master user for SSO..."
            """
            // Lo stesso pezzo di FullMailServerScript e FullMailStackScript.
            + org.mail_panel.system.DovecotMasterUser.shell() + """

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

    /** Sempre, tutto o niente, con l'impronta del jar (InstallScripts): mai uno script di una versione di prima. */
    public void write_file() {
        this.writed = InstallScripts.write(SCRIPT_PATH, this.data);
    }
}
