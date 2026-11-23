package org.daemoxcp.mail.scripts;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Rspamd Anti-Spam Installation Script for FreeBSD 15
 * On reinstall: completely removes Rspamd and reinstalls fresh
 *
 * Rspamd is a fast, free and open-source spam filtering system.
 */
public class RspamdScript {

    public boolean writed = false;
    private static final String SCRIPT_PATH = "./install_scripts/install_rspamd.sh";
    private final String data;

    public RspamdScript() {
        this.data = """
            #!/bin/sh
            # Rspamd Anti-Spam Installation for FreeBSD 15
            # REINSTALL MODE: Completely removes Rspamd before reinstalling

            echo "=== Rspamd Anti-Spam Installation ==="
            echo ""

            # Check root
            if [ "$(id -u)" -ne 0 ]; then
                echo "Error: Must run as root"
                exit 1
            fi

            #############################################
            # PHASE 1: COMPLETE CLEANUP
            #############################################

            echo "[CLEANUP] Stopping Rspamd..."
            service rspamd stop 2>/dev/null || true
            pkill -9 rspamd 2>/dev/null || true
            sleep 2

            echo "[CLEANUP] Removing Rspamd packages..."
            pkg delete -fy rspamd 2>/dev/null || true
            pkg autoremove -fy 2>/dev/null || true

            echo "[CLEANUP] Removing Rspamd data and config..."
            rm -rf /usr/local/etc/rspamd 2>/dev/null || true
            rm -rf /var/db/rspamd 2>/dev/null || true
            rm -rf /var/run/rspamd 2>/dev/null || true
            rm -rf /var/log/rspamd 2>/dev/null || true
            rm -rf /usr/local/etc/mail/dkim 2>/dev/null || true

            echo "[CLEANUP] Removing rspamd user..."
            pw userdel rspamd 2>/dev/null || true
            pw groupdel rspamd 2>/dev/null || true

            echo "[CLEANUP] Removing rc.conf entry..."
            sysrc -x rspamd_enable 2>/dev/null || true

            echo ""
            echo "[CLEANUP] Complete! Starting fresh installation..."
            echo ""

            #############################################
            # PHASE 2: FRESH INSTALLATION
            #############################################

            # Install Rspamd
            echo "[1/5] Installing Rspamd..."
            pkg install -y rspamd

            # Create directories
            echo "[2/5] Creating directories..."
            mkdir -p /usr/local/etc/rspamd/local.d
            mkdir -p /usr/local/etc/rspamd/override.d
            mkdir -p /var/db/rspamd
            mkdir -p /var/run/rspamd
            mkdir -p /var/log/rspamd

            chown rspamd:rspamd /var/db/rspamd
            chown rspamd:rspamd /var/run/rspamd
            chown rspamd:rspamd /var/log/rspamd

            # Configure Rspamd
            echo "[3/5] Configuring Rspamd..."

            # Worker configuration
            cat > /usr/local/etc/rspamd/local.d/worker-normal.inc << 'WORKERCONF'
bind_socket = "127.0.0.1:11333";
WORKERCONF

            cat > /usr/local/etc/rspamd/local.d/worker-proxy.inc << 'PROXYCONF'
bind_socket = "127.0.0.1:11332";
milter = yes;
timeout = 120s;
upstream "local" {
    default = yes;
    self_scan = yes;
}
PROXYCONF

            # Generate password for web UI
            RSPAMD_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
            RSPAMD_HASH=$(rspamadm pw -p "${RSPAMD_PASS}" 2>/dev/null || echo '$2$randomsalt$rspamdwebui')

            cat > /usr/local/etc/rspamd/local.d/worker-controller.inc << CTRLCONF
bind_socket = "127.0.0.1:11334";
password = "${RSPAMD_HASH}";
enable_password = "${RSPAMD_HASH}";
CTRLCONF

            # Save password
            echo "${RSPAMD_PASS}" > /usr/local/etc/mail/rspamd_password
            chmod 600 /usr/local/etc/mail/rspamd_password

            # Redis configuration (for learning/statistics)
            cat > /usr/local/etc/rspamd/local.d/redis.conf << 'REDISCONF'
servers = "127.0.0.1:6379";
REDISCONF

            # DKIM signing
            cat > /usr/local/etc/rspamd/local.d/dkim_signing.conf << 'DKIMCONF'
# DKIM Signing
# Keys are generated per-domain by the panel

allow_username_mismatch = true;
try_fallback = false;

domain {
    # Domains will be added here by the panel
    # example.com {
    #     path = "/usr/local/etc/mail/dkim/example.com.key";
    #     selector = "mail";
    # }
}
DKIMCONF

            # Classifier (Bayes)
            cat > /usr/local/etc/rspamd/local.d/classifier-bayes.conf << 'BAYESCONF'
backend = "redis";
autolearn = true;
BAYESCONF

            # Actions
            cat > /usr/local/etc/rspamd/local.d/actions.conf << 'ACTIONSCONF'
reject = 15;
add_header = 6;
greylist = 4;
ACTIONSCONF

            # Milter headers
            cat > /usr/local/etc/rspamd/local.d/milter_headers.conf << 'MILTERCONF'
use = ["x-spamd-bar", "x-spam-level", "authentication-results"];
MILTERCONF

            # Create DKIM key directory
            echo "[4/5] Creating DKIM directory..."
            mkdir -p /usr/local/etc/mail/dkim
            chmod 750 /usr/local/etc/mail/dkim
            chown rspamd:rspamd /usr/local/etc/mail/dkim

            # Enable and start
            echo "[5/5] Enabling service..."
            """
            // The local recursive resolver, before rspamd starts: without it, the Spamhaus lists
            // do not answer. The same piece is in FullMailServerScript and FullMailStackScript.
            + LocalResolverScript.SHELL + """
            sysrc rspamd_enable="YES"
            service rspamd start

            echo ""
            echo "=== Rspamd Installation Complete ==="
            echo ""
            echo "Configuration: /usr/local/etc/rspamd/"
            echo "Web UI:        http://127.0.0.1:11334/"
            echo "Web UI Pass:   ${RSPAMD_PASS}"
            echo "(Password also saved to /usr/local/etc/mail/rspamd_password)"
            echo ""
            echo "Ports:"
            echo "  Proxy (milter):  11332"
            echo "  Normal worker:   11333"
            echo "  Controller/UI:   11334"
            echo ""
            echo "To train spam: rspamc learn_spam < message.eml"
            echo "To train ham:  rspamc learn_ham < message.eml"
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
