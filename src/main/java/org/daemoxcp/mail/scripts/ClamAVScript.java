package org.daemoxcp.mail.scripts;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * ClamAV Antivirus Installation Script for FreeBSD 15
 * On reinstall: completely removes ClamAV and reinstalls fresh
 */
public class ClamAVScript {

    public boolean writed = false;
    private static final String SCRIPT_PATH = "./install_scripts/install_clamav.sh";
    private final String data;

    public ClamAVScript() {
        this.data = """
            #!/bin/sh
            # ClamAV Antivirus Installation for FreeBSD 15
            # REINSTALL MODE: Completely removes ClamAV before reinstalling

            echo "=== ClamAV Antivirus Installation ==="
            echo ""

            # Check root
            if [ "$(id -u)" -ne 0 ]; then
                echo "Error: Must run as root"
                exit 1
            fi

            #############################################
            # PHASE 1: COMPLETE CLEANUP
            #############################################

            echo "[CLEANUP] Stopping ClamAV services..."
            service clamav_clamd stop 2>/dev/null || true
            service clamav_freshclam stop 2>/dev/null || true
            pkill -9 clamd 2>/dev/null || true
            pkill -9 freshclam 2>/dev/null || true
            sleep 2

            echo "[CLEANUP] Removing ClamAV packages..."
            pkg delete -fy clamav 2>/dev/null || true
            pkg autoremove -fy 2>/dev/null || true

            echo "[CLEANUP] Removing ClamAV data and config..."
            rm -rf /var/db/clamav 2>/dev/null || true
            rm -rf /var/run/clamav 2>/dev/null || true
            rm -rf /var/log/clamav 2>/dev/null || true
            rm -f /usr/local/etc/clamd.conf 2>/dev/null || true
            rm -f /usr/local/etc/freshclam.conf 2>/dev/null || true

            echo "[CLEANUP] Removing clamav user..."
            pw userdel clamav 2>/dev/null || true
            pw groupdel clamav 2>/dev/null || true

            echo "[CLEANUP] Removing rc.conf entries..."
            sysrc -x clamav_clamd_enable 2>/dev/null || true
            sysrc -x clamav_freshclam_enable 2>/dev/null || true

            echo ""
            echo "[CLEANUP] Complete! Starting fresh installation..."
            echo ""

            #############################################
            # PHASE 2: FRESH INSTALLATION
            #############################################

            # Install ClamAV
            echo "[1/4] Installing ClamAV..."
            pkg install -y clamav

            # Configure ClamAV
            echo "[2/4] Configuring ClamAV..."

            # clamd.conf
            cat > /usr/local/etc/clamd.conf << 'CLAMDCONF'
# ClamAV Daemon Configuration
# Managed by DaemoxCP Mail

LocalSocket /var/run/clamav/clamd.sock
FixStaleSocket yes
LocalSocketMode 666

User clamav

ScanMail yes
ScanArchive yes
ArchiveBlockEncrypted no
MaxFileSize 25M
MaxScanSize 100M

TCPSocket 3310
TCPAddr 127.0.0.1

LogFile /var/log/clamav/clamd.log
LogTime yes
LogVerbose no

DatabaseDirectory /var/db/clamav
CLAMDCONF

            # freshclam.conf (virus database updater)
            cat > /usr/local/etc/freshclam.conf << 'FRESHCONF'
# Freshclam Configuration
# Managed by DaemoxCP Mail

DatabaseDirectory /var/db/clamav
DatabaseOwner clamav

UpdateLogFile /var/log/clamav/freshclam.log
LogTime yes

DatabaseMirror database.clamav.net

Checks 24
FRESHCONF

            # Create directories
            echo "[3/4] Creating directories..."
            mkdir -p /var/run/clamav
            mkdir -p /var/log/clamav
            mkdir -p /var/db/clamav
            chown clamav:clamav /var/run/clamav
            chown clamav:clamav /var/log/clamav
            chown clamav:clamav /var/db/clamav

            # Update virus database
            echo "[4/4] Updating virus database (this may take a while)..."
            freshclam || echo "Warning: Could not update database. Will retry on next run."

            # Enable and start
            sysrc clamav_clamd_enable="YES"
            sysrc clamav_freshclam_enable="YES"
            service clamav_freshclam start
            service clamav_clamd start

            echo ""
            echo "=== ClamAV Installation Complete ==="
            echo ""
            echo "Configuration: /usr/local/etc/clamd.conf"
            echo "Socket:        /var/run/clamav/clamd.sock"
            echo "TCP Port:      3310 (localhost only)"
            echo ""
            echo "Database updates run automatically via freshclam."
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
