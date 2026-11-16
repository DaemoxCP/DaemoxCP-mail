package org.mail_panel.scripts;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.*;

/**
 * System Time and DNS Configuration Script for FreeBSD Mail Panel
 * Sets the time zone chosen in the menu (first argument, reperto 242; before: always Europe/Rome), configures NTP,
 * and the DNS resolver (1.1.1.1 until the installation turns on the local recursive resolver).
 */
public class SetTimeOnSystem {

    private final String data;

    public SetTimeOnSystem() {
        this.data = """
            #!/bin/sh
            # System Time and DNS Configuration for FreeBSD Mail Panel
            # Sets timezone, configures NTP, and sets Cloudflare DNS

            echo "=== System Time and DNS Configuration ==="
            echo ""

            # Check root
            if [ "$(id -u)" -ne 0 ]; then
                echo "Error: Must run as root"
                exit 1
            fi

            # The time zone chosen in the menu (SystemTimeZone checks it too): an IANA name present in
            # /usr/share/zoneinfo as a plain file. Never a path with "..", never a link.
            TZ_NAME="${1:-}"
            if [ -z "$TZ_NAME" ]; then
                echo "Error: no time zone given (the menu passes it, for example Europe/Rome or UTC)"
                exit 1
            fi
            case "$TZ_NAME" in
                *..*|/*|*[!A-Za-z0-9_+/-]*)
                    echo "Error: \"$TZ_NAME\" is not a time zone name"
                    exit 1 ;;
            esac
            if [ ! -f "/usr/share/zoneinfo/$TZ_NAME" ] || [ -L "/usr/share/zoneinfo/$TZ_NAME" ]; then
                echo "Error: /usr/share/zoneinfo/$TZ_NAME does not exist"
                exit 1
            fi

            echo "Current time:"
            date

            echo ""
            echo "[1/5] Setting timezone to $TZ_NAME..."
            cp "/usr/share/zoneinfo/$TZ_NAME" /etc/localtime
            echo "$TZ_NAME" > /var/db/zoneinfo

            echo "New time after timezone setting:"
            date

            echo ""
            echo "[2/5] Configuring NTP service..."
            sysrc ntpd_enable="YES"
            sysrc ntpd_sync_on_start="YES"

            echo ""
            echo "[3/5] Starting NTP service..."
            service ntpd stop 2>/dev/null || true
            service ntpd start

            echo ""
            echo "[4/5] Synchronizing time with NTP server..."
            ntpdate -u pool.ntp.org 2>/dev/null || echo "Warning: Could not sync with NTP (will sync on next boot)"

            echo ""
            echo "Final time after synchronization:"
            date

            echo ""
            echo "[5/5] Configuring DNS settings (Cloudflare)..."

            # Con il risolutore ricorsivo locale acceso (LocalResolverScript, lo accende
            # l'installazione) il DNS resta com'e': rimettere 1.1.1.1 farebbe rifiutare da Spamhaus
            # ogni domanda di rspamd (DBL_BLOCKED_OPENRESOLVER, misurato il 29/10/2026).
            DNS_SUMMARY="1.1.1.1, 1.0.0.1 (Cloudflare)"
            if [ "$(sysrc -n local_unbound_enable 2>/dev/null)" = "YES" ] && grep -q "^nameserver 127.0.0.1" /etc/resolv.conf; then
                DNS_SUMMARY="127.0.0.1 (local_unbound, left as it is)"
                echo "Local recursive resolver in use: resolv.conf and dhclient.conf left as they are."
            else

            # Update resolv.conf
            if grep -q "nameserver 1.1.1.1" /etc/resolv.conf && grep -q "nameserver 1.0.0.1" /etc/resolv.conf; then
                echo "resolv.conf already contains Cloudflare DNS servers."
            else
                echo "Updating /etc/resolv.conf..."
                cat > /etc/resolv.conf << 'RESOLVCONF'
nameserver 1.1.1.1
nameserver 1.0.0.1
RESOLVCONF
                echo "resolv.conf updated with Cloudflare DNS servers."
            fi

            # Update dhclient.conf to persist DNS settings
            if grep -q "supersede domain-name-servers 1.1.1.1, 1.0.0.1;" /etc/dhclient.conf 2>/dev/null; then
                echo "dhclient.conf already contains correct DNS configuration."
            else
                if grep -q "supersede domain-name-servers" /etc/dhclient.conf 2>/dev/null; then
                    sed -i '' 's/supersede domain-name-servers.*$/supersede domain-name-servers 1.1.1.1, 1.0.0.1;/' /etc/dhclient.conf
                    echo "Updated existing DNS configuration in dhclient.conf"
                else
                    echo 'supersede domain-name-servers 1.1.1.1, 1.0.0.1;' >> /etc/dhclient.conf
                    echo "Added DNS configuration to dhclient.conf"
                fi
            fi

            fi

            echo ""
            echo "=== Configuration Complete ==="
            echo ""
            echo "Timezone:  $TZ_NAME"
            echo "NTP:       Enabled (syncs on boot)"
            echo "DNS:       $DNS_SUMMARY"
            echo ""
            """;
    }

    public String getScriptContent() {
        return this.data;
    }
}
