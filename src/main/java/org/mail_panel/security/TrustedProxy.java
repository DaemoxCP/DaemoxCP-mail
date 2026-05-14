package org.mail_panel.security;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/**
 * Verifica se un indirizzo IP appartiene a un proxy considerato "trusted",
 * cioè uno dei cui header forwarding (CF-Connecting-IP, X-Forwarded-For,
 * X-Real-IP) ci possiamo fidare.
 *
 * Lista corrente:
 *  - IP range ufficiali di Cloudflare (https://www.cloudflare.com/ips/)
 *  - localhost (127.0.0.1, ::1) — per setup con nginx davanti sullo stesso host
 *  - rete privata 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — per setup
 *    in cui un reverse proxy è in LAN
 *
 * Se il TCP source di una richiesta NON è in queste liste, NON ci si deve
 * fidare degli header forwarding (un attaccante potrebbe averli falsificati).
 *
 * Le IP range Cloudflare possono cambiare nel tempo. Andrebbero aggiornate
 * periodicamente dai file ufficiali:
 *   https://www.cloudflare.com/ips-v4
 *   https://www.cloudflare.com/ips-v6
 *
 * Aggiornato: 2025-12 (lista Cloudflare ufficiale)
 */
public final class TrustedProxy {
    private TrustedProxy() {}

    // Cloudflare IPv4 ranges — https://www.cloudflare.com/ips-v4
    private static final List<String> CLOUDFLARE_V4 = Arrays.asList(
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22"
    );

    // Cloudflare IPv6 ranges — https://www.cloudflare.com/ips-v6
    private static final List<String> CLOUDFLARE_V6 = Arrays.asList(
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32"
    );

    // Range privati / loopback per setup interni
    private static final List<String> PRIVATE_RANGES = Arrays.asList(
        "127.0.0.0/8",     // loopback IPv4
        "::1/128",         // loopback IPv6
        "10.0.0.0/8",      // RFC1918
        "172.16.0.0/12",   // RFC1918
        "192.168.0.0/16",  // RFC1918
        "fc00::/7"         // IPv6 ULA
    );

    /**
     * Ritorna true se l'IP appartiene a un range Cloudflare o privato/loopback.
     * @param ipString l'IP da verificare in formato testuale
     */
    public static boolean isTrustedProxy(String ipString) {
        if (ipString == null || ipString.isEmpty()) return false;
        try {
            InetAddress addr = InetAddress.getByName(ipString);
            byte[] addrBytes = addr.getAddress();

            List<String> ranges;
            if (addrBytes.length == 4) {
                ranges = CLOUDFLARE_V4;
            } else if (addrBytes.length == 16) {
                ranges = CLOUDFLARE_V6;
            } else {
                return false;
            }

            for (String cidr : ranges) {
                if (isInRange(addrBytes, cidr)) return true;
            }
            for (String cidr : PRIVATE_RANGES) {
                if (isInRange(addrBytes, cidr)) return true;
            }
        } catch (UnknownHostException e) {
            return false;
        }
        return false;
    }

    /**
     * Confronta i bit di addrBytes contro un CIDR (es. "173.245.48.0/20").
     */
    private static boolean isInRange(byte[] addrBytes, String cidr) {
        try {
            int slashIdx = cidr.indexOf('/');
            if (slashIdx < 0) return false;
            String network = cidr.substring(0, slashIdx);
            int prefixLen = Integer.parseInt(cidr.substring(slashIdx + 1));

            byte[] networkBytes = InetAddress.getByName(network).getAddress();
            if (addrBytes.length != networkBytes.length) return false;

            int fullBytes = prefixLen / 8;
            int remainingBits = prefixLen % 8;

            for (int i = 0; i < fullBytes; i++) {
                if (addrBytes[i] != networkBytes[i]) return false;
            }
            if (remainingBits > 0 && fullBytes < addrBytes.length) {
                int mask = 0xFF << (8 - remainingBits);
                if ((addrBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask)) return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
