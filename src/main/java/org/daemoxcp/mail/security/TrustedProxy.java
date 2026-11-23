package org.daemoxcp.mail.security;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/**
 * Who the panel recognises as Cloudflare: the only one from which it accepts the CF-Connecting-IP header with
 * the real address of whoever is knocking (r18). From any other address, loopback and private networks included,
 * the forwarding headers (CF-Connecting-IP, X-Forwarded-For, X-Real-IP) are text anyone can
 * write, and only the TCP address counts.
 *
 * The loopback and the private networks (10/8, 172.16/12, 192.168/16, fc00::/7) used to be trusted too:
 * another machine in the same private network of the provider was enough, or a request to the public surface
 * on 443 (nginx passes the client's headers to the panel), to pick one's own address in the logs and
 * in the attempt limits.
 *
 * Cloudflare IP ranges can change over time: the "Who the panel recognises as
 * Cloudflare" tab compares them with the official ones.
 *   https://www.cloudflare.com/ips-v4
 *   https://www.cloudflare.com/ips-v6
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

    /**
     * When the list above was compared with the official one, by a human being.
     *
     * On 2026-09-02 the comparison was really run against cloudflare.com/ips-v4 and
     * ips-v6: 15 IPv4 ranges and 7 IPv6 ones, no divergence in either direction.
     * The list has not changed since December - it was verified, which is a different thing and worth
     * distinguishing: "written back then" does not say whether it is still right.
     */
    public static final String UPDATED_ON = "2026-09-02";

    /**
     * The ranges compiled into the panel: those from which the forwarding
     *  headers are accepted. They are exposed so they can be SHOWN, not only compared:
     *  a list that decides whom to trust and that nobody can read is a secret rule.
     */
    public static List<String> cloudflareV4() { return List.copyOf(CLOUDFLARE_V4); }
    public static List<String> cloudflareV6() { return List.copyOf(CLOUDFLARE_V6); }

    /**
     * Does the address belong to Cloudflare? Only the published ranges, compared bit by bit.
     * @param ipString the IP to check in text form (never a name: DNS is not queried)
     */
    public static boolean isCloudflare(String ipString) {
        if (ipString == null || ipString.isEmpty() || !InputValidator.isValidIp(ipString.trim())) return false;
        try {
            byte[] addrBytes = InetAddress.getByName(ipString.trim()).getAddress();
            List<String> ranges = addrBytes.length == 4 ? CLOUDFLARE_V4 : addrBytes.length == 16 ? CLOUDFLARE_V6 : List.of();
            for (String cidr : ranges) {
                if (isInRange(addrBytes, cidr)) return true;
            }
        } catch (UnknownHostException e) {
            return false;
        }
        return false;
    }

    /**
     * The address of whoever is knocking (r18): the one in CF-Connecting-IP if the connection comes from Cloudflare and
     * the header is a valid address, otherwise the TCP one. Nothing else: X-Forwarded-For and
     * X-Real-IP count from nobody, because Cloudflare always sends CF-Connecting-IP.
     */
    public static String clientAddress(String tcpAddress, String cfConnectingIp) {
        if (isCloudflare(tcpAddress) && cfConnectingIp != null) {
            String claimed = cfConnectingIp.trim();
            if (InputValidator.isValidIp(claimed)) return claimed;
        }
        return tcpAddress;
    }

    /**
     * Compares the bits of addrBytes against a CIDR (e.g. "173.245.48.0/20").
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
