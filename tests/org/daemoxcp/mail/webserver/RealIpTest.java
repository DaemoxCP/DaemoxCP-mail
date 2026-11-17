package org.daemoxcp.mail.webserver;

import org.daemoxcp.mail.security.TrustedProxy;

/**
 * The address of whoever is knocking (r18): CF-Connecting-IP only when the connection really comes from
 * Cloudflare, otherwise the TCP address. Never X-Forwarded-For or X-Real-IP, from anyone.
 *
 * Before, the loopback and the private networks were trusted like Cloudflare: another machine in the
 * provider's private network, or a request to the 443 surface (nginx passes the client's headers on to the
 * panel over the loopback), could choose its own address in the logs and in the limit on sign-in attempts.
 *
 * It runs anywhere (it calls nothing):
 *   java -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.webserver.RealIpTest
 */
public class RealIpTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }
    static void expected(String tcp, String header, String wanted) {
        String got = TrustedProxy.clientAddress(tcp, header);
        boolean ok = wanted.equals(got);
        System.out.println((ok ? "  OK   " : "  FAILED ")
                + String.format("%-24s CF-Connecting-IP %-22s -> %s", tcp, header == null ? "(none)" : "\"" + header + "\"", got)
                + (ok ? "" : "   (expected " + wanted + ")"));
        if (!ok) failed++;
    }

    public static void main(String[] a) {
        System.out.println("\n== from Cloudflare: the address Cloudflare writes ==");
        expected("172.68.1.1", "203.0.113.9", "203.0.113.9");
        expected("2606:4700::6812:1", "2001:db8::9", "2001:db8::9");
        // The form the TCP address has in Java (getHostAddress): uncompressed.
        expected("2606:4700:0:0:0:0:6812:1", "203.0.113.9", "203.0.113.9");
        expected("172.68.1.1", "  203.0.113.9  ", "203.0.113.9");

        System.out.println("\n== from Cloudflare without a usable header: the TCP address, nothing made up ==");
        expected("172.68.1.1", null, "172.68.1.1");
        expected("172.68.1.1", "", "172.68.1.1");
        expected("172.68.1.1", "not-an-address", "172.68.1.1");
        expected("172.68.1.1", "203.0.113.9, 198.51.100.7", "172.68.1.1");

        System.out.println("\n== from anyone else the header is only text: the TCP address ==");
        expected("198.51.100.7", "203.0.113.9", "198.51.100.7");
        expected("127.0.0.1", "203.0.113.9", "127.0.0.1");
        expected("0:0:0:0:0:0:0:1", "203.0.113.9", "0:0:0:0:0:0:0:1");
        expected("10.1.2.3", "203.0.113.9", "10.1.2.3");
        expected("172.16.5.5", "203.0.113.9", "172.16.5.5");
        expected("192.168.1.1", "203.0.113.9", "192.168.1.1");
        expected("fd12:3456:789a:1::1", "203.0.113.9", "fd12:3456:789a:1::1");

        System.out.println("\n== who is Cloudflare: the published ranges only, compared on bits ==");
        require("104.23.255.255 is inside 104.16.0.0/13 (a text comparison would miss it)",
                TrustedProxy.isCloudflare("104.23.255.255"));
        require("173.245.64.1 is NOT inside 173.245.48.0/20 (a text comparison would accept it)",
                !TrustedProxy.isCloudflare("173.245.64.1"));
        require("188.114.97.7 is recognised: it is the address the two panels answer on",
                TrustedProxy.isCloudflare("188.114.97.7"));
        require("2606:4700::1 is inside 2606:4700::/32, 2606:4701::1 is not",
                TrustedProxy.isCloudflare("2606:4700::1") && !TrustedProxy.isCloudflare("2606:4701::1"));
        require("the loopback and the private networks are not Cloudflare any more",
                !TrustedProxy.isCloudflare("127.0.0.1") && !TrustedProxy.isCloudflare("::1")
                        && !TrustedProxy.isCloudflare("10.0.0.1") && !TrustedProxy.isCloudflare("172.16.0.1")
                        && !TrustedProxy.isCloudflare("192.168.1.1") && !TrustedProxy.isCloudflare("fd00::1"));
        require("a name is never an address: no DNS lookup, not Cloudflare",
                !TrustedProxy.isCloudflare("cloudflare.com") && !TrustedProxy.isCloudflare("localhost")
                        && !TrustedProxy.isCloudflare(null) && !TrustedProxy.isCloudflare(""));

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }
}
