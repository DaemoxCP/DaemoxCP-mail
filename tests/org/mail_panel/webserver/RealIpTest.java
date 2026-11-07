package org.mail_panel.webserver;

/**
 * Which piece of X-Forwarded-For gives the address of whoever is knocking.
 *
 * It is the line that, read from the left, made the limit on sign-in attempts useless: changing
 * the header at every try was enough never to be blocked.
 */
public class RealIpTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }
    static void expected(String header, String wanted) {
        String got = SSLMailServer.ipFromForwardedFor(header);
        boolean ok = (wanted == null) ? (got == null) : wanted.equals(got);
        System.out.println((ok ? "  OK   " : "  FAILED ")
                + String.format("%-46s -> %s", "\"" + header + "\"", got)
                + (ok ? "" : "   (expected " + wanted + ")"));
        if (!ok) failed++;
    }

    public static void main(String[] a) {
        System.out.println("\n== the normal case behind Cloudflare ==");
        // Cloudflare appends the real sender after whatever the client sent.
        expected("203.0.113.9", "203.0.113.9");
        expected("9.9.9.9, 203.0.113.9", "203.0.113.9");

        System.out.println("\n== the forgery that used to pass ==");
        // Before, the FIRST piece was taken: here it would have returned 1.2.3.4, that is an address
        // chosen by whoever knocks. Changing it at every try, no block would ever have fired.
        require("an address put by the client does not win over the value added by the proxy",
                !"1.2.3.4".equals(SSLMailServer.ipFromForwardedFor("1.2.3.4, 203.0.113.9")));
        expected("1.2.3.4, 203.0.113.9", "203.0.113.9");

        System.out.println("\n== chains with more trusted proxies at the end ==");
        expected("203.0.113.9, 172.68.1.1", "203.0.113.9");
        expected("203.0.113.9, 172.68.1.1, 104.16.0.5", "203.0.113.9");

        System.out.println("\n== invalid values: skipped, not accepted ==");
        expected("foo, 203.0.113.9", "203.0.113.9");
        expected("203.0.113.9, foo", "203.0.113.9");
        expected("foo", null);
        expected("", null);
        expected(null, null);

        System.out.println("\n== if they are ALL trusted nothing is made up ==");
        // The caller falls back on the TCP address: better a real and useless address than a
        // plausible and false one.
        expected("127.0.0.1", null);
        expected("172.68.1.1, 104.16.0.5", null);

        System.out.println("\n== spaces and sloppy forms ==");
        expected("  203.0.113.9  ,  172.68.1.1  ", "203.0.113.9");
        expected("203.0.113.9,172.68.1.1", "203.0.113.9");

        System.out.println("\n== and the CIDR comparison is on bits, not on strings ==");
        require("104.23.255.255 is inside 104.16.0.0/13 (a text comparison would miss it)",
                org.mail_panel.security.TrustedProxy.isTrustedProxy("104.23.255.255"));
        require("173.245.64.1 is NOT inside 173.245.48.0/20 (a text comparison would accept it)",
                !org.mail_panel.security.TrustedProxy.isTrustedProxy("173.245.64.1"));
        require("188.114.97.7 is recognised: it is the address the two panels answer on",
                org.mail_panel.security.TrustedProxy.isTrustedProxy("188.114.97.7"));

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }
}
