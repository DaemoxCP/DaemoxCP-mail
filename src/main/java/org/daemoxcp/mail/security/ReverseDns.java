package org.daemoxcp.mail.security;

import java.net.InetAddress;
import java.util.Locale;
import java.util.function.BiFunction;

/**
 * The reverse DNS of an address, IPv4 or IPv6, and its forward confirmation: the name the PTR gives must be that
 * of the mail server, and that name must point back to the same address (A for IPv4, AAAA for IPv6).
 *
 * Gmail requires it from senders (support.google.com/a/answer/81126: "550 5.7.1 This message does not meet IPv6 sending
 * guidelines regarding PTR records and authentication"), Microsoft 365 too (450 4.7.25 without a PTR for IPv6). The
 * previous check (DnsRecordsGenerator.checkPtrAndFcrdns) always looked for an A record: for an IPv6 address it could
 * never match. This one works for both families.
 *
 * The queries go to the servers that publish the records (FreshDns), not to the cache of the server's resolver: the reverse
 * DNS just saved by the administrator is visible at once.
 */
public final class ReverseDns {

    /** Outcome: fine or not, the PTR found (or null), and the reason as a language key (null if fine). */
    public record Check(boolean ok, String ptr, String reason) {
        /**
         * The reverse DNS gives the mail server's name, even if that name does not lead back to the address yet. It is
         * the administrator's step in the guide: the way back (the A or AAAA record) is written by the panel
         * AFTERWARDS, and requiring it here would block the guide forever (seen on the production server: IPv6 reverse
         * DNS right, no AAAA yet, step stuck). The full check (ok) remains the one needed before sending.
         */
        public boolean givesName() {
            return ok || "server.rdns.notBack".equals(reason);
        }
    }

    /** The DNS query (type, name): to the servers that publish the record (FreshDns), or a fake one in tests. */
    static BiFunction<String, String, String> lookup = FreshDns::query;

    private ReverseDns() {}

    public static Check check(String ip, String hostname) {
        InetAddress a = literal(ip);
        if (a == null) return new Check(false, null, "server.rdns.noIp");
        if (hostname == null || !hostname.matches("[A-Za-z0-9.-]{1,253}")) return new Check(false, null, "server.rdns.noHost");
        String ptr = firstName(lookup.apply("PTR", FreshDns.reverseName(a)));
        if (ptr == null) return new Check(false, null, "server.rdns.none");
        if (!ptr.equalsIgnoreCase(hostname)) return new Check(false, ptr, "server.rdns.otherName");
        String fwd = lookup.apply(a instanceof java.net.Inet6Address ? "AAAA" : "A", ptr);
        if (!DnsRecordsGenerator.containsAddress(fwd, ip)) return new Check(false, ptr, "server.rdns.notBack");
        return new Check(true, ptr, null);
    }

    /** The first name in a dig +short output, without the trailing dot; null if there is none. */
    static String firstName(String out) {
        if (out == null) return null;
        for (String line : out.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith(";")) continue;
            if (t.endsWith(".")) t = t.substring(0, t.length() - 1);
            return t.matches("[A-Za-z0-9.-]{1,253}") ? t.toLowerCase(Locale.ROOT) : null;
        }
        return null;
    }

    private static InetAddress literal(String s) {
        if (s == null || !s.matches("[0-9A-Fa-f:.]{2,45}")) return null;
        try {
            return InetAddress.ofLiteral(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
