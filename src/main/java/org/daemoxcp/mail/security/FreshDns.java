package org.daemoxcp.mail.security;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.daemoxcp.mail.util.Shell;

/**
 * A DNS question to whoever is in charge of the name: the authoritative servers of its zone, without going through
 * the cache of the server's resolver.
 *
 * <p>Why. The server has its own resolver (local_unbound) that remembers answers, negative ones too: a "no name" or
 * a "no AAAA" stays valid until the zone's negative TTL (the SOA minimum: 86400 s for Hetzner's reverse DNS, which
 * unbound shortens to one hour at most). Seen on the production server on 2026-11-19: the administrator had already
 * saved the IPv6 reverse DNS, Hetzner, Cloudflare and Google returned it, and the addresses guide still said "no
 * name" for another 12 minutes, because it had asked the resolver before it was saved. The same would have happened
 * with the AAAA record just written on Cloudflare. To know how a record that the administrator or the panel has just
 * changed stands now, ask whoever publishes it.
 *
 * <p>How. The SOA says which zone the name belongs to (even from a negative answer); its NS records say whom to ask;
 * each one is asked without recursion (+norecurse), with a short wait. If nobody answers (a network that closes
 * outbound port 53, an authoritative server that is down) the server's resolver is asked as before: a possibly
 * stale answer is better than none. The names that come from DNS (the zone, the servers) go through the same allowed
 * characters as the names the panel asks for before becoming an argument of dig; dig runs without a shell.
 */
public final class FreshDns {

    /** The types the panel asks for: nothing else reaches dig. */
    static final java.util.Set<String> TYPES = java.util.Set.of("A", "AAAA", "PTR", "MX", "TXT");
    /** A DNS name: letters, digits, dot and hyphen (reverse DNS names fit in), at most 253. */
    static final Pattern NAME = Pattern.compile("[A-Za-z0-9.-]{1,253}");
    /** The SOA line in +noall +answer +authority: the first field is the zone. */
    private static final Pattern SOA_LINE = Pattern.compile("(?m)^(\\S+)\\s+\\d+\\s+IN\\s+SOA\\s");
    /** How many servers of the zone are tried, at most. */
    static final int MAX_SERVERS = 4;

    /**
     * dig with its arguments: the output if dig got an answer (code 0), null if not (no server reached,
     * timeout). The real one, or a fake one in the tests.
     */
    static Function<String[], String> dig = args -> {
        Shell.Result r = Shell.run(Duration.ofSeconds(12), args);
        return r.success() ? r.outputTrim() : null;
    };

    private FreshDns() {}

    /**
     * The answers of that type for that name, as dig +short gives them (one per line), asked of the servers of its
     * zone; if none of them answers, of the server's resolver. Empty if the record is not there (or the name is not
     * valid).
     */
    public static String query(String type, String name) {
        if (type == null || !TYPES.contains(type) || !validName(name)) return "";
        String zone = zoneOf(name);
        if (zone != null) {
            for (String server : servers(zone)) {
                String out = dig.apply(new String[] {"dig", "+short", "+norecurse", "+time=3", "+tries=1", "@" + server, type, name});
                if (out != null && !out.contains(";;")) return out;
            }
        }
        String out = dig.apply(new String[] {"dig", "+short", type, name});
        return out == null || out.contains(";;") ? "" : out;
    }

    /** The reverse DNS name of an address: 10.2.0.192.in-addr.arpa, or the 32 nibbles reversed and ip6.arpa. */
    public static String reverseName(InetAddress a) {
        byte[] b = a.getAddress();
        StringBuilder s = new StringBuilder();
        if (a instanceof Inet4Address) {
            for (int i = 3; i >= 0; i--) s.append(b[i] & 0xff).append('.');
            return s.append("in-addr.arpa").toString();
        }
        for (int i = 15; i >= 0; i--) {
            int v = b[i] & 0xff;
            s.append(Character.forDigit(v & 0xf, 16)).append('.').append(Character.forDigit(v >> 4, 16)).append('.');
        }
        return s.append("ip6.arpa").toString();
    }

    /** The zone of the name, from the SOA the resolver returns with the answer (even a negative one); null if not known. */
    static String zoneOf(String name) {
        String out = dig.apply(new String[] {"dig", "+noall", "+answer", "+authority", "SOA", name});
        if (out == null) return null;
        Matcher m = SOA_LINE.matcher(out);
        if (!m.find()) return null;
        String zone = strip(m.group(1));
        return validName(zone) ? zone : null;
    }

    /** The authoritative servers of the zone (its NS records), at most MAX_SERVERS, valid names only. */
    static List<String> servers(String zone) {
        List<String> out = new ArrayList<>();
        String ns = dig.apply(new String[] {"dig", "+short", "NS", zone});
        if (ns == null) return out;
        for (String line : ns.split("\n")) {
            String s = strip(line.trim());
            if (validName(s) && s.contains(".") && !out.contains(s)) out.add(s);
            if (out.size() == MAX_SERVERS) break;
        }
        return out;
    }

    static boolean validName(String s) {
        return s != null && NAME.matcher(s).matches() && !s.startsWith("-") && !s.startsWith(".");
    }

    private static String strip(String s) {
        s = s.toLowerCase(Locale.ROOT);
        return s.endsWith(".") ? s.substring(0, s.length() - 1) : s;
    }
}
