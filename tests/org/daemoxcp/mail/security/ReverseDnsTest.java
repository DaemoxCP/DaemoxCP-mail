package org.daemoxcp.mail.security;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The reverse DNS of an address, IPv4 or IPv6, confirmed forward (ReverseDns), and the pure parts of the A/AAAA records
 * on Cloudflare (HostRecords). The check before (checkPtrAndFcrdns) always looked for an A record, so for an IPv6 it
 * could never pass; Gmail and Microsoft require it for mail over IPv6.
 *
 *  1. IPv4 and IPv6, with the DNS answered by a fake: the PTR must give the mail name, the name must point back with A
 *     for IPv4 and AAAA for IPv6.
 *  2. Another name, no PTR, a name that does not point back, bad input: refused with the reason. The guide's reverse
 *     DNS step only needs the name (givesName): the AAAA is written by the panel AFTER it, so requiring it there
 *     stopped the guide for good on the real server.
 *  3. FreshDns: the question goes to the zone's own servers (found through its SOA and NS), not to the server's
 *     resolver, which remembers a «no name» for up to an hour (seen on the real server: 12 more minutes of «no name»
 *     after the reverse DNS was saved). Timeouts, odd server names, the fallback.
 *  4. HostRecords: the names it accepts, the records of the same name and type.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.ReverseDnsTest
 */
public class ReverseDnsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final List<String> asked = new ArrayList<>();

    /** The reverse names of the two test addresses, written by hand (FreshDns.reverseName must give the same). */
    static final String R4 = "10.2.0.192.in-addr.arpa";
    static final String R6 = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";

    /** A fake DNS: the answers of a test zone, by "TYPE name". */
    static void dns(Map<String, String> answers) {
        asked.clear();
        ReverseDns.lookup = (type, name) -> {
            String q = type + " " + name;
            asked.add(q);
            return answers.getOrDefault(q, "");
        };
    }

    public static void main(String[] args) {
        System.out.println("== 1. IPv4 and IPv6 ==");
        dns(Map.of("PTR " + R4, "mail.example.org.",
                "A mail.example.org", "192.0.2.10",
                "PTR " + R6, "mail.example.org.",
                "AAAA mail.example.org", "2001:db8:0:0:0:0:0:1"));
        ReverseDns.Check c4 = ReverseDns.check("192.0.2.10", "mail.example.org");
        check("IPv4: the PTR gives the name, the name points back (A)", c4.ok() && "mail.example.org".equals(c4.ptr()) && c4.reason() == null
                && asked.contains("PTR " + R4) && asked.contains("A mail.example.org"));
        asked.clear();
        ReverseDns.Check c6 = ReverseDns.check("2001:db8::1", "MAIL.example.org");
        check("IPv6: confirmed with AAAA, not A (and the name in any case, the address in any form)", c6.ok()
                && asked.contains("PTR " + R6) && asked.contains("AAAA mail.example.org") && !asked.contains("A mail.example.org"));

        System.out.println("\n== 2. When it is not right ==");
        dns(Map.of("PTR " + R6, "static.1.0.0.0.example-provider.net."));
        ReverseDns.Check other = ReverseDns.check("2001:db8::1", "mail.example.org");
        check("the provider's default name: another name (" + other.ptr() + "), and not the guide's step either",
                !other.ok() && "server.rdns.otherName".equals(other.reason())
                && "static.1.0.0.0.example-provider.net".equals(other.ptr()) && !other.givesName());
        dns(Map.of());
        ReverseDns.Check none = ReverseDns.check("2001:db8::1", "mail.example.org");
        check("no PTR at all", "server.rdns.none".equals(none.reason()) && !none.givesName());
        dns(Map.of("PTR " + R6, "mail.example.org.", "AAAA mail.example.org", "2001:db8::99"));
        check("the name points elsewhere: not confirmed", "server.rdns.notBack".equals(ReverseDns.check("2001:db8::1", "mail.example.org").reason()));
        dns(Map.of("PTR " + R6, "mail.example.org."));
        ReverseDns.Check early = ReverseDns.check("2001:db8::1", "mail.example.org");
        check("the PTR gives the mail name, no AAAA yet: not confirmed, but the guide's reverse DNS step is done (the AAAA is the next one)",
                !early.ok() && "server.rdns.notBack".equals(early.reason()) && early.givesName());
        dns(Map.of("PTR " + R6, ";; connection timed out; no servers could be reached"));
        check("dig's own error lines are not a name", "server.rdns.none".equals(ReverseDns.check("2001:db8::1", "mail.example.org").reason()));
        check("not an address, or a name with other characters: refused before dig",
                "server.rdns.noIp".equals(ReverseDns.check("2001:db8::1; reboot", "mail.example.org").reason())
                        && "server.rdns.noHost".equals(ReverseDns.check("2001:db8::1", "mail.example.org; reboot").reason()));

        System.out.println("\n== 3. FreshDns: the zone's own servers ==");
        check("the reverse names: " + R4 + " and the 32 nibbles of an IPv6",
                FreshDns.reverseName(InetAddress.ofLiteral("192.0.2.10")).equals(R4) && FreshDns.reverseName(InetAddress.ofLiteral("2001:db8::1")).equals(R6));
        String zone6 = "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
        String soa = "dig +noall +answer +authority SOA " + R6, ns = "dig +short NS " + zone6, local = "dig +short PTR " + R6;
        String at1 = "dig +short +norecurse +time=3 +tries=1 @ns1.example-dns.net PTR " + R6;
        String at2 = "dig +short +norecurse +time=3 +tries=1 @ns2.example-dns.net PTR " + R6;
        Map<String, String> net = new HashMap<>();
        net.put(soa, zone6 + ". 3600 IN SOA ns1.example-dns.net. hostmaster.example-dns.net. 1 7200 3600 1209600 86400");
        net.put(ns, "ns1.example-dns.net.\nns2.example-dns.net.");
        net.put(at1, "mail.example.org.");
        net.put(at2, "mail.example.org.");
        net.put(local, "");   // the server's resolver still remembers «no name»
        String out = fresh(net, "PTR", R6);
        check("the PTR asked to the zone's first server, without recursion: the name, not the remembered «no name»",
                out.equals("mail.example.org.") && digs.contains(at1) && !digs.contains(local));
        net.put(at1, null);   // the first server does not answer
        out = fresh(net, "PTR", R6);
        check("the first server does not answer: the second one", out.equals("mail.example.org.") && digs.contains(at1) && digs.contains(at2) && !digs.contains(local));
        net.put(at2, ";; connection timed out; no servers could be reached");
        net.put(local, "mail.example.org.");
        out = fresh(net, "PTR", R6);
        check("no server of the zone answers (port 53 closed outward): the server's resolver, as before", out.equals("mail.example.org.") && digs.contains(local));
        net.put(at1, "");
        out = fresh(net, "PTR", R6);
        check("the zone's server says there is no record: that is the answer, the resolver is not asked", out.isEmpty() && !digs.contains(local));
        net.put(ns, "ns1.example-dns.net.\nevil;reboot.example.\n-x.example.");
        net.put(at1, null);
        out = fresh(net, "PTR", R6);
        check("a server name from the DNS with other characters never reaches dig", digs.stream().noneMatch(d -> d.contains("evil") || d.contains("@-x")));
        net.put(soa, ";; no SOA");
        net.put(local, "mail.example.org.");
        out = fresh(net, "PTR", R6);
        check("no zone found: the server's resolver", out.equals("mail.example.org.") && digs.size() == 2);
        boolean quiet = true;
        for (String[] q : new String[][] {{"ANY", "example.org"}, {"A", "example.org; reboot"}, {"A", "-x.example.org"}, {null, "example.org"}})
            quiet &= fresh(net, q[0], q[1]).isEmpty() && digs.isEmpty();
        check("a type the panel never asks, or a name with other characters: nothing reaches dig", quiet);

        System.out.println("\n== 4. HostRecords ==");

        check("names it accepts", HostRecords.validHost("mail.example.org") && HostRecords.validHost("panel.mail.example.org")
                && !HostRecords.validHost("localhost") && !HostRecords.validHost("-bad.example.org") && !HostRecords.validHost("a b.example.org")
                && !HostRecords.validHost(null));
        List<CloudflareManager.DnsRecordInfo> zone = new ArrayList<>();
        zone.add(record("A", "mail.example.org", "192.0.2.10"));
        zone.add(record("AAAA", "Mail.Example.org", "2001:db8::1"));
        zone.add(record("AAAA", "webmail.example.org", "2001:db8::1"));
        zone.add(record("TXT", "mail.example.org", "v=spf1 mx -all"));
        check("the records of the same name and type, whatever the case",
                HostRecords.sameName(zone, "mail.example.org", "AAAA").size() == 1 && HostRecords.sameName(zone, "mail.example.org", "A").size() == 1
                        && HostRecords.sameName(zone, "mail.example.org", "MX").isEmpty() && HostRecords.sameName(null, "x.example.org", "A").isEmpty());

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    static final List<String> digs = new ArrayList<>();

    /** FreshDns.query with dig answered by a fake network: a missing entry is an empty answer, null no answer. */
    static String fresh(Map<String, String> net, String type, String name) {
        digs.clear();
        FreshDns.dig = a -> {
            String q = String.join(" ", a);
            digs.add(q);
            return net.containsKey(q) ? net.get(q) : "";
        };
        return FreshDns.query(type, name);
    }

    static CloudflareManager.DnsRecordInfo record(String type, String name, String content) {
        CloudflareManager.DnsRecordInfo r = new CloudflareManager.DnsRecordInfo();
        r.type = type;
        r.name = name;
        r.content = content;
        return r;
    }
}
