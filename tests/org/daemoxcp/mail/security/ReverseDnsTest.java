package org.daemoxcp.mail.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The reverse DNS of an address, IPv4 or IPv6, confirmed forward (ReverseDns), and the pure parts of the A/AAAA records
 * on Cloudflare (HostRecords). The check before (checkPtrAndFcrdns) always looked for an A record, so for an IPv6 it
 * could never pass; Gmail and Microsoft require it for mail over IPv6.
 *
 *  1. IPv4 and IPv6, with dig answered by a fake: the PTR must give the mail name, the name must point back with A for
 *     IPv4 and AAAA for IPv6.
 *  2. Another name, no PTR, a name that does not point back, bad input: refused with the reason.
 *  3. HostRecords: the names it accepts, the records of the same name and type.
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

    /** A fake DNS: the reverse and forward answers of a test zone. */
    static void dns(Map<String, String> answers) {
        asked.clear();
        ReverseDns.dig = args -> {
            String q = String.join(" ", args);
            asked.add(q);
            return answers.getOrDefault(q, "");
        };
    }

    public static void main(String[] args) {
        System.out.println("== 1. IPv4 and IPv6 ==");
        dns(Map.of("dig +short -x 192.0.2.10", "mail.example.org.",
                "dig +short A mail.example.org", "192.0.2.10",
                "dig +short -x 2001:db8::1", "mail.example.org.",
                "dig +short AAAA mail.example.org", "2001:db8:0:0:0:0:0:1"));
        ReverseDns.Check c4 = ReverseDns.check("192.0.2.10", "mail.example.org");
        check("IPv4: the PTR gives the name, the name points back (A)", c4.ok() && "mail.example.org".equals(c4.ptr()) && c4.reason() == null
                && asked.contains("dig +short A mail.example.org"));
        asked.clear();
        ReverseDns.Check c6 = ReverseDns.check("2001:db8::1", "MAIL.example.org");
        check("IPv6: confirmed with AAAA, not A (and the name in any case, the address in any form)", c6.ok()
                && asked.contains("dig +short AAAA mail.example.org") && !asked.contains("dig +short A mail.example.org"));

        System.out.println("\n== 2. When it is not right ==");
        dns(Map.of("dig +short -x 2001:db8::1", "static.1.0.0.0.example-provider.net."));
        ReverseDns.Check other = ReverseDns.check("2001:db8::1", "mail.example.org");
        check("the provider's default name: another name (" + other.ptr() + ")", !other.ok() && "server.rdns.otherName".equals(other.reason())
                && "static.1.0.0.0.example-provider.net".equals(other.ptr()));
        dns(Map.of());
        check("no PTR at all", "server.rdns.none".equals(ReverseDns.check("2001:db8::1", "mail.example.org").reason()));
        dns(Map.of("dig +short -x 2001:db8::1", "mail.example.org.", "dig +short AAAA mail.example.org", "2001:db8::99"));
        check("the name points elsewhere: not confirmed", "server.rdns.notBack".equals(ReverseDns.check("2001:db8::1", "mail.example.org").reason()));
        dns(Map.of("dig +short -x 2001:db8::1", ";; connection timed out; no servers could be reached"));
        check("dig's own error lines are not a name", "server.rdns.none".equals(ReverseDns.check("2001:db8::1", "mail.example.org").reason()));
        check("not an address, or a name with other characters: refused before dig",
                "server.rdns.noIp".equals(ReverseDns.check("2001:db8::1; reboot", "mail.example.org").reason())
                        && "server.rdns.noHost".equals(ReverseDns.check("2001:db8::1", "mail.example.org; reboot").reason()));

        System.out.println("\n== 3. HostRecords ==");
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

    static CloudflareManager.DnsRecordInfo record(String type, String name, String content) {
        CloudflareManager.DnsRecordInfo r = new CloudflareManager.DnsRecordInfo();
        r.type = type;
        r.name = name;
        r.content = content;
        return r;
    }
}
