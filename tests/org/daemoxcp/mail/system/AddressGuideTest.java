package org.daemoxcp.mail.system;

import java.util.List;

/**
 * The guide of the server's addresses (AddressGuide): from the facts and the goal, the steps in order, each done, now,
 * next or blocked. Pure logic, no network.
 *
 *  1. Towards IPv4 and IPv6 from a server with IPv4 only (the real server on 18/11/2026), one step at a time.
 *  2. Mail moves to IPv6 only with the IPv6 reverse DNS in place.
 *  3. Towards IPv4 only (the way back): web names, mail, the AAAA record, then the address; not while the panel is
 *     reached over IPv6.
 *  4. Towards IPv6 only: web names, mail (only from IPv6), the A record, the provider (only from IPv6 and with SSH on
 *     IPv6), the configuration left behind.
 *  5. A server born with IPv6 only, and from there back to both.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.AddressGuideTest
 */
public class AddressGuideTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final IpFamily.Family BOTH = IpFamily.Family.BOTH, V4 = IpFamily.Family.IPV4, V6 = IpFamily.Family.IPV6;

    /** Facts with the usual defaults; the builder methods change one thing at a time. */
    static final class F {
        boolean v4 = true, v4Internet = true, v4Config = true, v6 = false, v6Internet = false, v6Firewall = false, sshOnV6 = true;
        Boolean a = true, aaaa = false, ptr4 = true, ptr6 = null, webAaaa = null, webA = null;
        IpFamily.Family mail = V4, via = V4;

        AddressGuide.Facts build() {
            return new AddressGuide.Facts(v4, v4Internet, v4Config, v6, v6Internet, v6Firewall, a, aaaa, ptr4, ptr6, webAaaa, webA, mail, via, sshOnV6);
        }
    }

    static String now(List<AddressGuide.Step> plan) {
        for (AddressGuide.Step s : plan) if (!"done".equals(s.status())) return s.id() + "/" + s.status() + (s.blocked() == null ? "" : "/" + s.blocked());
        return "reached";
    }

    static String ids(List<AddressGuide.Step> plan) {
        StringBuilder b = new StringBuilder();
        for (AddressGuide.Step s : plan) b.append(b.length() == 0 ? "" : ",").append(s.id());
        return b.toString();
    }

    public static void main(String[] args) {
        System.out.println("== 1. Towards IPv4 and IPv6, from IPv4 only ==");
        F f = new F();
        List<AddressGuide.Step> p = AddressGuide.plan(f.build(), AddressGuide.Goal.BOTH);
        check("the steps: " + ids(p), ids(p).equals("v4Address,v4Ptr,v4Dns,v6Address,v6Firewall,v6Ptr,v6Dns,mailBoth"));
        check("IPv4 done, now the IPv6 address (" + now(p) + ")", now(p).equals("v6Address/now")
                && p.get(0).status().equals("done") && p.get(4).status().equals("next") && p.get(6).status().equals("next"));
        check("exactly one step is now", p.stream().filter(s -> s.status().equals("now") || s.status().equals("blocked")).count() == 1);
        check("the provider's firewall and the reverse DNS are the administrator's, the address the panel's",
                p.get(3).who().equals("panel") && p.get(4).who().equals("you") && p.get(5).who().equals("you") && p.get(1).who().equals("you"));
        f.v6 = true; f.v6Internet = true; f.ptr6 = false;
        check("address added: now the provider's firewall, which the server cannot see from inside (" + now(AddressGuide.plan(f.build(), AddressGuide.Goal.BOTH)) + ")",
                now(AddressGuide.plan(f.build(), AddressGuide.Goal.BOTH)).equals("v6Firewall/now"));
        f.v6Firewall = true;
        check("firewall confirmed: now the IPv6 reverse DNS", now(AddressGuide.plan(f.build(), AddressGuide.Goal.BOTH)).equals("v6Ptr/now"));
        f.v6Internet = false;
        check("an address that does not reach the internet is not done", now(AddressGuide.plan(f.build(), AddressGuide.Goal.BOTH)).equals("v6Address/now"));
        f.v6Internet = true; f.ptr6 = true;
        check("reverse DNS set: now the AAAA record", now(AddressGuide.plan(f.build(), AddressGuide.Goal.BOTH)).equals("v6Dns/now"));
        f.aaaa = true;
        check("AAAA published: now mail over both", now(AddressGuide.plan(f.build(), AddressGuide.Goal.BOTH)).equals("mailBoth/now"));
        f.mail = BOTH;
        check("mail on both: the goal is reached", AddressGuide.reached(AddressGuide.plan(f.build(), AddressGuide.Goal.BOTH)));

        System.out.println("\n== 2. Mail over IPv6 only with the IPv6 reverse DNS ==");
        F g = new F();
        g.v6 = true; g.v6Internet = true; g.ptr6 = false; g.aaaa = true;
        check("mail on both blocked without the IPv6 reverse DNS", AddressGuide.blocked(g.build(), "mailBoth").equals("guide.blocked.ptr6"));
        check("mail on IPv6 only blocked without it", AddressGuide.blocked(g.build(), "mailV6").equals("guide.blocked.ptr6"));
        g.v6 = false;
        check("no IPv6 address: mail on both is not blocked (mail does not leave over IPv6)", AddressGuide.blocked(g.build(), "mailBoth") == null);

        System.out.println("\n== 3. Towards IPv4 only (the way back) ==");
        F b = new F();
        b.v6 = true; b.v6Internet = true; b.ptr6 = true; b.aaaa = true; b.mail = BOTH;
        p = AddressGuide.plan(b.build(), AddressGuide.Goal.V4);
        check("the steps: " + ids(p), ids(p).equals("v4Address,v4Ptr,v4Dns,webA,mailV4,v6DnsRemove,v6AddressRemove"));
        check("web names not known (no Cloudflare): not a dead end, now mail over IPv4 (" + now(p) + ")", now(p).equals("mailV4/now"));
        b.webA = false;
        check("web names still on IPv6: they come first", now(AddressGuide.plan(b.build(), AddressGuide.Goal.V4)).equals("webA/now"));
        b.webA = true; b.via = V6;
        check("reaching the panel over IPv6: mail over IPv4 only is blocked",
                now(AddressGuide.plan(b.build(), AddressGuide.Goal.V4)).equals("mailV4/blocked/guide.blocked.viaV6"));
        b.via = V4; b.mail = V4;
        check("mail on IPv4: now the AAAA record goes", now(AddressGuide.plan(b.build(), AddressGuide.Goal.V4)).equals("v6DnsRemove/now"));
        b.aaaa = false;
        check("then the address", now(AddressGuide.plan(b.build(), AddressGuide.Goal.V4)).equals("v6AddressRemove/now"));
        b.via = V6;
        check("not while the panel is reached over IPv6", now(AddressGuide.plan(b.build(), AddressGuide.Goal.V4)).equals("v6AddressRemove/blocked/guide.blocked.viaV6"));
        b.via = null;
        check("from an SSH tunnel (loopback): not blocked", now(AddressGuide.plan(b.build(), AddressGuide.Goal.V4)).equals("v6AddressRemove/now"));
        b.v6 = false; b.v6Internet = false;
        check("address gone: IPv4 only reached", AddressGuide.reached(AddressGuide.plan(b.build(), AddressGuide.Goal.V4)));

        System.out.println("\n== 4. Towards IPv6 only ==");
        F s = new F();
        s.v6 = true; s.v6Internet = true; s.v6Firewall = true; s.ptr6 = true; s.aaaa = true; s.mail = BOTH; s.webAaaa = false;
        p = AddressGuide.plan(s.build(), AddressGuide.Goal.V6);
        check("the steps: " + ids(p), ids(p).equals("v6Address,v6Firewall,v6Ptr,v6Dns,webAaaa,mailV6,v4DnsRemove,v4Provider,v4Clean"));
        check("first the web names over IPv6", now(p).equals("webAaaa/now"));
        s.webAaaa = true;
        check("mail over IPv6 only blocked while the panel is reached over IPv4",
                now(AddressGuide.plan(s.build(), AddressGuide.Goal.V6)).equals("mailV6/blocked/guide.blocked.viaV4"));
        s.via = V6;
        check("from IPv6: mail over IPv6 only is now", now(AddressGuide.plan(s.build(), AddressGuide.Goal.V6)).equals("mailV6/now"));
        s.mail = V6;
        check("then the A record goes", now(AddressGuide.plan(s.build(), AddressGuide.Goal.V6)).equals("v4DnsRemove/now"));
        s.a = false; s.sshOnV6 = false;
        check("the provider step is blocked if SSH does not answer over IPv6",
                now(AddressGuide.plan(s.build(), AddressGuide.Goal.V6)).equals("v4Provider/blocked/guide.blocked.sshV4"));
        s.sshOnV6 = true; s.via = V4;
        check("and if the panel is reached over IPv4", now(AddressGuide.plan(s.build(), AddressGuide.Goal.V6)).equals("v4Provider/blocked/guide.blocked.viaV4"));
        s.via = V6;
        p = AddressGuide.plan(s.build(), AddressGuide.Goal.V6);
        check("otherwise it is the administrator's step at the provider", now(p).equals("v4Provider/now") && p.get(7).who().equals("you"));
        s.v4Internet = false;
        check("IPv4 removed by the provider, its configuration still there: now the clean-up",
                now(AddressGuide.plan(s.build(), AddressGuide.Goal.V6)).equals("v4Clean/now"));
        s.v4 = false; s.v4Config = false;
        check("cleaned: IPv6 only reached", AddressGuide.reached(AddressGuide.plan(s.build(), AddressGuide.Goal.V6)));

        System.out.println("\n== 5. A server born with IPv6 only, and back to both ==");
        F n = new F();
        n.v4 = false; n.v4Internet = false; n.v4Config = false; n.a = false; n.ptr4 = null;
        n.v6 = true; n.v6Internet = true; n.v6Firewall = true; n.ptr6 = true; n.aaaa = true; n.mail = V6; n.via = V6; n.webAaaa = true;
        check("IPv6 only is already reached", AddressGuide.reached(AddressGuide.plan(n.build(), AddressGuide.Goal.V6)));
        p = AddressGuide.plan(n.build(), AddressGuide.Goal.BOTH);
        check("towards both: first IPv4 from the provider and DHCP (" + now(p) + ")", now(p).equals("v4Address/now") && p.get(0).who().equals("panel"));
        n.v4 = true; n.v4Internet = true; n.v4Config = true;
        check("then its reverse DNS", now(AddressGuide.plan(n.build(), AddressGuide.Goal.BOTH)).equals("v4Ptr/now"));
        n.ptr4 = true;
        check("then the A record", now(AddressGuide.plan(n.build(), AddressGuide.Goal.BOTH)).equals("v4Dns/now"));
        n.a = true;
        check("then mail over both", now(AddressGuide.plan(n.build(), AddressGuide.Goal.BOTH)).equals("mailBoth/now"));

        System.out.println("\n== The goals ==");
        check("the saved values", AddressGuide.Goal.of("both") == AddressGuide.Goal.BOTH && AddressGuide.Goal.of("ipv4") == AddressGuide.Goal.V4
                && AddressGuide.Goal.of("ipv6") == AddressGuide.Goal.V6 && AddressGuide.Goal.of("v6") == null && AddressGuide.Goal.of(null) == null);

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
