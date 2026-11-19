package org.daemoxcp.mail.security;

import java.util.List;
import java.util.Map;

/**
 * The server's IPv6 in the domains' SPF (SpfIp6), for mail over IPv6 only going out: the mail name has no AAAA, so
 * «mx» no longer covers the IPv6 and the SPF needs «ip6:». Only the panel's own form is rewritten; an SPF written by hand
 * is left alone and reported.
 *
 *  1. The panel's form: «v=spf1 [ip4:...] [ip6:...] mx -all», any case; anything else is not the panel's.
 *  2. Adding and removing the ip6 (replacing an old one), nothing to do when it is already so.
 *  3. Whether an SPF authorises an address: exact, inside a prefix, «+», and never «-», «~», «?».
 *  4. The state of several domains, with the DNS answered by a fake: covered, not covered, two SPF, none.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.SpfIp6Test
 */
public class SpfIp6Test {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String V6 = "2a01:4f8:1c1f:b920::1";

    public static void main(String[] args) {
        System.out.println("== 1. The panel's form ==");
        check("ip4 and mx, ip4 ip6 and mx, ip6 only, mx only: the panel's",
                SpfIp6.isPanelForm("v=spf1 ip4:203.0.113.10 mx -all") && SpfIp6.isPanelForm("v=spf1 ip4:203.0.113.10 ip6:" + V6 + " mx -all")
                        && SpfIp6.isPanelForm("v=spf1 ip6:" + V6 + " mx -all") && SpfIp6.isPanelForm("v=spf1 mx -all"));
        check("the same in capitals and with more spaces", SpfIp6.isPanelForm("V=SPF1  IP4:203.0.113.10   MX -ALL"));
        check("written by hand: an include, ~all, another mechanism, another order",
                !SpfIp6.isPanelForm("v=spf1 include:_spf.example.net ~all") && !SpfIp6.isPanelForm("v=spf1 ip4:203.0.113.10 mx ~all")
                        && !SpfIp6.isPanelForm("v=spf1 ip4:203.0.113.10 a mx -all") && !SpfIp6.isPanelForm("v=spf1 ip6:" + V6 + " ip4:203.0.113.10 mx -all")
                        && !SpfIp6.isPanelForm("") && !SpfIp6.isPanelForm(null));

        System.out.println("\n== 2. Adding and removing the ip6 ==");
        check("added after the ip4", ("v=spf1 ip4:203.0.113.10 ip6:" + V6 + " mx -all").equals(SpfIp6.withIp6("v=spf1 ip4:203.0.113.10 mx -all", V6)));
        check("already there: nothing to do", SpfIp6.withIp6("v=spf1 ip4:203.0.113.10 ip6:" + V6 + " mx -all", V6) == null);
        check("an old ip6 replaced", ("v=spf1 ip4:203.0.113.10 ip6:" + V6 + " mx -all")
                .equals(SpfIp6.withIp6("v=spf1 ip4:203.0.113.10 ip6:2a01:4f8:1c1f:aaaa::1 mx -all", V6)));
        check("written by hand, or not an address: not touched", SpfIp6.withIp6("v=spf1 include:_spf.example.net ~all", V6) == null
                && SpfIp6.withIp6("v=spf1 mx -all", "203.0.113.10") == null && SpfIp6.withIp6("v=spf1 mx -all", "::1; rm") == null);
        check("removed", "v=spf1 ip4:203.0.113.10 mx -all".equals(SpfIp6.withoutIp6("v=spf1 ip4:203.0.113.10 ip6:" + V6 + " mx -all")));
        check("nothing to remove, or written by hand: null", SpfIp6.withoutIp6("v=spf1 ip4:203.0.113.10 mx -all") == null
                && SpfIp6.withoutIp6("v=spf1 ip6:" + V6 + " include:_spf.example.net -all") == null);
        check("the panel's ip6 seen (for the way back)", SpfIp6.hasPanelIp6("v=spf1 ip4:203.0.113.10 ip6:" + V6 + " mx -all")
                && !SpfIp6.hasPanelIp6("v=spf1 ip4:203.0.113.10 mx -all") && !SpfIp6.hasPanelIp6("v=spf1 ip6:" + V6 + " include:x.example ~all"));

        System.out.println("\n== 3. Whether it authorises the address ==");
        check("exact, also written in full", SpfIp6.covers("v=spf1 ip6:" + V6 + " mx -all", V6)
                && SpfIp6.covers("v=spf1 ip6:2a01:04f8:1c1f:b920:0000:0000:0000:0001 -all", V6));
        check("inside a /64, with +", SpfIp6.covers("v=spf1 ip6:2a01:4f8:1c1f:b920::/64 -all", V6) && SpfIp6.covers("v=spf1 +ip6:" + V6 + " -all", V6));
        check("another /64, or another address: no", !SpfIp6.covers("v=spf1 ip6:2a01:4f8:1c1f:b921::/64 -all", V6)
                && !SpfIp6.covers("v=spf1 ip6:2a01:4f8:1c1f:b920::2 -all", V6));
        check("-ip6, ~ip6, ?ip6 do not authorise; mx alone not either (no AAAA on the mail name)",
                !SpfIp6.covers("v=spf1 -ip6:" + V6 + " +all", V6) && !SpfIp6.covers("v=spf1 ~ip6:" + V6 + " -all", V6)
                        && !SpfIp6.covers("v=spf1 ?ip6:" + V6 + " -all", V6) && !SpfIp6.covers("v=spf1 ip4:203.0.113.10 mx -all", V6));
        check("broken lengths and addresses do not authorise", !SpfIp6.covers("v=spf1 ip6:2a01:4f8::/x -all", V6)
                && !SpfIp6.covers("v=spf1 ip6:2a01:4f8::/200 -all", V6) && !SpfIp6.covers("v=spf1 ip6:zz::1 -all", V6)
                && !SpfIp6.covers("v=spf1 ip6:" + V6 + " -all", "") && !SpfIp6.covers(null, V6));

        System.out.println("\n== 4. The domains' state ==");
        Map<String, String> txt = Map.of(
                "one.example", "\"v=spf1 ip4:203.0.113.10 ip6:" + V6 + " mx -all\"\n\"google-site-verification=abc\"",
                "two.example", "\"v=spf1 ip4:203.0.113.10 mx -all\"",
                "three.example", "\"v=spf1 mx -all\"\n\"v=spf1 ip4:203.0.113.10 -all\"",
                "four.example", "");
        SpfIp6.Status st = SpfIp6.status(List.of("one.example", "two.example", "three.example", "four.example"), d -> txt.getOrDefault(d, ""), V6);
        check("not all covered: " + st.uncovered(), !st.allCovered() && st.uncovered().equals(List.of("two.example", "three.example", "four.example")));
        check("the panel's ip6 is in one of them (the way back has something to remove)", st.anyPanelIp6());
        SpfIp6.Status good = SpfIp6.status(List.of("one.example"), d -> txt.getOrDefault(d, ""), V6);
        check("all covered", good.allCovered() && good.uncovered().isEmpty());
        check("no domain at all: not «all covered»", !SpfIp6.status(List.of(), d -> "", V6).allCovered());
        SpfIp6.Status none = SpfIp6.status(List.of("two.example"), d -> txt.getOrDefault(d, ""), V6);
        check("no panel ip6 anywhere: nothing to remove", !none.anyPanelIp6());

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
