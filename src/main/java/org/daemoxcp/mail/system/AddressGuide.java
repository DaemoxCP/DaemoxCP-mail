package org.daemoxcp.mail.system;

import java.util.ArrayList;
import java.util.List;

/**
 * The address guide: from the server's state and the goal (IPv4 and IPv6, IPv4 only, IPv6 only) the steps, in
 * order, each "done", "now", "later" or "blocked" with the reason. The panel shows the current step with ONE
 * button (guided-one-step-with-logs); the steps the administrator must do outside the panel (the reverse DNS in the
 * provider's console, the IPv4 that only the provider assigns or removes) have "Check again".
 *
 * Logic only, no commands: the facts are gathered by the caller (ServerAddresses, the DNS checks), so every
 * combination can be tested without touching a network.
 *
 * The order, chosen so as not to lose mail and not to lock anyone out:
 *  - towards IPv4 and IPv6: first each family complete (address that goes out to the internet, the provider's firewall
 *    letting IPv6 in, reverse DNS, records), then mail over both. The provider's firewall (Hetzner Cloud Firewalls and
 *    similar) cannot be seen from the server: without IPv6 open, mail over IPv6 does not arrive (senders retry over
 *    IPv4, late), so the administrator confirms it. Mail goes over IPv6 only with the IPv6 reverse DNS in place: Gmail
 *    and Microsoft reject without it.
 *  - towards IPv4 only: the panel and webmail names back to IPv4 on Cloudflare, mail IPv4 only, then
 *    the AAAA record removed, then the IPv6 address (senders over IPv6 stop trying before the address disappears).
 *  - the names with the Cloudflare proxy: with A and AAAA together Cloudflare reaches the server over IPv4 ("Cloudflare
 *    will prefer the IPv4 address", developers.cloudflare.com/network/ipv6-compatibility/). So towards IPv6 only AAAA
 *    and the A records removed, towards IPv4 only A and the AAAA records removed: otherwise the panel and the webmail
 *    can no longer be reached.
 *  - towards IPv4 and IPv6 with mail in IPv6 outgoing only (the "Mail also comes in over IPv6" box unchecked): the
 *    same steps as IPv4 and IPv6 (a single name, the mail one, with its AAAA and its reverse DNS), and at the end
 *    mail in IpFamily.IPV6_OUT: pf lets nothing in over IPv6 and answers "no" at once, so whoever tries to deliver
 *    over IPv6 falls back to IPv4 without waiting. Checking or unchecking the box changes only the last step.
 *  - towards IPv6 only: IPv6 complete, the panel and webmail names over IPv6 too, mail IPv6 only, the A record removed,
 *    then the IPv4 removed by the provider and its leftover configuration. Removing IPv4 is blocked until whoever uses
 *    the panel reaches it over IPv6 and until sshd listens on IPv6: afterwards, that would be the only way in.
 */
public final class AddressGuide {

    public enum Goal {
        BOTH("both"), V4("ipv4"), V6("ipv6"), SEND6("send6");
        public final String key;
        Goal(String key) { this.key = key; }
        public static Goal of(String k) {
            for (Goal g : values()) if (g.key.equals(k)) return g;
            return null;
        }
    }

    /**
     * What is known about the server. Null Booleans mean "unknown" (a DNS check that was not possible, for
     * example without a mail name): they count as "not done".
     */
    public record Facts(boolean v4, boolean v4Internet, boolean v4Config,
                        boolean v6, boolean v6Internet, boolean v6Firewall,
                        Boolean a, Boolean aaaa, Boolean ptr4, Boolean ptr6, Boolean webAaaa, Boolean webA,
                        IpFamily.Family mail, IpFamily.Family via, boolean sshOnV6) {}

    /** A step: id (which is also the text key), who does it ("panel" or "you"), state, reason if blocked. */
    public record Step(String id, String who, String status, String blocked) {}

    private AddressGuide() {}

    public static List<Step> plan(Facts f, Goal g) {
        List<String> ids = new ArrayList<>();
        switch (g) {
            case BOTH -> {
                ids.addAll(List.of("v4Address", "v4Ptr", "v4Dns"));
                ids.addAll(List.of("v6Address", "v6Firewall", "v6Ptr", "v6Dns"));
                ids.add("mailBoth");
            }
            case SEND6 -> {
                // As towards both: the provider's firewall must let IPv6 reach the server, which then
                // answers "no" at once (a provider firewall that keeps silent would make whoever tries IPv6 wait).
                ids.addAll(List.of("v4Address", "v4Ptr", "v4Dns", "v6Address", "v6Firewall", "v6Ptr", "v6Dns", "mailSend6"));
            }
            case V4 -> {
                ids.addAll(List.of("v4Address", "v4Ptr", "v4Dns"));
                ids.addAll(List.of("webA", "mailV4", "v6DnsRemove", "v6AddressRemove"));
            }
            case V6 -> {
                ids.addAll(List.of("v6Address", "v6Firewall", "v6Ptr", "v6Dns", "webAaaa", "mailV6"));
                ids.addAll(List.of("v4DnsRemove", "v4Provider", "v4Clean"));
            }
        }
        List<Step> out = new ArrayList<>();
        boolean nowGiven = false;
        for (String id : ids) {
            if (done(f, id)) {
                out.add(new Step(id, who(id), "done", null));
                continue;
            }
            if (nowGiven) {
                out.add(new Step(id, who(id), "next", null));
                continue;
            }
            nowGiven = true;
            String why = blocked(f, id);
            out.add(new Step(id, who(id), why == null ? "now" : "blocked", why));
        }
        return out;
    }

    /** Whether the server's state already matches the goal (all steps done). */
    public static boolean reached(List<Step> plan) {
        for (Step s : plan) if (!"done".equals(s.status())) return false;
        return true;
    }

    static String who(String id) {
        return switch (id) {
            case "v4Ptr", "v6Ptr", "v6Firewall", "v4Provider" -> "you";
            default -> "panel";
        };
    }

    static boolean done(Facts f, String id) {
        return switch (id) {
            case "v4Address" -> f.v4() && f.v4Internet();
            case "v4Ptr" -> Boolean.TRUE.equals(f.ptr4());
            case "v4Dns" -> Boolean.TRUE.equals(f.a());
            case "v6Address" -> f.v6() && f.v6Internet();
            // The server cannot see the provider's firewall from inside: the administrator confirms it, after looking
            // at it.
            case "v6Firewall" -> f.v6Firewall();
            case "v6Ptr" -> Boolean.TRUE.equals(f.ptr6());
            case "mailSend6" -> f.mail() == IpFamily.Family.IPV6_OUT;
            case "v6Dns" -> Boolean.TRUE.equals(f.aaaa());
            // Without a Cloudflare account that can see the zone this cannot be known: the guide is not blocked (null =
            // done).
            case "webAaaa" -> !Boolean.FALSE.equals(f.webAaaa());
            case "webA" -> !Boolean.FALSE.equals(f.webA());
            case "mailBoth" -> f.mail() == IpFamily.Family.BOTH;
            case "mailV4" -> f.mail() == IpFamily.Family.IPV4;
            case "mailV6" -> f.mail() == IpFamily.Family.IPV6;
            case "v6DnsRemove" -> !Boolean.TRUE.equals(f.aaaa());
            case "v6AddressRemove" -> !f.v6();
            case "v4DnsRemove" -> !Boolean.TRUE.equals(f.a());
            case "v4Provider" -> !f.v4Internet();
            case "v4Clean" -> !f.v4() && !f.v4Config();
            default -> false;
        };
    }

    /** The complete IPv6 reverse DNS: the PTR gives the mail name, and that name has the address's AAAA. */
    static boolean fcrdns6(Facts f) {
        return Boolean.TRUE.equals(f.ptr6()) && Boolean.TRUE.equals(f.aaaa());
    }

    /** Why the current step cannot be done yet (language key), or null. */
    static String blocked(Facts f, String id) {
        return switch (id) {
            // Mail over IPv6 only with the IPv6 reverse DNS forward-confirmed: the PTR gives the name (ptr6) and the
            // name has the address's AAAA (aaaa). Without it, Gmail and Microsoft reject.
            case "mailBoth" -> f.v6() && !fcrdns6(f) ? "guide.blocked.ptr6" : null;
            // IPv6 only for the panel too (pf enforces it): whoever chooses it must already reach it over IPv6.
            // Even outgoing only, mail over IPv6 needs the reverse DNS forward-confirmed.
            case "mailSend6" -> f.v6() && !fcrdns6(f) ? "guide.blocked.ptr6" : null;
            case "mailV6" -> !fcrdns6(f) ? "guide.blocked.ptr6"
                    : f.via() == IpFamily.Family.IPV4 ? "guide.blocked.viaV4" : null;
            case "mailV4" -> f.via() == IpFamily.Family.IPV6 ? "guide.blocked.viaV6" : null;
            // The family from which the administrator is using the panel is not removed.
            case "v6AddressRemove" -> f.via() == IpFamily.Family.IPV6 ? "guide.blocked.viaV6" : null;
            case "v4Provider" -> f.via() != IpFamily.Family.IPV6 ? "guide.blocked.viaV4"
                    : !f.sshOnV6() ? "guide.blocked.sshV4" : null;
            case "v4Clean" -> f.v4Internet() ? "guide.blocked.v4Works" : null;
            default -> null;
        };
    }
}
