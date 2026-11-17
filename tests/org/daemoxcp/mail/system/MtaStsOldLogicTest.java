package org.daemoxcp.mail.system;

import java.util.ArrayList;
import java.util.List;

/**
 * The OLD logic, copied unchanged from commit 7204765, put in front of the same two cases. It
 * shows that the test's checks are not decorative: if they passed here too, they would be
 * checking nothing.
 */
public class MtaStsOldLogicTest {
    public static void main(String[] a) {
        List<MtaStsSetup.NameReview> cases = List.of(
            new MtaStsSetup.NameReview("domain-d.test", MtaStsSetup.NameState.ABSENT,
                "there is no record with this name in the zone", true),
            new MtaStsSetup.NameReview("x.it", MtaStsSetup.NameState.TO_FIX,
                "points to \"other.host\" instead of \"mail.domain-b.test\"; goes through Cloudflare", true));

        List<String> absent = new ArrayList<>(), crooked = new ArrayList<>(),
                     proxied = new ArrayList<>(), blind = new ArrayList<>(),
                     propagating = new ArrayList<>();
        for (MtaStsSetup.NameReview e : cases) {
            switch (e.state) {
                case ABSENT -> absent.add(e.domain + " (" + e.reason + ")");
                case BLIND -> blind.add(e.domain + " (" + e.reason + ")");
                case TO_FIX -> {
                    if (e.reason.contains("Cloudflare")) proxied.add(e.domain);
                    else crooked.add(e.domain + " (" + e.reason + ")");
                }
                case RIGHT -> { if (!e.resolves) propagating.add(e.domain); }
            }
        }
        System.out.println("OLD LOGIC, same two cases:");
        System.out.println("  proxied  = " + proxied);
        System.out.println("  crooked  = " + crooked);
        boolean bugA = !proxied.contains("domain-d.test (there is no record, the wildcard *.domain-d.test behind Cloudflare answers)")
                    && proxied.stream().noneMatch(s -> s.startsWith("domain-d.test"));
        boolean bugB = crooked.isEmpty();
        System.out.println("\n  domain-d.test does NOT show as going through the proxy  -> " + bugA
                         + "   (step 5 green: \"none goes through Cloudflare\")");
        System.out.println("  the record pointing ELSEWHERE does not show as crooked -> " + bugB
                         + "   (step 4 green: \"all present and right\")");
        System.out.println("\n" + ((bugA && bugB)
              ? "The two defects reproduce: the test's checks tell them apart."
              : "WARNING: the defects do NOT reproduce, the test proves nothing."));
        if (!(bugA && bugB)) System.exit(1);
    }
}
