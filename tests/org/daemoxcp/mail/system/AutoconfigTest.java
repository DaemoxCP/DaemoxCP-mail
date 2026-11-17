package org.daemoxcp.mail.system;

/** The Autoconfig card's verdict: the row that declared a served file not served. */
public class AutoconfigTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) {
        System.out.println("\n== ready(listRead, examined, working) ==");

        require("five domains out of five: ready",
                Autoconfig.ready(true, 5, 5));
        require("four out of five is NOT enough: a domain is left to configure by hand",
                !Autoconfig.ready(true, 5, 4));
        require("zero out of five: not ready",
                !Autoconfig.ready(true, 5, 0));

        // "0 == 0" is true, and without the condition examined>0 the panel would say green
        // exactly when it looked at nothing. It is the quietest false green.
        require("ZERO domains tried is not green, even if 0 out of 0 'add up'",
                !Autoconfig.ready(true, 0, 0));

        // If the list of domains could not be read, nothing was tried: "I did not check" is
        // not "it is fine".
        require("list not read: not ready, whatever the counts say",
                !Autoconfig.ready(false, 5, 5));
        require("list not read and zero tries: not ready",
                !Autoconfig.ready(false, 0, 0));

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }
}
