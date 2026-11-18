package org.daemoxcp.mail.webserver;

import org.daemoxcp.mail.i18n.I18n;

/**
 * The two rules of a catch-all in the alias API (SSLMailServer): what a catch-all source is, and a destination that
 * would send the mail back to the catch-all itself. Without a database or Postfix; the rule that Postfix must have the
 * mailbox map is in MailboxAddressMapTest, the real deliveries in catch-all-browser-test.js.
 *
 * It runs anywhere:
 *   java -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.webserver.CatchAllTest
 */
public class CatchAllTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) {
        I18n.setCurrent("en");
        System.out.println("== A catch-all source ==");
        check("@ and a domain", SSLMailServer.validCatchAllSource("@example.test") && SSLMailServer.validCatchAllSource("@mail.example.test"));
        boolean refused = true;
        for (String bad : new String[]{"@", "example.test", "x@example.test", "@@example.test", "@exa mple.test",
                "@example.test;", "@-example.test", "@" + "a".repeat(254) + ".test", null})
            if (SSLMailServer.validCatchAllSource(bad)) { refused = false; System.out.println("    accepted: " + bad); }
        check("refused: no domain, a name before the @, two @, spaces, symbols, too long, null", refused);

        System.out.println("\n== Its destination ==");
        check("a mailbox of the same domain that receives: fine", SSLMailServer.catchAllLoop("@example.test", "inbox@example.test", true) == null);
        check("an address of another domain: fine", SSLMailServer.catchAllLoop("@example.test", "owner@example.net", false) == null);
        String loop = SSLMailServer.catchAllLoop("@example.test", "nobody@example.test", false);
        check("an address of the same domain that is not a mailbox that receives: refused, saying why (" + loop + ")",
                loop != null && loop.contains("nobody@example.test") && loop.contains("come back to the catch-all"));
        check("a subdomain is another domain", SSLMailServer.catchAllLoop("@example.test", "x@mail.example.test", false) == null);

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
