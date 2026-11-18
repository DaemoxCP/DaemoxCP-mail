package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.FullMailServerScript;
import org.daemoxcp.mail.scripts.FullMailStackScript;
import org.daemoxcp.mail.scripts.PostfixMaps;

import java.util.List;

/**
 * The Postfix map that makes a catch-all safe (MailboxAddressMap): every mailbox maps to itself, after the aliases.
 * Here the decisions, without Postfix: when the start adds the map, when it leaves Postfix alone, the map's text made
 * from the aliases' map, when a catch-all can be created, and that both installers write the map in the right place.
 * The real deliveries are in catch-all-browser-test.js, on the test machine.
 *
 * It runs anywhere:
 *   java -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.system.MailboxAddressMapTest
 */
public class MailboxAddressMapTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String DIR = "/usr/local/etc/postfix";
    static final String ALIASES = "mysql:" + DIR + "/mysql-virtual-aliases.cf";
    static final String OWN = "mysql:" + DIR + "/mysql-virtual-mailbox-addresses.cf";

    public static void main(String[] args) {
        System.out.println("== What the start does ==");
        MailboxAddressMap.Decision d = MailboxAddressMap.decide(true, DIR, ALIASES, true);
        check("only the aliases: adds the map after them (" + d.newValue() + ")",
                d.action() == MailboxAddressMap.Action.ADD && (ALIASES + ", " + OWN).equals(d.newValue()));
        check("in place but the file says something else (an older query): rewritten, main.cf untouched",
                MailboxAddressMap.decide(true, DIR, ALIASES + ", " + OWN, true, false).action() == MailboxAddressMap.Action.REWRITE
                        && MailboxAddressMap.decide(true, DIR, ALIASES + ", " + OWN, true, false).newValue() == null);
        check("already in place, with commas or spaces: nothing",
                MailboxAddressMap.decide(true, DIR, ALIASES + ", " + OWN, true).action() == MailboxAddressMap.Action.NOTHING
                        && MailboxAddressMap.decide(true, DIR, ALIASES + "  " + OWN, true).action() == MailboxAddressMap.Action.NOTHING);
        check("a list written by hand: left alone, and it says so",
                MailboxAddressMap.decide(true, DIR, ALIASES + ", hash:" + DIR + "/virtual", true).action() == MailboxAddressMap.Action.LEFT_ALONE
                        && MailboxAddressMap.decide(true, DIR, OWN + ", " + ALIASES, true).action() == MailboxAddressMap.Action.LEFT_ALONE
                        && MailboxAddressMap.decide(true, DIR, "", true).action() == MailboxAddressMap.Action.LEFT_ALONE);
        check("no Postfix, or not the panel's (no aliases map): nothing",
                MailboxAddressMap.decide(false, "", "", false).action() == MailboxAddressMap.Action.NOTHING
                        && MailboxAddressMap.decide(true, DIR, ALIASES, false).action() == MailboxAddressMap.Action.NOTHING);

        System.out.println("\n== The map's text, from the aliases' map ==");
        String aliases = "user = daemoxcp_mail_postfix\npassword = secret-value\nhosts = 127.0.0.1\ndbname = daemoxcp_mail\n"
                + "query = SELECT destination FROM aliases WHERE source='%s' AND active=1\n";
        String text = MailboxAddressMap.mapText(aliases);
        check("the same connection, the new query", ("user = daemoxcp_mail_postfix\npassword = secret-value\nhosts = 127.0.0.1\n"
                + "dbname = daemoxcp_mail\nquery = " + PostfixMaps.MAILBOX_ADDRESSES_QUERY + "\n").equals(text));
        check("without a final newline it still ends with one line", MailboxAddressMap.mapText(aliases.strip()) != null
                && MailboxAddressMap.mapText(aliases.strip()).endsWith("receive_enabled=1\n"));
        check("no query line, or two: not the panel's file, null",
                MailboxAddressMap.mapText("user = x\nhosts = 127.0.0.1\n") == null
                        && MailboxAddressMap.mapText(aliases + "query = SELECT 1\n") == null && MailboxAddressMap.mapText(null) == null);
        // Postfix takes as valid every address it finds in virtual_alias_maps: a mailbox that does not receive must not be
        // there, or it would accept mail from outside even without a catch-all (measured on the VM).
        check("only the mailboxes that receive, as virtual_mailbox_maps",
                PostfixMaps.MAILBOX_ADDRESSES_QUERY.equals("SELECT email FROM mailboxes WHERE email='%s' AND active=1 AND receive_enabled=1"));

        System.out.println("\n== When a catch-all can be created ==");
        check("the map after the aliases: yes", MailboxAddressMap.notReady(DIR, ALIASES + ", " + OWN) == null);
        check("without the map: no (" + MailboxAddressMap.notReady(DIR, ALIASES) + ")", MailboxAddressMap.notReady(DIR, ALIASES) != null);
        check("the map before the aliases: no, an alias of a mailbox would stop working",
                MailboxAddressMap.notReady(DIR, OWN + ", " + ALIASES) != null);
        check("more tables, the map after the aliases: yes",
                MailboxAddressMap.notReady(DIR, "hash:" + DIR + "/virtual, " + ALIASES + ", " + OWN) == null);
        check("the tables of a list", MailboxAddressMap.tables(" a, b  c,,d ").equals(List.of("a", "b", "c", "d")));

        System.out.println("\n== The installers ==");
        for (Object[] s : new Object[][]{{"full installation", new FullMailServerScript().getScriptContent()},
                {"mail stack", new FullMailStackScript().getScriptContent()}}) {
            String script = (String) s[1];
            check(s[0] + ": virtual_alias_maps has the aliases, then the mailboxes",
                    script.contains("\nvirtual_alias_maps = " + ALIASES + ", " + OWN + "\nvirtual_transport = "));
            int at = script.indexOf("cat > " + DIR + "/mysql-virtual-mailbox-addresses.cf << ");
            String block = at < 0 ? "" : script.substring(at, Math.min(script.length(), at + 400));
            check(s[0] + ": the map is written, with its query on its own line",
                    at >= 0 && block.contains("\nquery = " + PostfixMaps.MAILBOX_ADDRESSES_QUERY + "\nMYSQL"));
            check(s[0] + ": before the chown of the maps (root:postfix 0640)",
                    at >= 0 && at < script.indexOf("chown root:postfix /usr/local/etc/postfix/mysql-*.cf"));
        }
        check("MailDbUsers moves this map to Postfix's MySQL user too", MailDbUsers.POSTFIX_MAPS.contains(PostfixMaps.MAILBOX_ADDRESSES_FILE));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
