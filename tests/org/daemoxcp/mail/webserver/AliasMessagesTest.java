package org.daemoxcp.mail.webserver;

import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.i18n.I18n;

import java.util.ArrayList;
import java.util.List;

/**
 * What the panel says after creating, editing, turning off or deleting an alias.
 *
 * Postfix reads only the aliases with active=1 and applies them before the mailboxes. Since an
 * alias can be turned off, "there is the mailbox -> mailbox line" no longer means "the mailbox keeps
 * a copy": the old logic looked at the line and not at whether it was active, and kept quiet
 * exactly in the case where the mailbox had stopped receiving.
 *
 * The panel's messages are read in English (I18n.setCurrent): outside a request it writes Italian.
 */
public class AliasMessagesTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static MailDatabase.Alias alias(String source, String destination, boolean active) {
        MailDatabase.Alias a = new MailDatabase.Alias();
        a.source = source;
        a.destination = destination;
        a.active = active;
        return a;
    }

    static List<MailDatabase.Alias> table(MailDatabase.Alias... lines) {
        return new ArrayList<>(List.of(lines));
    }

    static String note(String address, boolean mailbox, List<MailDatabase.Alias> lines) {
        return SSLMailServer.afterAliases(address, mailbox, lines);
    }

    /** The old logic (creation only): a mailbox -> mailbox line was enough, active or not. */
    static boolean oldWarned(String source, boolean mailbox, List<MailDatabase.Alias> lines) {
        boolean copyInMailbox = false;
        for (MailDatabase.Alias a : lines)
            if (a.source.equals(source) && a.destination.equals(source)) copyInMailbox = true;
        return mailbox && !copyInMailbox;
    }

    public static void main(String[] x) {
        I18n.setCurrent("en");
        String io = "info@domain-a.test", outside = "report@domain-b.test", other = "owner@domain-b.test";

        System.out.println("\n== a mailbox ==");
        require("without aliases it receives: nothing to say", note(io, true, table()) == null);
        require("with only \"itself -> itself\" it receives: nothing to say",
                note(io, true, table(alias(io, io, true))) == null);
        require("forwarded but with the copy active: nothing to say",
                note(io, true, table(alias(io, outside, true), alias(io, io, true))) == null);
        require("with the forward turned off it receives again: nothing to say",
                note(io, true, table(alias(io, outside, false))) == null);

        String n = note(io, true, table(alias(io, outside, true)));
        require("forwarded without a copy: it says so", n != null && n.contains("only goes to " + outside));
        require("  and it says to ADD the copy, which is not there", n != null && n.contains("add the alias " + io + " -> " + io));

        n = note(io, true, table(alias(io, outside, true), alias(io, other, true)));
        require("with two destinations it names both", n != null && n.contains("only goes to " + outside + ", " + other));

        n = note(io, true, table(alias(io, outside, true), alias(io, io, false)));
        require("copy TURNED OFF: the mailbox does not receive, and it says so", n != null && n.contains("only goes to " + outside));
        require("  and it says to TURN IT BACK ON: adding it would give \"Alias already exists\"",
                n != null && n.contains("turn the alias " + io + " -> " + io + " back on"));

        require("the aliases of another address of the same domain do not count",
                note(io, true, table(alias("sales@domain-a.test", outside, true))) == null);

        System.out.println("\n== an address that is not a mailbox ==");
        String onlyOne = "dmarc@domain-a.test";
        require("with an active alias it exists: nothing to say", note(onlyOne, false, table(alias(onlyOne, outside, true))) == null);
        n = note(onlyOne, false, table(alias(onlyOne, outside, false)));
        require("with its only alias turned off the mail is refused, and it says so", n != null && n.contains("is refused"));
        require("after deleting the last alias, the same", note(onlyOne, false, table()) != null);
        require("another alias still active keeps it alive",
                note(onlyOne, false, table(alias(onlyOne, outside, false), alias(onlyOne, other, true))) == null);
        require("an ACTIVE catch-all of the domain collects its mail: no refusal",
                note(onlyOne, false, table(alias(onlyOne, outside, false), alias("@domain-a.test", other, true))) == null);
        require("a catch-all turned off collects nothing",
                note(onlyOne, false, table(alias("@domain-a.test", other, false))) != null);
        require("the comparison is exact: xdmarc@... does not keep dmarc@... alive",
                note(onlyOne, false, table(alias("x" + onlyOne, outside, true))) != null);
        require("a source without @ (an old line) breaks nothing",
                note("postmaster", false, table(alias("postmaster", outside, true))) == null);

        System.out.println("\n== and the old logic kept quiet exactly here ==");
        List<MailDatabase.Alias> copyOff = table(alias(io, outside, true), alias(io, io, false));
        require("the old logic did NOT warn with the copy turned off (if one day it warns, this test no longer tells them apart)",
                !oldWarned(io, true, copyOff));
        require("the new one does", note(io, true, copyOff) != null);

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }
}
