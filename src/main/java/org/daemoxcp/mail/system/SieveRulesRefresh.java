package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.integration.SieveGenerator;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * The panel's Sieve rules already written, rewritten from the database as the panel writes them now (finding
 * 229).
 *
 * <p>When what SieveGenerator writes changed, the rules already on the servers stayed as they were until
 * someone saved the mailbox again. With finding 229 "Move" and "Copy" create the folder that does not exist
 * (fileinto :create): without this step a filter written earlier towards a new folder would have kept moving
 * nothing.
 *
 * <p>At the start of the root part, after SieveRulesOwner, MailSpoolSticky, SieveStorage and SieveForcedKeep:
 * for every mailbox in the database the text is generated as it is now and compared with the file. It is
 * written only if:
 * <ul>
 *   <li>the file exists, starts with one of the require lines the panel wrote (it is the panel's, not a
 *       hand-made script) and is different;</li>
 *   <li>or the file does not exist and the mailbox has rules in the database (a write refused earlier,
 *       finding 223).</li>
 * </ul>
 * The write is the one of SieveGenerator.saveSieveScript: RootOnlyPath, compiled with sievec. At the second
 * startup the texts are equal and nothing is written. In the log the mailboxes with their number, never the
 * address.
 */
public final class SieveRulesRefresh {

    private static final Logger LOGGER = Logger.getLogger(SieveRulesRefresh.class.getName());

    private SieveRulesRefresh() {}

    /** A mailbox: the number (for the log) and the address (for the path). */
    record Box(int id, String email) {}

    /** What is needed, to test it without MySQL or /var/mail. */
    interface Rules {
        List<Box> mailboxes() throws Exception;
        /** The text the panel would write now for the mailbox. */
        String generate(Box b);
        /** The file as it is, null if it is not there. */
        String current(Box b);
        /** Writes and compiles; false if it was not written (the reason is in the writer's log). */
        boolean write(Box b, String script);
    }

    /** How many mailboxes rewritten and which not (the numbers). */
    record Outcome(int written, List<Integer> notWritten) {}

    /** The require lines the panel wrote, newest first: a script that starts like that is the panel's. */
    static boolean panelScript(String script) {
        if (script == null) return false;
        return script.startsWith(SieveGenerator.REQUIRE) || script.startsWith(SieveGenerator.REQUIRE_BEFORE_MAILBOX)
                || script.startsWith(SieveForcedKeep.REQUIRE_WITHOUT_DATE);
    }

    /** Pure with respect to {@link Rules}. */
    static Outcome refresh(Rules r) throws Exception {
        int written = 0;
        List<Integer> failed = new ArrayList<>();
        for (Box b : r.mailboxes()) {
            String now = r.generate(b);
            if (now == null) continue;
            String cur = r.current(b);
            boolean write;
            if (cur == null) write = !now.equals(SieveGenerator.REQUIRE);   // rules in the database, file missing
            else write = panelScript(cur) && !cur.equals(now);
            if (!write) continue;
            if (r.write(b, now)) written++;
            else failed.add(b.id());
        }
        return new Outcome(written, failed);
    }

    /** At the start of the root part, with the server's generator. */
    public static void ensureAtBoot(SieveGenerator generator) {
        try {
            MailDatabase db = Main.mailDatabase;
            if (generator == null || db == null || !Main.mysqlAvailable) return;
            Outcome o = refresh(new Rules() {
                @Override public List<Box> mailboxes() throws Exception {
                    List<Box> out = new ArrayList<>();
                    for (MailDatabase.Mailbox m : db.getAllMailboxes()) out.add(new Box(m.id, m.email));
                    return out;
                }
                @Override public String generate(Box b) { return generator.generateSieveScript(b.id(), db); }
                @Override public String current(Box b) { return generator.getSieveScript(b.email()); }
                @Override public boolean write(Box b, String script) { return generator.saveSieveScript(b.email(), script); }
            });
            if (o.written() > 0)
                LOGGER.info("[SieveRulesRefresh] DONE: " + o.written() + " Sieve rule file(s) of the panel written again from the"
                        + " database as the panel writes them now (move and copy create a folder that is not there yet)");
            if (!o.notWritten().isEmpty())
                LOGGER.warning("[SieveRulesRefresh] the rules of mailbox(es) #" + o.notWritten() + " were not written again:"
                        + " they keep the earlier text; the reason is in the lines of SieveGenerator above");
        } catch (Throwable t) {
            LOGGER.warning("[SieveRulesRefresh] failed: " + t);
        }
    }
}
