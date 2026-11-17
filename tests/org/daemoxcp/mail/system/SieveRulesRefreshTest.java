package org.daemoxcp.mail.system;

import org.daemoxcp.mail.integration.SieveGenerator;
import org.daemoxcp.mail.integration.SieveGeneratorTest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The panel's Sieve rules already written are written again from the database when what the panel writes changed
 * (reperto 229: move and copy now create a missing folder, fileinto :create).
 *
 * <p>With a fake store of rule files and the real generator on fake database rows:
 * <ul>
 *   <li>a file written before reperto 229 (no "mailbox", no :create) is written again, once; the second run writes
 *       nothing;</li>
 *   <li>a file already as the panel writes it now: nothing;</li>
 *   <li>a file that is not the panel's (another require line, a script written by hand): left as it is;</li>
 *   <li>no file but rules in the database (a write refused before, reperto 223): written; no file and no rules:
 *       nothing;</li>
 *   <li>a write that fails: counted by the mailbox's number, the others still written.</li>
 * </ul>
 * It calls nothing on the machine.
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveRulesRefreshTest
 */
public class SieveRulesRefreshTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The rule files as a map address -> text, and the rows of every mailbox. */
    static final class Store implements SieveRulesRefresh.Rules {
        final SieveGenerator generator = new SieveGenerator();
        final List<SieveRulesRefresh.Box> boxes = new ArrayList<>();
        final Map<Integer, SieveGeneratorTest.Rules> rows = new HashMap<>();
        final Map<String, String> files = new HashMap<>();
        final List<String> writes = new ArrayList<>();
        String refuse;

        void box(int id, String email, SieveGeneratorTest.Rules r, String file) {
            boxes.add(new SieveRulesRefresh.Box(id, email));
            rows.put(id, r);
            if (file != null) files.put(email, file);
        }

        @Override public List<SieveRulesRefresh.Box> mailboxes() { return boxes; }
        @Override public String generate(SieveRulesRefresh.Box b) { return generator.generateSieveScript(b.id(), rows.get(b.id())); }
        @Override public String current(SieveRulesRefresh.Box b) { return files.get(b.email()); }
        @Override public boolean write(SieveRulesRefresh.Box b, String script) {
            writes.add(b.email());
            if (b.email().equals(refuse)) return false;
            files.put(b.email(), script);
            return true;
        }
    }

    public static void main(String[] args) throws Exception {
        SieveGenerator g = new SieveGenerator();
        SieveGeneratorTest.Rules move = new SieveGeneratorTest.Rules().filter("invoices", "move", "INBOX.Invoices");
        String moveNow = g.generateSieveScript(1, move);
        String moveBefore = SieveForcedKeepTest.before229(moveNow);
        check("the text of before differs from today's (no mailbox, no :create)", !moveBefore.equals(moveNow)
                && !moveBefore.contains(":create") && moveNow.contains("fileinto :create \"INBOX.Invoices\";"));

        System.out.println("\n== What is written again");
        Store s = new Store();
        s.box(1, "alice@example.test", move, moveBefore);
        s.box(2, "bob@example.test", move, moveNow);
        s.box(3, "carol@example.test", move, "require [\"fileinto\"];\nfileinto \"Mine\";\n");
        s.box(4, "dave@example.test", move, null);
        s.box(5, "erin@example.test", new SieveGeneratorTest.Rules(), null);
        s.box(6, "frank@example.test", move, moveBefore.replace(SieveGenerator.REQUIRE_BEFORE_MAILBOX, SieveForcedKeep.REQUIRE_WITHOUT_DATE));
        SieveRulesRefresh.Outcome o = SieveRulesRefresh.refresh(s);
        check("written: the file of before, the missing one with rules, the one without date (" + s.writes + ")",
                s.writes.equals(List.of("alice@example.test", "dave@example.test", "frank@example.test")) && o.written() == 3
                        && o.notWritten().isEmpty());
        check("  alice's file is today's text", s.files.get("alice@example.test").equals(moveNow));
        check("  bob's, already today's, untouched", s.files.get("bob@example.test").equals(moveNow));
        check("  carol's, written by hand, untouched", s.files.get("carol@example.test").startsWith("require [\"fileinto\"];\nfileinto \"Mine\""));
        check("  erin has no rules and no file: still no file", !s.files.containsKey("erin@example.test"));
        s.writes.clear();
        o = SieveRulesRefresh.refresh(s);
        check("a second run writes nothing (" + s.writes + ")", s.writes.isEmpty() && o.written() == 0);

        System.out.println("\n== A write that fails");
        Store f = new Store();
        f.box(7, "gina@example.test", move, moveBefore);
        f.box(8, "hugo@example.test", move, moveBefore);
        f.refuse = "gina@example.test";
        o = SieveRulesRefresh.refresh(f);
        check("gina's refused, counted by number; hugo's written (" + o + ")", o.written() == 1 && o.notWritten().equals(List.of(7))
                && f.files.get("gina@example.test").equals(moveBefore) && f.files.get("hugo@example.test").equals(moveNow));

        System.out.println("\n== Whose script it is");
        check("today's require line, the one before mailbox, the one before date: the panel's",
                SieveRulesRefresh.panelScript(moveNow) && SieveRulesRefresh.panelScript(moveBefore)
                        && SieveRulesRefresh.panelScript(SieveForcedKeep.REQUIRE_WITHOUT_DATE + "keep;\n"));
        check("anything else, or nothing: not the panel's", !SieveRulesRefresh.panelScript("require \"fileinto\";\n")
                && !SieveRulesRefresh.panelScript(null) && !SieveRulesRefresh.panelScript(""));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
