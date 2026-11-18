package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * PendingDbPassword's decisions, with a fake MySQL: a set of passwords it accepts, and a switch for
 * "does not answer". No real file: the Postfix file lives in a temporary folder
 * (PendingDbPassword.postfixMap).
 *
 * The rule under test: the panel's password changes ONLY into one MySQL accepted in front of us,
 * and a pending password is thrown away only when MySQL said no.
 *
 * Uso: java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PendingDbPasswordTest
 */
public class PendingDbPasswordTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The panel's passwords, in memory. */
    static final class FakeStore implements PendingDbPassword.Store {
        String current = "", pending = "";
        int adopts = 0;
        boolean pendingWriteFails = false;
        public String current() { return current; }
        public void adopt(String p) { current = p; adopts++; }
        public String pending() { return pending; }
        public void setPending(String p) {
            if (pendingWriteFails) throw new IllegalStateException("test: secrets file not writable");
            pending = p == null ? "" : p;
        }
    }

    /** Fake MySQL: it accepts the passwords of the set, or does not answer at all. */
    static final class FakeMysql implements PendingDbPassword.Probe {
        final Set<String> accepts = new HashSet<>();
        boolean answers = true;
        final List<String> asked = new ArrayList<>();
        FakeMysql knows(String... p) { accepts.addAll(List.of(p)); return this; }
        public PendingDbPassword.Answer ask(String p) {
            asked.add(p);
            if (!answers) return PendingDbPassword.Answer.NO_ANSWER;
            if (p == null || p.isEmpty()) return PendingDbPassword.Answer.REJECTED;
            return accepts.contains(p) ? PendingDbPassword.Answer.ACCEPTED : PendingDbPassword.Answer.REJECTED;
        }
    }

    static Path map;

    static void postfix(String user, String password) throws Exception {
        Files.writeString(map, "# written by the script\nuser = " + user + "\npassword = " + password
                + "\nhosts = 127.0.0.1\ndbname = daemoxcp_mail\nquery = SELECT domain FROM domains WHERE domain='%s' AND active=1\n");
    }

    static void noPostfix() throws Exception {
        Files.deleteIfExists(map);
    }

    public static void main(String[] args) throws Exception {
        Path d = Files.createTempDirectory("pending-db-password");
        map = d.resolve("mysql-virtual-domains.cf");
        PendingDbPassword.postfixMap = map;
        final String U = "daemoxcp_mail";

        System.out.println("== The script exits before phase 3 (Roundcube, parameter, turn, packages) ==");
        FakeStore s = new FakeStore();
        s.current = "Old1";
        FakeMysql m = new FakeMysql().knows("Old1");
        PendingDbPassword.Prepared pr = PendingDbPassword.prepare(s, m, U);
        check("before the script the panel's password does NOT change", s.current.equals("Old1") && s.adopts == 0);
        check("the new one is pending, and it is the one given to the script", !pr.password().isEmpty() && pr.password().equals(s.pending));
        check("the new one differs from the old one, 24 letters and digits", !pr.password().equals("Old1") && pr.password().matches("[A-Za-z0-9]{24}"));
        PendingDbPassword.Result r = PendingDbPassword.settle(s, m, U);
        check("MySQL does not know it: the old one is kept", r.outcome() == PendingDbPassword.Outcome.OLD_KEPT && s.current.equals("Old1"));
        check("and the new one is thrown away", s.pending.isEmpty());
        check("the message says so", !r.message().isEmpty());

        System.out.println("\n== The script fails AFTER phase 3, or succeeds ==");
        s = new FakeStore();
        s.current = "Old1";
        m = new FakeMysql().knows("Old1");
        pr = PendingDbPassword.prepare(s, m, U);
        m.accepts.clear();
        m.knows(pr.password());                       // the script gave it to MySQL
        r = PendingDbPassword.settle(s, m, U);
        check("MySQL accepts the new one: now it is the panel's", r.outcome() == PendingDbPassword.Outcome.NEW_ADOPTED && s.current.equals(pr.password()));
        check("the pending one is removed", s.pending.isEmpty());

        System.out.println("\n== MySQL does not answer after the script ==");
        s = new FakeStore();
        s.current = "Old1";
        m = new FakeMysql().knows("Old1");
        pr = PendingDbPassword.prepare(s, m, U);
        m.answers = false;
        r = PendingDbPassword.settle(s, m, U);
        check("it is not decided", r.outcome() == PendingDbPassword.Outcome.UNDECIDED);
        check("the panel's password stays the old one", s.current.equals("Old1") && s.adopts == 0);
        check("the new one stays pending", s.pending.equals(pr.password()));

        System.out.println("\n== A later installation, with MySQL still silent: it reuses the pending one ==");
        String left = s.pending;
        pr = PendingDbPassword.prepare(s, m, U);
        check("the script gets the pending one again, not a new one", pr.password().equals(left) && s.pending.equals(left));
        check("and it says so", !pr.note().isEmpty());
        check("the panel's password does not change", s.current.equals("Old1"));

        System.out.println("\n== A later installation, and MySQL knows the one left pending ==");
        s = new FakeStore();
        s.current = "Old1";
        s.pending = "Leftover1";
        m = new FakeMysql().knows("Leftover1");
        pr = PendingDbPassword.prepare(s, m, U);
        check("the one left becomes the panel's before anything else", s.current.equals("Leftover1"));
        check("and the script gets a new one, pending", !pr.password().equals("Leftover1") && s.pending.equals(pr.password()));

        System.out.println("\n== A later installation, and MySQL does not know the one left ==");
        s = new FakeStore();
        s.current = "Old1";
        s.pending = "Leftover1";
        m = new FakeMysql().knows("Old1");
        pr = PendingDbPassword.prepare(s, m, U);
        check("the old one is kept", s.current.equals("Old1"));
        check("the one left is thrown away, the script gets a new one", !pr.password().equals("Leftover1") && s.pending.equals(pr.password()));

        System.out.println("\n== The pending password cannot be written ==");
        s = new FakeStore();
        s.current = "Old1";
        s.pendingWriteFails = true;
        boolean refused = false;
        try { PendingDbPassword.prepare(s, new FakeMysql().knows("Old1"), U); }
        catch (IllegalStateException e) { refused = true; }
        check("prepare refuses (the script must not start)", refused);
        check("the panel's password does not change", s.current.equals("Old1") && s.adopts == 0);

        System.out.println("\n== Stop between the adoption and the cleanup: the two are equal ==");
        s = new FakeStore();
        s.current = "New1";
        s.pending = "New1";
        r = PendingDbPassword.settle(s, new FakeMysql().knows("New1"), U);
        check("it closes without changing anything", r.outcome() == PendingDbPassword.Outcome.NEW_ADOPTED && s.current.equals("New1") && s.pending.isEmpty());

        System.out.println("\n== MySQL refuses both, no Postfix copy ==");
        noPostfix();
        s = new FakeStore();
        s.current = "Old1";
        s.pending = "New1";
        r = PendingDbPassword.settle(s, new FakeMysql().knows("Other1"), U);
        check("none accepted", r.outcome() == PendingDbPassword.Outcome.NONE_ACCEPTED);
        check("the panel's password does not change", s.current.equals("Old1") && s.adopts == 0);
        check("the new one, refused by MySQL, is thrown away", s.pending.isEmpty());

        System.out.println("\n== MySQL refuses both, and accepts Postfix's ==");
        postfix(U, "Postfix1");
        s = new FakeStore();
        s.current = "Old1";
        s.pending = "New1";
        r = PendingDbPassword.settle(s, new FakeMysql().knows("Postfix1"), U);
        check("Postfix's becomes the panel's", r.outcome() == PendingDbPassword.Outcome.COPY_ADOPTED && s.current.equals("Postfix1"));
        check("the pending one is removed", s.pending.isEmpty());

        System.out.println("\n== Server broken by the old version: nothing pending, password refused ==");
        postfix(U, "Postfix1");
        s = new FakeStore();
        s.current = "Broken1";
        m = new FakeMysql().knows("Postfix1");
        r = PendingDbPassword.settle(s, m, U);
        check("Postfix's, which MySQL accepts, is adopted", r.outcome() == PendingDbPassword.Outcome.COPY_ADOPTED && s.current.equals("Postfix1"));
        check("and the message names the file", r.message().contains(map.toString()));

        System.out.println("\n== Postfix's copy refused too ==");
        postfix(U, "Postfix1");
        s = new FakeStore();
        s.current = "Broken1";
        r = PendingDbPassword.settle(s, new FakeMysql().knows("Other1"), U);
        check("none accepted, nothing changes", r.outcome() == PendingDbPassword.Outcome.NONE_ACCEPTED && s.current.equals("Broken1") && s.adopts == 0);

        System.out.println("\n== Postfix's copy of another user ==");
        postfix("otheruser", "Postfix1");
        s = new FakeStore();
        s.current = "Broken1";
        m = new FakeMysql().knows("Postfix1");
        r = PendingDbPassword.settle(s, m, U);
        check("it is not even looked at", r.outcome() == PendingDbPassword.Outcome.NONE_ACCEPTED && s.current.equals("Broken1") && !m.asked.contains("Postfix1"));

        System.out.println("\n== The usual case: nothing pending, password accepted ==");
        postfix(U, "Postfix1");
        s = new FakeStore();
        s.current = "Good1";
        m = new FakeMysql().knows("Good1", "Postfix1");
        r = PendingDbPassword.settle(s, m, U);
        check("nothing to do, nothing changes", r.outcome() == PendingDbPassword.Outcome.NOTHING_TO_DO && s.current.equals("Good1") && s.adopts == 0);
        check("a single question to MySQL", m.asked.equals(List.of("Good1")));
        check("nothing to say", r.message().isEmpty());

        System.out.println("\n== Panel never installed ==");
        s = new FakeStore();
        m = new FakeMysql();
        r = PendingDbPassword.settle(s, m, U);
        check("nothing to do, MySQL not asked", r.outcome() == PendingDbPassword.Outcome.NOTHING_TO_DO && m.asked.isEmpty());

        System.out.println("\n== Nothing pending, MySQL silent ==");
        s = new FakeStore();
        s.current = "Good1";
        m = new FakeMysql();
        m.answers = false;
        r = PendingDbPassword.settle(s, m, U);
        check("nothing is changed", r.outcome() == PendingDbPassword.Outcome.NOTHING_TO_DO && s.current.equals("Good1") && s.adopts == 0);

        System.out.println("\n== MySQL silent on the old one after refusing the new one ==");
        s = new FakeStore();
        s.current = "Old1";
        s.pending = "New1";
        PendingDbPassword.Probe flaky = p -> p.equals("New1") ? PendingDbPassword.Answer.REJECTED : PendingDbPassword.Answer.NO_ANSWER;
        r = PendingDbPassword.settle(s, flaky, U);
        check("it is not decided: the new one stays pending", r.outcome() == PendingDbPassword.Outcome.UNDECIDED && s.pending.equals("New1") && s.current.equals("Old1"));

        System.out.println("\n== The Postfix file ==");
        Files.writeString(map, "user=daemoxcp_mail\npassword=  Spaces1  \n#password = Comment\n");
        check("values without spaces around, comments skipped", PendingDbPassword.postfixCopy("daemoxcp_mail").equals("Spaces1"));
        Files.writeString(map, "password = Withoutuser\n");
        check("without a user: nothing", PendingDbPassword.postfixCopy("daemoxcp_mail").isEmpty());
        noPostfix();
        check("without a file: nothing", PendingDbPassword.postfixCopy("daemoxcp_mail").isEmpty());

        Files.deleteIfExists(map);
        Files.deleteIfExists(d);
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
