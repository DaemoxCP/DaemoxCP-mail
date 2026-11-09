package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * "Update everything" (reperto 207): what may start, and when a step's plan, worked out again when its turn comes, may
 * still run. Each step is the job of always (the patches, the other packages, a mail server package or family,
 * Roundcube, the panel's Java last), tested elsewhere; here only the two rules of the chain:
 *  - the steps the page sends: in the fixed order, each kind once (the packages one per family), valid names and
 *    signatures, valid changes shown in the confirmation;
 *  - a plan whose signature is not the one read runs only inside the chain, and only if every change it makes was shown
 *    in the confirmation, at the same version, with nothing removed or downgraded. On the real server postfix-mysql's
 *    plan included lmdb, which the other packages update first: with the signature alone the step would stop.
 *
 * Usage (from the project root, after mvn package):
 *   javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/system/EverythingTest.java
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.EverythingTest
 */
public class EverythingTest {

    private static int failed = 0;

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    private static final String SIG = "0123456789abcdef";

    private static UpdateManager.EverythingStep step(String kind, String name, String sig) {
        return new UpdateManager.EverythingStep(kind, name, sig);
    }

    private static boolean starts(List<UpdateManager.EverythingStep> steps, Map<String, String> approved) {
        return UpdateManager.everythingProblem(steps, approved) == null;
    }

    private static JSONObject plan(String... changes) {
        JSONArray a = new JSONArray();
        for (String c : changes) {
            String[] f = c.split(" ");
            a.put(new JSONObject().put("type", f[0]).put("name", f[1]).put("from", f.length > 3 ? f[3] : "").put("to", f[2]));
        }
        return new JSONObject().put("measured", true).put("changes", a);
    }

    public static void main(String[] args) {
        Map<String, String> shown = new HashMap<>(Map.of("lmdb", "1.0.3,1", "postfix-mysql", "3.11.7_5,1", "nginx", "1.30.6_10,3",
                "pcre2", "10.47_2", "php84", "8.4.27_2", "php84-ctype", "8.4.27_2"));
        System.out.println("== What may start ==");
        List<UpdateManager.EverythingStep> real = List.of(step("os", "", ""), step("plain", "", SIG), step("package", "nginx", SIG),
                step("package", "php84", SIG), step("package", "postfix-mysql", SIG), step("roundcube", "", SIG), step("java", "", SIG));
        check("the real server's: patches, the other packages, three mail server steps, Roundcube, Java", starts(real, shown));
        check("one step alone", starts(List.of(step("package", "nginx", SIG)), shown));
        check("a package step without a signature: held only by a package an earlier step updates, checked at its turn",
                starts(List.of(step("package", "mysql84-client", SIG), step("package", "postfix-mysql", "")), shown));
        check("nothing approved is fine when the steps change nothing yet (only the patches)", starts(List.of(step("os", "", "")), Map.of()));

        System.out.println("\n== What does not ==");
        check("no step, or missing lists", !starts(List.of(), shown) && !starts(null, shown) && !starts(real, null));
        check("out of order: Java before Roundcube, packages before the patches",
                !starts(List.of(step("java", "", SIG), step("roundcube", "", SIG)), shown)
                && !starts(List.of(step("package", "nginx", SIG), step("os", "", "")), shown));
        check("a kind twice (the other packages twice), or one not known",
                !starts(List.of(step("plain", "", SIG), step("plain", "", SIG)), shown) && !starts(List.of(step("shell", "", SIG)), shown));
        check("the same family twice: php84 and php84-ctype are one step",
                !starts(List.of(step("package", "php84", SIG), step("package", "php84-ctype", SIG)), shown));
        check("a signature that is not one, or a name with a dash first (an option of pkg)",
                !starts(List.of(step("package", "nginx", "abc")), shown) && !starts(List.of(step("package", "-r", SIG)), shown)
                && !starts(List.of(step("roundcube", "", "")), shown));
        check("the patches with a name or a signature", !starts(List.of(step("os", "x", "")), shown));
        Map<String, String> badVersion = new HashMap<>(shown);
        badVersion.put("nginx", "1.30;rm");
        check("a change shown with a version that is not one", !starts(List.of(step("package", "nginx", SIG)), badVersion));
        List<UpdateManager.EverythingStep> many = new ArrayList<>();
        for (int i = 0; i < 31; i++) many.add(step("package", "p" + i, SIG));
        check("more than 30 steps", !starts(many, shown));

        System.out.println("\n== A plan worked out again: within what was shown ==");
        JSONObject postfix = plan("upgrade postfix-mysql 3.11.7_5,1 3.11.7_1,1");
        check("the signature read: runs, as always", UpdateManager.planAccepted(SIG, SIG, postfix));
        check("another signature outside the chain: does not run (as before)", !UpdateManager.planAccepted(SIG, "ffffffffffffffff", postfix));
        UpdateManager.APPROVED_CHANGES.set(shown);
        try {
            check("inside the chain, postfix-mysql without lmdb (done by the step before): runs",
                    UpdateManager.planAccepted(SIG, "ffffffffffffffff", postfix));
            check("  a package that was not shown: does not run",
                    !UpdateManager.planAccepted(SIG, "ffffffffffffffff", plan("upgrade postfix-mysql 3.11.7_5,1", "install mysql97-client 9.7.2")));
            check("  a version other than the one shown: does not run",
                    !UpdateManager.planAccepted(SIG, "ffffffffffffffff", plan("upgrade nginx 1.30.6_11,3")));
            check("  a removal or a downgrade, even of a package shown: does not run",
                    !UpdateManager.planAccepted(SIG, "ffffffffffffffff", plan("remove lmdb 1.0.3,1"))
                    && !UpdateManager.planAccepted(SIG, "ffffffffffffffff", plan("downgrade nginx 1.30.6_10,3")));
            check("  a reinstall of a package shown: runs (its dependencies changed)",
                    UpdateManager.planAccepted(SIG, "ffffffffffffffff", plan("reinstall php84 8.4.27_2")));
            check("  a plan that could not be measured: does not run",
                    !UpdateManager.planAccepted(SIG, "ffffffffffffffff", new JSONObject().put("measured", false).put("changes", new JSONArray())));
        } finally {
            UpdateManager.APPROVED_CHANGES.remove();
        }
        check("after the chain, outside it again: does not run", !UpdateManager.planAccepted(SIG, "ffffffffffffffff", postfix));
        check("a step checked at its turn (no signature) runs inside the chain only within what was shown",
                !UpdateManager.planAccepted("", "ffffffffffffffff", postfix));

        System.out.println("\n== What was not shown, said by name (reperto 208) ==");
        // The real server: postfix-mysql waited for mysql84-client; at its turn its plan also installed lmdb0.
        JSONObject withLmdb0 = plan("install lmdb0 0.9.36_1", "upgrade postfix-mysql 3.11.7_5,1 3.11.7_1,1");
        java.util.List<String> outside = UpdateManager.outsideApproved(withLmdb0, shown);
        check("the new library not shown is named: " + outside, outside.size() == 1 && outside.get(0).contains("lmdb0") && outside.get(0).contains("0.9.36_1")
                && !UpdateManager.withinApproved(withLmdb0, shown));
        Map<String, String> withIt = new HashMap<>(shown);
        withIt.put("lmdb0", "0.9.36_1");
        check("  shown in the confirmation: nothing outside, it runs", UpdateManager.outsideApproved(withLmdb0, withIt).isEmpty()
                && UpdateManager.withinApproved(withLmdb0, withIt));
        check("  a version other than the one shown is named too, a removal as well",
                UpdateManager.outsideApproved(plan("upgrade nginx 1.30.6_11,3", "remove lmdb 1.0.3,1"), shown).size() == 2);
        // What the step says when it stops, and what its log says (the real server's case, with its fingerprint).
        org.mail_panel.i18n.I18n.setCurrent("en");
        try {
            JobJournal.dir = java.nio.file.Files.createTempDirectory("everything-test").resolve("jobs");
        } catch (java.io.IOException e) { throw new RuntimeException(e); }
        UpdateManager.Job job = new UpdateManager.Job("all-9", "update_everything");
        String why;
        UpdateManager.APPROVED_CHANGES.set(shown);
        try { why = UpdateManager.planRefused(job, withLmdb0, "", "ff78b7795ec38548", "server.um.runGuidedUpdate.2"); }
        finally { UpdateManager.APPROVED_CHANGES.remove(); }
        String log = job.toJson().getString("consoleLog");
        System.out.println("    " + why + "\n    " + log.trim().replace("\n", "\n    "));
        check("  the reason names it and says nothing of the step was done", why.contains("lmdb0") && why.contains("nothing of this step was done")
                && !why.contains("Prepare"));
        check("  the log has the plan as it is now and the line not shown", log.contains("what pkg would do now:") && log.contains("install lmdb0")
                && log.contains("not in what the confirmation showed: install lmdb0"));
        UpdateManager.Job alone = new UpdateManager.Job("guid-9", "guided_update");
        String whyAlone = UpdateManager.planRefused(alone, withLmdb0, "0123456789abcdef", "ff78b7795ec38548", "server.um.runGuidedUpdate.2");
        check("  outside the chain: «the plan has changed», with the plan in the log, and no button that is not there any more",
                whyAlone.startsWith("The plan has changed since you read it") && !whyAlone.contains("Prepare")
                && alone.toJson().getString("consoleLog").contains("install lmdb0"));

        System.out.println("\n== A service that takes a while to start ==");
        // MySQL 8.4.11 -> 8.4.13 on the VM: «not running» right after the restart, running a few seconds later.
        int[] asked = {0};
        long t0 = System.currentTimeMillis();
        check("up at the third look: it is up (asked 3 times)", UpdateManager.waitUntil(5, 50, () -> ++asked[0] >= 3) && asked[0] == 3);
        check("never up: no, after the time given and not long after", !UpdateManager.waitUntil(1, 100, () -> false)
                && System.currentTimeMillis() - t0 < 4000);

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
