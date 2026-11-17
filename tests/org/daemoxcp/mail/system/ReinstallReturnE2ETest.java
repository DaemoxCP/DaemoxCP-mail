package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Going back to the server before a reinstallation without losing the mail that arrived after it
 * (ReinstallReturn, reperto 169), with real bectl, without restarting.
 *
 * A test mailbox in /var/vmail with five "old" messages and a Dovecot file; the reinstallation's
 * way back; then what a reinstallation does: the five deleted, three new messages arrived later,
 * the Dovecot file changed. The way back:
 *  - in the way back there are the five old ones AND the three new ones;
 *  - the Dovecot file is the one of back then (a file already there is not overwritten);
 *  - the way back is the one of the next start (bectl: R);
 *  - mail stopped until the restart (Postfix and Dovecot off, as it must be);
 *  - the refusals: a name that is not a reinstallation's, one that is no longer there; and there
 *    the mail stays up.
 * Then everything put back: the current boot environment again for the next start, the way back
 * removed, the test mailbox removed, mail on again. ONLY on a test clone, -De2e.vm=yes, root.
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.ReinstallReturnE2ETest
 */
public class ReinstallReturnE2ETest {

    static int failed = 0;
    static final Path PROBE = Path.of("/var/vmail/e2e-way-back.test/probe");

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(600), cmd).outputTrim();
    }

    static boolean up(String svc) {
        return Shell.runShell(Duration.ofSeconds(30), "service " + svc + " status").success();
    }

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("SKIPPED: it needs -De2e.vm=yes (a test clone on the FreeBSD VM, as root).");
            System.exit(0);
        }
        for (String n : sh("bectl list -H | cut -f1").split("\n"))
            if (PackageWayBack.REINSTALL_OWN.matcher(n.trim()).matches()) {
                System.out.println("STOPPED: there is already a reinstallation way back (" + n.trim() + ").");
                System.exit(2);
            }
        if (!PackageWayBack.dataInside().contains("/var/vmail")) {
            System.out.println("STOPPED: /var/vmail is not in the boot environment, there is nothing to merge here.");
            System.exit(2);
        }
        I18n.setCurrent("en");
        String running = "";
        for (String line : sh("bectl list -H").split("\n")) {
            String[] f = line.split("\t");
            if (f.length >= 2 && f[1].contains("N")) running = f[0].trim();
        }
        String nextBoot = "";
        for (String line : sh("bectl list -H").split("\n")) {
            String[] f = line.split("\t");
            if (f.length >= 2 && (f[1].contains("R") || f[1].contains("T"))) nextBoot = f[0].trim();
        }
        System.out.println("in use: " + running + ", at the next start: " + nextBoot);
        List<String> log = new ArrayList<>();
        String name = "";
        try {
            for (String sub : List.of("cur", "new", "tmp")) Files.createDirectories(PROBE.resolve(sub));
            for (int i = 1; i <= 5; i++)
                Files.writeString(PROBE.resolve("cur/1700000000.M" + i + "P1.e2e:2,S"), "From: test\nSubject: from before " + i + "\n\nold message\n");
            Files.writeString(PROBE.resolve("dovecot-uidlist"), "3 V1 N6 from before\n");
            sh("chown -R vmail:vmail /var/vmail/e2e-way-back.test 2>/dev/null");

            PackageWayBack.Prepared p = PackageWayBack.beforeInstallation(log::add);
            name = p.name();
            check("the reinstallation's way back is there: " + name, PackageWayBack.REINSTALL_OWN.matcher(name).matches());

            // What a reinstallation does, and the mail that arrives after it.
            for (int i = 1; i <= 5; i++) Files.delete(PROBE.resolve("cur/1700000000.M" + i + "P1.e2e:2,S"));
            for (int i = 1; i <= 3; i++)
                Files.writeString(PROBE.resolve("new/1800000000.M" + i + "P2.e2e"), "From: test\nSubject: arrived after " + i + "\n\nnew message\n");
            Files.writeString(PROBE.resolve("dovecot-uidlist"), "3 V2 N1 from after\n");
            // Like a real delivery: the new messages belong to vmail (before the fix they were root's,
            // and the owners check could not pass).
            sh("chown -R vmail:vmail /var/vmail/e2e-way-back.test 2>/dev/null");

            System.out.println("\n== The refusals ==");
            boolean postfixUp = up("postfix");
            JSONObject r = ReinstallReturn.goBack("packages-before-2026-11-06-120000-e2e", log::add);
            check("a name that is not a reinstallation's", !r.optBoolean("success") && r.optString("error").contains("not the way back of a complete reinstallation"));
            r = ReinstallReturn.goBack("reinstall-before-2000-01-01-000000", log::add);
            check("one that is no longer there", !r.optBoolean("success") && r.optString("error").contains("not there any more"));
            check("and the mail stays as it was", up("postfix") == postfixUp);

            System.out.println("\n== The way back ==");
            log.clear();
            r = ReinstallReturn.goBack(name, log::add);
            for (String l : log) System.out.println("      | " + l);
            check("succeeded", r.optBoolean("success"));
            check("and it says how many files it added (at least the three new ones): " + r.optInt("merged"), r.optInt("merged") >= 3);
            String state = "";
            for (String line : sh("bectl list -H").split("\n")) {
                String[] f = line.split("\t");
                if (f.length >= 2 && f[0].trim().equals(name)) state = f[1].trim();
            }
            check("the way back is the one of the next start (" + state + ")", state.contains("R"));
            check("mail is stopped until the restart", !up("postfix") && !up("dovecot"));
            Path mnt = Files.createTempDirectory(Path.of("/var/tmp"), "e2e-way-back-check");
            check("it is mounted to look inside", Shell.runShell(Duration.ofSeconds(120), "bectl mount " + name + " " + mnt).success());
            Path inside = Path.of(mnt + PROBE.toString());
            int oldOnes = 0, newOnes = 0;
            for (int i = 1; i <= 5; i++) if (Files.exists(inside.resolve("cur/1700000000.M" + i + "P1.e2e:2,S"))) oldOnes++;
            for (int i = 1; i <= 3; i++) if (Files.exists(inside.resolve("new/1800000000.M" + i + "P2.e2e"))) newOnes++;
            check("inside there are the five old messages", oldOnes == 5);
            check("and the three that arrived later", newOnes == 3);
            check("the Dovecot file is the one of back then", Files.readString(inside.resolve("dovecot-uidlist")).contains("from before"));
            check("owner and permissions kept", sh("stat -f %Su " + inside.resolve("new/1800000000.M1P2.e2e")).equals("vmail")
                    || sh("id vmail >/dev/null 2>&1 || echo nouser").equals("nouser"));
            Shell.runShell(Duration.ofSeconds(120), "bectl umount " + name);
            Files.deleteIfExists(mnt);
        } finally {
            // Putting back. bectl activate PROMOTES a clone: after the way back the way back owns the
            // snapshot and the boot environment in use depends on it. So: first the one in use is
            // activated again (it owns its snapshot again), then the way back is removed (now it is a
            // leaf), then the next start goes back to the old one, which is not a clone and is not promoted.
            if (!name.isEmpty() && !running.isEmpty()) System.out.println("      | " + sh("bectl activate " + running + " 2>&1"));
            if (!name.isEmpty()) System.out.println("      | way back removed: " + (PackageWayBack.destroy(name) == null));
            if (!nextBoot.isEmpty()) System.out.println("      | " + sh("bectl activate " + nextBoot + " 2>&1"));
            sh("rm -rf /var/vmail/e2e-way-back.test");
            sh("service dovecot start >/dev/null 2>&1; service postfix start >/dev/null 2>&1");
        }
        check("at the end: mail up again, the test mailbox removed", up("postfix") && up("dovecot") && !Files.exists(PROBE));
        String after = "";
        for (String line : sh("bectl list -H").split("\n")) {
            String[] f = line.split("\t");
            if (f.length >= 2 && f[1].contains("R")) after = f[0].trim();
        }
        check("the next start is " + nextBoot + " again", after.equals(nextBoot) || nextBoot.isEmpty());
        check("no way back left", !sh("bectl list -H | cut -f1").contains("reinstall-before-"));
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
