package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

/**
 * The move to Dovecot 2.4 going back by itself (finding 213), end to end on the VM.
 *
 * The move itself is proven from the page (dovecot24-move-browser-test.js). Here the way back: the job runs for real,
 * replaces the packages and writes the 2.4 configuration, and then a problem the test adds after the tests on 2.4
 * (UpdateManager.dovecot24ProblemsForTest, the same place where a failed test or a lost port would stop it) makes it
 * put 2.3 back. Afterwards:
 *   1. the job ended in error, saying 2.3 is back and the mail passes the tests of before, and naming the problem;
 *   2. the packages are those of before, at the same versions (the dependencies brought only for 2.4 gone), and the
 *      same ones protected;
 *   3. the configuration is the one of before, file by file; the refused 2.4 configuration is in the copy;
 *   4. Dovecot runs and listens where it did; the log has the tests again on 2.3, all passing;
 *   5. no list of unlocked packages left;
 *   6. the panel's Sieve rules compiled by Pigeonhole on each side: once on 2.4, once more on 2.3 (finding 241).
 * The job runs connected to MySQL, as in the panel's root part: without it MailDbUsers leaves Dovecot on the panel's
 * MySQL user and that is a second problem the test did not add (seen on 2026-11-16): the error must name only the
 * test's problem.
 *
 * It touches the system. Only on the test VM with Dovecot 2.3, as root, with -De2e.vm=yes, from the panel's folder:
 *   cd /home/panel && java -De2e.vm=yes -cp "<tests>:<panel jar>" org.daemoxcp.mail.system.Dovecot24MoveE2ETest
 * The job's log goes to /var/tmp/dovecot24-move-back.log; the boot environment the job makes stays (its way back).
 */
public class Dovecot24MoveE2ETest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("Without -De2e.vm=yes this test does nothing: it changes packages.");
            return;
        }
        if (!sh("id -u").trim().equals("0")) { System.out.println("Root is needed."); System.exit(2); }
        I18n.setCurrent("en");
        org.daemoxcp.mail.Main.dbManager = org.daemoxcp.mail.sqli.dataBaseManager.readOnly();
        java.lang.reflect.Method connect = org.daemoxcp.mail.Main.class.getDeclaredMethod("connectFromConfig");
        connect.setAccessible(true);
        String noMysql = (String) connect.invoke(null);
        if (noMysql != null) { System.out.println("MySQL: " + noMysql); System.exit(2); }
        if (!ok("pkg info -e dovecot-mysql")) { System.out.println("Dovecot 2.3 (dovecot-mysql) is needed."); System.exit(2); }

        System.out.println("== The checks and the plan ==");
        JSONObject pf = UpdateManager.dovecot24Preflight();
        JSONArray checks = pf.optJSONArray("checks");
        for (int i = 0; checks != null && i < checks.length(); i++) {
            JSONObject c = checks.getJSONObject(i);
            System.out.println("  [" + c.optString("level") + "] " + c.optString("label") + ": " + c.optString("detail"));
        }
        check("the job can start", pf.optBoolean("canProceed"));
        if (!pf.optBoolean("canProceed")) { end(); return; }

        String packagesBefore = inventory(), configBefore = config(), portsBefore = ports();
        Set<String> lockedBefore = locked();

        System.out.println("\n== The move, with a problem after the tests on 2.4 ==");
        UpdateManager.dovecot24ProblemsForTest = () -> List.of("Problem added by Dovecot24MoveE2ETest.");
        JSONObject started = UpdateManager.startDovecot24Move(pf.optString("signature"));
        JSONObject job = waitJob(started.optString("jobId"));
        UpdateManager.dovecot24ProblemsForTest = null;
        String log = job == null ? "" : job.optString("consoleLog");
        Files.writeString(Path.of("/var/tmp/dovecot24-move-back.log"), log);
        for (String l : log.split("\n"))
            if (l.matches(".*(\\[[0-9]/8\\]|  ok  |  NO  |Putting Dovecot|configuration is back|mail tests again|Protecting).*")) System.out.println("  | " + l);
        String error = job == null ? String.valueOf(started) : job.optString("errorMessage");
        System.out.println("  outcome: " + (job == null ? "-" : job.optString("status")) + ": " + error);

        check("1 the job ended in error", job != null && "error".equals(job.optString("status")));
        check("1   saying 2.3 is back and passes the tests of before, naming the problem",
                error.contains("The panel put 2.3 back from the copy, and the mail passes the tests of before")
                && error.contains("Problem added by Dovecot24MoveE2ETest."));
        check("1   the only problem is the one the test added",
                error.startsWith("Dovecot 2.4 did not pass: Problem added by Dovecot24MoveE2ETest. The panel put 2.3 back"));
        check("1   it really got to 2.4 first (packages replaced, configuration written, tests on 2.4)",
                log.contains("[5/8]") && log.contains("[7/8]") && log.contains("doveconf accepts the configuration"));
        check("2 the packages of before, at the same versions", inventory().equals(packagesBefore));
        check("2 the same ones protected", locked().equals(lockedBefore));
        check("3 the configuration of before, file by file", config().equals(configBefore));
        String copy = sh("ls -d /var/db/daemoxcp-mail/dovecot24/* 2>/dev/null | tail -1").trim();
        check("3 the refused 2.4 configuration kept in the copy (" + copy + ")",
                !copy.isEmpty() && ok("grep -q dovecot_config_version " + copy + "/etc-2.4-refused/dovecot.conf")
                && sh("stat -f %Lp " + copy).trim().equals("700"));
        check("4 Dovecot runs, listening where it did", ok("service dovecot status") && ports().equals(portsBefore));
        String again = log.contains("The mail tests again, on 2.3:") ? log.substring(log.indexOf("The mail tests again, on 2.3:")) : "";
        check("4 the tests again on 2.3, all passing", again.contains("ok  IMAP login on 993") && again.contains("ok  doveconf -n")
                && !again.contains("  NO  "));
        check("5 no list of unlocked packages left", !PackageQueue.statePresent());
        int compiledLines = log.split("Sieve rules of the panel compiled by the Pigeonhole installed now", -1).length - 1;
        check("6 the panel's Sieve rules compiled on 2.4 and again on 2.3 (" + compiledLines + " lines)", compiledLines == 2);
        end();
    }

    static JSONObject waitJob(String id) throws Exception {
        if (id == null || id.isEmpty()) return null;
        long deadline = System.currentTimeMillis() + 1_800_000;
        Thread.sleep(500);
        while (PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject s = UpdateManager.jobStatus(id);
        return s.optBoolean("success") ? s.getJSONObject("job") : null;
    }

    /** Every installed package with its version. */
    static String inventory() { return sh("pkg query %n-%v | sort"); }

    /** Every file of Dovecot's configuration with its checksum, owner and mode. */
    static String config() {
        return sh("cd /usr/local/etc/dovecot && find . -type f | sort | while read f; do echo \"$f $(sha256 -q \"$f\") $(stat -f '%Su:%Sg %Lp' \"$f\")\"; done");
    }

    static String ports() {
        return String.join(",", MailProbes.dovecotListeners(sh("sockstat -46lq -P tcp")));
    }

    static Set<String> locked() {
        Set<String> r = new TreeSet<>();
        for (String l : sh("pkg lock -l 2>/dev/null").split("\n"))
            if (!l.trim().isEmpty() && !l.trim().endsWith(":")) r.add(l.trim().replaceAll("-[^-]+$", ""));
        return r;
    }

    static boolean ok(String cmd) { return Shell.runShell(Duration.ofSeconds(60), cmd + " >/dev/null 2>&1").success(); }

    static String sh(String cmd) { return Shell.runShell(Duration.ofSeconds(600), cmd).output(); }

    static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }

    static void end() {
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }
}
