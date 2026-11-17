package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * The three dedicated package jobs, end to end on the machine, under the signed plan.
 *
 * The Roundcube update, the Python transition and the MySQL 8.4 migration ran pkg without the
 * guarantees of the guided update: no exact plan approved by whoever presses, no inventory before
 * and after. Now they compute the plan on a copy of pkg's database (for the two jobs that remove
 * packages first, the copy forgets what pkg delete will remove), the page shows it with its
 * fingerprint, the job recomputes it at the start and after downloading, and at the end every line
 * of the plan is checked against the inventory.
 *
 * Each mode needs the machine prepared by tests/signed-jobs-setup.sh with the same mode:
 *   roundcube  Roundcube recorded one version behind the catalog, so pkg upgrades it
 *   python     py311-build installed by request and protected, py312 the default
 *   mysql84    mysql80-server and mysql80-client with the data of the 8.4 loaded back
 *
 * For every mode, in this order:
 *   1. the checks and the plan: measured, with a fingerprint, the job can start
 *   2. without a fingerprint the job does not start
 *   3. with a fingerprint that is not the plan's, the job starts and refuses BEFORE touching
 *      anything: same packages, same protections, no list of unlocked packages
 *   4. with the plan's fingerprint the job runs and completes: every line of the plan where it
 *      said, nothing changed outside the plan, the protections back, the list closed
 *
 * It touches the system. Only on a test machine, as root, with -De2e.vm=yes, from the panel's folder (it
 * reads the panel's configuration read-only, like the jobs in the service):
 *   cd /home/panel && java -De2e.vm=yes -cp "/root/signed/tests:/root/signed/target/daemoxcp-mail-1.0.jar" \
 *       org.daemoxcp.mail.system.SignedJobsE2ETest roundcube
 * With -Doutside=<package> (a small one, not installed: tree) the real run also gets a change outside its plan,
 * a real package installed between the inventory photo and pkg, and must end in error naming it; with
 * -Doutside.when=before the same package goes in before the job, and those checks must fail.
 * The full log of each job goes to /var/tmp/signed-jobs-<mode>-<attempt>.log. The boot
 * environments the jobs create as their way back stay: they are the way back of the run, and
 * the script removes them with "cleanup".
 */
public class SignedJobsE2ETest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("Without -De2e.vm=yes this test does nothing: it changes packages.");
            return;
        }
        if (!sh("id -u").trim().equals("0")) { System.out.println("Root is needed."); System.exit(2); }
        if (args.length != 1 || !List.of("roundcube", "python", "mysql84").contains(args[0])) {
            System.out.println("Mode: roundcube, python or mysql84");
            System.exit(2);
        }
        I18n.setCurrent("en");
        String mode = args[0];
        // In the service the jobs read the panel's configuration (the MySQL account of the mail database):
        // here the same, read-only, from the panel's folder (the test starts there).
        org.daemoxcp.mail.Main.dbManager = org.daemoxcp.mail.sqli.dataBaseManager.readOnly();
        // -Doutside=<package>: a real package installed while the job runs, between the inventory photo and pkg
        // (UpdateManager.PlanWatch.afterTaken), as someone running pkg from SSH. The job must not call it a success,
        // and must name it. With -Doutside.when=before it is installed before the job instead, so it is in the
        // inventory: then the job completes, and the checks of this mode must FAIL (the test can tell).
        String outside = System.getProperty("outside", "");
        boolean outsideBefore = "before".equals(System.getProperty("outside.when", "during"));
        if (!outside.isEmpty() && !PackagePlan.isValidName(outside)) { System.out.println("invalid -Doutside"); System.exit(2); }
        if (!outside.isEmpty() && ok("pkg info -e " + outside)) {
            System.out.println(outside + " is already installed: it would not be a change");
            System.exit(2);
        }
        if (!outside.isEmpty() && outsideBefore) {
            System.out.println("== 0. " + outside + " installed BEFORE the job (falsification of the -Doutside checks) ==");
            sh("pkg install -y -U " + outside + " 2>&1");
        }

        System.out.println("== 1. The checks and the plan (" + mode + ") ==");
        JSONObject pf = preflight(mode);
        JSONArray checks = pf.optJSONArray("checks");
        for (int i = 0; checks != null && i < checks.length(); i++) {
            JSONObject c = checks.getJSONObject(i);
            System.out.println("  [" + c.optString("level") + "] " + c.optString("label") + ": " + c.optString("detail"));
        }
        JSONObject plan = pf.optJSONObject("plan");
        String signature = pf.optString("signature", "");
        if (plan != null) {
            System.out.println("  plan computed with: " + plan.optString("command"));
            for (String l : PackagePlan.changesInLines(plan)) System.out.println("    " + l);
            System.out.println("  unlocked in the copy: " + plan.optJSONArray("unlockedPackages"));
        }
        check("1 the plan is there and measured", plan != null && plan.optBoolean("measured"));
        check("1 with a fingerprint", signature.matches("[0-9a-f]{16}"));
        check("1 the job can start", pf.optBoolean("canProceed"));
        if (!pf.optBoolean("canProceed") || plan == null) { end(); return; }
        if (!mode.equals("roundcube")) {
            int intended = 0;
            for (Object o : plan.getJSONArray("changes"))
                if (((JSONObject) o).optBoolean("intended")) intended++;
            check("1 the plan says first what the job removes", intended > 0
                    && plan.getJSONArray("changes").getJSONObject(0).optBoolean("intended"));
        }

        String packagesBefore = inventory();
        Set<String> lockedBefore = locked();

        System.out.println("\n== 2. Without a fingerprint ==");
        JSONObject none = start(mode, "");
        System.out.println("  " + none);
        check("2 the job does not start", !none.optBoolean("success") && none.optString("jobId").isEmpty());
        check("2 and says why", none.optString("error").equals(I18n.tr("server.um.plan.signatureMissing")));

        System.out.println("\n== 3. With a fingerprint that is not the plan's ==");
        JSONObject wrongStart = start(mode, "0123456789abcdef");
        JSONObject wrong = waitJob(wrongStart.optString("jobId"));
        save(mode, "wrong", wrong);
        System.out.println("  outcome: " + (wrong == null ? "no job: " + wrongStart : wrong.optString("status") + ": " + wrong.optString("errorMessage")));
        check("3 the job refuses", wrong != null && "error".equals(wrong.optString("status"))
                && wrong.optString("errorMessage").equals(I18n.tr("server.um.plan.changedSinceRead")));
        check("3 the same packages, at the same versions", inventory().equals(packagesBefore));
        check("3 the same protections", locked().equals(lockedBefore));
        check("3 no list of unlocked packages", !PackageQueue.statePresent());

        System.out.println("\n== 4. With the plan's fingerprint" + (outside.isEmpty() ? "" : ", and " + outside
                + (outsideBefore ? " installed before the job" : " installed while it runs")) + " ==");
        if (!outside.isEmpty() && !outsideBefore)
            UpdateManager.PlanWatch.afterTaken = () -> sh("pkg install -y -U " + outside + " 2>&1");
        JSONObject realStart = start(mode, signature);
        JSONObject job = waitJob(realStart.optString("jobId"));
        UpdateManager.PlanWatch.afterTaken = null;
        save(mode, outside.isEmpty() ? "real" : "outside", job);
        String log = job == null ? "" : job.optString("consoleLog");
        for (String l : log.split("\n"))
            if (l.contains("exact plan") || l.contains("ok  ") || l.contains("NO  ") || l.contains("fingerprint")
                    || l.contains("outside the plan") || l.contains("Protecting") || l.contains("[") && l.contains("/"))
                System.out.println("  | " + l);
        System.out.println("  outcome: " + (job == null ? "no job: " + realStart : job.optString("status") + " " + job.optString("errorMessage")));
        check("4 the plan was the approved one", log.contains(I18n.tr("server.um.x.exactPlan", java.util.Map.of("f", signature))));
        // The lines of the comparison with the plan ("ok  name: expected x, found y"): all ok, also with a change outside.
        boolean planFollowed = log.contains(I18n.tr("server.um.runGuidedUpdate.12").trim())
                && !log.matches("(?s).*NO  [^\n]*" + java.util.regex.Pattern.quote(": expected ") + ".*");
        check("4 every line of the plan where it said", planFollowed);
        if (outside.isEmpty()) {
            check("4 the job completes", job != null && "completed".equals(job.optString("status")));
            check("4 nothing changed outside the plan", log.contains("ok  " + I18n.tr("server.plan.d.none")) && !log.contains("NO  "));
        } else {
            String version = sh("pkg query %v " + outside).trim();
            String line = I18n.tr("server.plan.d.installed", java.util.Map.of("name", outside, "version", version));
            check("4 the job does not call it a success", job != null && "error".equals(job.optString("status")));
            check("4 the log names it against the inventory: \"" + line + "\"", log.contains("NO  " + line));
            check("4 the outcome says it, and only it", job != null
                    && job.optString("errorMessage").contains(I18n.tr("server.um.x.divergenceFound.one", java.util.Map.of("list", outside))));
        }
        check("4 the list of unlocked packages is closed", !PackageQueue.statePresent());
        afterChecks(mode, pf);
        if (!outside.isEmpty()) {
            sh("pkg delete -y " + outside + " 2>&1");
            check("the test removed " + outside + " again", !ok("pkg info -e " + outside));
        }
        end();
    }

    static JSONObject preflight(String mode) {
        return switch (mode) {
            case "roundcube" -> UpdateManager.roundcubePreflight();
            case "python" -> UpdateManager.pythonPreflight();
            default -> UpdateManager.mysql84Preflight();
        };
    }

    static JSONObject start(String mode, String signature) {
        return switch (mode) {
            case "roundcube" -> UpdateManager.startRoundcubeUpdate(signature);
            case "python" -> UpdateManager.startPythonTransition(signature);
            default -> UpdateManager.startMysql84Migration(signature);
        };
    }

    /** What each job must have left, besides the plan. */
    static void afterChecks(String mode, JSONObject pf) {
        Set<String> lockedNow = locked();
        switch (mode) {
            case "roundcube" -> {
                String pkg = pf.optString("pkg");
                check("4 " + pkg + " at the catalog's version", sh("pkg query %v " + pkg).trim().equals(pf.optString("available")));
                check("4 " + pkg + " protected again", lockedNow.contains(pkg));
                check("4 php-fpm running", ok("service php_fpm status"));
            }
            case "python" -> {
                String old = pf.optString("old");
                check("4 no py" + old + " package left", sh("pkg query %n | grep -c -E '^(py" + old + "-|python" + old + "$)'").trim().equals("0"));
                for (Object n : pf.getJSONArray("newPackages")) {
                    check("4 " + n + " installed", ok("pkg info -e " + n));
                    check("4 " + n + " protected", lockedNow.contains(String.valueOf(n)));
                }
            }
            default -> {
                for (String n : List.of("mysql84-server", "mysql84-client")) {
                    check("4 " + n + " installed", ok("pkg info -e " + n));
                    check("4 " + n + " protected", lockedNow.contains(n));
                }
                check("4 no mysql80 package left", sh("pkg query %n | grep -c '^mysql80-'").trim().equals("0"));
                for (String s : List.of("mysql-server", "postfix", "dovecot"))
                    check("4 " + s + " running", ok("service " + s + " status"));
            }
        }
    }

    static JSONObject waitJob(String id) throws Exception {
        if (id == null || id.isEmpty()) return null;
        long deadline = System.currentTimeMillis() + 3_600_000;
        Thread.sleep(500);
        while (PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject s = UpdateManager.jobStatus(id);
        return s.optBoolean("success") ? s.getJSONObject("job") : null;
    }

    static void save(String mode, String attempt, JSONObject job) throws Exception {
        if (job == null) return;
        Files.writeString(Path.of("/var/tmp/signed-jobs-" + mode + "-" + attempt + ".log"), job.optString("consoleLog"));
    }

    /** Every installed package with its version: two equal strings, two equal machines. */
    static String inventory() {
        return sh("pkg query %n-%v | sort");
    }

    static Set<String> locked() {
        Set<String> r = new TreeSet<>();
        for (String l : sh("pkg lock -l 2>/dev/null").split("\n"))
            if (!l.trim().isEmpty() && !l.trim().endsWith(":")) r.add(l.trim().replaceAll("-[^-]+$", ""));
        return r;
    }

    static boolean ok(String cmd) {
        return Shell.runShell(Duration.ofSeconds(60), cmd + " >/dev/null 2>&1").success();
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(600), cmd).output();
    }

    static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }

    static void end() {
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    @SuppressWarnings("unused")
    private static List<String> lines(String s) {
        List<String> r = new ArrayList<>();
        for (String l : s.split("\n")) if (!l.isBlank()) r.add(l);
        return r;
    }
}
