package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Reperto 42: a package's install script changes the live configuration, and the update declares
 * itself successful.
 *
 * Measured on the FreeBSD 15.1 VM on 24/10/2026: updating postfix-mysql 3.11.7_1,1 -> 3.11.7_3,1
 * the script wrote {@code inet_protocols = ipv4} into main.cf while postfix listened on IPv4 and
 * IPv6. At the restart IPv6 disappears, and every check of the guided update passes: valid
 * configuration, service running, pid changed. And the messages filter, on the real output of
 * that update, returned zero messages.
 *
 * Two parts.
 *
 * A. The messages filter on the REAL output of that update, 61 lines copied from /tmp/agg.log on
 *    the VM. It runs anywhere.
 *
 * B. The three real jobs — guided update, update of the unprotected packages, full maintenance —
 *    on a fake package, nginx-drift-probe, built here with {@code pkg create}. Its version 1.1 does
 *    what the postfix script did: it prints a "COMPATIBILITY: editing", adds
 *    {@code protocols = ipv4} to the live configuration, and the service stops listening on IPv6;
 *    and it also writes a file in /etc, which nobody looked at before. Version 1.2 changes only its
 *    own files and creates its user, as the ports do: it must pass clean, and it is the direction
 *    that says the check does not cry wolf.
 *
 *    The name starts with "nginx" on purpose: the panel takes it for a piece of nginx, so the
 *    guided update has a real service to restart — harmless to restart on the VM. In the dirty
 *    case it must NOT restart it (the restart would put into force a configuration nobody read); in
 *    the clean case it must. The nginx pid says it.
 *
 *    The service is an nc listening on 127.0.0.1 and ::1, port 47425. The 1.1 script does not
 *    restart it: it turns off the IPv6 side, which is the effect of the restart. The reason is
 *    measured: a service restarted by the install script does not survive the installation (after
 *    the update nothing was listening any more, not even on IPv4).
 *
 *    To keep the real packages out, during the test the FreeBSD-ports and FreeBSD-ports-kmods
 *    repositories are turned off (a file in /usr/local/etc/pkg/repos, removed at the end), and
 *    before every job it is checked that the plan contains ONLY drift-probe. The maintenance really
 *    unlocks and locks again the machine's protected packages, as always. It touches the system
 *    and puts everything back as it was, and checks it: it is turned on only with -De2e.vm=yes, as
 *    root, on FreeBSD. Only on a test machine.
 *
 * With the jar without the fix part A finds zero messages and the "dirty" cases of part B end
 * "completed": this is the test that fails without it and passes with it.
 */
public class InstallScriptDriftTest {

    private static int failures = 0, skipped = 0;

    /** pkg's output for the postfix-mysql update, 24/10/2026, line by line. */
    static final String POSTFIX_UPGRADE_OUTPUT = """
            Checking integrity... done (1 conflicting)
              - lmdb0-0.9.35 [FreeBSD-ports] conflicts with lmdb-1.0.2,1 [installed] on /usr/local/bin/mdb_copy
            Checking integrity... done (0 conflicting)
            The following 3 package(s) will be affected (of 0 checked):

            New packages to be INSTALLED:
            \tlmdb0: 0.9.35 [FreeBSD-ports]

            Installed packages to be UPGRADED:
            \tpostfix-mysql: 3.11.7_1,1 -> 3.11.7_3,1 [FreeBSD-ports]

            Installed packages to be REMOVED:
            \tlmdb: 1.0.2,1

            Number of packages to be removed: 1
            Number of packages to be installed: 1
            Number of packages to be upgraded: 1
            [1/4] Deinstalling postfix-mysql-3.11.7_1,1...
            [1/4] Deleting files for postfix-mysql-3.11.7_1,1: .......... done
            ==> You should manually remove the "postfix" user
            ==> You should manually remove the "maildrop" group
            ==> You should manually remove the "postfix" group
            [2/4] Deinstalling lmdb-1.0.2,1...
            [2/4] Deleting files for lmdb-1.0.2,1: .......... done
            [3/4] Installing lmdb0-0.9.35...
            [3/4] Extracting lmdb0-0.9.35: .......... done
            [4/4] Installing postfix-mysql-3.11.7_3,1...
            ===> Creating groups
            Using existing group 'mail'
            Using existing group 'maildrop'
            Using existing group 'postfix'
            ===> Creating users
            Using existing user 'postfix'
            ===> Creating homedir(s)
            [4/4] Extracting postfix-mysql-3.11.7_3,1: .......... done
            postfix: Postfix is using backwards-compatible default settings
            postfix: See https://www.postfix.org/COMPATIBILITY_README.html for details
            postfix: To disable backwards compatibility use "postconf compatibility_level=3.11" and "postfix reload"
            Editing /usr/local/etc/postfix/master.cf, adding missing entry for postscreen TCP service
            Editing /usr/local/etc/postfix/master.cf, adding missing entry for smtpd unix-domain service
            Editing /usr/local/etc/postfix/master.cf, adding missing entry for dnsblog unix-domain service
            Editing /usr/local/etc/postfix/master.cf, adding missing entry for tlsproxy unix-domain service
                COMPATIBILITY: editing /usr/local/etc/postfix/main.cf, setting
                inet_protocols=ipv4.  Specify inet_protocols explicitly if you
                want to enable IPv6.  In a future release IPv6 will be enabled
                by default.

            ===============================================================
            Postfix was *not* activated in //usr/local/etc/mail/mailer.conf!\s

            To finish installation run the following commands:

              mkdir -p //usr/local/etc/mail
              install -m 0644 //usr/local/share/postfix/mailer.conf.postfix //usr/local/etc/mail/mailer.conf
            ===============================================================

            You may need to manually remove /usr/local/etc/postfix/main.cf if it is no longer needed.
            You may need to manually remove /usr/local/etc/postfix/master.cf if it is no longer needed.
            Message from postfix-mysql-3.11.7_1,1:
            If you remove postfix permanent, adjust / remove the the following file:
              - /usr/local/etc/mail/mailer.conf
            """;

    public static void main(String[] args) throws Exception {
        messages();
        if ("yes".equals(System.getProperty("e2e.vm"))) {
            if (onFreeBsdAsRoot()) endToEnd();
            else { skipped++; System.out.println("\n  SKIPPED  part B: it needs FreeBSD and root"); }
        } else {
            skipped++;
            System.out.println("\n  SKIPPED  part B: it touches the system, turned on with -De2e.vm=yes (only on a test VM)");
        }
        System.out.println(failures == 0 ? "\nALL OK" + (skipped > 0 ? " (" + skipped + " parts skipped, said above)" : "")
                                         : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    // ===================== A. the messages filter =====================

    private static void messages() {
        System.out.println("A. The messages filter on the real output of the postfix-mysql update");
        List<String> m = UpdateManager.messagesAskingForAction(POSTFIX_UPGRADE_OUTPUT);
        System.out.println("     messages found: " + m.size());
        check("the COMPATIBILITY notice, outside any \"Message from\" block, is picked up",
                any(m, "COMPATIBILITY: editing /usr/local/etc/postfix/main.cf") && any(m, "inet_protocols=ipv4"));
        check("  whole: the line saying IPv6 is lost too", any(m, "want to enable IPv6"));
        check("the master.cf changes announced by the script too",
                any(m, "Editing /usr/local/etc/postfix/master.cf, adding missing entry"));
        check("the mailer.conf box, with the commands to run",
                any(m, "Postfix was *not* activated") && any(m, "install -m 0644"));
        check("pkg's sentence on files that differ from the sample is not an action",
                !any(m, "You may need to manually remove"));
        check("nor is the ports' one on the user of a package being reinstalled",
                !any(m, "You should manually remove the \"postfix\" user"));
        check("the message of the OLD version, which is being uninstalled, asks for nothing",
                !any(m, "If you remove postfix permanent"));

        // What the filter already knew how to do must not be lost.
        String rspamd = "[1/1] Upgrading rspamd from 3.12 to 4.1...\n[1/1] Extracting rspamd-4.1: .... done\n"
                + "=====\nMessage from rspamd-4.1:\n\n--\nThe statistics format changed.\nIt is recommended to remove\nthe old cache files:\n  rm /var/db/rspamd/*.hs*\n";
        List<String> r = UpdateManager.messagesAskingForAction(rspamd);
        check("a \"Message from\" block that asks for an action is still picked up, whole",
                r.size() == 1 && r.get(0).contains("It is recommended") && r.get(0).contains("rm /var/db/rspamd"));
        check("an output with nothing to do gives no messages",
                UpdateManager.messagesAskingForAction("[1/1] Upgrading nginx from 1.30.5_2,3 to 1.30.6,3...\n"
                        + "[1/1] Extracting nginx-1.30.6,3: .......... done\n"
                        + "You may need to manually remove /usr/local/etc/nginx/nginx.conf if it is no longer needed.\n").isEmpty());
    }

    private static boolean any(List<String> messages, String text) {
        for (String s : messages) if (s.contains(text)) return true;
        return false;
    }

    // ===================== B. the three real jobs =====================

    static final String PKG = "nginx-drift-probe";
    static final String ETC_FILE = "/etc/drift-probe.conf";
    static final String USER = "driftprobe";
    static final String NGINX_PID = "/var/run/nginx.pid";
    /** Where the panel must put the version of before: written out in full here, because the test
     *  also runs against the jar without the fix, where the constant does not exist. */
    static final String SAVED_DIR = "/var/db/daemoxcp-mail/config-before-update";
    static final String CONF = "/usr/local/etc/drift-probe/drift-probe.conf";
    static final String RESTART = "/usr/local/libexec/drift-probe/restart";
    static final String REPO_CONF = "/usr/local/etc/pkg/repos/zzz-drift-probe.conf";
    static final String REPO_DB = "/var/db/pkg/repos/" + PKG;
    static final String PID4 = "/var/run/drift-probe.4.pid", PID6 = "/var/run/drift-probe.6.pid";
    static final int PORT = 47425;
    static Path work;
    static boolean createdReposDir;

    private static boolean onFreeBsdAsRoot() {
        return sh("uname -s").trim().equals("FreeBSD") && sh("id -u").trim().equals("0");
    }

    private static void endToEnd() throws Exception {
        System.out.println("\nB. The three real jobs, with a package whose script changes the configuration");
        // The leftovers of an interrupted run would skew the final comparison: away before measuring.
        removePackage();
        sh("rm -f " + REPO_CONF + "; rm -rf " + REPO_DB);
        String packagesBefore = sh("pkg query %n-%v | sort | sha256");
        String bootEnvironmentsBefore = sh("bectl list -H 2>/dev/null | cut -f1 | sort");
        String savedBefore = sh("ls " + SAVED_DIR + " 2>/dev/null");
        boolean savedDirExisted = Files.isDirectory(Path.of(SAVED_DIR));
        Set<String> lockedBefore = locked();
        work = Files.createTempDirectory(Path.of("/var/tmp"), "drift-probe");
        try {
            buildPackage("1.0", false);
            buildPackage("1.1", true);    // the dirty script
            buildPackage("1.2", false);   // changes only its own files
            // On a freshly installed machine the folder is not there: the branch change creates it.
            // Measured on the VM restored on 24/10/2026, where the test fell here.
            if (!Files.isDirectory(Path.of(REPO_CONF).getParent())) {
                Files.createDirectories(Path.of(REPO_CONF).getParent());
                createdReposDir = true;
            }
            Files.writeString(Path.of(REPO_CONF),
                    "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n"
                  + PKG + ": { url: \"file://" + work.resolve("repo") + "\", signature_type: \"none\", enabled: yes }\n");
            String repos = sh("pkg -vv 2>/dev/null | sed -n '/^Repositories/,$p'");
            if (!enabledOnly(repos, PKG)) {
                check("the real repositories are turned off for the test (otherwise it does not start)", false);
                System.out.println(repos);
                return;
            }
            for (String flow : new String[]{"guided", "unprotected", "maintenance"}) {
                runCase(flow, "1.1", true);
                runCase(flow, "1.2", false);
            }
        } finally {
            removePackage();
            sh("rm -f " + REPO_CONF + "; rm -rf " + REPO_DB + " " + work);
            removeWayBacks(bootEnvironmentsBefore);
            if (createdReposDir) sh("rmdir " + Path.of(REPO_CONF).getParent());
            // The "before" copies the dirty cases set aside: they belong to the test.
            for (String d : sh("ls " + SAVED_DIR + " 2>/dev/null").split("\n"))
                if (!d.isBlank() && !savedBefore.contains(d.trim())) sh("rm -rf " + SAVED_DIR + "/" + d.trim());
            if (!savedDirExisted) sh("rmdir " + SAVED_DIR + " 2>/dev/null");
            // And the note and the signs of the locked packages, which need realigning after the package is removed.
            UpdateManager.refreshLockTrace();
            String after = sh("pkg query %n-%v | sort | sha256");
            check("at the end: the same boot environments as before",
                    sh("bectl list -H 2>/dev/null | cut -f1 | sort").equals(bootEnvironmentsBefore));
            check("at the end: the same packages as before, at the same versions", after.equals(packagesBefore));
            check("at the end: the same protected packages as before", locked().equals(lockedBefore));
            check("at the end: FreeBSD-ports turned on again",
                    sh("pkg -vv 2>/dev/null | grep -A3 '^  FreeBSD-ports: {' | grep -c 'enabled *: yes'").trim().equals("1"));
            check("at the end: nothing listening on the test's port",
                    sh("sockstat -46lq -P tcp -p " + PORT).trim().isEmpty());
            check("at the end: no test file in /etc, no test user",
                    !Files.exists(Path.of(ETC_FILE)) && !sh("pw usershow " + USER + " 2>&1").startsWith(USER + ":"));
            check("at the end: the \"before\" copies are the ones that were there",
                    sh("ls " + SAVED_DIR + " 2>/dev/null").equals(savedBefore)
                    && Files.isDirectory(Path.of(SAVED_DIR)) == savedDirExisted);
        }
    }

    /** One case: drift-probe 1.0 installed and listening, the given version in the catalog, and the job. */
    private static void runCase(String flow, String version, boolean dirty) throws Exception {
        System.out.println("\n  --- " + flow + ", 1.0 -> " + version + (dirty ? " (the script changes the configuration)" : " (clean)") + " ---");
        removePackage();
        sh("pkg add " + work.resolve("pkgs/" + PKG + "-1.0.pkg") + " 2>&1");
        // An administrator's configuration: different from its sample, like main.cf.
        Files.writeString(Path.of(CONF), Files.readString(Path.of(CONF)) + "banner = drift probe\n", StandardCharsets.UTF_8);
        sh(RESTART);
        if (!waitListening(true)) { check(flow + " " + version + ": the test service listens on IPv4 and IPv6 before the job", false); return; }
        String nginxPidBefore = sh("cat " + NGINX_PID + " 2>/dev/null").trim();
        Path repo = work.resolve("repo");
        sh("rm -rf " + repo + " && mkdir -p " + repo + " && cp " + work.resolve("pkgs/" + PKG + "-" + version + ".pkg") + " " + repo
                + " && pkg repo " + repo + " >/dev/null 2>&1 && pkg update -f -r " + PKG + " >/dev/null 2>&1");
        if (!flow.equals("unprotected")) sh("pkg lock -y " + PKG);

        JSONObject plan, start;
        String signature;
        switch (flow) {
            case "guided" -> {
                JSONObject pf = UpdateManager.packagePreflight(PKG);
                plan = pf.optJSONObject("plan");
                signature = pf.optString("signature");
                if (!pf.optBoolean("canProceed")) {
                    check(flow + " " + version + ": the preflight lets it start", false);
                    System.out.println("     " + pf.optJSONArray("checks"));
                    return;
                }
            }
            case "unprotected" -> {
                JSONObject st = UpdateManager.updatesStatus();
                plan = st.optJSONObject("plan");
                signature = st.optString("signature");
            }
            default -> {
                JSONObject pv = UpdateManager.maintenancePreview();
                plan = pv.optJSONObject("plan");
                signature = pv.optString("signature");
            }
        }
        Set<String> inPlan = new TreeSet<>();
        JSONArray ch = plan == null ? new JSONArray() : plan.optJSONArray("changes");
        for (int i = 0; ch != null && i < ch.length(); i++) inPlan.add(ch.getJSONObject(i).optString("name"));
        if (!inPlan.equals(Set.of(PKG))) {
            // A plan with other packages would change the machine for real: it does not start.
            check(flow + " " + version + ": the plan contains only " + PKG + " (found " + inPlan + ")", false);
            return;
        }
        start = switch (flow) {
            case "guided" -> UpdateManager.startGuidedUpdate(PKG, signature);
            case "unprotected" -> UpdateManager.startUnlockedPackagesUpdate(signature);
            default -> UpdateManager.startMaintenance(signature);
        };
        String id = start.optString("jobId");
        if (id.isEmpty()) { check(flow + " " + version + ": the job starts (" + start + ")", false); return; }
        // The end is the free turn, not the status: the maintenance says "completed" before its
        // final checks (reperto 43), and whoever stopped there would look at a job half done.
        long deadline = System.currentTimeMillis() + 600_000;
        while (PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = UpdateManager.jobStatus(id).getJSONObject("job");
        // -De2e.dump=<folder>: the job's JSON as it is, what the page receives from job_status. It
        // serves to show a browser the real outcome, not one written by hand.
        String dump = System.getProperty("e2e.dump");
        if (dump != null) Files.writeString(Path.of(dump, flow + "-" + version + ".json"),
                new JSONObject().put("success", true).put("job", job).toString(2));
        String log = job.optString("consoleLog"), error = job.optString("errorMessage"), status = job.optString("status");
        System.out.println("     outcome: " + status + " in " + job.optLong("elapsedSeconds") + " s"
                + (error.isEmpty() ? "" : "\n     error: " + error));
        for (String l : log.split("\n")) System.out.println("       | " + l);

        String nginxPidAfter = sh("cat " + NGINX_PID + " 2>/dev/null").trim();
        String label = flow + " 1.0 -> " + version + ": ";
        if (dirty) {
            check(label + "the job does NOT declare itself successful", "error".equals(status));
            check(label + "the outcome names the file the script changed", error.contains(CONF));
            check(label + "  and the one it wrote in /etc", error.contains(ETC_FILE));
            check(label + "the outcome names the lost address", error.contains("[::1]:" + PORT));
            check(label + "the log shows the line the script added", log.contains("+ protocols = ipv4"));
            String header = I18n.tr("server.um.runGuidedUpdate.33");
            int h = log.lastIndexOf(header);
            check(label + "and it prints the script's COMPATIBILITY notice again at the end",
                    h >= 0 && log.indexOf("COMPATIBILITY: editing", h) > h);
            // The version of before, set aside: the log says the path, the test knows the content,
            // because it is what the test itself wrote before the job.
            String saved = null;
            for (String l : log.split("\n")) {
                int c = l.indexOf("cp -p ");
                if (c >= 0 && l.trim().endsWith(" " + CONF)) saved = l.substring(c + 6, l.lastIndexOf(" " + CONF)).trim();
            }
            check(label + "the version of before of " + CONF + " is set aside, and it is the right one",
                    saved != null && Files.exists(Path.of(saved))
                    && Files.readString(Path.of(saved)).equals("port = " + PORT + "\nbanner = drift probe\n"));
            check(label + "  and the log says " + ETC_FILE + " was not there before",
                    log.contains(I18n.tr("server.drift.savedCreated", java.util.Map.of("path", ETC_FILE))));
            if (flow.equals("guided")) {
                check(label + "nginx was NOT restarted (pid " + nginxPidBefore + " -> " + nginxPidAfter + ")",
                        !nginxPidBefore.isEmpty() && nginxPidBefore.equals(nginxPidAfter));
                check(label + "  and the outcome says so, with the command to do it later",
                        error.contains(I18n.tr("server.drift.restartHeldProblem", java.util.Map.of("list", "nginx")))
                        && log.contains("service nginx restart"));
            }
        } else {
            check(label + "successful, without alarms", "completed".equals(status) && error.isEmpty());
            check(label + "  and the configuration check took place", log.contains(I18n.tr("server.drift.configHeader")));
            check(label + "  and the addresses one too", log.contains(I18n.tr("server.drift.listenHeader")));
            check(label + "  the user created by the package is said, without an alarm",
                    log.contains("/etc/passwd: ") && log.contains(I18n.tr("server.drift.kind.accounts")));
            if (flow.equals("guided"))
                check(label + "nginx restarted as always (pid " + nginxPidBefore + " -> " + nginxPidAfter + ")",
                        !nginxPidAfter.isEmpty() && !nginxPidBefore.equals(nginxPidAfter));
        }
    }

    /** The test package: a .sample, the script that starts the service, and pkg's two scripts. */
    private static void buildPackage(String version, boolean dirty) throws Exception {
        Path root = work.resolve("root-" + version);
        Path etc = Files.createDirectories(root.resolve("usr/local/etc/drift-probe"));
        Path libexec = Files.createDirectories(root.resolve("usr/local/libexec/drift-probe"));
        Files.writeString(etc.resolve("drift-probe.conf.sample"),
                "port = " + PORT + "\n" + ("1.2".equals(version) ? "# sample of 1.2\n" : ""));
        Files.writeString(libexec.resolve("restart"), String.join("\n",
                "#!/bin/sh",
                "# drift-probe " + version + ": listening on IPv4, and on IPv6 unless the configuration removes it",
                "C=" + CONF,
                "for f in " + PID4 + " " + PID6 + "; do [ -f $f ] && kill $(cat $f) 2>/dev/null; rm -f $f; done",
                "sleep 1",
                "daemon -f -p " + PID4 + " nc -dkl 127.0.0.1 " + PORT,
                "grep -q '^protocols *= *ipv4' $C 2>/dev/null || daemon -f -p " + PID6 + " nc -6 -dkl ::1 " + PORT,
                "exit 0", ""));
        sh("chmod 755 " + libexec.resolve("restart"));
        String postInstall = "C=" + CONF + "\n[ -f $C ] || cp $C.sample $C\n";
        if (dirty) postInstall += String.join("\n",
                "echo 'daily_drift_probe_enable=\"YES\"' > " + ETC_FILE,
                "echo \"    COMPATIBILITY: editing $C, setting\"",
                "echo \"    protocols=ipv4.  Specify protocols explicitly if you want to enable IPv6.\"",
                "grep -q '^protocols' $C || echo 'protocols = ipv4' >> $C",
                "[ -f " + PID6 + " ] && kill $(cat " + PID6 + ") 2>/dev/null",
                "rm -f " + PID6, "");
        postInstall += "exit 0\n";
        // As the ports do with USERS and GROUPS: the group and the user, if they are not there.
        String preInstall = "1.2".equals(version)
                ? "pw groupshow " + USER + " >/dev/null 2>&1 || pw groupadd " + USER + "\n"
                + "pw usershow " + USER + " >/dev/null 2>&1 || pw useradd " + USER + " -g " + USER
                + " -d /nonexistent -s /usr/sbin/nologin -c 'drift probe'\nexit 0\n"
                : "exit 0\n";
        String preDeinstall = "C=" + CONF + "\nif cmp -s $C $C.sample; then rm -f $C; else "
                + "echo \"You may need to manually remove $C if it is no longer needed.\"; fi\nexit 0\n";
        Path manifest = work.resolve("manifest-" + version);
        Files.writeString(manifest, "name: " + PKG + "\nversion: \"" + version + "\"\norigin: misc/" + PKG
                + "\ncomment: \"test for reperto 42\"\ndesc: \"test for reperto 42\"\nmaintainer: root@localhost\n"
                + "www: https://localhost/\nprefix: /usr/local\nscripts: {\n"
                + "  pre-install: <<EOD\n" + preInstall + "EOD\n"
                + "  post-install: <<EOD\n" + postInstall + "EOD\n"
                + "  pre-deinstall: <<EOD\n" + preDeinstall + "EOD\n}\n");
        Path plist = work.resolve("plist-" + version);
        Files.writeString(plist, "/usr/local/etc/drift-probe/drift-probe.conf.sample\n/usr/local/libexec/drift-probe/restart\n");
        Files.createDirectories(work.resolve("pkgs"));
        String out = sh("pkg create -M " + manifest + " -r " + root + " -p " + plist + " -o " + work.resolve("pkgs") + " 2>&1");
        if (!Files.exists(work.resolve("pkgs/" + PKG + "-" + version + ".pkg")))
            throw new IllegalStateException("pkg create " + version + ": " + out);
    }

    private static void removePackage() {
        sh("for f in " + PID4 + " " + PID6 + "; do [ -f $f ] && kill $(cat $f) 2>/dev/null; rm -f $f; done; "
         + "pkill -f 'nc -dkl 127.0.0.1 " + PORT + "'; pkill -f 'nc -6 -dkl ::1 " + PORT + "'; "
         + "pkg unlock -y " + PKG + " >/dev/null 2>&1; pkg delete -y " + PKG + " >/dev/null 2>&1; "
         + "rm -rf /usr/local/etc/drift-probe /usr/local/libexec/drift-probe " + ETC_FILE + "; "
         + "pw userdel " + USER + " >/dev/null 2>&1; pw groupdel " + USER + " >/dev/null 2>&1; true");
    }

    private static boolean waitListening(boolean both) throws Exception {
        for (int i = 0; i < 10; i++) {
            String s = sh("sockstat -46lq -P tcp -p " + PORT);
            if (s.contains("127.0.0.1:" + PORT) && (!both || s.contains("[::1]:" + PORT))) return true;
            Thread.sleep(500);
        }
        return false;
    }

    /** In pkg -vv's Repositories block, the only enabled repository is the given one. */
    private static boolean enabledOnly(String repos, String name) {
        String current = null;
        Set<String> enabled = new TreeSet<>();
        for (String l : repos.split("\n")) {
            String t = l.trim();
            if (t.endsWith(": {")) current = t.substring(0, t.length() - 3).trim();
            else if (current != null && t.matches("enabled\\s*:\\s*yes,?")) enabled.add(current);
        }
        return enabled.equals(Set.of(name));
    }

    private static Set<String> locked() {
        Set<String> r = new TreeSet<>();
        for (String l : sh("pkg lock -l 2>/dev/null").split("\n"))
            if (!l.trim().isEmpty() && !l.trim().endsWith(":")) r.add(l.trim());
        return r;
    }

    private static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(300), cmd).output();
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }

    /**
     * The boot environments the test's jobs created before touching the packages (PackageWayBack,
     * since 06/11/2026): they are removed, as everything else is put back.
     */
    private static void removeWayBacks(String before) {
        for (String n : sh("bectl list -H 2>/dev/null | cut -f1").split("\n"))
            if (n.trim().startsWith(PackageWayBack.PREFIX) && !before.contains(n.trim())) PackageWayBack.destroy(n.trim());
    }
}
