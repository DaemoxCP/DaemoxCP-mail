package org.mail_panel.system;

import org.mail_panel.Main;
import org.mail_panel.sqli.dataBaseManager;
import org.mail_panel.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * The full reinstallation detached from the menu (ReinstallJob, reperto 163): the menu dies and it
 * goes on to the end.
 *
 *  J1. the menu killed with kill -9 halfway;
 *  J2. the menu's terminal closing: SIGHUP to its whole process group (the menu starts under
 *      daemon(8), so it has a group of its own as in front of a real terminal);
 *  J3. a menu killed halfway and a second menu opened while it works: the second follows the one
 *      running, it does not start another;
 *  J5. without daemon(8) (not FreeBSD): the menu runs it inside itself, as before, with the script
 *      rewritten from its jar (reperto 172);
 *  J4. the reinstallation itself killed with kill -9: the menu says so and does not count it as
 *      succeeded, and a "service" running with the guardian (UpdateManager.startInterruptionWatch,
 *      reperto 166) locks the packages again by itself and writes the notice with the way back. The
 *      same service stays on during J1-J3, and there it must touch nothing.
 * After each: the outcome, the end of the script, the packages locked again, the turn free.
 *
 * The script is planted with a shadow class of FullMailServerScript (tests/planted, before the jar
 * in the classpath: the reinstallation always rewrites it from its jar), and at the start there is
 * an OLD script on disk that must never run. The planted script: phase 1, twelve one-second steps,
 * then a mark. The rest is real: the
 * detached JVM (Main --reinstall), the turn, the unlock and relock of the protected packages (real
 * pkg), the way back (real bectl). The test panel lives in a folder of its own, with its own
 * SQLite, secrets and logs; MySQL is not needed (port 1). ONLY on a test clone: it is switched on
 * with -De2e.vm=yes, as root, and it refuses to start if there are already real ways back (the
 * pruning would remove some) or packages unlocked by an interrupted job.
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ReinstallJobTest
 */
public class ReinstallJobTest {

    static final String HOST = "mail.e2e.test";
    static int failed = 0;
    static Path base, panel, logs;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(300), cmd).outputTrim();
    }

    static int locked() {
        return (int) sh("pkg query -e '%k = 1' '%n' 2>/dev/null").lines().filter(l -> !l.isBlank()).count();
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("child")) { child(args); return; }
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("SKIPPED: it needs -De2e.vm=yes (a test clone on the FreeBSD VM, as root).");
            System.exit(0);
        }
        // Without the shadow class before the jar the reinstallation would write and run the REAL script.
        if (!new org.mail_panel.scripts.FullMailServerScript().getScriptContent().contains("shadow class")) {
            System.out.println("STOPPED: the shadow class of tests/planted is missing before the jar: this test would run the real script.");
            System.exit(2);
        }
        for (String n : sh("bectl list -H 2>/dev/null | cut -f1").split("\n"))
            if (PackageWayBack.REINSTALL_OWN.matcher(n.trim()).matches()) {
                System.out.println("STOPPED: there is already a reinstallation's way back (" + n.trim() + "): the pruning would remove it.");
                System.exit(2);
            }
        if (PackageQueue.statePresent()) {
            System.out.println("STOPPED: there is the list of an interrupted package job: close it first.");
            System.exit(2);
        }
        int lockedBefore = locked();
        String beBefore = sh("bectl list -H | cut -f1 | sort");
        base = Files.createTempDirectory("reinstall-job");
        panel = base.resolve("panel");
        logs = base.resolve("logs");
        Files.createDirectories(panel);
        System.out.println("protected packages before: " + lockedBefore);
        Path notice = base.resolve("package-job-interrupted.json");
        Path serviceOut = base.resolve("service.out");
        Process service = null;
        try {
            check("test panel ready", run(panel, "setup").contains("SETUP OK"));
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            service = new ProcessBuilder(java, "-cp", absolute(System.getProperty("java.class.path")),
                    ReinstallJobTest.class.getName(), "child", "service-watch", notice.toString())
                    .directory(base.toFile()).redirectErrorStream(true).redirectOutput(serviceOut.toFile()).start();
            for (int i = 0; i < 40 && !(Files.exists(serviceOut) && Files.readString(serviceOut).contains("WATCHING")); i++) Thread.sleep(250);
            check("the service with the guardian is on", Files.readString(serviceOut).contains("WATCHING"));

            System.out.println("\n== J1. The menu killed with kill -9 halfway ==");
            Process menu = startMenu("j1");
            long job = waitJobStep(3);
            check("the detached reinstallation started and is at step 3", job > 0);
            check("in another session than the menu (" + sess(job) + " and " + sess(menu.pid()) + ")",
                    sess(job).matches("[0-9]+") && sess(menu.pid()).matches("[0-9]+") && !sess(job).equals(sess(menu.pid())));
            menu.destroyForcibly();
            menu.waitFor();
            afterJob("J1", job, lockedBefore);

            System.out.println("\n== J2. The menu's terminal closes: SIGHUP to its process group ==");
            Path menuPid = base.resolve("menu-j2.pid");
            sh("cd " + panel + " && /usr/sbin/daemon -o " + base.resolve("menu-j2.out") + " -p " + menuPid + " " + String.join(" ", menuCommand()));
            job = waitJobStep(3);
            long menuJ2 = Long.parseLong(Files.readString(menuPid).trim());
            String pgid = sh("ps -o pgid= -p " + menuJ2).trim();
            check("the menu has a group of its own (" + pgid + ") and the reinstallation is outside it", job > 0 && !pgid.isEmpty()
                    && !pgid.equals(sh("ps -o pgid= -p " + job).trim()));
            sh("kill -HUP -" + pgid);
            check("the menu died with its terminal", waitGone(menuJ2));
            afterJob("J2", job, lockedBefore);

            System.out.println("\n== J3. A menu killed, a second menu opened while the reinstallation works ==");
            menu = startMenu("j3a");
            job = waitJobStep(3);
            menu.destroyForcibly();
            menu.waitFor();
            Process second = startMenu("j3b");
            String out = new String(second.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int code = second.waitFor();
            echo(out);
            check("the second menu follows the one running", out.contains("already running") && out.contains("pid " + job));
            check("and it does not start another", count(out, "runs by itself") == 0 && jobLogs() == 3);
            check("it follows it to the end and counts it as succeeded", code == 0 && out.contains("step 12") && out.contains("MENU RESULT true"));
            // The panel's accounts are deleted with the tables: it says so, with the command to get back in.
            check("and it says the panel's accounts are deleted, and how to create the first administrator",
                    out.contains("panel accounts were deleted") && out.contains("--create-admin"));
            afterJob("J3", job, lockedBefore);

            System.out.println("\n== J5. Without daemon(8): the reinstallation inside the menu, as before ==");
            Files.writeString(panel.resolve("install_scripts/install_mail_server.sh"),
                    "#!/bin/sh\n# a script from an older version\necho \"stale script ran\"\nexit 42\n");
            List<String> noDaemon = new ArrayList<>(menuCommand());
            noDaemon.add("no-daemon");
            Process inside = new ProcessBuilder(noDaemon).directory(panel.toFile()).redirectErrorStream(true)
                    .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
            String insideOut = new String(inside.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int insideCode = inside.waitFor();
            echo(insideOut);
            check("the menu says it runs it inside itself", insideOut.contains("is not here: the reinstallation runs inside this menu"));
            check("and it runs it to the end, succeeded", insideCode == 0 && insideOut.contains("step 12") && insideOut.contains("MENU RESULT true"));
            check("with its jar's script, not the old one", !insideOut.contains("stale script ran") && Files.exists(panel.resolve("script-done")));
            check("locked again, no list, the turn free", locked() == lockedBefore && !PackageQueue.statePresent() && takeAndRelease());
            Files.deleteIfExists(panel.resolve("script-done"));


            System.out.println("\n== J4. The reinstallation itself killed with kill -9 ==");
            menu = startMenu("j4");
            job = waitJobStep(3);
            check("during J1-J3 and J5 the guardian touched nothing", !Files.exists(notice)
                    && !Files.readString(serviceOut).contains("Interrupted package job detected"));
            sh("kill -9 " + job);
            out = new String(menu.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            code = menu.waitFor();
            echo(out);
            check("the menu says it stopped without finishing", out.contains("stopped without finishing"));
            check("and it does not count it as succeeded", code != 0 && out.contains("MENU RESULT false"));
            boolean relocked = false;
            for (int i = 0; i < 60 && !relocked; i++) {
                Thread.sleep(1000);
                relocked = !PackageQueue.statePresent() && locked() == lockedBefore;
            }
            check("the running service notices it and locks the packages again by itself", relocked);
            org.json.JSONObject n = Files.exists(notice) ? new org.json.JSONObject(Files.readString(notice)) : new org.json.JSONObject();
            check("and it writes the notice: it was the reinstallation, with its way back (" + n.optString("wayBack") + ")",
                    n.optBoolean("reinstall") && PackageWayBack.REINSTALL_OWN.matcher(n.optString("wayBack")).matches());
            echo(Files.readString(serviceOut));
        } finally {
            if (service != null) { service.getOutputStream().close(); service.waitFor(); }
            // The ways back made by the test reinstallations.
            for (String n : sh("bectl list -H | cut -f1").split("\n"))
                if (PackageWayBack.REINSTALL_OWN.matcher(n.trim()).matches()) PackageWayBack.destroy(n.trim());
            if (PackageQueue.statePresent()) UpdateManager.restoreLocksAfterCrash();
            removeTree(base);
        }
        check("at the end: the same boot environments and the same protected packages",
                sh("bectl list -H | cut -f1 | sort").equals(beBefore) && locked() == lockedBefore);
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** After a reinstallation left alone: outcome, script finished, packages locked again, turn free. */
    static void afterJob(String name, long job, int lockedBefore) throws Exception {
        Path exit = latestExit(120);
        check(name + ": the reinstallation reaches the end by itself, outcome 0", exit != null && Files.readString(exit).trim().equals("0"));
        check(name + ": the script finished (the mark is there)", Files.exists(panel.resolve("script-done")));
        if (exit == null) {
            // No outcome: the test goes on with the others, without reading a log it cannot find.
            check(name + ": the reinstallation's log is found", false);
            waitGone(job);
            if (PackageQueue.statePresent()) UpdateManager.restoreLocksAfterCrash();
            Files.deleteIfExists(panel.resolve("script-done"));
            return;
        }
        String log = Files.readString(Path.of(exit.toString().replace(".exit", ".log")));
        check(name + ": the log has everything, up to the relocking", log.contains("step 12") && log.contains("packages locked again"));
        check(name + ": the old script did not run", !log.contains("stale script ran"));
        check(name + ": before the way back it looked at the space", log.contains("The way back keeps the mail and the database"));
        check(name + ": the packages protected again, no list", locked() == lockedBefore && !PackageQueue.statePresent());
        check(name + ": the reinstallation is gone and the turn is free", waitGone(job) && takeAndRelease());
        Files.deleteIfExists(panel.resolve("script-done"));
    }

    static boolean takeAndRelease() {
        String r = PackageQueue.take("check", "check");
        PackageQueue.release("check");
        return r == null;
    }

    static boolean waitGone(long pid) throws Exception {
        for (int i = 0; i < 60 && pid > 0; i++) {
            if (ProcessHandle.of(pid).map(h -> !h.isAlive()).orElse(true)) return true;
            Thread.sleep(500);
        }
        return pid <= 0 || ProcessHandle.of(pid).map(h -> !h.isAlive()).orElse(true);
    }

    static String sess(long pid) {
        return sh("ps -o sid= -p " + pid).trim();     // on FreeBSD "sess" is not there: ps exits with an error and nothing
    }

    static int count(String s, String w) {
        int n = 0, i = 0;
        while ((i = s.indexOf(w, i)) >= 0) { n++; i += w.length(); }
        return n;
    }

    static long jobLogs() throws Exception {
        if (!Files.isDirectory(logs)) return 0;
        try (var f = Files.list(logs)) { return f.filter(p -> p.toString().endsWith(".log")).count(); }
    }

    /** Waits until the most recent reinstallation is at step n of the script; its pid, or 0. */
    static long waitJobStep(int n) throws Exception {
        for (int i = 0; i < 240; i++) {
            Thread.sleep(500);
            if (!Files.isDirectory(logs)) continue;
            Path log;
            try (var f = Files.list(logs)) {
                log = f.filter(p -> p.getFileName().toString().matches("reinstall-[0-9-]+\\.log")).sorted().reduce((a, b) -> b).orElse(null);
            }
            if (log == null || !Files.readString(log).contains("step " + n)) continue;
            Path pid = Path.of(log.toString().replace(".log", ".pid"));
            String s = Files.exists(pid) ? Files.readString(pid).trim() : "";
            return s.matches("[0-9]+") ? Long.parseLong(s) : 0;
        }
        return 0;
    }

    static Path latestExit(int seconds) throws Exception {
        for (int i = 0; i < seconds * 2; i++) {
            try (var f = Files.list(logs)) {
                Path log = f.filter(p -> p.getFileName().toString().matches("reinstall-[0-9-]+\\.log")).sorted().reduce((a, b) -> b).orElse(null);
                if (log != null) {
                    Path exit = Path.of(log.toString().replace(".log", ".exit"));
                    if (Files.exists(exit)) return exit;
                }
            }
            Thread.sleep(500);
        }
        return null;
    }

    static List<String> menuCommand() {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        return List.of(java, "-Dmailpanel.secrets.dir=" + base.resolve("secrets"), "-Dmailpanel.reinstall.dir=" + logs,
                "-cp", absolute(System.getProperty("java.class.path")),
                ReinstallJobTest.class.getName(), "child", "menu", HOST);
    }

    static Process startMenu(String name) throws Exception {
        return new ProcessBuilder(menuCommand()).directory(panel.toFile()).redirectErrorStream(true)
                .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
    }

    static String run(Path dir, String... step) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>(List.of(java, "-Dmailpanel.secrets.dir=" + base.resolve("secrets"),
                "-cp", absolute(System.getProperty("java.class.path")), ReinstallJobTest.class.getName(), "child"));
        cmd.addAll(List.of(step));
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        echo(out);
        return out;
    }

    static void echo(String out) {
        for (String l : out.split("\n")) if (!l.isBlank()) System.out.println("      | " + l.replaceAll("\u001b\\[[0-9;]*m", ""));
    }

    static void child(String[] a) throws Exception {
        switch (a[1]) {
            case "setup" -> {
                Main.dbManager = new dataBaseManager();
                Main.dbManager.ensureMailHostnameColumn();
                Main.dbManager.ensureSslChainColumn();
                Main.dbManager.ensureRoundcubeColumns();
                Main.dbManager.ensurePostfixColumn();
                if (Main.dbManager.check_tables() < 1) { Main.dbManager.create_tables(); Main.dbManager.insert_data_default(); }
                Main.dbManager.update_mysql_config("127.0.0.1", "1", "e2e_nobody", "E2eNobody1", "e2e_nobody");
                // An OLD script on disk: the reinstallation must rewrite it from its jar (here the
                // shadow class of tests/planted) and not run this one (InstallScripts, reperto 169).
                Files.createDirectories(Path.of("install_scripts"));
                Files.writeString(Path.of("install_scripts/install_mail_server.sh"),
                        "#!/bin/sh\n# a script from an older version\necho \"stale script ran\"\nexit 42\n");
                System.out.println("SETUP OK");
                System.exit(0);
            }
            case "service-watch" -> {
                // The guardian of the --web service, with a 3-second round instead of 60.
                UpdateManager.watchSeconds = 3;
                PackageRecovery.notice = Path.of(a[2]);
                UpdateManager.startInterruptionWatch();
                System.out.println("WATCHING");
                System.out.flush();
                System.in.read();
                System.exit(0);
            }
            case "menu" -> {
                if (a.length > 3 && a[3].equals("no-daemon")) {
                    ReinstallJob.daemon = "/nonexistent/daemon";
                    // Without daemon the reinstallation runs in this process, which like the real menu
                    // has the panel's configuration open (Main.main opens it before the menu).
                    Main.dbManager = new dataBaseManager();
                    Main.dbManager.ensureMailHostnameColumn();
                    Main.dbManager.ensureSslChainColumn();
                    Main.dbManager.ensureRoundcubeColumns();
                    Main.dbManager.ensurePostfixColumn();
                }
                boolean ok = ReinstallJob.runFromMenu(a[2], System.out);
                System.out.println("MENU RESULT " + ok);
                System.exit(ok ? 0 : 1);
            }
            default -> throw new IllegalArgumentException(a[1]);
        }
    }

    static String absolute(String cp) {
        StringBuilder b = new StringBuilder();
        for (String part : cp.split(java.io.File.pathSeparator)) {
            if (b.length() > 0) b.append(java.io.File.pathSeparator);
            b.append(Path.of(part).toAbsolutePath());
        }
        return b.toString();
    }

    static void removeTree(Path p) throws Exception {
        if (!Files.exists(p)) return;
        try (var walk = Files.walk(p)) {
            for (Path q : walk.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(q);
        }
    }
}
