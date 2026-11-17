package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.daemoxcp.mail.i18n.I18n;

/**
 * The detached script that upgrades the JVM the panel runs on (reperto 195).
 *
 * Tried from the browser on the VM on 08/11/2026, the old script reported SUCCEEDED while:
 *  - the panel came back outside its service (no pidfile: "service daemoxcp_mail status" said it was off,
 *    a stop would not stop it, a start would start a second one);
 *  - it never checked the panel answered: separated, the port belongs to the web part, the root
 *    part has none, so the port was "not known" and the check was skipped;
 *  - two report lines were broken by a half-done rename ({VIA} and {backupPath} are not variables
 *    of the script: "way back: " empty and "{backupPath}" printed as it is);
 *  - pkg upgraded four libraries the page never showed, and downloaded 185 MB with the panel off.
 *
 * Here the script is generated as the panel does and RUN, with fake pkg, sockstat, curl, ps and
 * java in front of the PATH, a sleeping process as the panel and another as the web part's
 * supervisor. Nothing real is touched: the panel log, the backup folder and the pidfiles are in a
 * temporary folder. FreeBSD only (sh, stat -f): on the VM.
 */
public class JavaUpdateScriptTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        I18n.setCurrent("en");
        Path root = Files.createTempDirectory("java-update-test");
        try {
            staticChecks(root);
            serviceDetection(root);
            succeeded(root);
            fetchFails(root);
            createFails(root);
            wrongListener(root);
            javaBroken(root);
        } finally {
            run(List.of("rm", "-rf", root.toString()), 30);
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    // ===== The text of the script, in both languages =====

    static void staticChecks(Path root) throws Exception {
        System.out.println("== the script as text, in English and in Italian ==");
        for (String lang : List.of("en", "it")) {
            I18n.setCurrent(lang);
            String s = UpdateManager.javaUpdateScript(plan(root.resolve("static-" + lang), "service", 1234, 2096, "daemoxcp_mail", "/x/web-supervisor.pid"));
            I18n.setCurrent("en");
            Path f = root.resolve("static-" + lang + ".sh");
            Files.writeString(f, s);
            check(lang + ": sh -n reads it", run(List.of("sh", "-n", f.toString()), 30).exit == 0);
            Matcher left = Pattern.compile("\\{[A-Za-z_]+\\}").matcher(s);
            check(lang + ": no placeholder left in the text" + (left.find() ? " (" + left.group() + ")" : ""), !left.reset().find());
            // Every variable an echo line prints must be set by the script: {VIA} and {BK} were not.
            List<String> unset = new ArrayList<>();
            for (String line : s.split("\n")) {
                if (!line.contains("echo '")) continue;
                Matcher v = Pattern.compile("\"\\$([A-Z_]+)\"").matcher(line);
                while (v.find()) {
                    String name = v.group(1);
                    boolean set = Pattern.compile("(?m)(^|[\\s;])" + name + "=|for " + name + " in ").matcher(s).find();
                    if (!set && !unset.contains(name)) unset.add(name);
                }
            }
            check(lang + ": every variable the report prints is set" + (unset.isEmpty() ? "" : " " + unset), unset.isEmpty());
            check(lang + ": every date in UTC", !s.contains("$(date)") && s.contains("date -u"));
            int fetch = s.indexOf("pkg upgrade -F -y"), stop = s.indexOf("kill \"$PANEL_PID\""), upgrade = s.indexOf("pkg upgrade -y \"$PKG\"");
            check(lang + ": download, then stop, then upgrade", fetch > 0 && stop > fetch && upgrade > stop);
            // The command itself, not the report line that names it (that one would pass with the check gone).
            check(lang + ": started by the service, checked by the service",
                    Pattern.compile("(?m)^if \\[ \\$SERVICE -eq 1 \\] && ! /usr/sbin/service daemoxcp_mail status >/dev/null 2>&1; then$").matcher(s).find()
                    && s.contains("SERVICE=1"));
        }
    }

    static void serviceDetection(Path root) throws Exception {
        System.out.println("\n== started by the service? ==");
        Path rc = root.resolve("rc-mailpanel"), pidfile = root.resolve("mailpanel.pid");
        String rcBefore = UpdateManager.rcScript, pidBefore = UpdateManager.rcPidfile;
        UpdateManager.rcScript = rc.toString();
        UpdateManager.rcPidfile = pidfile.toString();
        try {
            check("no rc script: no", !UpdateManager.startedByService(4242));
            Files.writeString(rc, "#!/bin/sh\n");
            check("rc script without pidfile: no", !UpdateManager.startedByService(4242));
            Files.writeString(pidfile, "4242\n");
            check("its pid in the pidfile: yes", UpdateManager.startedByService(4242));
            check("another pid in the pidfile: no", !UpdateManager.startedByService(4243));
        } finally {
            UpdateManager.rcScript = rcBefore;
            UpdateManager.rcPidfile = pidBefore;
        }
    }

    // ===== The script run, with fakes =====

    static void succeeded(Path root) throws Exception {
        System.out.println("\n== everything works ==");
        Run r = execute(root.resolve("ok"), "daemoxcp_mail", "");
        check("SUCCEEDED", r.log.contains("=== OUTCOME: SUCCEEDED"));
        check("the way back is named in the report", r.log.contains("way back: " + r.dir.resolve("backup/openjdk25-25.0.4.pkg")));
        check("the backup folder is named in the report", r.log.contains("The way back stays in " + r.dir.resolve("backup")));
        check("no placeholder in the report", !Pattern.compile("\\{[A-Za-z_]+\\}").matcher(r.log).find());
        int create = at(r, "create -o " + r.dir.resolve("backup") + " openjdk25"), unlockJdk = at(r, "unlock -y openjdk25"),
                unlockLib = at(r, "unlock -y libX11"), fetch = at(r, "upgrade -F -y openjdk25"),
                upgrade = at(r, "upgrade -y openjdk25"), lockJdk = at(r, "lock -y openjdk25"), lockLib = at(r, "lock -y libX11");
        check("pkg: way back, unlock both, download, upgrade, lock both", create >= 0 && unlockJdk > create && unlockLib > create
                && fetch > Math.max(unlockJdk, unlockLib) && upgrade > fetch && lockJdk > upgrade && lockLib > upgrade);
        check("the download came before the panel stopped", r.log.indexOf("Downloading") < r.log.indexOf("Stopping the panel"));
        check("the panel process was stopped", !r.panel.isAlive());
        check("the web part's supervisor was stopped, and the report says so", !r.web.isAlive() && r.log.contains("the web part was still running: stopped"));
        check("the panel was started again", Files.exists(r.dir.resolve("started")));
        check("it checked who holds the port", r.log.contains("the panel answers on port 2096"));
        check("every date in UTC", r.log.contains(" UTC ==="));
    }

    static void fetchFails(Path root) throws Exception {
        System.out.println("\n== the download fails ==");
        Run r = execute(root.resolve("fetch"), "daemoxcp_mail", "fetch");
        check("CANCELLED", r.log.contains("=== OUTCOME: CANCELLED"));
        check("nothing upgraded", at(r, "upgrade -y openjdk25") < 0);
        check("both protected again", at(r, "lock -y openjdk25") > at(r, "upgrade -F -y openjdk25") && at(r, "lock -y libX11") > at(r, "upgrade -F -y openjdk25"));
        check("the report says nothing was updated and why the panel restarts", r.log.contains("Nothing was updated and the protections are back"));
        check("the panel restarted anyway, to close the job", !r.panel.isAlive() && Files.exists(r.dir.resolve("started")));
    }

    static void createFails(Path root) throws Exception {
        System.out.println("\n== no way back ==");
        Run r = execute(root.resolve("create"), "daemoxcp_mail", "create");
        check("CANCELLED", r.log.contains("=== OUTCOME: CANCELLED"));
        check("nothing unlocked, nothing downloaded, nothing upgraded",
                r.calls.lines().noneMatch(l -> l.startsWith("unlock ") || l.startsWith("upgrade ")));
        check("the report says pkg create failed", r.log.contains("pkg create failed"));
    }

    static void wrongListener(Path root) throws Exception {
        System.out.println("\n== the panel comes back without the separation ==");
        Run r = execute(root.resolve("user"), "root", "");
        check("TO CHECK, not SUCCEEDED", r.log.contains("=== OUTCOME: TO CHECK") && !r.log.contains("OUTCOME: SUCCEEDED"));
        check("the report says who holds the port", r.log.contains("port 2096 is held by root, not by daemoxcp_mail"));
    }

    static void javaBroken(Path root) throws Exception {
        System.out.println("\n== the new java does not start ==");
        Run r = execute(root.resolve("java"), "daemoxcp_mail", "java");
        check("the way back is installed", at(r, "add -f " + r.dir.resolve("backup/openjdk25-25.0.4.pkg")) > at(r, "upgrade -y openjdk25"));
        check("TO CHECK, not SUCCEEDED", r.log.contains("=== OUTCOME: TO CHECK") && !r.log.contains("OUTCOME: SUCCEEDED"));
    }

    record Run(Path dir, String log, String calls, Process panel, Process web) { }

    /** The position of the first pkg call that is exactly this line, or -1. */
    static int at(Run r, String call) {
        return r.calls().lines().toList().indexOf(call);
    }

    /** Generates the script as the panel does and runs it with the fakes; fail is "", "create", "fetch" or "java". */
    static Run execute(Path dir, String listener, String fail) throws Exception {
        Files.createDirectories(dir.resolve("bin"));
        Files.createDirectories(dir.resolve("jdk/bin"));
        Files.createDirectories(dir.resolve("backup"));
        Path calls = dir.resolve("calls");
        Files.writeString(calls, "");
        fake(dir.resolve("bin/pkg"), "echo \"$*\" >> '" + calls + "'\n"
                + "case \"$1\" in\n"
                + "  create) [ '" + fail + "' = create ] && exit 1; touch \"$3/$4-25.0.4.pkg\" ;;\n"
                + "  upgrade) [ \"$2\" = -F ] && [ '" + fail + "' = fetch ] && exit 1 ;;\n"
                + "esac\nexit 0\n");
        fake(dir.resolve("bin/sockstat"), "echo 'USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS'\n"
                + "echo '" + listener + " java 999 5 tcp46 *:2096 *:*'\n");
        fake(dir.resolve("bin/curl"), "exit 0\n");
        Process panel = new ProcessBuilder("sleep", "600").start();
        Process web = new ProcessBuilder("sleep", "600").start();
        Files.writeString(dir.resolve("web-supervisor.pid"), web.pid() + "\n");
        // ps: the web part's supervisor is recognised by its daemon(8) title.
        fake(dir.resolve("bin/ps"), "[ \"$4\" = " + web.pid() + " ] && echo 'daemon: " + PanelSeparation.TITLE + "[1000] (daemon)'\nexit 0\n");
        // java: broken only between the upgrade and the way back, when asked to be.
        fake(dir.resolve("jdk/bin/java"), "if [ '" + fail + "' = java ] && grep -q '^upgrade -y' '" + calls + "' && ! grep -q '^add -f' '" + calls + "'; then exit 1; fi\n"
                + "echo 'openjdk version \"25.0.5\"'\n");
        UpdateManager.JavaScriptPlan p = new UpdateManager.JavaScriptPlan("openjdk25", dir.resolve("jdk").toString(),
                dir.resolve("backup").toString(), dir.resolve("report.log").toString(), panel.pid(), List.of("openjdk25", "libX11"),
                "touch '" + dir.resolve("started") + "'", dir.toString(), false, 2096, "daemoxcp_mail",
                dir.resolve("web-supervisor.pid").toString(), dir.resolve("log/panel.log").toString());
        Path script = dir.resolve("upgrade-jdk.sh");
        Files.writeString(script, UpdateManager.javaUpdateScript(p));
        ProcessBuilder pb = new ProcessBuilder("sh", script.toString());
        pb.environment().put("PATH", dir.resolve("bin") + ":/bin:/usr/bin:/sbin:/usr/sbin");
        Result r = run(pb, 240);
        check("the script ended by itself (exit " + r.exit + ")", r.exit >= 0);
        panel.waitFor(5, TimeUnit.SECONDS);
        web.waitFor(5, TimeUnit.SECONDS);
        String log = Files.exists(dir.resolve("report.log")) ? Files.readString(dir.resolve("report.log")) : "";
        Run out = new Run(dir, log, Files.readString(calls), panel, web);
        if (panel.isAlive()) panel.destroyForcibly();
        if (web.isAlive()) web.destroyForcibly();
        return out;
    }

    /** The plan of the static checks: only the text matters there. */
    static UpdateManager.JavaScriptPlan plan(Path dir, String start, long pid, int port, String user, String supervisor) {
        return new UpdateManager.JavaScriptPlan("openjdk25", "/usr/local/openjdk25", dir.resolve("backup").toString(),
                dir.resolve("report.log").toString(), pid, List.of("openjdk25", "libX11"),
                "/usr/sbin/service daemoxcp_mail onestart", dir.toString(), "service".equals(start), port, user, supervisor,
                dir.resolve("panel.log").toString());
    }

    static void fake(Path f, String body) throws Exception {
        Files.writeString(f, "#!/bin/sh\n" + body);
        Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rwxr-xr-x"));
    }

    record Result(int exit, String output) { }

    static Result run(List<String> cmd, int seconds) throws Exception {
        return run(new ProcessBuilder(cmd), seconds);
    }

    static Result run(ProcessBuilder pb, int seconds) throws Exception {
        pb.redirectErrorStream(true);
        Process p = pb.start();
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes());
        if (!p.waitFor(seconds, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            return new Result(-1, out);
        }
        return new Result(p.exitValue(), out);
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
