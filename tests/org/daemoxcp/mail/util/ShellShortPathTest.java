package org.daemoxcp.mail.util;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

/**
 * The panel started with rc.d's short PATH (/sbin:/bin:/usr/sbin:/usr/bin, without /usr/local)
 * still finds the programs in /usr/local (reperto 181).
 *
 * On the real server, on 07/11/2026, the first start of the new panel left three migrations stuck
 * on "Cannot run program "nginx"": Shell put the full PATH in the child's environment, but Java
 * looks for the program to run with the panel's own PATH. That server's rc.d script does not set
 * the PATH (the snapshot's on the VM does), so the rehearsal could not see it.
 *
 * The test starts a child panel with that short PATH, and there:
 *  1. the process's PATH really is the short one;
 *  2. Shell.run("nginx", "-v") starts and answers (like the migrations' "nginx -T");
 *  3. a command through sh -c finds nginx with the full PATH;
 *  4. a program that exists nowhere still gives the right error.
 * It needs nginx in /usr/local/sbin (the FreeBSD VM); without it, it says so and skips.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.util.ShellShortPathTest
 */
public class ShellShortPathTest {

    static final String SHORT_PATH = "/sbin:/bin:/usr/sbin:/usr/bin";
    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("child")) { child(); return; }
        if (!Files.isExecutable(Path.of("/usr/local/sbin/nginx"))) {
            System.out.println("SKIPPED: it needs nginx in /usr/local/sbin (the FreeBSD VM).");
            System.exit(0);
        }
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        ProcessBuilder pb = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                ShellShortPathTest.class.getName(), "child").inheritIO();
        // As rc.subr starts it: no /usr/local.
        pb.environment().put("PATH", SHORT_PATH);
        System.exit(pb.start().waitFor());
    }

    static void child() {
        System.out.println("== A panel started with rc.d's short PATH ==");
        check("the process's PATH is the short one (" + System.getenv("PATH") + ")", SHORT_PATH.equals(System.getenv("PATH")));
        Shell.Result v = Shell.run(Duration.ofSeconds(20), "nginx", "-v");
        check("Shell.run(\"nginx\", \"-v\") starts and answers (" + v.exitCode() + ": " + v.outputTrim() + ")",
                v.success() && v.outputTrim().contains("nginx version"));
        Shell.Result t = Shell.run(Duration.ofSeconds(30), "nginx", "-t");
        check("nginx -t too, like the migrations that read the configuration (" + t.exitCode() + ")",
                t.exitCode() >= 0 && !t.outputTrim().contains("Cannot run program"));
        Shell.Result sh = Shell.runShell(Duration.ofSeconds(10), "command -v nginx");
        check("through sh -c the full PATH finds nginx (" + sh.outputTrim() + ")", sh.outputTrim().equals("/usr/local/sbin/nginx"));
        Shell.Result missing = Shell.run(Duration.ofSeconds(10), "no-such-program-anywhere-e2e");
        check("a program that is nowhere: the right error (" + missing.exitCode() + ")",
                !missing.success() && missing.outputTrim().contains("no-such-program-anywhere-e2e"));
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
