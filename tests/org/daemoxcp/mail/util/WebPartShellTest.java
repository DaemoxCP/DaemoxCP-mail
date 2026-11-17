package org.daemoxcp.mail.util;

import java.time.Duration;
import java.util.List;

/**
 * In the web part of the separated panel Shell runs no system command
 * except the few the web part needs and that change nothing: dig, drill, host, sendmail, postconf,
 * hostname, and two shell lines (the server's name for the login codes' sender). Everything else stops
 * before it starts, with a line in the log saying which command, so that an operation forgotten in the
 * web part is seen instead of failing silently.
 *
 *  1. before webPartOnly() nothing is stopped;
 *  2. after it: a command of the root part (pkg, service, sysrc, rm, /bin/sh -c with something else),
 *     through Shell.run, Shell.runShell and a ProcessBuilder passed to applyPath, is refused;
 *  3. the web part's own commands pass the check (whether they then exist on this machine is not the
 *     point).
 *
 * Usage (on the VM; it turns the check on for this JVM only):
 *   java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.util.WebPartShellTest
 */
public class WebPartShellTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static boolean refused(Runnable r) {
        try {
            r.run();
            return false;
        } catch (SecurityException e) {
            return true;
        }
    }

    public static void main(String[] args) {
        System.out.println("== 1. Before ==");
        check("a root command is not stopped before the web part starts", !refused(() -> Shell.run(Duration.ofSeconds(10), "true")));

        Shell.webPartOnly();
        System.out.println("\n== 2. In the web part, the root part's commands ==");
        for (List<String> cmd : List.of(List.of("pkg", "info"), List.of("service", "postfix", "reload"), List.of("sysrc", "-a"),
                List.of("/bin/rm", "-rf", "/tmp/x"), List.of("true"))) {
            check("Shell.run " + cmd + " refused", refused(() -> Shell.run(Duration.ofSeconds(10), cmd.toArray(new String[0]))));
        }
        check("Shell.runShell with another line refused", refused(() -> Shell.runShell(Duration.ofSeconds(10), "postconf -h myhostname; id")));
        check("a ProcessBuilder through applyPath refused", refused(() -> Shell.applyPath(new ProcessBuilder("doveadm", "reload"))));
        check("sh -c with a root command refused", refused(() -> Shell.applyPath(new ProcessBuilder("sh", "-c", "service nginx reload"))));

        System.out.println("\n== 3. In the web part, its own commands ==");
        for (List<String> cmd : List.of(List.of("dig", "+short", "example.com"), List.of("/usr/local/sbin/sendmail", "-t"),
                List.of("/usr/sbin/sendmail", "-t"), List.of("hostname"))) {
            check(cmd + " passes the check", !refused(() -> Shell.allowed(cmd)));
        }
        check("the two shell lines of PanelMail pass", !refused(() -> Shell.allowed(List.of("sh", "-c", "postconf -h myhostname 2>/dev/null")))
                && !refused(() -> Shell.allowed(List.of("sh", "-c", "hostname"))));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
