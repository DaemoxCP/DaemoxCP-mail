package org.mail_panel.scripts;

import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * install_mail_server.sh started BY HAND checks that it belongs to the panel version the service
 * uses (InstallScripts, reperto 169), before changing anything.
 *
 *  A. written by this jar, and the panel service uses another jar: it stops at once, saying so;
 *  B. the service uses this same jar (rc.conf mailpanel_jar): it passes the check and stops later,
 *     at its own first check (MYSQL_PASSWORD missing), still before phase 1;
 *  C. started by the panel (MAIL_PANEL_FROM_PANEL=1) with another jar in the service: the check is
 *     not made (the panel has just written the script) and it stops at its own check.
 * In no case does it reach phase 1. rc.conf is put back as it was. Real script, as root, on the VM:
 * it is switched on with -De2e.vm=yes.
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.scripts.InstallScriptVersionTest
 */
public class InstallScriptVersionTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static Shell.Result sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(120), cmd);
    }

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("SKIPPED: it needs -De2e.vm=yes (FreeBSD VM, root).");
            System.exit(0);
        }
        Path d = Files.createTempDirectory("install-script-version");
        Path script = d.resolve("install_mail_server.sh");
        check("the script written by this jar", InstallScripts.write(script.toString(), new FullMailServerScript().getScriptContent()));
        String jar = Path.of(InstallScripts.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        Shell.Result before = sh("sysrc -n mailpanel_jar 2>/dev/null");
        String rcBefore = before.success() ? before.outputTrim() : null;
        String serviceJar = rcBefore != null ? rcBefore
                : sh("sed -n 's/^: \\${mailpanel_jar:=\"\\(.*\\)\"}$/\\1/p' /usr/local/etc/rc.d/mailpanel").outputTrim();
        System.out.println("service jar: " + serviceJar + (rcBefore == null ? " (default of the rc.d script)" : " (rc.conf)"));
        try {
            String other = sh("sha256 -q " + serviceJar).outputTrim();
            if (other.equals(InstallScripts.jarSha256())) {
                System.out.println("FAILED: the service already uses this same jar, case A cannot be tested here.");
                System.exit(1);
            }

            System.out.println("== A. The service uses another jar ==");
            Shell.Result a = sh("cd " + d + " && env -u MAIL_PANEL_FROM_PANEL sh " + script + " 2>&1");
            check("it stops at once, saying why", !a.success() && a.outputTrim().contains("written by another version of the mail panel"));
            check("before any other check and before phase 1", !a.outputTrim().contains("MYSQL_PASSWORD") && !a.outputTrim().contains("PHASE 1/10"));

            System.out.println("\n== B. The service uses this jar ==");
            sh("sysrc -q mailpanel_jar=" + jar);
            Shell.Result b = sh("cd " + d + " && env -u MAIL_PANEL_FROM_PANEL sh " + script + " 2>&1");
            check("it passes the version check", !b.outputTrim().contains("written by another version"));
            check("and it stops at its first check, before phase 1", !b.success()
                    && b.outputTrim().contains("MYSQL_PASSWORD not in the environment") && !b.outputTrim().contains("PHASE 1/10"));

            System.out.println("\n== C. Started by the panel, with the service on another jar ==");
            restore(rcBefore);
            Shell.Result c = sh("cd " + d + " && env MAIL_PANEL_FROM_PANEL=1 sh " + script + " 2>&1");
            check("the version check is not made", !c.outputTrim().contains("written by another version"));
            check("and it stops at its first check, before phase 1", !c.success()
                    && c.outputTrim().contains("MYSQL_PASSWORD not in the environment") && !c.outputTrim().contains("PHASE 1/10"));
        } finally {
            restore(rcBefore);
            try (var walk = Files.walk(d)) {
                for (Path q : walk.sorted((x, y) -> y.compareTo(x)).toList()) Files.deleteIfExists(q);
            }
        }
        Shell.Result after = sh("sysrc -n mailpanel_jar 2>/dev/null");
        check("rc.conf as it was", rcBefore == null ? !after.success() : after.outputTrim().equals(rcBefore));
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void restore(String rcBefore) {
        if (rcBefore == null) sh("sysrc -q -x mailpanel_jar 2>/dev/null");
        else sh("sysrc -q mailpanel_jar=" + rcBefore);
    }
}
