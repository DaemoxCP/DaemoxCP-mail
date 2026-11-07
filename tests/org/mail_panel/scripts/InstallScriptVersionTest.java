package org.mail_panel.scripts;

import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * install_mail_server.sh lanciato A MANO controlla di essere della versione del pannello che il
 * servizio usa (InstallScripts, reperto 169), prima di cambiare qualunque cosa.
 *
 *  A. scritto da questo jar, e il servizio del pannello usa un altro jar: si ferma subito, dicendolo;
 *  B. il servizio usa questo stesso jar (rc.conf mailpanel_jar): passa il controllo e si ferma piu'
 *     avanti, al primo controllo suo (MYSQL_PASSWORD che manca), sempre prima della fase 1;
 *  C. lanciato dal pannello (MAIL_PANEL_FROM_PANEL=1) con un altro jar nel servizio: il controllo non
 *     si fa (lo script il pannello l'ha appena scritto) e si ferma al controllo suo.
 * In nessun caso arriva alla fase 1. rc.conf si rimette com'era. Script vero, da root, sulla VM: si
 * accende con -De2e.vm=yes.
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
            System.out.println("SALTATA: serve -De2e.vm=yes (VM FreeBSD, root).");
            System.exit(0);
        }
        Path d = Files.createTempDirectory("install-script-version");
        Path script = d.resolve("install_mail_server.sh");
        check("lo script scritto da questo jar", InstallScripts.write(script.toString(), new FullMailServerScript().getScriptContent()));
        String jar = Path.of(InstallScripts.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        Shell.Result before = sh("sysrc -n mailpanel_jar 2>/dev/null");
        String rcBefore = before.success() ? before.outputTrim() : null;
        String serviceJar = rcBefore != null ? rcBefore
                : sh("sed -n 's/^: \\${mailpanel_jar:=\"\\(.*\\)\"}$/\\1/p' /usr/local/etc/rc.d/mailpanel").outputTrim();
        System.out.println("jar del servizio: " + serviceJar + (rcBefore == null ? " (predefinito dello script rc.d)" : " (rc.conf)"));
        try {
            String other = sh("sha256 -q " + serviceJar).outputTrim();
            if (other.equals(InstallScripts.jarSha256())) {
                System.out.println("FALLITA: il servizio usa gia' questo stesso jar, il caso A non si puo' provare qui.");
                System.exit(1);
            }

            System.out.println("== A. Il servizio usa un altro jar ==");
            Shell.Result a = sh("cd " + d + " && env -u MAIL_PANEL_FROM_PANEL sh " + script + " 2>&1");
            check("si ferma subito, dicendo perche'", !a.success() && a.outputTrim().contains("written by another version of the mail panel"));
            check("prima di qualunque altro controllo e della fase 1", !a.outputTrim().contains("MYSQL_PASSWORD") && !a.outputTrim().contains("PHASE 1/10"));

            System.out.println("\n== B. Il servizio usa questo jar ==");
            sh("sysrc -q mailpanel_jar=" + jar);
            Shell.Result b = sh("cd " + d + " && env -u MAIL_PANEL_FROM_PANEL sh " + script + " 2>&1");
            check("passa il controllo della versione", !b.outputTrim().contains("written by another version"));
            check("e si ferma al suo primo controllo, prima della fase 1", !b.success()
                    && b.outputTrim().contains("MYSQL_PASSWORD not in the environment") && !b.outputTrim().contains("PHASE 1/10"));

            System.out.println("\n== C. Lanciato dal pannello, col servizio su un altro jar ==");
            restore(rcBefore);
            Shell.Result c = sh("cd " + d + " && env MAIL_PANEL_FROM_PANEL=1 sh " + script + " 2>&1");
            check("il controllo della versione non si fa", !c.outputTrim().contains("written by another version"));
            check("e si ferma al suo primo controllo, prima della fase 1", !c.success()
                    && c.outputTrim().contains("MYSQL_PASSWORD not in the environment") && !c.outputTrim().contains("PHASE 1/10"));
        } finally {
            restore(rcBefore);
            try (var walk = Files.walk(d)) {
                for (Path q : walk.sorted((x, y) -> y.compareTo(x)).toList()) Files.deleteIfExists(q);
            }
        }
        Shell.Result after = sh("sysrc -n mailpanel_jar 2>/dev/null");
        check("rc.conf com'era", rcBefore == null ? !after.success() : after.outputTrim().equals(rcBefore));
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void restore(String rcBefore) {
        if (rcBefore == null) sh("sysrc -q -x mailpanel_jar 2>/dev/null");
        else sh("sysrc -q mailpanel_jar=" + rcBefore);
    }
}
