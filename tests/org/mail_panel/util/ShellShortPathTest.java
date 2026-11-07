package org.mail_panel.util;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

/**
 * Il pannello avviato col PATH corto di rc.d (/sbin:/bin:/usr/sbin:/usr/bin, senza /usr/local) trova
 * lo stesso i programmi di /usr/local (reperto 181).
 *
 * Sul server vero, il 07/11/2026, il primo avvio del pannello nuovo ha lasciato ferme tre migrazioni su
 * «Cannot run program "nginx"»: Shell metteva il PATH completo nell'ambiente del figlio, ma Java cerca
 * il programma da lanciare col PATH del pannello stesso. Lo script rc.d di quel server non imposta il
 * PATH (quello della fotografia sulla VM si'), quindi la prova generale non poteva vederlo.
 *
 * La prova lancia un pannello figlio con quel PATH corto, e li':
 *  1. il PATH del processo e' davvero quello corto;
 *  2. Shell.run("nginx", "-v") parte e risponde (come «nginx -T» delle migrazioni);
 *  3. un comando via sh -c trova nginx col PATH completo;
 *  4. un programma che non esiste da nessuna parte da' ancora l'errore giusto.
 * Vuole nginx in /usr/local/sbin (la VM FreeBSD); senza, lo dice e si salta.
 *
 * Uso: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.util.ShellShortPathTest
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
            System.out.println("SALTATA: serve nginx in /usr/local/sbin (la VM FreeBSD).");
            System.exit(0);
        }
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        ProcessBuilder pb = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                ShellShortPathTest.class.getName(), "child").inheritIO();
        // Come lo avvia rc.subr: niente /usr/local.
        pb.environment().put("PATH", SHORT_PATH);
        System.exit(pb.start().waitFor());
    }

    static void child() {
        System.out.println("== Un pannello avviato col PATH corto di rc.d ==");
        check("il PATH del processo e' quello corto (" + System.getenv("PATH") + ")", SHORT_PATH.equals(System.getenv("PATH")));
        Shell.Result v = Shell.run(Duration.ofSeconds(20), "nginx", "-v");
        check("Shell.run(\"nginx\", \"-v\") parte e risponde (" + v.exitCode() + ": " + v.outputTrim() + ")",
                v.success() && v.outputTrim().contains("nginx version"));
        Shell.Result t = Shell.run(Duration.ofSeconds(30), "nginx", "-t");
        check("anche nginx -t, come le migrazioni che leggono la configurazione (" + t.exitCode() + ")",
                t.exitCode() >= 0 && !t.outputTrim().contains("Cannot run program"));
        Shell.Result sh = Shell.runShell(Duration.ofSeconds(10), "command -v nginx");
        check("via sh -c il PATH completo trova nginx (" + sh.outputTrim() + ")", sh.outputTrim().equals("/usr/local/sbin/nginx"));
        Shell.Result missing = Shell.run(Duration.ofSeconds(10), "no-such-program-anywhere-e2e");
        check("un programma che non c'e' da nessuna parte: l'errore giusto (" + missing.exitCode() + ")",
                !missing.success() && missing.outputTrim().contains("no-such-program-anywhere-e2e"));
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
