package org.mail_panel.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * La rimozione di un pacchetto si ferma o va avanti secondo il verdetto del jar (panelUsage).
 *
 * Il 25/10/2026 i verdetti sono passati all'inglese su due lati (chi li produce e la pagina), ma
 * non sul terzo: la guardia della rimozione cercava ancora il prefisso italiano del verdetto delle
 * librerie, e da allora la rimozione di una libreria che il pannello non usa veniva rifiutata. La
 * compilazione non lo vede. Qui: i verdetti che la guardia accetta sono esattamente quelli voluti,
 * e ognuno e' uno di quelli che panelUsage produce davvero (letto dal sorgente).
 *
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.JarVerdictTest &lt;radice dei sorgenti&gt;
 */
public class JarVerdictTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    static final Set<String> ACCEPTED = Set.of("PANEL_DOES_NOT_USE", "NAMES_NOT_THEIRS", "LIBRARY_ONLY");

    public static void main(String[] args) throws Exception {
        Path root = Path.of(args.length > 0 ? args[0] : ".");
        String src = Files.readString(root.resolve("src/main/java/org/mail_panel/system/UpdateManager.java"));

        // I verdetti che panelUsage produce: le stringhe assegnate a "verdict" nel suo corpo.
        int from = src.indexOf("static JSONObject panelUsage(");
        int to = from < 0 ? -1 : src.indexOf("\n    }\n", from);
        String body = from < 0 || to < 0 ? "" : src.substring(from, to);
        Set<String> produced = new LinkedHashSet<>();
        Matcher m = Pattern.compile("verdict\\s*=[^;]*").matcher(body);
        while (m.find()) {
            Matcher q = Pattern.compile("\"([A-Z_]+)\"").matcher(m.group());
            while (q.find()) produced.add(q.group(1));
        }
        check("dal sorgente, i verdetti di panelUsage: " + produced, produced.size() >= 5);

        for (String v : produced)
            check((ACCEPTED.contains(v) ? "lascia procedere " : "ferma ") + v,
                    UpdateManager.removableByJarVerdict(v) == ACCEPTED.contains(v));
        check("ognuno di quelli che lasciano procedere viene da panelUsage", produced.containsAll(ACCEPTED));
        check("un verdetto vuoto o sconosciuto ferma", !UpdateManager.removableByJarVerdict("")
                && !UpdateManager.removableByJarVerdict(null) && !UpdateManager.removableByJarVerdict("absent"));

        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        if (failed > 0) System.exit(1);
    }
}
