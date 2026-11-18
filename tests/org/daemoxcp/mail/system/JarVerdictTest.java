package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Removing a package stops or goes on according to the jar's verdict (panelUsage).
 *
 * On 25/10/2026 the verdicts moved to English on two sides (whoever produces them and the page),
 * but not on the third: the removal guard still looked for the Italian prefix of the libraries
 * verdict, and from then on removing a library the panel does not use was refused. The compiler
 * does not see it. Here: the verdicts the guard accepts are exactly the intended ones, and each is
 * one that panelUsage really produces (read from the source).
 *
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail.jar" org.daemoxcp.mail.system.JarVerdictTest &lt;source root&gt;
 */
public class JarVerdictTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final Set<String> ACCEPTED = Set.of("PANEL_DOES_NOT_USE", "NAMES_NOT_THEIRS", "LIBRARY_ONLY");

    public static void main(String[] args) throws Exception {
        Path root = Path.of(args.length > 0 ? args[0] : ".");
        String src = Files.readString(root.resolve("src/main/java/org/daemoxcp/mail/system/UpdateManager.java"));

        // The verdicts panelUsage produces: the strings assigned to "verdict" in its body.
        int from = src.indexOf("static JSONObject panelUsage(");
        int to = from < 0 ? -1 : src.indexOf("\n    }\n", from);
        String body = from < 0 || to < 0 ? "" : src.substring(from, to);
        Set<String> produced = new LinkedHashSet<>();
        Matcher m = Pattern.compile("verdict\\s*=[^;]*").matcher(body);
        while (m.find()) {
            Matcher q = Pattern.compile("\"([A-Z_]+)\"").matcher(m.group());
            while (q.find()) produced.add(q.group(1));
        }
        check("from the source, panelUsage's verdicts: " + produced, produced.size() >= 5);

        for (String v : produced)
            check((ACCEPTED.contains(v) ? "lets it proceed " : "stops ") + v,
                    UpdateManager.removableByJarVerdict(v) == ACCEPTED.contains(v));
        check("each of those that let it proceed comes from panelUsage", produced.containsAll(ACCEPTED));
        check("an empty or unknown verdict stops", !UpdateManager.removableByJarVerdict("")
                && !UpdateManager.removableByJarVerdict(null) && !UpdateManager.removableByJarVerdict("absent"));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
