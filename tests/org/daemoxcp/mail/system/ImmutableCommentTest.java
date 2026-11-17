package org.daemoxcp.mail.system;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * A file the panel keeps immutable (chflags schg, as /var/unbound/forward.conf) gets the product name in its comments
 * like the others, and stays immutable (PanelMarker.rewrite / replaceKeeping). On the real server, on 17/11/2026, the
 * rename could not replace forward.conf ("Operation not permitted") and the upgrade stopped at the first start.
 *
 * It needs FreeBSD and root (chflags), in a temporary folder; anywhere else it says so and stops:
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.ImmutableCommentTest
 */
public class ImmutableCommentTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String sh(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes()).trim();
        p.waitFor();
        return out;
    }

    public static void main(String[] args) throws Exception {
        if (!"root".equals(System.getProperty("user.name")) || !Files.isExecutable(Path.of("/bin/chflags"))) {
            OUT.println("  --   it needs root and chflags (the FreeBSD VM): not run");
            return;
        }
        String old = LegacyNames.oldNamesOf("panelSignature", PanelMarker.WRITTEN).get(2);
        Path dir = Files.createTempDirectory("immutable-comment");
        Path f = dir.resolve("forward.conf");
        Files.writeString(f, "# " + old + ": direct recursive mode\nserver:\n");
        sh("/bin/chflags", "schg", f.toString());
        try {
            check("the file starts immutable", PanelMarker.immutableFlags(f).contains("schg"));

            OUT.println("\n== The product name in the comments of an immutable file ==");
            List<String> done = new ArrayList<>(), problems = new ArrayList<>();
            boolean ok = PanelMarker.rewrite(f, "productComments", done, problems);
            OUT.println("        -> done " + done + ", problems " + problems);
            check("rewritten, no problem", ok && done.contains(f.toString()) && problems.isEmpty());
            check("  the comment has today's name, the rest is the same",
                    Files.readString(f).equals("# " + PanelMarker.WRITTEN + ": direct recursive mode\nserver:\n"));
            check("  and the file is immutable again (" + sh("/usr/bin/stat", "-f", "%Sf", f.toString()) + ")",
                    PanelMarker.immutableFlags(f).contains("schg"));
            check("  no temporary file left", sh("/bin/ls", "-a", dir.toString()).lines().noneMatch(l -> l.endsWith(".tmp")));

            OUT.println("\n== The second start ==");
            done.clear();
            problems.clear();
            check("nothing to do", !PanelMarker.stale(f, "productComments"));
        } finally {
            sh("/bin/chflags", "noschg", f.toString());
            Files.deleteIfExists(f);
            Files.deleteIfExists(dir);
        }

        OUT.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
