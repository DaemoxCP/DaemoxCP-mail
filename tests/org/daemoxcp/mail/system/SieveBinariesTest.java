package org.daemoxcp.mail.system;

import org.daemoxcp.mail.integration.SieveGenerator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The panel's Sieve rules compiled by the Pigeonhole installed now (finding 241). After the move to Dovecot 2.4 the
 * binaries next to the panel's rules were still 2.3's: Dovecot compiled the rules again at every message and logged two
 * errors each time, and neither the move nor the panel's start noticed. Without sievec, against a fake compiler and a
 * folder made here:
 *  1. every rule is compiled; the binary is replaced only where it differs (COMPILED), kept where it is the same
 *     (UNCHANGED); a rule that does not compile is counted with its status, never with its path;
 *  2. rules that cannot be listed: nothing compiled, the reason given;
 *  3. which files are the panel's rules: domain/name/.dovecot.sieve starting with the panel's require lines; a script
 *     written by hand, a link to a folder or to a file, a file too big, a missing root: left out.
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveBinariesTest
 */
public class SieveBinariesTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** A compiler that answers from a table, and remembers what it was asked. */
    static final class Fake implements SieveBinaries.Compiler {
        final List<Path> scripts;
        final Map<Path, SieveCompiler.Status> answers;
        final List<Path> asked = new ArrayList<>();
        boolean unreadable = false;

        Fake(List<Path> scripts, Map<Path, SieveCompiler.Status> answers) { this.scripts = scripts; this.answers = answers; }

        @Override public List<Path> scripts() throws IOException {
            if (unreadable) throw new IOException("Permission denied");
            return scripts;
        }
        @Override public SieveCompiler.Outcome refresh(Path script) {
            asked.add(script);
            return new SieveCompiler.Outcome(answers.get(script), "");
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. Compiled where the binary differs, kept where it is the same");
        Path a = Path.of("/var/mail/sieve/example.test/alice/.dovecot.sieve");
        Path b = Path.of("/var/mail/sieve/example.test/bob/.dovecot.sieve");
        Path c = Path.of("/var/mail/sieve/example.test/carol/.dovecot.sieve");
        Fake f = new Fake(List.of(a, b, c), Map.of(a, SieveCompiler.Status.COMPILED, b, SieveCompiler.Status.UNCHANGED,
                c, SieveCompiler.Status.REFUSED));
        SieveBinaries.Result r = SieveBinaries.run(f);
        check("every rule asked, once", f.asked.equals(List.of(a, b, c)));
        check("1 compiled again, 1 already right", r.recompiled() == 1 && r.unchanged() == 1);
        check("the one that does not compile counted with its status, without its path",
                r.failed().equals(List.of("refused")) && !String.join(" ", r.failed()).contains("carol"));
        Fake same = new Fake(List.of(a, b), Map.of(a, SieveCompiler.Status.UNCHANGED, b, SieveCompiler.Status.UNCHANGED));
        r = SieveBinaries.run(same);
        check("all already right (the second start): nothing compiled, nothing failed",
                r.recompiled() == 0 && r.unchanged() == 2 && r.failed().isEmpty());

        System.out.println("\n== 2. Rules that cannot be listed");
        Fake locked = new Fake(List.of(a), Map.of(a, SieveCompiler.Status.COMPILED));
        locked.unreadable = true;
        r = SieveBinaries.run(locked);
        check("nothing compiled, the reason given", locked.asked.isEmpty() && r.recompiled() == 0
                && r.failed().size() == 1 && r.failed().get(0).contains("could not be listed"));

        System.out.println("\n== 3. Which files are the panel's rules");
        Path root = Files.createTempDirectory("sieve-binaries-test");
        Path other = Files.createTempDirectory("sieve-binaries-elsewhere");
        try {
            Path mine = write(root.resolve("example.test/alice/.dovecot.sieve"), SieveGenerator.REQUIRE + "keep;\n");
            write(root.resolve("example.test/bob/.dovecot.sieve"), "require \"fileinto\";\nkeep;\n");   // by hand
            Path elsewhere = write(other.resolve("carol/.dovecot.sieve"),
                    SieveGenerator.REQUIRE + "keep;\n");
            Files.createSymbolicLink(root.resolve("example.test/carol"), elsewhere.getParent());          // a folder link
            Files.createDirectories(root.resolve("example.test/dave"));
            Files.createSymbolicLink(root.resolve("example.test/dave/.dovecot.sieve"), mine);             // a file link
            Files.createSymbolicLink(root.resolve("linked.test"), root.resolve("example.test"));          // a domain link
            write(root.resolve("example.test/erin/.dovecot.sieve"), SieveGenerator.REQUIRE + "#".repeat(70_000) + "\n");
            List<Path> found = SieveBinaries.panelScripts(root);
            check("only the panel's own rule: " + found, found.equals(List.of(mine)));
            check("a missing root: nothing", SieveBinaries.panelScripts(root.resolve("missing")).isEmpty());
        } finally {
            deleteTree(root);
            deleteTree(other);
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static Path write(Path p, String text) throws IOException {
        Files.createDirectories(p.getParent());
        Files.writeString(p, text);
        return p;
    }

    static void deleteTree(Path p) throws IOException {
        if (!Files.exists(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return;
        if (Files.isDirectory(p, java.nio.file.LinkOption.NOFOLLOW_LINKS))
            try (var s = Files.list(p)) { for (Path q : s.toList()) deleteTree(q); }
        Files.delete(p);
    }
}
