package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * The jar without the version in its name (0.9.0): on servers installed before, the panel adds daemoxcp-mail.jar next
 * to daemoxcp-mail-1.0.jar as a link (JarName), so the README's console commands work everywhere. In a temporary folder.
 *
 * It runs anywhere:
 *   java -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.system.JarNameTest
 */
public class JarNameTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("jar-name-test");
        try {
            Path old = dir.resolve("daemoxcp-mail-1.0.jar"), link = dir.resolve("daemoxcp-mail.jar");
            Files.write(old, new byte[]{1, 2, 3});

            System.out.println("== A server installed before 0.9.0 ==");
            check("first start: the link is made", JarName.ensure(old) == JarName.Outcome.LINKED);
            check("it is a link, relative, to the running jar", Files.isSymbolicLink(link)
                    && Files.readSymbolicLink(link).equals(Path.of("daemoxcp-mail-1.0.jar")));
            check("through it, the same bytes", Arrays.equals(Files.readAllBytes(link), new byte[]{1, 2, 3}));
            check("second start: nothing to do", JarName.ensure(old) == JarName.Outcome.NOTHING);
            Files.write(old, new byte[]{4, 5});
            check("the jar replaced in place (upgrade-panel.sh): the link follows it",
                    Arrays.equals(Files.readAllBytes(link), new byte[]{4, 5}));

            System.out.println("\n== Links and files that are not ours ==");
            Files.delete(link);
            Files.createSymbolicLink(link, Path.of("somewhere-else.jar"));
            check("a link to something else is pointed back at the running jar", JarName.ensure(old) == JarName.Outcome.RELINKED
                    && Files.readSymbolicLink(link).equals(Path.of("daemoxcp-mail-1.0.jar")));
            Files.delete(link);
            Files.write(link, new byte[]{9});
            check("a real file with that name is left alone", JarName.ensure(old) == JarName.Outcome.BLOCKED
                    && Arrays.equals(Files.readAllBytes(link), new byte[]{9}));
            Files.delete(link);

            System.out.println("\n== A server installed from 0.9.0 ==");
            Files.move(old, link);
            check("the jar already has the name: nothing", JarName.ensure(link) == JarName.Outcome.NOTHING && !Files.isSymbolicLink(link));
            check("no jar: nothing", JarName.ensure(dir.resolve("missing.jar")) == JarName.Outcome.NOTHING);
        } finally {
            try (var s = Files.list(dir)) { s.forEach(p -> { try { Files.delete(p); } catch (Exception ignored) { } }); }
            Files.deleteIfExists(dir);
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
