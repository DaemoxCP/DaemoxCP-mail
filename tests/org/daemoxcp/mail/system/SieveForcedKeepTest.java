package org.daemoxcp.mail.system;

import org.daemoxcp.mail.integration.SieveGenerator;
import org.daemoxcp.mail.integration.SieveGeneratorTest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;

/**
 * The forced keep taken out of the panel's Sieve scripts already written, at boot (reperto 216).
 *
 *  1. fixed(): a script the panel wrote before (both require lines it ever wrote, with and without "date") loses only the
 *     tail, and becomes byte for byte what SieveGenerator writes now for the same rules; anything else (already fixed,
 *     written by hand, another require, the tail not at the end) is left alone.
 *  2. repair() on a folder like /var/mail/sieve: only domain/user/.dovecot.sieve regular files of the panel, owner and
 *     mode kept, each compiled once; a ManageSieve link and files at other depths untouched; a script that the compiler
 *     refuses goes back as it was; the second run finds nothing.
 *  3. With -De2e.vm=yes, on the VM: the real sievec through the panel's compileScript, the binary newer than the script.
 *
 *   java [-De2e.vm=yes] -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.SieveForcedKeepTest
 */
public class SieveForcedKeepTest {

    private static int failures = 0;

    /** What the generator wrote before reperto 229: the require line without "mailbox", fileinto without :create. */
    static String before229(String script) {
        return script.replace(SieveGenerator.REQUIRE, SieveGenerator.REQUIRE_BEFORE_MAILBOX)
                .replace("fileinto :copy :create ", "fileinto :copy ").replace("fileinto :create ", "fileinto ");
    }

    public static void main(String[] args) throws Exception {
        SieveGenerator generator = new SieveGenerator();
        // The scripts this repair meets were written before reperto 229 (no "mailbox", no :create): "now" here is what
        // the generator wrote then, without the forced keep. SieveRulesRefresh brings them to today's text afterwards.
        String moveNow = before229(generator.generateSieveScript(1, new SieveGeneratorTest.Rules().filter("spam", "move", "Junk")));
        String forwardNow = before229(generator.generateSieveScript(1, new SieveGeneratorTest.Rules().forward("bob@example.test", false)
                .away("Away", "Back on Monday")));
        String noneNow = before229(generator.generateSieveScript(1, new SieveGeneratorTest.Rules()));
        check("the generator's text before reperto 229 starts with the require line of then",
                moveNow.startsWith(SieveGenerator.REQUIRE_BEFORE_MAILBOX) && !moveNow.contains(":create"));
        String moveBefore = moveNow + SieveGenerator.OLD_FORCED_KEEP;

        System.out.println("== 1. fixed() ==");
        check("a move written before: exactly what the generator writes now", moveNow.equals(SieveForcedKeep.fixed(moveBefore)));
        check("a forward and an autoresponder written before: the same",
                forwardNow.equals(SieveForcedKeep.fixed(forwardNow + SieveGenerator.OLD_FORCED_KEEP)));
        check("a script without rules written before: just the require line",
                noneNow.equals(SieveForcedKeep.fixed(noneNow + SieveGenerator.OLD_FORCED_KEEP)));
        String olderRequire = moveBefore.replace(SieveGenerator.REQUIRE_BEFORE_MAILBOX, SieveForcedKeep.REQUIRE_WITHOUT_DATE);
        check("the require line of before \"date\": the tail goes, the rest stays",
                !olderRequire.equals(moveBefore) && SieveForcedKeep.fixed(olderRequire) != null
                && SieveForcedKeep.fixed(olderRequire).equals(moveNow.replace(SieveGenerator.REQUIRE_BEFORE_MAILBOX, SieveForcedKeep.REQUIRE_WITHOUT_DATE)));
        check("already fixed: nothing", SieveForcedKeep.fixed(moveNow) == null && SieveForcedKeep.fixed(noneNow) == null);
        check("written by hand, ending with keep: nothing", SieveForcedKeep.fixed("require \"fileinto\";\nfileinto \"X\";\n"
                + "\n# Default action\nkeep;\n") == null);
        check("another require line: nothing", SieveForcedKeep.fixed(moveBefore.replace("\"date\"", "\"date\", \"mailbox\"")) == null);
        check("the tail not at the end: nothing", SieveForcedKeep.fixed(moveBefore + "stop;\n") == null);
        check("a keep the user chose inside a rule stays (only the last lines go)",
                SieveForcedKeep.fixed(moveBefore.replace("fileinto \"Junk\";", "keep;")).contains("  keep;\n"));
        check("no file: nothing", SieveForcedKeep.fixed(null) == null);

        System.out.println("\n== 2. repair() on a folder ==");
        Path root = Files.createTempDirectory(Path.of(System.getProperty("java.io.tmpdir")), "sieve-forced-keep");
        try {
            Path rules = Files.createDirectories(root.resolve("sieve"));
            Path alice = write(rules.resolve("example.test/alice/.dovecot.sieve"), moveBefore);
            Files.setPosixFilePermissions(alice, PosixFilePermissions.fromString("rw-r-----"));
            Path bob = write(rules.resolve("example.test/bob/.dovecot.sieve"), forwardNow);
            Path carolScript = write(rules.resolve("example.test/carol/mine.sieve"), moveBefore);
            Path carol = Files.createSymbolicLink(rules.resolve("example.test/carol/.dovecot.sieve"), Path.of("mine.sieve"));
            Path global = write(rules.resolve("global/.dovecot.sieve"), moveBefore);
            Path deep = write(rules.resolve("example.test/dave/x/.dovecot.sieve"), moveBefore);
            Path other = write(rules.resolve("example.test/erin/old.sieve"), moveBefore);
            String aliceOwner = Files.getOwner(alice).getName();

            List<Path> compiled = new ArrayList<>();
            SieveForcedKeep.Outcome o = SieveForcedKeep.repair(rules, p -> { compiled.add(p); return true; });
            check("one script fixed (" + o.fixed() + "), none put back", o.fixed() == 1 && o.putBack().isEmpty());
            check("  the panel's script with the tail: as the generator writes it now", Files.readString(alice).equals(moveNow));
            check("  same mode and owner as before", PosixFilePermissions.toString(Files.getPosixFilePermissions(alice)).equals("rw-r-----")
                    && Files.getOwner(alice).getName().equals(aliceOwner));
            check("  compiled once, that one only", compiled.equals(List.of(alice)));
            try (var left = Files.list(alice.getParent())) {
                check("  no temporary file left beside it", left.map(p -> p.getFileName().toString()).toList().equals(List.of(".dovecot.sieve")));
            }
            check("already fixed: untouched", Files.readString(bob).equals(forwardNow));
            check("a ManageSieve link and what it points to: untouched", Files.isSymbolicLink(carol)
                    && Files.readString(carolScript).equals(moveBefore));
            check("files at another depth or with another name: untouched", Files.readString(global).equals(moveBefore)
                    && Files.readString(deep).equals(moveBefore) && Files.readString(other).equals(moveBefore));
            check("second run: nothing to do", SieveForcedKeep.repair(rules, p -> { compiled.add(p); return true; }).fixed() == 0
                    && compiled.size() == 1);

            Path frank = write(rules.resolve("example.test/frank/.dovecot.sieve"), moveBefore);
            List<String> seen = new ArrayList<>();
            SieveForcedKeep.Outcome refused = SieveForcedKeep.repair(rules, p -> {
                try { seen.add(Files.readString(p)); } catch (Exception e) { seen.add("?"); }
                return seen.size() > 1;
            });
            check("the compiler refuses: the script goes back as it was", refused.fixed() == 0
                    && refused.putBack().equals(List.of(frank)) && Files.readString(frank).equals(moveBefore));
            check("  compiled without the tail first, then as it was", seen.equals(List.of(moveNow, moveBefore)));
            check("no folder: nothing", SieveForcedKeep.repair(root.resolve("none"), p -> true).fixed() == 0);

            System.out.println("\n== 3. The real sievec ==");
            Path sievec = Path.of("/usr/local/bin/sievec");
            if ("yes".equals(System.getProperty("e2e.vm")) && Files.isExecutable(sievec)) {
                // A folder of its own: frank, above, was put back with the tail on purpose. Open to everyone like
                // /var/mail/sieve: sievec runs as its own user (reperto 218) and must reach the script.
                Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-xr-x"));
                Path real3 = Files.createDirectories(root.resolve("sieve-real"));
                Path gina = write(real3.resolve("example.test/gina/.dovecot.sieve"), moveBefore);
                check("the old script compiles", generator.compileScript(gina.toString()));
                Path binary = gina.resolveSibling(".dovecot.svbin");
                check("  and its binary is beside it", Files.isRegularFile(binary));
                Thread.sleep(1100);
                SieveForcedKeep.Outcome real = SieveForcedKeep.repair(real3, p -> generator.compileScript(p.toString()));
                check("fixed with the real sievec", real.fixed() == 1 && real.putBack().isEmpty()
                        && Files.readString(gina).equals(moveNow));
                check("  the compiled binary is newer than the script, so Dovecot uses it", Files.isRegularFile(binary)
                        && Files.getLastModifiedTime(binary).compareTo(Files.getLastModifiedTime(gina)) > 0);
            } else {
                System.out.println("  (skipped: needs sievec, turned on with -De2e.vm=yes on the VM)");
            }
        } finally {
            new ProcessBuilder("rm", "-rf", root.toString()).start().waitFor();
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    static Path write(Path file, String content) throws Exception {
        Files.createDirectories(file.getParent());
        return Files.writeString(file, content);
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
