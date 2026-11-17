package org.daemoxcp.mail.system;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Resetting the memory of the automatic replies, and the boot repair of what the old reset left (reperto 219).
 *
 * Until 10/11/2026 the panel's "reset tracking" also deleted the compiled binary beside the panel's Sieve rules and ran
 * `service dovecot restart`. Pigeonhole keeps the senders already answered in .dovecot.lda-dupes in the mailbox's home,
 * and nowhere else. Without a system:
 *  1. duplicatesOf(): the file is vmail/domain/user/home/.dovecot.lda-dupes (Dovecot's home, reperto 217), and an
 *     address that is not one gives nothing
 *     (it comes from MySQL, and root makes a path of it);
 *  2. reset() on a folder like /var/vmail: only that file goes; the mail, the lock folder beside it and the other
 *     mailboxes stay; twice is fine; an address that would leave the folder touches nothing;
 *  3. stale(): a binary that is missing, older, as old as the script or a link is stale; a strictly newer one is not;
 *  4. repair() on a folder like /var/mail/sieve: only the panel's scripts without a newer binary are compiled, once; a
 *     ManageSieve link and files at other depths are left; a compiler that fails, or says yes and installs nothing, is
 *     reported; the second run finds nothing.
 * The real deliveries, the binary left alone and Dovecot not restarted are in VacationTrackingE2ETest.
 *
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.VacationTrackingTest
 */
public class VacationTrackingTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory(Path.of(System.getProperty("java.io.tmpdir")), "vacation-tracking");
        try {
            run(base);
        } finally {
            new ProcessBuilder("rm", "-rf", base.toString()).start().waitFor();
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    static void run(Path base) throws Exception {
        Path homes = Files.createDirectories(base.resolve("vmail"));

        System.out.println("== 1. duplicatesOf() ==");
        check("alice@example.test: vmail/example.test/alice/home/.dovecot.lda-dupes",
                homes.resolve("example.test/alice/home/.dovecot.lda-dupes").equals(VacationTracking.duplicatesOf(homes, "alice@example.test")));
        check("the name of the file is Dovecot's duplicate database", VacationTracking.DUPLICATES.equals(".dovecot.lda-dupes"));
        for (String bad : new String[]{"../../outside@example.test", "alice@..", "a/b@example.test", "alice@example.test@x.test",
                "alice", "", "@example.test", "alice@", ".alice@example.test", "al..ice@example.test"})
            check("not an address, nothing: \"" + bad + "\"", VacationTracking.duplicatesOf(homes, bad) == null);
        check("no address, nothing", VacationTracking.duplicatesOf(homes, null) == null);

        System.out.println("\n== 2. reset() on a folder like /var/vmail ==");
        Path alice = Files.createDirectories(homes.resolve("example.test/alice"));
        Path aliceHome = Files.createDirectories(alice.resolve("home"));
        Path dupes = write(aliceHome.resolve(".dovecot.lda-dupes"), "tracking");
        Path oldDupes = write(alice.resolve(".dovecot.lda-dupes"), "tracking of before reperto 217");
        Path locks = Files.createDirectories(aliceHome.resolve(".dovecot.lda-dupes.locks"));
        Path mail = write(Files.createDirectories(alice.resolve("cur")).resolve("1.mail:2,S"), "a message");
        Path bobDupes = write(Files.createDirectories(homes.resolve("example.test/bob/home")).resolve(".dovecot.lda-dupes"), "bob's");
        Path outside = write(Files.createDirectories(base.resolve("outside")).resolve(".dovecot.lda-dupes"), "not a mailbox");
        check("reset(alice@example.test) says yes", VacationTracking.reset(homes, "alice@example.test"));
        check("  her .dovecot.lda-dupes is gone", !Files.exists(dupes));
        check("  and the one of before, in the mailbox's root, too", !Files.exists(oldDupes));
        check("  her mail stays", Files.isRegularFile(mail));
        check("  the lock folder beside it stays (Dovecot's own)", Files.isDirectory(locks));
        check("  bob's memory stays", Files.isRegularFile(bobDupes));
        check("twice: yes again, nothing to do", VacationTracking.reset(homes, "alice@example.test"));
        check("a mailbox with no memory yet: yes", VacationTracking.reset(homes, "carol@example.test")
                && !Files.exists(homes.resolve("example.test/carol")));
        check("an address that would leave the folder: no, and nothing outside is touched",
                !VacationTracking.reset(homes, "../../outside@example.test") && Files.isRegularFile(outside));

        System.out.println("\n== 3. stale() ==");
        Path rules = Files.createDirectories(base.resolve("sieve"));
        Path noBinary = script(rules, "example.test", "alice", null);
        Path older = script(rules, "example.test", "bob", -60_000L);
        Path same = script(rules, "example.test", "dave", 0L);
        Path newer = script(rules, "example.test", "carol", 60_000L);
        Path linked = script(rules, "example.test", "erin", null);
        Path target = write(base.resolve("elsewhere.svbin"), "binary");
        Files.setLastModifiedTime(target, FileTime.fromMillis(Files.getLastModifiedTime(linked).toMillis() + 60_000));
        Files.createSymbolicLink(linked.resolveSibling(".dovecot.svbin"), target);
        check("no binary: stale", VacationTracking.stale(noBinary));
        check("a binary older than the script: stale", VacationTracking.stale(older));
        check("a binary as old as the script: stale (Pigeonhole wants it strictly newer)", VacationTracking.stale(same));
        check("a binary strictly newer: not stale", !VacationTracking.stale(newer));
        check("a link to a newer binary: stale (not a binary of the panel)", VacationTracking.stale(linked));

        System.out.println("\n== 4. repair() on a folder like /var/mail/sieve ==");
        Path link = Files.createDirectories(rules.resolve("example.test/frank")).resolve(".dovecot.sieve");
        Files.createSymbolicLink(link, noBinary);
        Path otherDepth = write(Files.createDirectories(rules.resolve("global")).resolve(".dovecot.sieve"), "require \"fileinto\";\n");
        List<Path> asked = new ArrayList<>();
        VacationTracking.Outcome o = VacationTracking.repair(rules, s -> {
            asked.add(s);
            return install(s);
        });
        List<Path> expected = List.of(older, noBinary, same, linked);
        System.out.println("  compiled: " + names(rules, o.compiled()) + ", not compiled: " + names(rules, o.notCompiled()));
        check("compiled: the four without a newer binary (alice, bob, dave, erin)",
                o.compiled().size() == 4 && o.compiled().containsAll(expected) && o.notCompiled().isEmpty());
        check("  each once", asked.size() == 4);
        check("  each now with a binary of its own, newer", !VacationTracking.stale(noBinary) && !VacationTracking.stale(older)
                && !VacationTracking.stale(same) && !VacationTracking.stale(linked)
                && !Files.isSymbolicLink(linked.resolveSibling(".dovecot.svbin")));
        check("  carol's newer binary not compiled again", !asked.contains(newer));
        check("  the ManageSieve link and the file at another depth left", !asked.contains(link) && !asked.contains(otherDepth)
                && !Files.exists(otherDepth.resolveSibling(".dovecot.svbin")));
        asked.clear();
        o = VacationTracking.repair(rules, s -> { asked.add(s); return install(s); });
        check("the second run finds nothing", asked.isEmpty() && o.compiled().isEmpty() && o.notCompiled().isEmpty());

        Files.deleteIfExists(noBinary.resolveSibling(".dovecot.svbin"));
        Files.setLastModifiedTime(older, FileTime.fromMillis(Files.getLastModifiedTime(older.resolveSibling(".dovecot.svbin")).toMillis() + 60_000));
        o = VacationTracking.repair(rules, s -> s.equals(noBinary) ? false : true);
        check("a compiler that fails, and one that says yes and installs nothing: both reported, nothing counted as done",
                o.compiled().isEmpty() && o.notCompiled().size() == 2 && o.notCompiled().containsAll(List.of(noBinary, older)));
        check("the default folders are the panel's", VacationTracking.HOMES.equals(Path.of("/var/vmail"))
                && VacationTracking.PANEL_RULES.equals(Path.of("/var/mail/sieve")));
    }

    /** A script at rules/domain/user/.dovecot.sieve, with a binary beside it that many ms after it (null: no binary). */
    static Path script(Path rules, String domain, String user, Long binaryAfter) throws Exception {
        Path s = write(Files.createDirectories(rules.resolve(domain).resolve(user)).resolve(".dovecot.sieve"), "require \"vacation\";\n");
        FileTime t = FileTime.fromMillis(System.currentTimeMillis() - 3_600_000);
        Files.setLastModifiedTime(s, t);
        if (binaryAfter != null) {
            Path b = write(s.resolveSibling(".dovecot.svbin"), "binary");
            Files.setLastModifiedTime(b, FileTime.fromMillis(t.toMillis() + binaryAfter));
        }
        return s;
    }

    /** What a compiler that works does: a binary beside the script, a second after it. */
    static boolean install(Path script) {
        try {
            Path b = script.resolveSibling(".dovecot.svbin");
            Files.deleteIfExists(b);
            write(b, "compiled " + script);
            Files.setLastModifiedTime(b, FileTime.fromMillis(Files.getLastModifiedTime(script).toMillis() + 1000));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static List<String> names(Path root, List<Path> ps) {
        return ps.stream().map(p -> root.relativize(p).toString()).sorted().toList();
    }

    static Path write(Path p, String s) throws Exception {
        Files.writeString(p, s, StandardCharsets.UTF_8);
        return p;
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
