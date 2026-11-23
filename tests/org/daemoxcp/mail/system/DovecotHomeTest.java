package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.scripts.DovecotConfig;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Every mailbox's Dovecot home in its own folder, home/, not the mail root (finding 217).
 *
 * With home = the Maildir root (/var/vmail/domain/user), the files Dovecot keeps in the home showed up as mail folders:
 * after one autoreply IMAP LIST gave "dovecot", "dovecot.lda-dupes" and "dovecot.lda-dupes.locks" (measured on the VM).
 * Dovecot's documentation: the home should not be the Maildir; "home under mail" (home=/var/vmail/domain/user/home/) is
 * one of the layouts it lists.
 *
 *  1. What the panel writes from now on, 2.3 and 2.4: the home in home/, the mail where it was.
 *  2. The migration of the configuration: the home the panel wrote (2.3 args, 2.4 fields) gets /home, the rest of the
 *     file untouched; already done, written by hand, twice: nothing.
 *  3. The work on the files (the script vmail runs), on a folder like /var/vmail: prepare copies, undo takes the copies
 *     away, finish moves what is left in the root, removes the false folder unless it holds mail, never chooses between
 *     two different user scripts, never goes through a link; the second run does nothing.
 *
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.DovecotHomeTest      (on the VM)
 */
public class DovecotHomeTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        I18n.setCurrent("en");
        System.out.println("== 1. What the panel writes ==");
        String fragment = DovecotConfig.fromPanelConfig().scriptFragment();
        check("2.3: home in home/, inside the mailbox's folder", fragment.contains("  args = uid=vmail gid=vmail home=/var/vmail/%d/%n/home\n"));
        check("  the mail stays in the mailbox's root", fragment.contains("mail_location = maildir:/var/vmail/%d/%n\n"));
        String auth24 = DovecotConfig.file24().stream().filter(f -> f.path().equals("conf.d/auth-sql.conf.ext")).findFirst().get().content();
        String mail24 = DovecotConfig.file24().stream().filter(f -> f.path().equals("conf.d/10-mail.conf")).findFirst().get().content();
        check("2.4: home in home/", auth24.contains("    home = /var/vmail/%{user | domain}/%{user | username}/home\n"));
        check("  the mail stays in the mailbox's root", mail24.contains("mail_path = /var/vmail/%{user | domain}/%{user | username}\n"));
        check("both are what the migration calls done", DovecotHome.usesHome(fragment) && DovecotHome.usesHome(auth24)
                && DovecotHome.migrated(auth24) == null);
        check("the home of a mailbox", DovecotHome.of("example.test", "alice").equals(Path.of("/var/vmail/example.test/alice/home")));
        check("  not out of /var/vmail", throwsOn(() -> DovecotHome.of("..", "alice")) && throwsOn(() -> DovecotHome.of("example.test", "a/b")));

        System.out.println("\n== 2. The migration of the configuration ==");
        String before23 = "passdb {\n  driver = sql\n  args = /usr/local/etc/dovecot/dovecot-sql.conf\n}\nuserdb {\n"
                + "  driver = static\n  args = uid=vmail gid=vmail home=/var/vmail/%d/%n\n}\n";
        String after23 = DovecotHome.migrated(before23);
        check("2.3: the panel's home gets /home, nothing else changes", after23 != null
                && after23.equals(before23.replace("home=/var/vmail/%d/%n\n", "home=/var/vmail/%d/%n/home\n")));
        check("  with numeric ids (an older installer) too", DovecotHome.migrated(before23.replace("uid=vmail gid=vmail", "uid=5000 gid=5000")) != null);
        check("  home before other args too", "  args = home=/var/vmail/%d/%n/home uid=vmail\n".equals(
                DovecotHome.migrated("  args = home=/var/vmail/%d/%n uid=vmail\n")));
        check("  already done: nothing, and it is called done", DovecotHome.migrated(after23) == null && DovecotHome.usesHome(after23));
        check("  another home (written by hand): nothing", DovecotHome.migrated(before23.replace("%d/%n", "%d/%n/Maildir")) == null
                && DovecotHome.migrated(before23.replace("/var/vmail/", "/home/vmail/")) == null
                && !DovecotHome.usesHome(before23));
        check("  the panel's home twice (which one?): nothing", DovecotHome.migrated(before23 + before23) == null);
        String before24 = "passdb sql {\n  query = SELECT 1\n}\n\nuserdb static {\n  fields {\n    uid = vmail\n    gid = vmail\n"
                + "    home = /var/vmail/%{user | domain}/%{user | username}\n  }\n}\n";
        String after24 = DovecotHome.migrated(before24);
        check("2.4: the panel's home gets /home, same indentation, nothing else changes", after24 != null
                && after24.equals(before24.replace("%{user | username}\n  }", "%{user | username}/home\n  }")));
        check("  already done: nothing", DovecotHome.migrated(after24) == null && DovecotHome.usesHome(after24));
        check("  the 2.4 file the panel writes now: nothing to do", DovecotHome.migrated(auth24) == null);
        check("no file: nothing", DovecotHome.migrated(null) == null);

        System.out.println("\n== 3. The work on the files ==");
        Path tmp = Files.createTempDirectory(Path.of("/var/tmp"), "dovecot-home-test");
        try {
            Path root = Files.createDirectories(tmp.resolve("vmail"));
            Path alice = maildir(root.resolve("example.test/alice"));
            write(alice.resolve(".dovecot.lda-dupes"), "alice dupes");
            write(alice.resolve("sieve/own.sieve"), "require \"fileinto\";\n");
            Files.createSymbolicLink(alice.resolve("dovecot.sieve"), Path.of("sieve/own.sieve"));
            Path alicePhantom = maildir(alice.resolve(".dovecot.lda-dupes.locks"));
            write(alicePhantom.resolve("dovecot-uidlist"), "3 V1 N1\n");
            write(alicePhantom.resolve("0a1b2c3d"), "");
            Path bob = maildir(root.resolve("example.test/bob"));
            Path bobPhantom = maildir(bob.resolve(".dovecot.lda-dupes.locks"));
            write(bobPhantom.resolve("cur/1700000000.M1P1.host:2,S"), "Subject: moved here by the user\n\nhello\n");
            Path elsewhere = maildir(tmp.resolve("elsewhere/carol"));
            write(elsewhere.resolve(".dovecot.lda-dupes"), "not under the root");
            Files.createSymbolicLink(root.resolve("example.test/carol"), elsewhere);
            Path dave = maildir(root.resolve("example.test/dave"));
            Path erin = maildir(root.resolve("example.test/erin"));
            write(erin.resolve("sieve/old.sieve"), "keep;\n");
            write(erin.resolve("home/sieve/new.sieve"), "discard;\n");
            Path frank = maildir(root.resolve("other.test/frank"));
            write(frank.resolve(".dovecot.lda-dupes"), "frank older");
            write(frank.resolve("home/.dovecot.lda-dupes"), "frank newer");
            Files.setLastModifiedTime(frank.resolve(".dovecot.lda-dupes"), FileTime.fromMillis(System.currentTimeMillis() - 3_600_000));
            Path gina = maildir(root.resolve("other.test/gina"));
            write(gina.resolve(".dovecot.lda-dupes"), "gina newer");
            write(gina.resolve("home/.dovecot.lda-dupes"), "gina older");
            Files.setLastModifiedTime(gina.resolve("home/.dovecot.lda-dupes"), FileTime.fromMillis(System.currentTimeMillis() - 3_600_000));
            Path notYet = Files.createDirectories(root.resolve("other.test/henry"));

            List<String> out = run("prepare", root);
            check("prepare: it went well (exit 0)", lastExit == 0);
            check("prepare: alice's files copied into her home", out.contains("COPIED " + alice + "/.dovecot.lda-dupes")
                    && out.contains("COPIED " + alice + "/sieve") && out.contains("COPIED " + alice + "/dovecot.sieve")
                    && Files.readString(alice.resolve("home/.dovecot.lda-dupes")).equals("alice dupes")
                    && Files.readString(alice.resolve("home/sieve/own.sieve")).startsWith("require"));
            check("  the active script is still a link to sieve/own.sieve, inside the home",
                    Files.isSymbolicLink(alice.resolve("home/dovecot.sieve"))
                    && Files.readSymbolicLink(alice.resolve("home/dovecot.sieve")).equals(Path.of("sieve/own.sieve"))
                    && Files.readString(alice.resolve("home/dovecot.sieve")).startsWith("require"));
            check("  the originals are still in the root (the configuration of before uses them)",
                    Files.exists(alice.resolve(".dovecot.lda-dupes")) && Files.isDirectory(alice.resolve("sieve"))
                    && Files.isSymbolicLink(alice.resolve("dovecot.sieve")));
            check("  the home is for vmail only (0700)", "rwx------".equals(PosixFilePermissions.toString(Files.getPosixFilePermissions(alice.resolve("home")))));
            check("  nothing to copy: no home yet", !Files.exists(dave.resolve("home")) && !Files.exists(bob.resolve("home")));
            check("  a script already in the home is not overwritten", out.contains("BOTH " + frank + "/.dovecot.lda-dupes")
                    && Files.readString(frank.resolve("home/.dovecot.lda-dupes")).equals("frank newer"));
            check("  nothing through a link", !Files.exists(elsewhere.resolve("home")) && out.stream().noneMatch(l -> l.contains("/carol")));
            check("  the false folder is left alone for now", Files.isDirectory(alicePhantom));

            out = run("undo", root);
            check("undo: the copies go, and the empty home", !Files.exists(alice.resolve("home"))
                    && Files.readString(alice.resolve(".dovecot.lda-dupes")).equals("alice dupes") && Files.isDirectory(alice.resolve("sieve")));
            check("  what was in a home before stays (it differs)", Files.exists(erin.resolve("home/sieve/new.sieve"))
                    && Files.readString(frank.resolve("home/.dovecot.lda-dupes")).equals("frank newer"));

            run("prepare", root);
            write(gina.resolve("dovecot.sieve.log"), "written after prepare");
            out = run("finish", root);
            System.out.println(String.join("\n", out).replaceAll("(?m)^", "    | "));
            check("finish: it went well (exit 0)", lastExit == 0);
            check("  a file that appeared after prepare is moved too", out.contains("MOVED " + gina + "/dovecot.sieve.log")
                    && !Files.exists(gina.resolve("dovecot.sieve.log"))
                    && Files.readString(gina.resolve("home/dovecot.sieve.log")).equals("written after prepare"));
            check("finish: alice's files only in her home", out.contains("MOVED " + alice + "/.dovecot.lda-dupes")
                    && !Files.exists(alice.resolve(".dovecot.lda-dupes")) && !Files.exists(alice.resolve("sieve"))
                    && !Files.exists(alice.resolve("dovecot.sieve"), java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    && Files.readString(alice.resolve("home/.dovecot.lda-dupes")).equals("alice dupes")
                    && Files.readString(alice.resolve("home/dovecot.sieve")).startsWith("require"));
            check("  the false folder without mail removed", out.contains("PHANTOM_REMOVED " + alicePhantom) && !Files.exists(alicePhantom));
            check("  the false folder with a message in it left, and said", out.contains("PHANTOM_KEPT " + bobPhantom)
                    && Files.exists(bobPhantom.resolve("cur/1700000000.M1P1.host:2,S")));
            check("  a mailbox with mail gets its home", out.contains("CREATED " + dave + "/home") && Files.isDirectory(dave.resolve("home"))
                    && "rwx------".equals(PosixFilePermissions.toString(Files.getPosixFilePermissions(dave.resolve("home")))));
            check("  a folder with no mail yet does not", !Files.exists(notYet.resolve("home")));
            check("  two different scripts of the user: both left, and said", out.contains("BOTH_DIFFER " + erin + "/sieve")
                    && Files.exists(erin.resolve("sieve/old.sieve")) && Files.exists(erin.resolve("home/sieve/new.sieve")));
            check("  Dovecot's own file: the newer one stays (home newer)", !Files.exists(frank.resolve(".dovecot.lda-dupes"))
                    && Files.readString(frank.resolve("home/.dovecot.lda-dupes")).equals("frank newer"));
            check("  Dovecot's own file: the newer one stays (root newer)", !Files.exists(gina.resolve(".dovecot.lda-dupes"))
                    && Files.readString(gina.resolve("home/.dovecot.lda-dupes")).equals("gina newer"));
            check("  nothing through a link", !Files.exists(elsewhere.resolve("home"))
                    && Files.readString(elsewhere.resolve(".dovecot.lda-dupes")).equals("not under the root"));

            out = run("finish", root);
            check("second run: nothing moved, created or removed", out.stream().noneMatch(l -> l.startsWith("MOVED")
                    || l.startsWith("CREATED") || l.startsWith("PHANTOM_REMOVED") || l.startsWith("COPIED")));
            check("  what it still says: the folder with mail, the two scripts", out.contains("PHANTOM_KEPT " + bobPhantom)
                    && out.contains("BOTH_DIFFER " + erin + "/sieve") && out.size() == 2);

            Files.delete(dave.resolve("home"));
            write(dave.resolve("home"), "a file where the home goes");
            out = run("finish", root);
            check("something else where the home goes: said, and the run fails", out.contains("CONFLICT " + dave + "/home") && lastExit == 1
                    && Files.readString(dave.resolve("home")).equals("a file where the home goes"));
        } finally {
            new ProcessBuilder("rm", "-rf", tmp.toString()).start().waitFor();
        }

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static int lastExit;

    /** The script as vmail would run it, here as the current user: the lines it writes. */
    static List<String> run(String phase, Path root) throws Exception {
        Process p = new ProcessBuilder("/bin/sh", "-c", DovecotHome.SCRIPT, "sh", phase, root.toString()).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes()).trim();
        if (!p.waitFor(60, TimeUnit.SECONDS)) { p.destroyForcibly(); throw new IllegalStateException(phase + " did not finish"); }
        lastExit = p.exitValue();
        return out.isEmpty() ? List.of() : List.of(out.split("\n"));
    }

    static Path maildir(Path dir) throws Exception {
        for (String d : new String[]{"cur", "new", "tmp"}) Files.createDirectories(dir.resolve(d));
        return dir;
    }

    static Path write(Path file, String content) throws Exception {
        Files.createDirectories(file.getParent());
        return Files.writeString(file, content);
    }

    static boolean throwsOn(Runnable r) {
        try { r.run(); return false; } catch (IllegalArgumentException e) { return true; }
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
