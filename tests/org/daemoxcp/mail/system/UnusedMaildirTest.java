package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

/**
 * The empty Maildir/ folders the mailbox script used to create, and Dovecot never used, removed (UnusedMaildir). Found
 * on 20/11/2026 installing from the README on a clean VM; on the real server 12 mailboxes out of 12 had one, all empty.
 *  1. when Dovecot keeps the mail in a folder named Maildir, the folder is its own: nothing is removed;
 *  2. the script, run for real on a throwaway tree (as the user running the test; at boot it runs as vmail): an empty
 *     Maildir/ with cur, new and tmp goes; one with a message inside stays, with the message; one with an extra empty
 *     folder stays; a Maildir that is a link, and a mailbox that is a link, are not followed; a mailbox without
 *     Maildir/ is not touched; a second run finds nothing;
 *  3. the mailbox script creates the mailbox as Dovecot reads it: the mail in the mailbox's own folder, no Maildir/.
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.UnusedMaildirTest
 */
public class UnusedMaildirTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static void maildir(Path box) throws Exception {
        for (String s : new String[] {"cur", "new", "tmp"}) Files.createDirectories(box.resolve("Maildir").resolve(s));
    }

    public static void main(String[] a) throws Exception {
        System.out.println("== 1. Whose is the Maildir folder");
        check("Dovecot 2.4 path in the mailbox's folder: not Dovecot's", !UnusedMaildir.dovecotUsesMaildirFolder("/var/vmail/%{user | domain}/%{user | username}"));
        check("Dovecot 2.3 maildir:/var/vmail/%d/%n: not Dovecot's", !UnusedMaildir.dovecotUsesMaildirFolder("maildir:/var/vmail/%d/%n"));
        check("maildir:~/Maildir: Dovecot's, nothing removed", UnusedMaildir.dovecotUsesMaildirFolder("maildir:~/Maildir"));
        check("maildir:/var/vmail/%d/%n/Maildir:LAYOUT=fs: Dovecot's", UnusedMaildir.dovecotUsesMaildirFolder("maildir:/var/vmail/%d/%n/Maildir:LAYOUT=fs"));

        System.out.println("\n== 2. The script on a throwaway tree");
        Path root = Files.createTempDirectory("unused-maildir-");
        try {
            Path empty = root.resolve("example.test/alice"), full = root.resolve("example.test/bob"),
                 extra = root.resolve("example.test/carol"), none = root.resolve("example.test/dave"),
                 elsewhere = Files.createTempDirectory("unused-maildir-target-"), linked = root.resolve("example.test/erin");
            maildir(empty);
            maildir(full);
            Files.writeString(full.resolve("Maildir/new/1700000000.M1.host"), "Subject: kept\n\nhello\n");
            maildir(extra);
            Files.createDirectories(extra.resolve("Maildir/.Archive"));
            Files.createDirectories(none.resolve("cur"));
            maildir(elsewhere);
            Files.createDirectories(linked);
            Files.createSymbolicLink(linked.resolve("Maildir"), elsewhere.resolve("Maildir"));
            Files.createSymbolicLink(root.resolve("example.test/frank"), elsewhere);

            UnusedMaildir.Outcome o = UnusedMaildir.run(root);
            check("the empty one is removed (" + o.removed() + ")", o.removed().equals(java.util.List.of(empty.resolve("Maildir").toString()))
                    && !Files.exists(empty.resolve("Maildir")));
            check("the one with a message stays, message and all", o.kept().contains(full.resolve("Maildir").toString())
                    && Files.readString(full.resolve("Maildir/new/1700000000.M1.host")).contains("kept"));
            check("the one with an extra folder stays, untouched: cur, new and tmp are still there",
                    o.kept().contains(extra.resolve("Maildir").toString()) && Files.isDirectory(extra.resolve("Maildir/.Archive"))
                    && Files.isDirectory(extra.resolve("Maildir/cur")) && Files.isDirectory(extra.resolve("Maildir/tmp")));
            check("the one with a message keeps its empty cur and tmp too", Files.isDirectory(full.resolve("Maildir/cur"))
                    && Files.isDirectory(full.resolve("Maildir/tmp")));
            check("a Maildir that is a link is not followed: its target is intact", Files.isDirectory(elsewhere.resolve("Maildir/cur"))
                    && Files.isSymbolicLink(linked.resolve("Maildir")));
            check("a mailbox that is a link is not followed", !o.removed().toString().contains("frank") && !o.kept().toString().contains("frank"));
            check("a mailbox without Maildir/ is not touched", Files.isDirectory(none.resolve("cur")));
            UnusedMaildir.Outcome again = UnusedMaildir.run(root);
            check("a second run removes nothing", again.removed().isEmpty() && again.kept().size() == 2);
            deleteTree(elsewhere);
        } finally {
            deleteTree(root);
        }

        System.out.println("\n== 3. The mailbox script creates what Dovecot reads");
        String src = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/scripts/ConfigRegeneratorScript.java"));
        check("no Maildir/ under the mailbox any more", !src.contains("\"/Maildir/\""));
        check("cur, new and tmp in the mailbox's folder, and the home when Dovecot uses it",
                src.contains("String box = \"/var/vmail/\" + domain.domain + \"/\" + user + \"/\";")
                && src.contains("DovecotHome.configured()") && src.contains("DovecotHome.DIR"));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void deleteTree(Path p) throws Exception {
        if (!Files.exists(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return;
        try (Stream<Path> s = Files.walk(p)) {
            for (Path x : s.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(x);
        }
    }
}
