package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.DovecotScript;
import org.daemoxcp.mail.scripts.FullMailServerScript;
import org.daemoxcp.mail.scripts.FullMailStackScript;
import org.daemoxcp.mail.security.SafeOwnership;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Root giving a folder and its contents to a user without giving it other people's files (reperto 252). On FreeBSD
 * anyone can hard-link another user's file on the same file system (security.bsd.hardlink_check_uid is 0 by default),
 * and /var/vmail is on the same file system as /etc: "chown -R vmail:vmail /var/vmail", run by root at every
 * regeneration of the mail folders, gave vmail a root file linked in there (measured on the VM with a test file).
 *  1. SafeOwnership.safeToChange: a folder and a file with one name yes; a file with two names, a symbolic link, a FIFO no;
 *  2. SafeOwnership.shell on a real tree: folders and single-name files given to the user; a root file hard-linked in
 *     there and one behind a symbolic link stay root's, and the hard link is said; a second run changes nothing;
 *     names that are not a panel folder or a user are refused;
 *  3. the scripts: no "chown -R vmail:vmail /var/vmail" left in the installation scripts, the mail folders' regeneration
 *     creates them as vmail and gives them back with SafeOwnership, Roundcube's folders the same way, acme.sh's walk
 *     checks each file;
 *  4. RoundcubeUser.apply (the boot migration that gives Roundcube its folders) on a tree with a hard link: the
 *     linked file stays as it was.
 * As root on the TEST VM (chown needs root; the tree is in a temporary folder, owner nobody):
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.SafeOwnershipTest
 */
public class SafeOwnershipTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String owner(Path p) throws Exception {
        return Files.getOwner(p, LinkOption.NOFOLLOW_LINKS).getName();
    }

    static Shell.Result sh(String script) {
        return Shell.run(Duration.ofSeconds(60), "/bin/sh", "-c", script);
    }

    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory(Path.of("/var/tmp"), "safe-ownership-test");
        try {
            Path tree = base.resolve("tree"), outside = base.resolve("outside"), other = base.resolve("other");
            Files.createDirectories(tree.resolve("domain/user/Maildir/cur"));
            Files.writeString(tree.resolve("domain/user/Maildir/cur/message"), "mail");
            Files.writeString(outside, "root only");
            Files.writeString(other, "root only too");
            sh("chown -R root:wheel '" + base + "' && chmod 600 '" + outside + "' '" + other + "'");
            Files.createLink(tree.resolve("domain/planted-hardlink"), outside);
            Files.createSymbolicLink(tree.resolve("domain/planted-symlink"), other);
            sh("mkfifo '" + tree.resolve("domain/fifo") + "'");

            System.out.println("== 1. What is safe to change");
            check("a folder: yes", SafeOwnership.safeToChange(tree.resolve("domain")));
            check("a file with one name: yes", SafeOwnership.safeToChange(tree.resolve("domain/user/Maildir/cur/message")));
            check("a file with two names: no, under either name", !SafeOwnership.safeToChange(tree.resolve("domain/planted-hardlink"))
                    && !SafeOwnership.safeToChange(outside));
            check("a symbolic link: no", !SafeOwnership.safeToChange(tree.resolve("domain/planted-symlink")));
            check("a FIFO: no", !SafeOwnership.safeToChange(tree.resolve("domain/fifo")));

            System.out.println("\n== 2. The script piece on a real tree");
            Shell.Result r = sh(SafeOwnership.shell(tree.toString(), "nobody", "nobody"));
            System.out.println("    output: " + r.outputTrim().replace('\n', ' '));
            check("the folders and the file with one name are nobody's", owner(tree).equals("nobody")
                    && owner(tree.resolve("domain/user/Maildir/cur")).equals("nobody")
                    && owner(tree.resolve("domain/user/Maildir/cur/message")).equals("nobody"));
            check("the root file hard-linked inside stays root's", owner(outside).equals("root"));
            check("the root file behind a symbolic link stays root's", owner(other).equals("root"));
            check("the hard link is said, with its count", r.outputTrim().contains("WARNING: 1 file(s) in " + tree));
            Shell.Result again = sh(SafeOwnership.shell(tree.toString(), "nobody", "nobody") + "echo done");
            check("a second run: nothing more to change, the warning again", owner(outside).equals("root") && again.success());
            boolean refused = true;
            for (String[] bad : new String[][] {{"relative", "vmail"}, {"/var/../etc", "vmail"}, {"/var/vmail'; id #", "vmail"},
                    {"/var/vmail", "vmail; id"}, {"/var/vmail", "Root"}}) {
                try { SafeOwnership.shell(bad[0], bad[1], bad[1]); refused = false; } catch (IllegalArgumentException e) { /* refused */ }
            }
            check("names that are not a panel folder or a user name are refused", refused);

            System.out.println("\n== 3. The scripts");
            String vmail = SafeOwnership.shell("/var/vmail", "vmail", "vmail");
            for (var e : List.of(List.of("FullMailServerScript", new FullMailServerScript().getScriptContent()),
                    List.of("FullMailStackScript", new FullMailStackScript().getScriptContent()),
                    List.of("DovecotScript", new DovecotScript().getScriptContent()))) {
                String text = e.get(1);
                check(e.get(0) + ": no \"chown -R vmail\", and /var/vmail given with SafeOwnership", !text.contains("chown -R vmail")
                        && text.contains(vmail));
            }
            String regen = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/scripts/ConfigRegeneratorScript.java"));
            check("the mail folders' regeneration: created as vmail, given back with SafeOwnership, no chown -R",
                    regen.contains("script.append(AS_VMAIL).append(\"mkdir -p '/var/vmail/\")")
                    && regen.contains("script.append(AS_VMAIL).append(\"mkdir -p '\").append(maildir)")
                    && regen.contains("SafeOwnership.shell(\"/var/vmail\", \"vmail\", \"vmail\")") && !regen.contains("append(\"chown -R"));
            check("Roundcube's folders in the installation: no chown -R", !RoundcubeUser.shellOwnership().contains("chown -R"));
            String acme = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/security/AcmeUser.java"));
            check("acme.sh's walk checks each file", acme.contains("if (!SafeOwnership.safeToChange(x)) continue;"));

            System.out.println("\n== 4. RoundcubeUser.apply on a tree with a hard link");
            Path rc = base.resolve("roundcube-temp");
            Files.createDirectories(rc);
            Files.writeString(rc.resolve("cache"), "x");
            Path secret = base.resolve("secret");
            Files.writeString(secret, "root only");
            sh("chown -R root:wheel '" + rc + "' '" + secret + "' && chmod 600 '" + secret + "'");
            Files.createLink(rc.resolve("planted"), secret);
            @SuppressWarnings({"unchecked", "rawtypes"})
            List<String> changed = RoundcubeUser.apply(List.of(new RoundcubeUser.Ownership(rc, "nobody", "nobody", "rwx------", true)),
                    new java.util.ArrayDeque());
            check("the folder and its file with one name are nobody's", owner(rc).equals("nobody") && owner(rc.resolve("cache")).equals("nobody"));
            check("the root file hard-linked inside stays root's, and is not among the changed", owner(secret).equals("root")
                    && changed.stream().noneMatch(c -> c.endsWith("planted")));
        } finally {
            sh("rm -rf '" + base + "'");
        }
        System.out.println("\n" + (failed == 0 ? "ALL OK" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
