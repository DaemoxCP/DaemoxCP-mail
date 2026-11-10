package org.mail_panel.system;

import org.mail_panel.security.RootOnlyPath;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

/**
 * The panel's Sieve rules folder is given back to root at start (reperto 225).
 *
 * <p>On the real server /var/mail/sieve belonged to vmail (the installation of 11/10/2026), and since reperto 221 root
 * does not write rules where somebody else can change the path: the panel would have said "not written" for every save
 * of those mailboxes. SieveRulesOwner gives the folders and the rule files back to root, and refuses to touch anything
 * when the tree holds something it should not follow or expose.
 *
 * <p>In a test folder under /var/tmp, as root (the owners are real ones: vmail, nobody), with the layout copied from the
 * real server (owners, groups, modes; contents made up):
 * <ul>
 *   <li>the real server's layout: folders and rule files root's after, readable by vmail, no longer writable by vmail;
 *       root:vmail files, Dovecot's log and every content as they were; RootOnlyPath accepts the mailbox folders; a
 *       second run finds nothing to do;</li>
 *   <li>a link, a hard link to a root-only file of the same disk, a file of nobody, a FIFO, a spool that is not root's:
 *       nothing changed at all, and the reason given;</li>
 *   <li>a root folder that others can write loses only that write;</li>
 *   <li>a rule file that cannot be changed half way (system immutable flag): every entry already changed goes back.</li>
 * </ul>
 *
 * <p>Usage (on the VM, as root):
 * <pre>
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.SieveRulesOwnerTest
 * </pre>
 */
public class SieveRulesOwnerTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static UserPrincipalLookupService look;
    static UserPrincipal root, vmail, nobody;
    static GroupPrincipal wheel, vmailGroup, mail;

    static void owner(Path p, UserPrincipal u, GroupPrincipal g, String mode) throws IOException {
        PosixFileAttributeView v = Files.getFileAttributeView(p, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        v.setOwner(u);
        v.setGroup(g);
        Files.setAttribute(p, "unix:mode", Integer.parseInt(mode, 8), LinkOption.NOFOLLOW_LINKS);
    }

    static Path folder(Path p, UserPrincipal u, GroupPrincipal g, String mode) throws IOException {
        Files.createDirectories(p);
        owner(p, u, g, mode);
        return p;
    }

    static Path file(Path p, String content, UserPrincipal u, GroupPrincipal g, String mode) throws IOException {
        Files.writeString(p, content);
        owner(p, u, g, mode);
        return p;
    }

    /** The test spool: like /var/mail, root:mail 1775. */
    static Path spool(Path base, String name) throws IOException {
        return folder(base.resolve(name), root, mail, "1775");
    }

    /**
     * The real server's /var/mail/sieve, 10/11/2026: owners, groups and modes as they were there, made-up contents.
     * Mailbox a: root:vmail folder, rules and binary root:vmail 644. Mailbox b: vmail folder, rules vmail 755, binary
     * root:vmail 644, Dovecot's log vmail 600. Mailbox c: vmail folder, rules vmail 755, binary vmail 644.
     */
    static Path realServerTree(Path spool) throws IOException {
        Path sieve = folder(spool.resolve("sieve"), vmail, vmailGroup, "755");
        folder(sieve.resolve("global"), vmail, vmailGroup, "755");
        Path domain = folder(sieve.resolve("example.test"), vmail, vmailGroup, "755");
        Path a = folder(domain.resolve("a"), root, vmailGroup, "755");
        file(a.resolve(".dovecot.sieve"), "require [\"fileinto\"];\n# Default action\nkeep;\n", root, vmailGroup, "644");
        file(a.resolve(".dovecot.svbin"), "binary-a", root, vmailGroup, "644");
        Path b = folder(domain.resolve("b"), vmail, vmailGroup, "755");
        file(b.resolve(".dovecot.sieve"), "require [\"vacation\"];\n# Default action\nkeep;\n", vmail, vmailGroup, "755");
        file(b.resolve(".dovecot.svbin"), "binary-b", root, vmailGroup, "644");
        file(b.resolve(".dovecot.sieve.log"), "sieve: info: started log", vmail, vmailGroup, "600");
        Path c = folder(domain.resolve("c"), vmail, vmailGroup, "755");
        file(c.resolve(".dovecot.sieve"), "require [\"copy\"];\n# Default action\nkeep;\n", vmail, vmailGroup, "755");
        file(c.resolve(".dovecot.svbin"), "binary-c", vmail, vmailGroup, "644");
        return sieve;
    }

    /** Every entry: type, owner, group, mode, content hash. Without following links. */
    static Map<String, String> snapshot(Path top) throws Exception {
        Map<String, String> out = new TreeMap<>();
        try (Stream<Path> s = Files.walk(top)) {
            for (Path p : s.toList()) {
                Map<String, Object> a = Files.readAttributes(p, "unix:mode,owner,group", LinkOption.NOFOLLOW_LINKS);
                int mode = (Integer) a.get("mode");
                String hash = "";
                if ((mode & 0170000) == 0100000) {
                    hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p))).substring(0, 12);
                }
                out.put(top.relativize(p).toString(), Integer.toOctalString(mode) + " " + ((UserPrincipal) a.get("owner")).getName()
                        + ":" + ((GroupPrincipal) a.get("group")).getName() + " " + hash);
            }
        }
        return out;
    }

    static String ownerOf(Path p) throws IOException {
        Map<String, Object> a = Files.readAttributes(p, "unix:owner,group,mode", LinkOption.NOFOLLOW_LINKS);
        return ((UserPrincipal) a.get("owner")).getName() + ":" + ((GroupPrincipal) a.get("group")).getName() + " "
                + String.format("%04o", (Integer) a.get("mode") & 07777);
    }

    /** A command as vmail, its exit code (chroot -u, as the panel's own probes do). */
    static int asVmail(String... cmd) throws Exception {
        String[] full = new String[cmd.length + 6];
        full[0] = "chroot"; full[1] = "-u"; full[2] = "vmail"; full[3] = "-g"; full[4] = "vmail"; full[5] = "/";
        System.arraycopy(cmd, 0, full, 6, cmd.length);
        Process p = new ProcessBuilder(full).redirectErrorStream(true).start();
        p.getInputStream().readAllBytes();
        return p.waitFor();
    }

    static int run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        p.getInputStream().readAllBytes();
        return p.waitFor();
    }

    static boolean isRoot() {
        try {
            return new com.sun.security.auth.module.UnixSystem().getUid() == 0;
        } catch (Throwable t) {
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        if (!isRoot()) {
            System.out.println("This test needs root (real owners: vmail, nobody) on the test VM: skipped.");
            return;
        }
        look = Path.of("/").getFileSystem().getUserPrincipalLookupService();
        root = look.lookupPrincipalByName("root");
        vmail = look.lookupPrincipalByName("vmail");
        nobody = look.lookupPrincipalByName("nobody");
        wheel = look.lookupPrincipalByGroupName("wheel");
        vmailGroup = look.lookupPrincipalByGroupName("vmail");
        mail = look.lookupPrincipalByGroupName("mail");

        Path base = Files.createTempDirectory(Path.of("/var/tmp"), "sieve-rules-owner-");
        owner(base, root, wheel, "755");
        try {
            System.out.println("\n== The real server's layout ==");
            Path sp = spool(base, "real");
            Path sieve = realServerTree(sp);
            Path b = sieve.resolve("example.test/b");
            check("before: vmail can write in a mailbox folder", asVmail("touch", b.resolve("by-vmail").toString()) == 0);
            Files.deleteIfExists(b.resolve("by-vmail"));
            check("before: root would not write the rules there: " + RootOnlyPath.problem(b), RootOnlyPath.problem(b) != null);
            Map<String, String> before = snapshot(sieve);
            String r = SieveRulesOwner.ensure(sieve, "vmail", "mail");
            check("DONE: " + r, r != null && r.startsWith("DONE") && r.contains("5 folder(s)") && r.contains("3 rule file(s)")
                    && r.contains("1 other file(s)"));
            check("the rules folder is root:mail 0755", ownerOf(sieve).equals("root:mail 0755"));
            check("global and the domain folder too", ownerOf(sieve.resolve("global")).equals("root:mail 0755")
                    && ownerOf(sieve.resolve("example.test")).equals("root:mail 0755"));
            check("the mailbox folder that was root:vmail 0755 is left so (root's, nobody else writes)",
                    ownerOf(sieve.resolve("example.test/a")).equals("root:vmail 0755"));
            check("the vmail mailbox folders are root:mail 0755", ownerOf(b).equals("root:mail 0755")
                    && ownerOf(sieve.resolve("example.test/c")).equals("root:mail 0755"));
            check("vmail's rules are root:mail 0644", ownerOf(b.resolve(".dovecot.sieve")).equals("root:mail 0644")
                    && ownerOf(sieve.resolve("example.test/c/.dovecot.sieve")).equals("root:mail 0644"));
            check("vmail's binary is root:mail 0644", ownerOf(sieve.resolve("example.test/c/.dovecot.svbin")).equals("root:mail 0644"));
            check("the root:vmail files are left as they were", ownerOf(sieve.resolve("example.test/a/.dovecot.sieve")).equals("root:vmail 0644")
                    && ownerOf(b.resolve(".dovecot.svbin")).equals("root:vmail 0644"));
            check("Dovecot's log is left as it was", ownerOf(b.resolve(".dovecot.sieve.log")).equals("vmail:vmail 0600"));
            Map<String, String> after = snapshot(sieve);
            boolean sameContents = true;
            for (String k : before.keySet()) {
                String h1 = before.get(k).substring(before.get(k).lastIndexOf(' ') + 1), h2 = after.get(k).substring(after.get(k).lastIndexOf(' ') + 1);
                if (!h1.equals(h2)) sameContents = false;
            }
            check("every content as it was, nothing added or removed", sameContents && before.keySet().equals(after.keySet()));
            check("vmail still reads the rules and the binary (Dovecot delivers as vmail)",
                    asVmail("cat", b.resolve(".dovecot.sieve").toString()) == 0 && asVmail("cat", sieve.resolve("example.test/c/.dovecot.svbin").toString()) == 0);
            check("vmail can no longer write in the mailbox folder", asVmail("touch", b.resolve("by-vmail").toString()) != 0
                    && !Files.exists(b.resolve("by-vmail")));
            check("vmail can no longer change the rules", asVmail("sh", "-c", "echo x >> " + b.resolve(".dovecot.sieve")) != 0);
            check("RootOnlyPath accepts the mailbox folders now: " + RootOnlyPath.problem(b),
                    RootOnlyPath.problem(b) == null && RootOnlyPath.problem(sieve.resolve("example.test/c")) == null);
            check("a second run finds nothing to do", SieveRulesOwner.ensure(sieve, "vmail", "mail") == null
                    && snapshot(sieve).equals(after));

            System.out.println("\n== What makes it touch nothing ==");
            Path s1 = realServerTree(spool(base, "link"));
            Files.delete(s1.resolve("example.test/b/.dovecot.sieve.log"));
            Files.createSymbolicLink(s1.resolve("example.test/b/.dovecot.sieve.log"), Path.of("/etc/passwd"));
            refusedUnchanged("a link", s1, "is a link");
            Path sp2 = spool(base, "hardlink");
            Path secret = file(sp2.resolve("root-mailbox"), "root's own mail", root, wheel, "600");
            Path s2 = realServerTree(sp2);
            Files.delete(s2.resolve("example.test/c/.dovecot.sieve"));
            Files.createLink(s2.resolve("example.test/c/.dovecot.sieve"), secret);
            refusedUnchanged("a hard link to a root-only file", s2, "hard links");
            check("  the root-only file is still root's and 0600", ownerOf(secret).equals("root:wheel 0600"));
            Path s3 = realServerTree(spool(base, "nobody"));
            file(s3.resolve("example.test/c/.dovecot.sieve.db"), "x", nobody, vmailGroup, "644");
            refusedUnchanged("a file of nobody", s3, "belongs to nobody");
            Path s4 = realServerTree(spool(base, "fifo"));
            check("  (mkfifo)", run("mkfifo", s4.resolve("example.test/b/pipe").toString()) == 0);
            refusedUnchanged("a FIFO", s4, "is not a file or a folder");
            Path sp5 = folder(base.resolve("spool-of-nobody"), nobody, mail, "775");
            Path s5 = realServerTree(sp5);
            refusedUnchanged("a spool that is not root's", s5, "does not belong to root");

            System.out.println("\n== Already root's ==");
            Path s6 = folder(spool(base, "root").resolve("sieve"), root, mail, "755");
            Path m6 = folder(s6.resolve("example.test/x"), root, mail, "755");
            file(m6.resolve(".dovecot.sieve"), "keep;\n", root, mail, "644");
            check("a tree that is root's already: nothing to do", SieveRulesOwner.ensure(s6, "vmail", "mail") == null);
            owner(m6, root, mail, "775");
            String r6 = SieveRulesOwner.ensure(s6, "vmail", "mail");
            check("a root folder others can write: only that write goes: " + r6, r6 != null && r6.startsWith("DONE")
                    && ownerOf(m6).equals("root:mail 0755") && ownerOf(m6.resolve(".dovecot.sieve")).equals("root:mail 0644"));

            System.out.println("\n== Half way, it goes back ==");
            Path s7 = realServerTree(spool(base, "immutable"));
            Path stuck = s7.resolve("example.test/c/.dovecot.sieve");
            Map<String, String> before7 = snapshot(s7);
            check("  (chflags schg on mailbox c's rules)", run("chflags", "schg", stuck.toString()) == 0);
            String r7 = SieveRulesOwner.ensure(s7, "vmail", "mail");
            run("chflags", "noschg", stuck.toString());
            check("ROLLED_BACK: " + r7, r7 != null && r7.startsWith("ROLLED_BACK") && r7.contains("every entry is as it was"));
            check("every entry is as it was", snapshot(s7).equals(before7));
        } finally {
            run("chflags", "-R", "noschg", base.toString());
            run("rm", "-rf", base.toString());
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void refusedUnchanged(String what, Path sieve, String reason) throws Exception {
        Map<String, String> before = snapshot(sieve);
        String r = SieveRulesOwner.ensure(sieve, "vmail", "mail");
        check(what + ": nothing changed, and why: " + r, r != null && r.startsWith("left as it is, nothing changed") && r.contains(reason));
        check("  every entry as it was", snapshot(sieve).equals(before));
    }
}
