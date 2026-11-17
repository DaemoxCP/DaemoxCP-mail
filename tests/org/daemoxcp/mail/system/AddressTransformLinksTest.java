package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.RootOnlyPath;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Setting aside the old mail of an address without following vmail's links (reperto 222).
 *
 * When an alias becomes a mailbox and the administrator chooses to set the old mail aside, AddressTransform.archive moves
 * /var/vmail/domain/name into /var/vmail/.panel-archive/domain, and the panel's rules (/var/mail/sieve/domain/name) out
 * of their place. It ran as root, and /var/vmail with everything under it is vmail's: vmail (Dovecot's delivery user)
 * could plant links there, and root's mkdir and rename followed them. Now the mail is moved by vmail itself, and the
 * panel's rules stay in root's tree (RootOnlyPath): nothing root does goes through a folder vmail can change.
 *
 *  1. With -De2e.vm=yes, as root, on bench folders made like /var/vmail (vmail:vmail 0770) and /var/mail/sieve (root):
 *     a. control: the mail is set aside and put back, it stays vmail's, and nothing of root's (the panel's rules
 *        included) lands in vmail's tree;
 *     b. vmail makes .panel-archive a link to a root folder (the probe works; vmail alone cannot make a folder there):
 *        setting aside makes nothing in it, and the mail stays where it was;
 *     c. vmail makes the domain's folder a link to a root folder holding "alice" (vmail alone cannot move it): setting
 *        aside alice leaves root's folder where it is;
 *     d. after a setting aside, vmail puts in the archive a link to a root folder holding a folder with the archive's
 *        name: putting back leaves root's folder where it is.
 *  2. With -De2e.vm=yes, the real /var/vmail and /var/mail/sieve (domain address-transform.test in the mail database,
 *     created and removed; Dovecot writes the mail with doveadm save):
 *     a. a mailbox with mail and panel rules is set aside and put back, and Dovecot reads and writes it again;
 *     b. vmail plants /var/vmail/address-transform-link.test as a link to a root folder holding "alice" (in /var, on
 *        the same file system as /var/vmail): setting aside alice there leaves root's folder where it is.
 *     /var/mail gets the sticky bit for the duration if it does not have it (as MailSpoolSticky does at boot: RootOnlyPath
 *     wants it), and goes back as it was: the VM is shared.
 *
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.AddressTransformLinksTest [database]
 */
public class AddressTransformLinksTest {

    static final String DOMAIN = "address-transform.test", LINKED = "address-transform-link.test";
    static final String ALICE = "alice@" + DOMAIN;
    static final Path VMAIL = Path.of("/var/vmail"), RULES = Path.of("/var/mail/sieve"), SPOOL = Path.of("/var/mail");
    static final long NOW = System.currentTimeMillis();

    private static int failures = 0;
    private static String db;
    private static Path work;
    private static final String RUN = Long.toString(NOW % 100000000L, 36);
    static final Path REAL_BENCH = Path.of("/var/address-transform-" + RUN);

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm")) || !"root".equals(System.getProperty("user.name"))) {
            System.out.println("Without -De2e.vm=yes, as root, this test does nothing: it changes owners, plants links as"
                    + " vmail and writes in the real /var/vmail.");
            return;
        }
        db = args.length > 0 ? args[0] : "mailserver";
        if (!db.matches("[A-Za-z0-9_]+")) throw new IllegalArgumentException("database name not valid: " + db);
        work = Files.createTempDirectory(Path.of("/var/tmp"), "address-transform");
        // Born 0700: vmail must reach the bench, or every "cannot" passes for the wrong reason.
        Files.setPosixFilePermissions(work, PosixFilePermissions.fromString("rwxr-xr-x"));
        int spoolMode = mode(SPOOL);
        boolean vmailArchive = Files.exists(VMAIL.resolve(".panel-archive"), LinkOption.NOFOLLOW_LINKS);
        boolean rulesArchive = Files.exists(RULES.resolve(".panel-archive"), LinkOption.NOFOLLOW_LINKS);
        try {
            part1();
            part2();
        } finally {
            tearDown(spoolMode, vmailArchive, rulesArchive);
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    // ---------------------------------------------------------------- 1. bench folders

    static void part1() throws Exception {
        System.out.println("== 1. Bench folders made like /var/vmail and /var/mail/sieve, in " + work + " ==");
        Path saved = AddressTransform.vmail, savedRules = AddressTransform.sieve;
        try {
            control();
            archiveLink();
            domainLink();
            restoreLink();
        } finally {
            AddressTransform.vmail = saved;
            AddressTransform.sieve = savedRules;
        }
    }

    /** a. Nothing planted: set aside and put back. */
    static void control() throws Exception {
        System.out.println("\n-- a. control --");
        Path s = scenario("control");
        Path mail = AddressTransform.vmail.resolve("d.test/alice"), rules = AddressTransform.sieve.resolve("d.test/alice");
        vmailMail(mail);
        rootRules(rules);
        List<Path[]> moved = archive("alice@d.test");
        check("set aside: the mail and the rules left their places", moved != null && !exists(mail) && !exists(rules));
        if (moved == null) return;
        Path mailTo = to(moved, mail), rulesTo = to(moved, rules);
        check("  the mail is in vmail's archive, still vmail's: " + mailTo, mailTo != null
                && mailTo.startsWith(AddressTransform.vmail.resolve(".panel-archive/d.test"))
                && exists(mailTo.resolve("cur/1.M1")) && owner(mailTo).equals("vmail") && owner(mailTo.resolve("cur/1.M1")).equals("vmail"));
        check("  the rules are set aside too, still root's: " + rulesTo, rulesTo != null && exists(rulesTo.resolve(".dovecot.sieve"))
                && owner(rulesTo).equals("root"));
        check("  nothing of root's in vmail's tree (the panel's rules included): " + rootOwned(AddressTransform.vmail),
                rootOwned(AddressTransform.vmail).isEmpty());
        AddressTransform.restore(moved);
        check("put back: mail and rules where they were, the mail vmail's, the rules root's",
                exists(mail.resolve("cur/1.M1")) && owner(mail).equals("vmail") && exists(rules.resolve(".dovecot.sieve"))
                && owner(rules).equals("root"));
        check("  and nothing of root's in vmail's tree", rootOwned(AddressTransform.vmail).isEmpty());
    }

    /** b. .panel-archive is a link to a root folder. */
    static void archiveLink() throws Exception {
        System.out.println("\n-- b. .panel-archive is vmail's link to a root folder --");
        Path s = scenario("archive-link");
        Path target = s.resolve("root-folder");
        Path mail = AddressTransform.vmail.resolve("d.test/alice");
        vmailMail(mail);
        check("the probe works: vmail plants .panel-archive as a link to root's folder",
                asVmail("/bin/ln", "-s", target.toString(), AddressTransform.vmail.resolve(".panel-archive").toString())
                && Files.isSymbolicLink(AddressTransform.vmail.resolve(".panel-archive")));
        check("  vmail alone cannot make a folder in root's folder", !asVmail("/bin/mkdir", target.resolve("vmail-was-here").toString())
                && names(target).isEmpty());
        List<Path[]> moved = archive("alice@d.test");
        check("root made nothing in root's folder through the link: " + names(target), names(target).isEmpty());
        check("  the mail is where it was, vmail's", exists(mail.resolve("cur/1.M1")) && owner(mail).equals("vmail"));
        if (moved != null) AddressTransform.restore(moved);
    }

    /** c. The domain's folder is a link to a root folder holding "alice". */
    static void domainLink() throws Exception {
        System.out.println("\n-- c. the domain's folder is vmail's link to a root folder --");
        Path s = scenario("domain-link");
        Path target = s.resolve("root-folder");
        rootFolder(target.resolve("alice"));
        check("the probe works: vmail plants d.test as a link to root's folder",
                asVmail("/bin/ln", "-s", target.toString(), AddressTransform.vmail.resolve("d.test").toString())
                && Files.isSymbolicLink(AddressTransform.vmail.resolve("d.test")));
        check("  vmail alone cannot move root's alice", !asVmail("/bin/mv", target.resolve("alice").toString(),
                AddressTransform.vmail.resolve("stolen").toString()) && rootFolderIntact(target.resolve("alice")));
        List<Path[]> moved = archive("alice@d.test");
        check("root's alice is where it was, with its file", rootFolderIntact(target.resolve("alice")));
        check("  nothing of root's in vmail's tree: " + rootOwned(AddressTransform.vmail), rootOwned(AddressTransform.vmail).isEmpty());
        if (moved != null) AddressTransform.restore(moved);
    }

    /** d. After a setting aside, the archive's domain folder becomes a link to a root folder. */
    static void restoreLink() throws Exception {
        System.out.println("\n-- d. putting back through vmail's link --");
        Path s = scenario("restore-link");
        Path target = s.resolve("root-folder");
        Path mail = AddressTransform.vmail.resolve("d.test/alice");
        vmailMail(mail);
        List<Path[]> moved = archive("alice@d.test");
        Path mailTo = moved == null ? null : to(moved, mail);
        check("set aside", mailTo != null && !exists(mail));
        if (mailTo == null) return;
        rootFolder(target.resolve(mailTo.getFileName().toString()));
        Path archive = AddressTransform.vmail.resolve(".panel-archive");
        check("the probe works: vmail moves the archive away and puts a link to root's folder in its place",
                asVmail("/bin/mv", archive.toString(), archive + ".real")
                && asVmail("/bin/mkdir", archive.toString())
                && asVmail("/bin/ln", "-s", target.toString(), archive.resolve("d.test").toString())
                && Files.isSymbolicLink(archive.resolve("d.test")));
        AddressTransform.restore(moved);
        check("root's folder with the archive's name is where it was", rootFolderIntact(target.resolve(mailTo.getFileName().toString())));
        check("  nothing of root's took the mail's place: " + (exists(mail) ? owner(mail) : "nothing there"),
                !exists(mail) || !owner(mail).equals("root"));
    }

    // ---------------------------------------------------------------- 2. the real system

    static void part2() throws Exception {
        System.out.println("\n== 2. The real /var/vmail and /var/mail/sieve ==");
        Path cnf = rootCnf();
        String password = run(10, "openssl", "rand", "-hex", "16").trim();
        String hash = run(20, "doveadm", "pw", "-s", "BLF-CRYPT", "-p", password);
        if (hash == null || !hash.startsWith("{BLF-CRYPT}")) throw new IllegalStateException("doveadm pw gave no BLF-CRYPT hash");
        String sql = cleanupSql() + "INSERT INTO domains (domain, active) VALUES ('" + DOMAIN + "', 1);\n"
                + "INSERT INTO mailboxes (domain_id, email, password, name, active) SELECT id, '" + ALICE + "', '" + hash.trim()
                + "', 'address transform test', 1 FROM domains WHERE domain='" + DOMAIN + "';\n";
        if (mysql(cnf, sql) == null) throw new IllegalStateException("cannot create the test mailbox in " + db);
        System.out.println("test mailbox " + ALICE + " in " + db + "; run " + RUN);
        if ((mode(SPOOL) & 01000) == 0) {
            Files.setAttribute(SPOOL, "unix:mode", (mode(SPOOL) & 07777) | 01000, LinkOption.NOFOLLOW_LINKS);
            System.out.println(SPOOL + " sticky for the duration, as MailSpoolSticky makes it at boot");
        }

        System.out.println("\n-- a. a real mailbox, set aside and put back --");
        String first = "address-transform " + RUN + " first", second = "address-transform " + RUN + " second";
        check("Dovecot writes a message in " + ALICE, save(ALICE, first) && count(ALICE, first) == 1);
        Path mail = VMAIL.resolve(DOMAIN).resolve("alice");
        Path rulesDir = RootOnlyPath.folders(SPOOL, "sieve", DOMAIN, "alice");
        RootOnlyPath.replace(rulesDir, ".dovecot.sieve", "keep;\n".getBytes(StandardCharsets.US_ASCII), null, null,
                PosixFilePermissions.fromString("rw-r--r--"));
        check("  the mail is vmail's, the rules root's", owner(mail).equals("vmail") && owner(rulesDir).equals("root"));
        List<Path[]> moved = archive(ALICE);
        check("set aside: the mail and the rules left their places", moved != null && !exists(mail) && !exists(rulesDir));
        if (moved != null) {
            Path mailTo = to(moved, mail), rulesTo = to(moved, rulesDir);
            check("  the mail is in /var/vmail/.panel-archive, vmail's: " + mailTo, mailTo != null
                    && mailTo.startsWith(VMAIL.resolve(".panel-archive").resolve(DOMAIN)) && owner(mailTo).equals("vmail"));
            check("  the rules are set aside outside vmail's tree, root's: " + rulesTo, rulesTo != null
                    && !rulesTo.startsWith(VMAIL) && exists(rulesTo.resolve(".dovecot.sieve")) && owner(rulesTo).equals("root"));
            check("  nothing of root's in the archive of " + DOMAIN, rootOwned(VMAIL.resolve(".panel-archive").resolve(DOMAIN)).isEmpty());
            AddressTransform.restore(moved);
            check("put back: the mail vmail's, the rules root's", exists(mail) && owner(mail).equals("vmail")
                    && exists(rulesDir.resolve(".dovecot.sieve")) && owner(rulesDir).equals("root"));
            check("  Dovecot reads the message again and writes a new one",
                    count(ALICE, first) == 1 && save(ALICE, second) && count(ALICE, second) == 1);
        }

        System.out.println("\n-- b. /var/vmail/" + LINKED + " is vmail's link to a root folder --");
        // On the same file system as /var/vmail (on the VM /var/tmp is another ZFS dataset, and a rename across them
        // fails before it can show anything): a folder of root's straight in /var, removed at the end.
        Path target = folder(REAL_BENCH, "root:wheel", "0755");
        rootFolder(target.resolve("alice"));
        Path link = VMAIL.resolve(LINKED);
        check("the probe works: vmail plants " + link + " as a link to root's folder",
                asVmail("/bin/ln", "-s", target.toString(), link.toString()) && Files.isSymbolicLink(link));
        check("  vmail alone cannot move root's alice", !asVmail("/bin/mv", target.resolve("alice").toString(),
                VMAIL.resolve("address-transform-stolen-" + RUN).toString()) && rootFolderIntact(target.resolve("alice")));
        List<Path[]> linked = archive("alice@" + LINKED);
        check("root's alice is where it was, with its file", rootFolderIntact(target.resolve("alice")));
        Path linkedArchive = VMAIL.resolve(".panel-archive").resolve(LINKED);
        check("  nothing of root's in the archive of " + LINKED + ": " + rootOwned(linkedArchive), rootOwned(linkedArchive).isEmpty());
        if (linked != null) AddressTransform.restore(linked);
    }

    // ---------------------------------------------------------------- helpers

    /** A bench made like /var/vmail and /var/mail/sieve, and AddressTransform pointed at it. */
    static Path scenario(String name) throws Exception {
        Path s = folder(work.resolve(name), "root:wheel", "0755");
        AddressTransform.vmail = folder(s.resolve("vmail"), "vmail:vmail", "0770");
        AddressTransform.sieve = folder(s.resolve("sieve"), "root:wheel", "0755");
        folder(s.resolve("root-folder"), "root:wheel", "0755");
        return s;
    }

    static Path folder(Path p, String owner, String mode) throws Exception {
        Files.createDirectories(p);
        ok("chown", owner, p.toString());
        ok("chmod", mode, p.toString());
        return p;
    }

    /** A mailbox as Dovecot leaves it: vmail's, 0700 folders and 0600 files. */
    static void vmailMail(Path dir) throws Exception {
        for (String f : new String[]{"cur/1.M1", "new/2.M2"}) {
            Files.createDirectories(dir.resolve(f).getParent());
            Files.writeString(dir.resolve(f), "x");
        }
        Path top = dir.getParent();
        ok("chown", "-R", "vmail:vmail", top.toString());
        ok("chmod", "-R", "go-rwx", top.toString());
    }

    /** The panel's rules of a mailbox, as SieveGenerator writes them: root's. */
    static void rootRules(Path dir) throws Exception {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(".dovecot.sieve"), "keep;\n");
    }

    /** A folder of root's, 0700, with a file of root's, 0600. */
    static void rootFolder(Path dir) throws Exception {
        folder(dir, "root:wheel", "0700");
        Files.writeString(dir.resolve("secret"), "root's");
        ok("chmod", "0600", dir.resolve("secret").toString());
    }

    static boolean rootFolderIntact(Path dir) throws Exception {
        return Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS) && owner(dir).equals("root")
                && Files.isRegularFile(dir.resolve("secret"), LinkOption.NOFOLLOW_LINKS) && owner(dir.resolve("secret")).equals("root");
    }

    /** archive(), or null with the reason if it refuses. */
    static List<Path[]> archive(String address) {
        try {
            List<Path[]> moved = AddressTransform.archive(address, NOW);
            for (Path[] m : moved) System.out.println("    moved " + m[0] + " -> " + m[1]);
            return moved;
        } catch (IOException e) {
            System.out.println("    archive refused: " + e);
            return null;
        }
    }

    /** Where archive() moved a folder, or null. */
    static Path to(List<Path[]> moved, Path from) {
        for (Path[] m : moved) if (m[0].equals(from)) return m[1];
        return null;
    }

    /** The entries of root's under a folder, without following links (a link is vmail's even when it points to root). */
    static List<String> rootOwned(Path tree) throws Exception {
        List<String> out = new ArrayList<>();
        if (!Files.exists(tree, LinkOption.NOFOLLOW_LINKS)) return out;
        try (Stream<Path> s = Files.walk(tree)) {
            for (Path p : s.toList())
                if ((Integer) Files.getAttribute(p, "unix:uid", LinkOption.NOFOLLOW_LINKS) == 0) out.add(tree.relativize(p).toString());
        }
        return out;
    }

    static List<String> names(Path dir) throws Exception {
        try (Stream<Path> s = Files.list(dir)) {
            return s.map(x -> x.getFileName().toString()).sorted().toList();
        }
    }

    static boolean exists(Path p) {
        return Files.exists(p, LinkOption.NOFOLLOW_LINKS);
    }

    static String owner(Path p) throws Exception {
        return Files.getOwner(p, LinkOption.NOFOLLOW_LINKS).getName();
    }

    static int mode(Path p) throws Exception {
        return (Integer) Files.getAttribute(p, "unix:mode", LinkOption.NOFOLLOW_LINKS);
    }

    /** A command as vmail, with no other group: what Dovecot's delivery can do. */
    static boolean asVmail(String... cmd) throws Exception {
        List<String> c = new ArrayList<>(List.of("/usr/sbin/chroot", "-u", "vmail", "-g", "vmail", "-G", "vmail", "/"));
        c.addAll(List.of(cmd));
        return run(20, c.toArray(new String[0])) != null;
    }

    /** A message written by Dovecot itself in the INBOX of user. */
    static boolean save(String user, String subject) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("doveadm", "save", "-u", user).redirectErrorStream(true);
        pb.environment().put("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin");
        Process p = pb.start();
        try (OutputStream o = p.getOutputStream()) {
            o.write(("From: test@" + DOMAIN + "\nTo: " + user + "\nSubject: " + subject + "\n\nAddress transform test\n")
                    .getBytes(StandardCharsets.US_ASCII));
        }
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!p.waitFor(30, TimeUnit.SECONDS)) { p.destroyForcibly(); return false; }
        if (p.exitValue() != 0) System.out.println("    doveadm save: " + out.trim());
        return p.exitValue() == 0;
    }

    static int count(String user, String subject) throws Exception {
        return SieveActionsE2ETest.found(run(30, "doveadm", "search", "-u", user, "mailbox", "INBOX", "subject", subject));
    }

    static Path rootCnf() throws Exception {
        String rootPw = null;
        for (String f : new String[]{"/usr/local/etc/mail-panel/root-secrets.properties", "/usr/local/etc/mail-panel/panel-secrets.properties"}) {
            Path p = Path.of(f);
            if (!Files.isRegularFile(p)) continue;
            Properties props = new Properties();
            try (var in = Files.newInputStream(p)) { props.load(in); }
            rootPw = props.getProperty("mysql_root_password");
            if (rootPw != null && !rootPw.isEmpty()) break;
        }
        Path cnf = work.resolve("root.cnf");
        Files.writeString(cnf, "[client]\nuser=root\n" + (rootPw == null || rootPw.isEmpty() ? "" : "password=\"" + rootPw + "\"\n"));
        Files.setPosixFilePermissions(cnf, PosixFilePermissions.fromString("rw-------"));
        return cnf;
    }

    static String cleanupSql() {
        return "DELETE FROM mailboxes WHERE email='" + ALICE + "';\nDELETE FROM domains WHERE domain='" + DOMAIN + "';\n";
    }

    static String mysql(Path cnf, String sql) throws Exception {
        Path f = work.resolve("statements.sql");
        Files.writeString(f, sql);
        return run(30, "/bin/sh", "-c", "mysql --defaults-extra-file='" + cnf + "' " + db + " < '" + f + "'");
    }

    /** Everything back as it was: the test mailbox, its folders and archives, the link, /var/mail's mode, the bench. */
    static void tearDown(int spoolMode, boolean vmailArchive, boolean rulesArchive) throws Exception {
        try {
            if (Files.exists(work.resolve("root.cnf"))) mysql(work.resolve("root.cnf"), cleanupSql());
        } finally {
            try {
                if ((mode(SPOOL) & 07777) != (spoolMode & 07777)) {
                    Files.setAttribute(SPOOL, "unix:mode", spoolMode & 07777, LinkOption.NOFOLLOW_LINKS);
                    System.out.println(SPOOL + " put back to " + String.format("%04o", spoolMode & 07777));
                }
            } finally {
                List<String> rm = new ArrayList<>(List.of("rm", "-rf", VMAIL.resolve(DOMAIN).toString(), VMAIL.resolve(LINKED).toString(),
                        VMAIL.resolve("address-transform-stolen-" + RUN).toString(),
                        VMAIL.resolve(".panel-archive").resolve(DOMAIN).toString(), VMAIL.resolve(".panel-archive").resolve(LINKED).toString(),
                        RULES.resolve(DOMAIN).toString(), RULES.resolve(".panel-archive").resolve(DOMAIN).toString(), REAL_BENCH.toString(),
                        work.toString()));
                new ProcessBuilder(rm).start().waitFor();
                if (!vmailArchive) new ProcessBuilder("rmdir", VMAIL.resolve(".panel-archive").toString()).start().waitFor();
                if (!rulesArchive) new ProcessBuilder("rmdir", RULES.resolve(".panel-archive").toString()).start().waitFor();
            }
        }
    }

    /** The output of a command, or null if it fails or does not finish in time. */
    static String run(int seconds, String... cmd) throws Exception {
        return SieveActionsE2ETest.run(seconds, cmd);
    }

    static boolean ok(String... cmd) throws Exception {
        return run(30, cmd) != null;
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
