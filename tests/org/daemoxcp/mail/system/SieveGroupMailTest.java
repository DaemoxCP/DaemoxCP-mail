package org.daemoxcp.mail.system;

import org.daemoxcp.mail.integration.SieveGenerator;
import org.daemoxcp.mail.integration.SieveGeneratorTest.Rules;
import org.daemoxcp.mail.scripts.DovecotConfig;
import org.daemoxcp.mail.security.RootOnlyPath;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The panel's Sieve rules out of reach of the group mail (reperto 221).
 *
 * Measured on the VM on 10/11/2026: /var/mail is root:mail 0775 (FreeBSD's mtree), so a process with the group mail
 * (postfix, clamav, dma which is setgid mail, and Dovecot's mail processes through mail_privileged_group) could rename
 * /var/mail/sieve and put its own in its place; and SieveGenerator.saveSieveScript wrote as root following links, so a
 * .dovecot.sieve that was a link made root overwrite the file it pointed to. Now: root writes only through folders
 * nobody else can change, without following links (RootOnlyPath); /var/mail gets the sticky bit at boot
 * (MailSpoolSticky); Dovecot's mail processes lose the group mail (DovecotPrivilegedGroup, DovecotConfig).
 *
 *  1. Without a system: the sticky mode; the line taken out of dovecot.conf only when it is exactly the panel's, the
 *     result being what the installer writes now (2.3 and 2.4); mbox, /etc/group and procstat read right.
 *  2. With -De2e.vm=yes, as root, on bench folders: RootOnlyPath refuses links, folders of others and folders others
 *     can write (above the last one only with the sticky bit); a write over a planted link leaves the file it points to
 *     alone; in a spool made like /var/mail a process with the group mail renames a root folder (the probe works), and
 *     after MailSpoolSticky it cannot, while it can still make and remove a lock file of its own.
 *  3. With -De2e.vm=yes, the real system with real deliveries (domain sieve-group-mail.test, created and removed):
 *     a. MailSpoolSticky on the real /var/mail: a process with the group mail cannot rename a root folder in it (a probe
 *        folder: never /var/mail/sieve, which other tests use);
 *     b. DovecotPrivilegedGroup on the real dovecot.conf: an imap of the mailbox had the group mail before (the probe
 *        sees it), has it no more after; the second run does nothing;
 *     c. a rule saved by the panel moves a real delivery;
 *     d. a link planted at the rule's place: saving again leaves the file it points to (nobody's, 0600) as it was, the
 *        rule is root's again, and the next delivery still follows it.
 *     At the end dovecot.conf and the mode of /var/mail go back as they were: the VM is shared.
 *
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.SieveGroupMailTest [database]
 */
public class SieveGroupMailTest {

    static final String DOMAIN = "sieve-group-mail.test";
    static final String ALICE = "alice@" + DOMAIN, CAROL = "carol@" + DOMAIN;
    static final Path RULES = Path.of("/var/mail/sieve");
    static final Path SCRIPT = RULES.resolve(DOMAIN).resolve("alice").resolve(".dovecot.sieve");
    static final Path BINARY = SCRIPT.resolveSibling(".dovecot.svbin");
    static final Path SPOOL = Path.of("/var/mail");
    static final Path MAILLOG = Path.of("/var/log/maillog");
    static final Path DOVECOT_CONF = DovecotPrivilegedGroup.CONF;

    private static int failures = 0;
    private static String db;
    private static Path work;
    private static long logStart;
    private static final String RUN = Long.toString(System.currentTimeMillis() % 100000000L, 36);

    public static void main(String[] args) throws Exception {
        part1();
        if (!"yes".equals(System.getProperty("e2e.vm")) || !"root".equals(System.getProperty("user.name"))) {
            System.out.println("\nWithout -De2e.vm=yes, as root, parts 2 and 3 do not run: they change owners, modes and"
                    + " Dovecot's configuration, and deliver real mail.");
        } else {
            db = args.length > 0 ? args[0] : "mailserver";
            if (!db.matches("[A-Za-z0-9_]+")) throw new IllegalArgumentException("database name not valid: " + db);
            work = Files.createTempDirectory(Path.of("/var/tmp"), "sieve-group-mail");
            // Born 0700: vmail must reach the bench, or every "cannot" passes for the wrong reason.
            Files.setPosixFilePermissions(work, PosixFilePermissions.fromString("rwxr-xr-x"));
            int spoolMode = mode(SPOOL);
            byte[] conf = Files.readAllBytes(DOVECOT_CONF);
            PosixFileAttributes confAttrs = Files.readAttributes(DOVECOT_CONF, PosixFileAttributes.class);
            try {
                part2();
                setUp();
                part3(spoolMode, conf);
            } finally {
                tearDown(spoolMode, conf, confAttrs);
            }
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    // ---------------------------------------------------------------- 1. without a system

    /** dovecot.conf as the 2.3 installer writes it: the heredoc of the script fragment. */
    static String conf23() {
        String f = DovecotConfig.fromPanelConfig().scriptFragment();
        String start = "cat > \"$DOVECOT_ETC/dovecot.conf\" <<DOVECOT_MAIN\n";
        int a = f.indexOf(start) + start.length();
        return f.substring(a, f.indexOf("\nDOVECOT_MAIN\n", a) + 1);
    }

    static String conf24() {
        return DovecotConfig.file24().stream().filter(c -> c.path().equals("dovecot.conf")).findFirst().get().content();
    }

    static void part1() {
        System.out.println("== 1. Without a system ==");
        check("sticky: 0775 -> 1775", MailSpoolSticky.next(040775) == 01775);
        check("  0777 -> 1777", MailSpoolSticky.next(040777) == 01777);
        check("  already sticky, or nobody else writes: nothing", MailSpoolSticky.next(041775) == -1
                && MailSpoolSticky.next(040755) == -1 && MailSpoolSticky.next(040700) == -1);

        String now23 = conf23(), now24 = conf24();
        System.out.println("  the installer's dovecot.conf for 2.3:\n" + now23.indent(4).stripTrailing());
        check("the installer writes no mail_privileged_group, 2.3", now23.startsWith("# Dovecot — generated by FreeBSD Mail Panel\n")
                && !now23.contains("mail_privileged_group"));
        check("  nor 2.4", now24.startsWith("# Dovecot 2.4 — generated by FreeBSD Mail Panel\n") && !now24.contains("mail_privileged_group"));
        String before23 = now23.replace("listen = *, ::\n", "listen = *, ::\n" + DovecotPrivilegedGroup.LINE);
        String before24 = now24.replace("sendmail_path = /usr/local/sbin/sendmail\n",
                "sendmail_path = /usr/local/sbin/sendmail\n" + DovecotPrivilegedGroup.LINE);
        check("the file the panel wrote before, 2.3: the line goes, and it is what the installer writes now",
                !before23.equals(now23) && now23.equals(DovecotPrivilegedGroup.migrated(before23)));
        check("  2.4: the same", !before24.equals(now24) && now24.equals(DovecotPrivilegedGroup.migrated(before24)));
        check("already without the line: nothing", DovecotPrivilegedGroup.migrated(now23) == null
                && DovecotPrivilegedGroup.migrated(now24) == null);
        check("the line twice, or another value, or indented: not the panel's, nothing",
                DovecotPrivilegedGroup.migrated(before23 + DovecotPrivilegedGroup.LINE) == null
                && DovecotPrivilegedGroup.migrated(before23.replace("= mail\n", "= dovecot\n")) == null
                && DovecotPrivilegedGroup.migrated(before23.replace("\nmail_privileged_group", "\n  mail_privileged_group")) == null);
        check("a dovecot.conf not written by the panel: nothing", DovecotPrivilegedGroup.migrated(
                "protocols = imap\n" + DovecotPrivilegedGroup.LINE) == null && DovecotPrivilegedGroup.migrated(null) == null);
        check("mbox seen in doveconf -n (2.3 and 2.4)", DovecotPrivilegedGroup.usesMbox("mail_location = mbox:~/mail:INBOX=/var/mail/%u\n")
                && DovecotPrivilegedGroup.usesMbox("mail_driver = mbox\nmail_path = ~/mail\n")
                && DovecotPrivilegedGroup.usesMbox("mail_inbox_path = /var/mail/%{user}\n"));
        check("  Maildir is not mbox", !DovecotPrivilegedGroup.usesMbox("mail_location = maildir:/var/vmail/%d/%n\n")
                && !DovecotPrivilegedGroup.usesMbox("mail_driver = maildir\nmail_path = /var/vmail/%{user|domain}\n"));
        check("the gid of mail from /etc/group", DovecotPrivilegedGroup.gidOf("wheel:*:0:root\nmail:*:6:postfix,clamav\n", "mail") == 6
                && DovecotPrivilegedGroup.gidOf("wheel:*:0:root\n", "mail") == -1);
        String with = "52196 imap              5000  5000  5000  5000  5000     6   077 -     5000,143,5000";
        String without = "64718 imap              5000  5000  5000  5000  5000  5000   077 -     5000,143,5000";
        check("procstat -s: the saved group 6 is seen, measured lines", DovecotPrivilegedGroup.keepsGroup(with, 6)
                && !DovecotPrivilegedGroup.keepsGroup(without, 6));
        check("  and among the additional groups", DovecotPrivilegedGroup.keepsGroup(
                "1 imap 5000 5000 5000 5000 5000 5000 077 - 5000,6", 6));
    }

    // ---------------------------------------------------------------- 2. bench folders

    static void part2() throws Exception {
        System.out.println("\n== 2a. RootOnlyPath on bench folders (" + work + ") ==");
        Path ok = Files.createDirectories(work.resolve("ok/a/b"));
        check("root's folders from / down: accepted (" + RootOnlyPath.problem(ok) + ")", RootOnlyPath.problem(ok) == null);
        Path open = folder(work.resolve("open"), "root:wheel", "775");
        Path child = folder(open.resolve("child"), "root:wheel", "755");
        check("a folder others can write: refused (" + RootOnlyPath.problem(open) + ")", why(open).contains("written by others"));
        check("  and so is anything under it", why(child).contains("written by others"));
        ok("chmod", "1775", open.toString());
        check("with the sticky bit, what is under it: accepted (" + RootOnlyPath.problem(child) + ")", RootOnlyPath.problem(child) == null);
        check("  but not the sticky folder itself, to write in", why(open).contains("written by others"));
        Path link = Files.createSymbolicLink(work.resolve("link"), work.resolve("ok"));
        check("a link on the way: refused (" + RootOnlyPath.problem(link.resolve("a")) + ")", why(link.resolve("a")).contains("is a link"));
        Path others = folder(work.resolve("others"), "nobody:nobody", "755");
        check("a folder of another user: refused (" + RootOnlyPath.problem(others) + ")", why(others).contains("not to root"));
        Path file = Files.writeString(work.resolve("file"), "x");
        check("a file: refused", why(file).contains("not a folder"));

        System.out.println("\n== 2b. Writing over a planted link ==");
        Path victim = Files.writeString(work.resolve("victim"), "secret\n");
        ok("chown", "nobody:nobody", victim.toString());
        ok("chmod", "600", victim.toString());
        Path target = Files.createSymbolicLink(work.resolve("ok/target"), victim);
        RootOnlyPath.replace(work.resolve("ok"), "target", "rules\n".getBytes(StandardCharsets.UTF_8), null, null,
                PosixFilePermissions.fromString("rw-r--r--"));
        check("the file the link pointed to is as it was (" + attrs(victim) + ")", Files.readString(victim).equals("secret\n")
                && attrs(victim).equals("nobody:nobody rw-------"));
        check("  the link is replaced by a file of root's with the content (" + attrs(target) + ")",
                Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS) && Files.readString(target).equals("rules\n")
                && attrs(target).startsWith("root:") && attrs(target).endsWith(" rw-r--r--"));
        check("  no temporary file left", names(work.resolve("ok")).equals(List.of("a", "target")));
        UserPrincipalLookupService n = work.getFileSystem().getUserPrincipalLookupService();
        RootOnlyPath.replace(work.resolve("ok"), "given", new byte[]{1, 2, 3}, n.lookupPrincipalByName("nobody"),
                n.lookupPrincipalByGroupName("mail"), PosixFilePermissions.fromString("rw-r-----"));
        check("owner, group and mode as asked (" + attrs(work.resolve("ok/given")) + ")", attrs(work.resolve("ok/given")).equals("nobody:mail rw-r-----"));
        check("reading a link: refused", refused(() -> RootOnlyPath.read(link, 100)) && refused(() -> RootOnlyPath.read(
                Files.createSymbolicLink(work.resolve("ok/readlink"), victim), 100)));
        check("writing in a folder others can write: refused, nothing written", refused(() -> RootOnlyPath.replace(
                folder(work.resolve("open2"), "root:wheel", "777"), "x", new byte[0], null, null, null))
                && names(work.resolve("open2")).isEmpty());

        System.out.println("\n== 2c. A spool made like /var/mail, and a process with the group mail ==");
        Path spool = folder(work.resolve("mail"), "root:mail", "775");
        Path rules = folder(spool.resolve("sieve"), "root:mail", "755");
        check("root makes no folder under it without the sticky bit", refused(() -> RootOnlyPath.folders(spool, "sieve", "d.test", "u"))
                && !Files.exists(rules.resolve("d.test")));
        check("before: the group mail renames root's folder of the rules (the probe works)",
                asGroupMail("/bin/mv", rules.toString(), spool.resolve("stolen").toString()) && !Files.exists(rules));
        ok("/bin/mv", spool.resolve("stolen").toString(), rules.toString());
        String done = MailSpoolSticky.ensure(spool, rules);
        System.out.println("  " + done);
        check("MailSpoolSticky: done, " + String.format("%04o", mode(spool) & 07777), done != null && done.startsWith("DONE")
                && (mode(spool) & 07777) == 01775);
        check("after: the group mail cannot rename it", !asGroupMail("/bin/mv", rules.toString(), spool.resolve("stolen").toString())
                && Files.isDirectory(rules, LinkOption.NOFOLLOW_LINKS) && !Files.exists(spool.resolve("stolen")));
        if (Files.exists(spool.resolve("stolen"), LinkOption.NOFOLLOW_LINKS)) ok("/bin/mv", spool.resolve("stolen").toString(), rules.toString());
        check("  but can still make and remove a lock file of its own",
                asGroupMail("/usr/bin/touch", spool.resolve("vmail.lock").toString())
                && asGroupMail("/bin/rm", spool.resolve("vmail.lock").toString()) && !Files.exists(spool.resolve("vmail.lock")));
        check("root now makes the folders, root's, rwxr-xr-x", !refused(() -> RootOnlyPath.folders(spool, "sieve", "d.test", "u"))
                && attrs(rules.resolve("d.test/u")).equals("root:mail rwxr-xr-x"));
        check("the second run: nothing to do", MailSpoolSticky.ensure(spool, rules) == null);
        ok("chown", "vmail", rules.toString());
        String note = MailSpoolSticky.ensure(spool, rules);
        check("a rules folder not root's is said, not changed (" + note + ")", note != null && note.contains("WARNING")
                && attrs(rules).startsWith("vmail:"));
    }

    // ---------------------------------------------------------------- 3. the real system

    static void part3(int spoolMode, byte[] conf) throws Exception {
        System.out.println("\n== 3a. The real " + SPOOL + " (" + String.format("%04o", spoolMode & 07777) + " at the start) ==");
        Path probe = Files.createDirectory(SPOOL.resolve("sieve-group-mail-probe-" + RUN));
        Path moved = SPOOL.resolve("sieve-group-mail-probe-" + RUN + ".moved");
        if ((spoolMode & 01000) == 0) {
            check("before: the group mail renames a root folder in it (the probe works)",
                    asGroupMail("/bin/mv", probe.toString(), moved.toString()) && Files.isDirectory(moved));
            ok("/bin/mv", moved.toString(), probe.toString());
        } else {
            System.out.println("  (already sticky at the start: the control is part 2c)");
        }
        MailSpoolSticky.ensureAtBoot();
        check("after MailSpoolSticky: sticky (" + String.format("%04o", mode(SPOOL) & 07777) + ")", (mode(SPOOL) & 01000) != 0);
        check("  the group mail cannot rename a root folder in it", !asGroupMail("/bin/mv", probe.toString(), moved.toString())
                && Files.isDirectory(probe) && !Files.exists(moved));
        check("  root may write the panel's rules there (" + RootOnlyPath.problem(RULES) + ")", RootOnlyPath.problem(RULES) == null);

        System.out.println("\n== 3b. Dovecot's mail processes and the group mail ==");
        int mail = DovecotPrivilegedGroup.gidOf(Files.readString(Path.of("/etc/group")), "mail");
        boolean hadLine = new String(conf, StandardCharsets.UTF_8).contains("\n" + DovecotPrivilegedGroup.LINE);
        if (hadLine) {
            String[] p = DovecotPrivilegedGroup.userProcess(ALICE);
            System.out.println("  before: " + (p[0] == null ? "no imap: " + p[1].trim() : p[0].trim()));
            check("before: an imap of " + ALICE + " has the group mail (the probe sees it)",
                    p[0] != null && DovecotPrivilegedGroup.keepsGroup(p[0], mail));
        } else {
            System.out.println("  (dovecot.conf has no mail_privileged_group at the start: no control)");
        }
        String r = DovecotPrivilegedGroup.ensure();
        System.out.println("  " + r);
        check("DovecotPrivilegedGroup: done", !hadLine || (r != null && r.startsWith("DONE")));
        Process g = new ProcessBuilder("doveconf", "-h", "mail_privileged_group").redirectErrorStream(true).start();
        String value = new String(g.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        g.waitFor(15, TimeUnit.SECONDS);
        check("  doveconf gives no mail_privileged_group (\"" + value + "\")", value.isEmpty());
        String[] after = DovecotPrivilegedGroup.userProcess(ALICE);
        System.out.println("  after: " + (after[0] == null ? "no imap: " + after[1].trim() : after[0].trim()));
        check("  an imap of " + ALICE + " logs in, without the group mail", after[0] != null
                && !DovecotPrivilegedGroup.keepsGroup(after[0], mail));
        check("  the second run: nothing to do", DovecotPrivilegedGroup.ensure() == null);

        System.out.println("\n== 3c. A rule of the panel, a real delivery ==");
        SieveGenerator generator = new SieveGenerator();
        String rule = generator.generateSieveScript(0, new Rules().filter("groupmail-" + RUN, "move", "PanelRule"));
        check("a rule saved by the panel", generator.saveSieveScript(ALICE, rule));
        check("  root's, rw-r--r--, with its binary beside it (" + attrs(SCRIPT) + ")", attrs(SCRIPT).startsWith("root:")
                && attrs(SCRIPT).endsWith(" rw-r--r--") && Files.isRegularFile(BINARY, LinkOption.NOFOLLOW_LINKS));
        String s = deliver(CAROL, ALICE, "groupmail-" + RUN + "-a");
        check("a delivery follows it", count(ALICE, "PanelRule", s) == 1 && countAll(ALICE, s) == 1);

        System.out.println("\n== 3d. A link planted at the rule's place ==");
        Path victim = Files.writeString(work.resolve("victim-rule"), "secret of nobody\n");
        ok("chown", "nobody:nobody", victim.toString());
        ok("chmod", "600", victim.toString());
        Path binaryVictim = Files.writeString(work.resolve("victim-binary"), "another secret\n");
        ok("chown", "nobody:nobody", binaryVictim.toString());
        ok("chmod", "600", binaryVictim.toString());
        Files.deleteIfExists(SCRIPT);
        Files.createSymbolicLink(SCRIPT, victim);
        Files.deleteIfExists(BINARY);
        Files.createSymbolicLink(BINARY, binaryVictim);
        check("saving again", generator.saveSieveScript(ALICE, rule));
        check("  the file the link pointed to is as it was (" + attrs(victim) + ")",
                Files.readString(victim).equals("secret of nobody\n") && attrs(victim).equals("nobody:nobody rw-------"));
        check("  the binary's link too (" + attrs(binaryVictim) + ")",
                Files.readString(binaryVictim).equals("another secret\n") && attrs(binaryVictim).equals("nobody:nobody rw-------"));
        check("  the rule is a file of root's again, with the panel's text", Files.isRegularFile(SCRIPT, LinkOption.NOFOLLOW_LINKS)
                && attrs(SCRIPT).startsWith("root:") && Files.readString(SCRIPT).equals(rule));
        check("  and its binary a file beside it", Files.isRegularFile(BINARY, LinkOption.NOFOLLOW_LINKS));
        check("  no temporary file left", names(SCRIPT.getParent()).equals(List.of(".dovecot.sieve", ".dovecot.svbin")));
        s = deliver(CAROL, ALICE, "groupmail-" + RUN + "-b");
        check("the next delivery still follows the panel's rule", count(ALICE, "PanelRule", s) == 1 && countAll(ALICE, s) == 1);
    }

    // ---------------------------------------------------------------- helpers

    static Path folder(Path p, String owner, String mode) throws Exception {
        Files.createDirectories(p);
        ok("chown", owner, p.toString());
        ok("chmod", mode, p.toString());
        return p;
    }

    static String why(Path p) {
        String w = RootOnlyPath.problem(p);
        return w == null ? "" : w;
    }

    interface Action { void run() throws Exception; }

    static boolean refused(Action a) {
        try {
            a.run();
            return false;
        } catch (IOException e) {
            System.out.println("    refused: " + e.getMessage());
            return true;
        } catch (Exception e) {
            System.out.println("    failed otherwise: " + e);
            return false;
        }
    }

    static int mode(Path p) throws Exception {
        return (Integer) Files.getAttribute(p, "unix:mode", LinkOption.NOFOLLOW_LINKS);
    }

    static String attrs(Path p) throws Exception {
        if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) return "missing";
        PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return a.owner().getName() + ":" + a.group().getName() + " " + PosixFilePermissions.toString(a.permissions());
    }

    static List<String> names(Path dir) throws Exception {
        try (Stream<Path> s = Files.list(dir)) {
            return s.map(x -> x.getFileName().toString()).sorted().toList();
        }
    }

    /** A command as vmail with the group mail, as Dovecot's mail processes had it through mail_privileged_group. */
    static boolean asGroupMail(String... cmd) throws Exception {
        List<String> c = new ArrayList<>(List.of("/usr/sbin/chroot", "-u", "vmail", "-g", "vmail", "-G", "vmail,mail", "/"));
        c.addAll(List.of(cmd));
        return run(20, c.toArray(new String[0])) != null;
    }

    /** Sends a message through Postfix and waits until Postfix says the delivery is over; the subject to look for. */
    static String deliver(String from, String to, String token) throws Exception {
        String subject = "sieve-group-mail " + token;
        String id = token + "." + System.nanoTime() + "@" + DOMAIN;
        String msg = "From: " + from + "\nTo: " + to + "\nSubject: " + subject + "\nMessage-ID: <" + id + ">\n\nSieve test\n";
        Process p = new ProcessBuilder("/usr/sbin/sendmail", "-f", from, to).redirectErrorStream(true).start();
        try (OutputStream o = p.getOutputStream()) { o.write(msg.getBytes(StandardCharsets.US_ASCII)); }
        p.waitFor(30, TimeUnit.SECONDS);
        String status = awaitStatus(id, to);
        System.out.println("  delivered \"" + subject + "\": " + status);
        if (!"sent".equals(status)) check("Postfix delivered it to " + to, false);
        return token;
    }

    static String awaitStatus(String messageId, String to) throws Exception {
        Pattern queued = Pattern.compile("postfix/cleanup\\[\\d+\\]: ([0-9A-F]+): message-id=<" + Pattern.quote(messageId) + ">");
        for (int i = 0; i < 120; i++) {
            List<String> lines = newLog();
            for (String l : lines) {
                Matcher m = queued.matcher(l);
                if (!m.find()) continue;
                Pattern done = Pattern.compile(" " + m.group(1) + ": to=<" + Pattern.quote(to) + ">.* status=(\\w+)");
                for (String d : lines) { Matcher dm = done.matcher(d); if (dm.find()) return dm.group(1); }
            }
            Thread.sleep(500);
        }
        return null;
    }

    static List<String> newLog() throws Exception {
        List<String> out = new ArrayList<>();
        try (var in = Files.newInputStream(MAILLOG)) {
            in.skipNBytes(Math.min(logStart, Files.size(MAILLOG)));
            new BufferedReader(new InputStreamReader(in, StandardCharsets.ISO_8859_1)).lines().forEach(out::add);
        }
        return out;
    }

    static int count(String user, String folder, String text) throws Exception {
        return SieveActionsE2ETest.found(run(30, "doveadm", "search", "-u", user, "mailbox", folder, "subject", text));
    }

    static int countAll(String user, String text) throws Exception {
        return SieveActionsE2ETest.found(run(30, "doveadm", "search", "-u", user, "subject", text));
    }

    // ---------------------------------------------------------------- setting up and taking down

    static void setUp() throws Exception {
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

        String password = run(10, "openssl", "rand", "-hex", "16").trim();
        String hash = run(20, "doveadm", "pw", "-s", "BLF-CRYPT", "-p", password);
        if (hash == null || !hash.startsWith("{BLF-CRYPT}")) throw new IllegalStateException("doveadm pw gave no BLF-CRYPT hash");
        StringBuilder sql = new StringBuilder(cleanupSql())
                .append("INSERT INTO domains (domain, active) VALUES ('" + DOMAIN + "', 1);\n");
        for (String m : new String[]{ALICE, CAROL})
            sql.append("INSERT INTO mailboxes (domain_id, email, password, name, active) SELECT id, '").append(m).append("', '")
               .append(hash.trim()).append("', 'sieve group mail test', 1 FROM domains WHERE domain='" + DOMAIN + "';\n");
        if (mysql(sql.toString()) == null) throw new IllegalStateException("cannot create the test mailboxes in " + db);
        logStart = Files.size(MAILLOG);
        run(20, "doveadm", "mailbox", "create", "-u", ALICE, "PanelRule");
        System.out.println("\ntest mailboxes " + ALICE + ", " + CAROL + " in " + db + "; run " + RUN);
        System.out.println("packages: " + run(20, "pkg", "query", "-g", "%n-%v", "dovecot*").trim().replace('\n', ' '));
    }

    static String cleanupSql() {
        return "DELETE FROM mailboxes WHERE email IN ('" + ALICE + "', '" + CAROL + "');\n"
             + "DELETE FROM domains WHERE domain='" + DOMAIN + "';\n";
    }

    /** Everything back as it was: the test domain, the probe folders, dovecot.conf (with a reload) and /var/mail's mode. */
    static void tearDown(int spoolMode, byte[] conf, PosixFileAttributes confAttrs) throws Exception {
        try {
            if (Files.exists(work.resolve("root.cnf"))) mysql(cleanupSql());
        } finally {
            try {
                if (!java.util.Arrays.equals(Files.readAllBytes(DOVECOT_CONF), conf)) {
                    Files.write(DOVECOT_CONF, conf);
                    Files.setPosixFilePermissions(DOVECOT_CONF, confAttrs.permissions());
                    run(60, "service", "dovecot", "reload");
                    System.out.println("\n" + DOVECOT_CONF + " put back as it was, Dovecot reloaded");
                }
                if ((mode(SPOOL) & 07777) != (spoolMode & 07777)) {
                    Files.setAttribute(SPOOL, "unix:mode", spoolMode & 07777, LinkOption.NOFOLLOW_LINKS);
                    System.out.println(SPOOL + " put back to " + String.format("%04o", spoolMode & 07777));
                }
            } finally {
                new ProcessBuilder("rm", "-rf", "/var/vmail/" + DOMAIN, RULES + "/" + DOMAIN,
                        SPOOL + "/sieve-group-mail-probe-" + RUN, SPOOL + "/sieve-group-mail-probe-" + RUN + ".moved",
                        work.toString()).start().waitFor();
            }
        }
    }

    static String mysql(String sql) throws Exception {
        Path f = work.resolve("statements.sql");
        Files.writeString(f, sql);
        return run(30, "/bin/sh", "-c", "mysql --defaults-extra-file='" + work.resolve("root.cnf") + "' " + db + " < '" + f + "'");
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
