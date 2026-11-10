package org.mail_panel.system;

import org.mail_panel.integration.SieveGenerator;
import org.mail_panel.integration.SieveGeneratorTest.Rules;
import org.mail_panel.scripts.DovecotScript;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The folder of the panel's Sieve rules, /var/mail/sieve, stays root's (reperto 220).
 *
 * Until 10/11/2026 the script of the Dovecot component (DovecotScript) ran "chown -R vmail:vmail /var/mail/sieve". Since
 * reperto 214 the panel's rules (/var/mail/sieve/domain/user/.dovecot.sieve) are root's on purpose: vmail, the user that
 * delivers, reads and runs them but must never rewrite them. With the folder above them owned by vmail, vmail could
 * rename a domain's folder (root's) and make its own in its place, with rules of its own.
 *  1. Without a system: every line of the script that touches /var/mail/sieve gives it to root, and none gives write to
 *     group or others.
 *  2. With -De2e.vm=yes, as root on the VM: the script's own lines for /var/mail/sieve, run for real on a bench folder
 *     (its parent made like /var/mail, root:mail 0775), never on the real one:
 *     a. on a system with no folder: the folders are made root:mail 0755, and vmail can create nothing in them;
 *     b. on a folder the old script gave to vmail, with the panel's rules in it, a folder and a link vmail made when it
 *        could: first vmail can rename a domain's folder (so the probe works); after the lines, everything is root:mail
 *        with no write for group or others, vmail can rename, replace or add nothing, it still reads the rules, and
 *        the link was not followed.
 *  3. With -De2e.vm=yes, the real /var/mail/sieve with real deliveries: a rule saved by the panel moves a message; vmail
 *     can rename neither the domain's folder nor the mailbox's, nor the rule or its binary, nor rewrite them, nor add a
 *     folder or a file; the next delivery still follows the panel's rule.
 *
 * Part 3 creates a domain nobody can own (sieve-owner.test: .test is reserved) with two mailboxes in the mail database
 * and removes all of it at the end. Parts 2 and 3 only as root with -De2e.vm=yes, on the VM:
 *   java [-De2e.vm=yes] -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.SieveFolderOwnerTest [database]
 */
public class SieveFolderOwnerTest {

    static final String PANEL_RULES = "/var/mail/sieve";
    static final String DOMAIN = "sieve-owner.test";
    static final String ALICE = "alice@" + DOMAIN, CAROL = "carol@" + DOMAIN;
    static final Path SCRIPT = Path.of(PANEL_RULES, DOMAIN, "alice", ".dovecot.sieve");
    static final Path BINARY = SCRIPT.resolveSibling(".dovecot.svbin");
    static final Path PLANTED = Path.of(PANEL_RULES, "sieve-owner-planted.test");
    static final Path MAILLOG = Path.of("/var/log/maillog");

    private static int failures = 0;
    private static String db;
    private static Path work;
    private static long logStart;
    private static final String RUN = Long.toString(System.currentTimeMillis() % 100000000L, 36);

    public static void main(String[] args) throws Exception {
        List<String> lines = folderLines();
        part1(lines);
        if (!"yes".equals(System.getProperty("e2e.vm")) || !"root".equals(System.getProperty("user.name"))) {
            System.out.println("\nWithout -De2e.vm=yes, as root, parts 2 and 3 do not run: they change owners and deliver real mail.");
        } else {
            db = args.length > 0 ? args[0] : "mailserver";
            if (!db.matches("[A-Za-z0-9_]+")) throw new IllegalArgumentException("database name not valid: " + db);
            work = Files.createTempDirectory(Path.of("/var/tmp"), "sieve-owner");
            // Born 0700: vmail must reach the bench, or every "vmail cannot" passes for the wrong reason.
            Files.setPosixFilePermissions(work, PosixFilePermissions.fromString("rwxr-xr-x"));
            try {
                part2(lines);
                setUp();
                part3();
            } finally {
                tearDown();
            }
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    /** The commands that change files. */
    static final Pattern COMMAND = Pattern.compile("(mkdir|chown|chgrp|chmod|rm|mv|cp|ln|install|touch)\\s.*");

    /**
     * The commands of the Dovecot component's script that touch /var/mail/sieve. Dovecot's configuration, written by the
     * same script, names the folder too (sieve_before, sieve_global_dir): those are not commands.
     */
    static List<String> folderLines() {
        return new DovecotScript().getScriptContent().lines().map(String::strip)
                .filter(l -> l.contains(PANEL_RULES) && COMMAND.matcher(l).matches()).toList();
    }

    // ---------------------------------------------------------------- 1. the script's text

    static void part1(List<String> lines) {
        System.out.println("== 1. What the Dovecot component's script does to " + PANEL_RULES + " ==");
        lines.forEach(l -> System.out.println("  | " + l));
        check("it makes the folder", lines.stream().anyMatch(l -> l.startsWith("mkdir -p " + PANEL_RULES)));
        List<String> chowns = lines.stream().filter(l -> l.startsWith("chown ")).toList();
        check("it sets the owner", !chowns.isEmpty());
        for (String l : chowns) check("  \"" + l + "\" gives it to root", "root".equals(chownOwner(l)));
        for (String l : lines.stream().filter(l -> l.startsWith("chmod ")).toList())
            check("  \"" + l + "\" gives no write to group or others", !grantsGroupOrOtherWrite(chmodMode(l)));
        check("the owner check can fail: \"chown -R vmail:vmail " + PANEL_RULES + "\" is not root's",
                !"root".equals(chownOwner("chown -R vmail:vmail " + PANEL_RULES)));
        check("the mode check can fail: 775, 0777, g+w, a=rwx and u+x,o+w give write",
                grantsGroupOrOtherWrite("775") && grantsGroupOrOtherWrite("0777") && grantsGroupOrOtherWrite("g+w")
                        && grantsGroupOrOtherWrite("a=rwx") && grantsGroupOrOtherWrite("u+x,o+w"));
        check("  while 755, go-w and u+w do not", !grantsGroupOrOtherWrite("755") && !grantsGroupOrOtherWrite("go-w")
                && !grantsGroupOrOtherWrite("u+w"));
    }

    /** The user of a chown line: the first word that is not an option, up to ':'. */
    static String chownOwner(String line) {
        for (String w : line.split("\\s+")) {
            if (w.equals("chown") || w.startsWith("-")) continue;
            return w.split(":", 2)[0];
        }
        return null;
    }

    static String chmodMode(String line) {
        for (String w : line.split("\\s+")) {
            if (w.equals("chmod") || w.startsWith("-")) continue;
            return w;
        }
        return "";
    }

    /** True if the chmod mode, numeric or symbolic, gives write to the group or to others. */
    static boolean grantsGroupOrOtherWrite(String mode) {
        if (mode.matches("[0-7]{3,4}")) return (Integer.parseInt(mode, 8) & 022) != 0;
        for (String clause : mode.split(",")) {
            Matcher m = Pattern.compile("([ugoa]*)([-+=])([rwxXst]*)").matcher(clause);
            if (!m.matches() || m.group(2).equals("-") || !m.group(3).contains("w")) continue;
            String who = m.group(1);
            if (who.isEmpty() || who.contains("g") || who.contains("o") || who.contains("a")) return true;
        }
        return false;
    }

    // ---------------------------------------------------------------- 2. the script's lines, run on a bench

    static void part2(List<String> lines) throws Exception {
        Path parent = work.resolve("mail");
        Path folder = parent.resolve("sieve");
        String shell = String.join("\n", lines).replace(PANEL_RULES, folder.toString()) + "\n";

        System.out.println("\n== 2a. The script's lines on a system with no folder (bench: " + folder + ") ==");
        makeParent(parent);
        check("they run", ok("/bin/sh", "-c", shell));
        check("the folder is root:mail rwxr-xr-x (" + attrs(folder) + ")", attrs(folder).equals("root:mail rwxr-xr-x"));
        check("global is root:mail rwxr-xr-x (" + attrs(folder.resolve("global")) + ")",
                attrs(folder.resolve("global")).equals("root:mail rwxr-xr-x"));
        check("vmail reaches it (the probe works)", asVmail("/bin/ls", "-a", folder.resolve("global").toString()));
        check("vmail cannot make a folder in it", !asVmail("/bin/mkdir", folder.resolve("planted.test").toString())
                && !Files.exists(folder.resolve("planted.test")));
        check("vmail cannot put a script in global", !asVmail("/usr/bin/touch", folder.resolve("global/planted.sieve").toString())
                && !Files.exists(folder.resolve("global/planted.sieve")));

        System.out.println("\n== 2b. The script's lines on a folder the old script gave to vmail ==");
        makeParent(parent);
        Path domain = folder.resolve("dom.test");
        Path alice = domain.resolve("alice");
        Path script = alice.resolve(".dovecot.sieve");
        Path binary = alice.resolve(".dovecot.svbin");
        Files.createDirectories(alice);
        Files.writeString(script, "require \"fileinto\";\nfileinto \"Panel\";\n");
        Files.writeString(binary, "binary of the panel\n");
        ok("chown", "-R", "root:mail", folder.toString());
        ok("chmod", "755", folder.toString(), domain.toString(), alice.toString());
        ok("chmod", "644", script.toString(), binary.toString());
        ok("chown", "vmail:vmail", folder.toString());
        Path outside = work.resolve("outside");
        Files.writeString(outside, "not under the folder\n");
        ok("chown", "nobody:nobody", outside.toString());
        ok("chmod", "666", outside.toString());
        check("before: vmail can rename a domain's folder of root's (the probe works)",
                asVmail("/bin/mv", domain.toString(), folder.resolve("dom.test.aside").toString()));
        ok("/bin/mv", folder.resolve("dom.test.aside").toString(), domain.toString());
        check("  and make a domain's folder of its own, with a link in it", asVmail("/bin/mkdir", "-p", folder.resolve("vmail.test/bob").toString())
                && asVmail("/bin/ln", "-s", outside.toString(), folder.resolve("vmail.test/bob/.dovecot.sieve").toString()));
        check("they run", ok("/bin/sh", "-c", shell));
        List<String> wrong = new ArrayList<>();
        try (Stream<Path> all = Files.walk(folder)) {
            for (Path p : all.toList()) {
                if (Files.isSymbolicLink(p)) continue;
                PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!a.owner().getName().equals("root") || !a.group().getName().equals("mail")
                        || a.permissions().contains(PosixFilePermission.GROUP_WRITE)
                        || a.permissions().contains(PosixFilePermission.OTHERS_WRITE))
                    wrong.add(folder.relativize(p) + " " + attrs(p));
            }
        }
        check("everything under the folder is root:mail, no write for group or others" + (wrong.isEmpty() ? "" : ": " + wrong),
                wrong.isEmpty());
        check("the rule kept its mode (" + attrs(script) + ")", attrs(script).equals("root:mail rw-r--r--"));
        check("the link was not followed: the file outside is still nobody's, 0666 (" + attrs(outside) + ")",
                attrs(outside).equals("nobody:nobody rw-rw-rw-"));
        check("vmail cannot rename the domain's folder", !asVmail("/bin/mv", domain.toString(), folder.resolve("dom.test.aside").toString()));
        check("vmail cannot rename the mailbox's folder", !asVmail("/bin/mv", alice.toString(), domain.resolve("alice.aside").toString()));
        check("vmail cannot rename the folder it had made", !asVmail("/bin/mv", folder.resolve("vmail.test").toString(), folder.resolve("vmail.test.aside").toString()));
        check("vmail cannot rename the rule", !asVmail("/bin/mv", script.toString(), alice.resolve("aside").toString()));
        check("vmail cannot rewrite the rule", !asVmail("/bin/sh", "-c", "echo 'redirect \"x@example.com\";' >> '" + script + "'"));
        check("vmail cannot touch the binary", !asVmail("/usr/bin/touch", binary.toString()));
        check("vmail cannot make a folder", !asVmail("/bin/mkdir", folder.resolve("planted.test").toString()));
        check("vmail still reads the rule and its binary", asVmail("/bin/cat", script.toString(), binary.toString()));
        check("the rule is the panel's", Files.isRegularFile(script, LinkOption.NOFOLLOW_LINKS)
                && Files.readString(script).equals("require \"fileinto\";\nfileinto \"Panel\";\n"));
    }

    static void makeParent(Path parent) throws Exception {
        ok("rm", "-rf", parent.toString());
        Files.createDirectory(parent);
        ok("chown", "root:mail", parent.toString());
        ok("chmod", "775", parent.toString());
    }

    // ---------------------------------------------------------------- 3. the real folder, real deliveries

    static void part3() throws Exception {
        System.out.println("\n== 3. The real " + PANEL_RULES + ", with real deliveries ==");
        System.out.println("  " + PANEL_RULES + ": " + attrs(Path.of(PANEL_RULES)));
        check(PANEL_RULES + " is root's, with no write for group or others", attrs(Path.of(PANEL_RULES)).startsWith("root:")
                && attrs(Path.of(PANEL_RULES)).matches("\\S+ .{4}-.{2}-.*"));
        SieveGenerator generator = new SieveGenerator();
        check("a rule saved by the panel",
                generator.saveSieveScript(ALICE, generator.generateSieveScript(0, new Rules().filter("owner-" + RUN, "move", "PanelRule"))));
        check("  its binary is beside it", Files.isRegularFile(BINARY));
        String s = deliver(CAROL, ALICE, "owner-" + RUN + "-a");
        check("a delivery follows it", count(ALICE, "PanelRule", s) == 1 && countAll(ALICE, s) == 1);

        Path domain = Path.of(PANEL_RULES, DOMAIN);
        check("vmail cannot rename the domain's folder", !asVmail("/bin/mv", domain.toString(), domain + ".aside")
                && Files.isDirectory(domain));
        check("vmail cannot rename the mailbox's folder", !asVmail("/bin/mv", SCRIPT.getParent().toString(), SCRIPT.getParent() + ".aside"));
        check("vmail cannot rename the rule", !asVmail("/bin/mv", SCRIPT.toString(), SCRIPT + ".aside"));
        check("vmail cannot rename the binary", !asVmail("/bin/mv", BINARY.toString(), BINARY + ".aside"));
        check("vmail cannot rewrite the rule", !asVmail("/bin/sh", "-c", "echo 'redirect \"x@example.com\";' >> '" + SCRIPT + "'"));
        check("vmail cannot touch the binary", !asVmail("/usr/bin/touch", BINARY.toString()));
        check("vmail cannot make a domain's folder", !asVmail("/bin/mkdir", PLANTED.toString()) && !Files.exists(PLANTED));
        check("vmail cannot make a mailbox's folder", !asVmail("/bin/mkdir", domain.resolve("bob").toString()));
        if (Files.isDirectory(Path.of(PANEL_RULES, "global")))
            check("vmail cannot put a script in global", !asVmail("/usr/bin/touch", PANEL_RULES + "/global/sieve-owner-planted.sieve"));
        check("  (vmail can touch a file of its own: the probe works)",
                asVmail("/usr/bin/touch", "/var/vmail/" + DOMAIN + "/alice/vmail-probe-" + RUN));
        s = deliver(CAROL, ALICE, "owner-" + RUN + "-b");
        check("the next delivery still follows the panel's rule", count(ALICE, "PanelRule", s) == 1 && countAll(ALICE, s) == 1);
    }

    // ---------------------------------------------------------------- the mail system

    static boolean asVmail(String... cmd) throws Exception {
        List<String> c = new ArrayList<>(List.of("/usr/sbin/chroot", "-u", "vmail", "-g", "vmail", "-G", "vmail", "/"));
        c.addAll(List.of(cmd));
        return run(20, c.toArray(new String[0])) != null;
    }

    static String attrs(Path p) throws Exception {
        if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) return "missing";
        PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return a.owner().getName() + ":" + a.group().getName() + " " + PosixFilePermissions.toString(a.permissions());
    }

    /** Sends a message through Postfix and waits until Postfix says the delivery is over; the subject to look for. */
    static String deliver(String from, String to, String token) throws Exception {
        String subject = "sieve-owner " + token;
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

    /** The mode of /var/mail before setUp gave it the panel's boot state (reperto 221): put back at the end. */
    private static int spoolMode = -1;

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
               .append(hash.trim()).append("', 'sieve owner test', 1 FROM domains WHERE domain='" + DOMAIN + "';\n");
        if (mysql(sql.toString()) == null) throw new IllegalStateException("cannot create the test mailboxes in " + db);
        spoolMode = SieveActionsE2ETest.spoolAsAtBoot();
        logStart = Files.size(MAILLOG);
        run(20, "doveadm", "mailbox", "create", "-u", ALICE, "PanelRule");
        System.out.println("\ntest mailboxes " + ALICE + ", " + CAROL + " in " + db + "; run " + RUN);
        System.out.println("packages: " + run(20, "pkg", "query", "-g", "%n-%v", "dovecot*").trim().replace('\n', ' '));
    }

    static String cleanupSql() {
        return "DELETE FROM mailboxes WHERE email IN ('" + ALICE + "', '" + CAROL + "');\n"
             + "DELETE FROM domains WHERE domain='" + DOMAIN + "';\n";
    }

    static void tearDown() throws Exception {
        try {
            if (Files.exists(work.resolve("root.cnf"))) mysql(cleanupSql());
        } finally {
            new ProcessBuilder("rm", "-rf", "/var/vmail/" + DOMAIN, PANEL_RULES + "/" + DOMAIN, PANEL_RULES + "/" + DOMAIN + ".aside",
                    PLANTED.toString(), PANEL_RULES + "/global/sieve-owner-planted.sieve", work.toString()).start().waitFor();
            SieveActionsE2ETest.spoolBack(spoolMode);
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

    /** True if the command succeeds; its output is not needed. */
    static boolean ok(String... cmd) throws Exception {
        return run(30, cmd) != null;
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
