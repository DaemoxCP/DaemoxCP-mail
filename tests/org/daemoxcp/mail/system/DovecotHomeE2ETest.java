package org.daemoxcp.mail.system;

import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.integration.SieveGenerator;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Every mailbox's Dovecot home in home/, with real deliveries and the real configuration of the VM (finding 217).
 *
 * The VM must start with the home of before (home = the mail root). Then:
 *  1. Before: an autoreply written by the panel's SieveGenerator and a script of the mailbox's own (ManageSieve on 4190);
 *     one delivery through Postfix, and the false folders show up in IMAP LIST (the fault as it was). A second mailbox
 *     gets a message moved into its false folder, as a user could do from the webmail.
 *  2. A fault planted: Dovecot gives a home other than the one the panel expects. DovecotHome puts the configuration
 *     back as it was, reloads, and takes away the copies it had made.
 *  3. DovecotHome as at boot: the configuration with the new home, Dovecot's files in the home (moved as vmail), the
 *     false folders gone from IMAP LIST and from the subscriptions, the autoreply still remembers whom it answered (no second reply), the
 *     mailbox's own script still runs from the home; the false folder with a message in it stays.
 *  4. A mailbox whose rules the panel writes now: its home is there before the first delivery, and the first autoreply
 *     leaves no "duplicate db" error in the maillog.
 *  5. Second run: nothing changes.
 * At the end the configuration goes back as it was, Dovecot reloads, the other mailboxes of the VM get their files back
 * in the root, and the test domain (dovecot-home.test: .test is reserved) is removed.
 *
 * Only as root with -De2e.vm=yes, on the VM:
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.DovecotHomeE2ETest [database]
 */
public class DovecotHomeE2ETest {

    static final String DOMAIN = "dovecot-home.test";
    static final String ALICE = "alice@" + DOMAIN, BOB = "bob@" + DOMAIN, CAROL = "carol@" + DOMAIN, DAVE = "dave@" + DOMAIN;
    static final Path VMAIL = Path.of("/var/vmail");
    static final Path MAILLOG = Path.of("/var/log/maillog");
    static final Pattern FALSE = Pattern.compile("^dovecot(\\..*)?$");

    private static int failures = 0;
    private static String db, password, savedConf;
    private static Path work, fake;
    private static long logStart;
    private static final List<Path> homesBefore = new ArrayList<>();
    private static final SieveGenerator GENERATOR = new SieveGenerator();

    /** An autoreply, as the administrator sets it in the panel. */
    static final class Away extends MailDatabase {
        @Override public AutoResponder getAutoResponder(int mailboxId) {
            AutoResponder a = new AutoResponder();
            a.enabled = true;
            a.subject = "Away";
            a.body = "Back on Monday";
            a.intervalHours = 24;
            return a;
        }
        @Override public List<ForwardingRule> getForwardingRules(int mailboxId) { return List.of(); }
        @Override public List<SieveFilter> getSieveFilters(int mailboxId) { return List.of(); }
    }

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm")) || !"root".equals(System.getProperty("user.name"))) {
            System.out.println("Without -De2e.vm=yes, as root, this test does nothing: it changes Dovecot's configuration.");
            return;
        }
        db = args.length > 0 ? args[0] : "daemoxcp_mail";
        if (!db.matches("[A-Za-z0-9_]+")) throw new IllegalArgumentException("database name not valid: " + db);
        savedConf = Files.readString(DovecotHome.authSql);
        // Read here, not with DovecotHome: the code under test does not decide where the test starts from.
        if (!Pattern.compile("(?m)(home=/var/vmail/%d/%n|home = /var/vmail/%\\{user \\| domain\\}/%\\{user \\| username\\})[ \\t]*$")
                .matcher(savedConf).find()) {
            System.out.println("The VM must have the home of before (home = the mail root) in " + DovecotHome.authSql + ": nothing done.");
            System.exit(1);
        }
        work = Files.createTempDirectory(Path.of("/var/tmp"), "dovecot-home-e2e");
        try {
            setUp();
            run();
        } finally {
            tearDown();
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    static void run() throws Exception {
        String away = GENERATOR.generateSieveScript(0, new Away());
        Path aliceDir = VMAIL.resolve(DOMAIN).resolve("alice");

        System.out.println("\n== 1. Before: the home is the mail root ==");
        check("the panel's autoreply saved for alice and carol", GENERATOR.saveSieveScript(ALICE, away) && GENERATOR.saveSieveScript(CAROL, away));
        check("  no home made that the configuration does not use", !Files.exists(aliceDir.resolve("home")));
        check("alice's own script through ManageSieve", manageSieve(ALICE, "own",
                "require [\"fileinto\", \"copy\"];\r\nif header :contains \"subject\" \"home-e2e\" { fileinto :copy \"Own\"; }\r\n"));
        check("  stored in the mail root, as the configuration of before says", Files.isSymbolicLink(aliceDir.resolve("dovecot.sieve")));
        deliver(BOB, ALICE, "first");
        check("bob gets alice's autoreply", awaitReplies(ALICE, 1));
        check("alice's own script ran (a copy in Own)", count(ALICE, "Own", "home-e2e first") == 1);
        List<String> listed = imapList(ALICE);
        System.out.println("  IMAP LIST: " + listed);
        check("the false folders are there (the fault as it was)", listed.contains("dovecot.lda-dupes.locks"));
        run(20, "doveadm", "mailbox", "subscribe", "-u", ALICE, "dovecot.lda-dupes.locks");
        check("  alice subscribed to one in the webmail", subscribed(ALICE).contains("dovecot.lda-dupes.locks"));
        deliver(BOB, CAROL, "carol");
        run(30, "doveadm", "move", "-u", CAROL, "dovecot.lda-dupes.locks", "mailbox", "INBOX", "subject", "home-e2e carol");
        check("carol moved a message into her false folder", count(CAROL, "dovecot.lda-dupes.locks", "home-e2e carol") == 1);

        System.out.println("\n== 2. A fault planted: Dovecot gives another home ==");
        fake = Files.createTempDirectory(Path.of("/var/tmp"), "dovecot-home-fake");
        Path fakeAlice = Files.createDirectories(fake.resolve(DOMAIN).resolve("alice"));
        Files.writeString(fakeAlice.resolve(".dovecot.lda-dupes"), "fake");
        run(10, "chown", "-R", "vmail:vmail", fake.toString());
        DovecotHome.vmail = fake;
        String r = DovecotHome.ensure();
        DovecotHome.vmail = VMAIL;
        System.out.println("  " + r);
        check("put back, and said why", r != null && r.startsWith("ROLLED_BACK") && r.contains("doveadm user"));
        check("  the configuration exactly as before", Files.readString(DovecotHome.authSql).equals(savedConf));
        check("  the copy it had made is gone", !Files.exists(fakeAlice.resolve("home")) && Files.exists(fakeAlice.resolve(".dovecot.lda-dupes")));
        check("  Dovecot gives the home of before again", home(ALICE).equals(aliceDir.toString()));

        System.out.println("\n== 3. DovecotHome as at boot ==");
        r = DovecotHome.ensure();
        System.out.println("  " + r);
        check("done", r == null);
        check("  the configuration with the new home", DovecotHome.usesHome(Files.readString(DovecotHome.authSql)));
        check("  Dovecot gives alice the home in her folder", home(ALICE).equals(aliceDir.resolve("home").toString()));
        listed = imapList(ALICE);
        System.out.println("  IMAP LIST: " + listed);
        check("  no false folder in IMAP LIST, the real ones still there", listed.stream().noneMatch(n -> FALSE.matcher(n).matches())
                && listed.contains("INBOX") && listed.contains("Own"));
        check("  the subscription to the false folder is gone, the one to Own stays",
                !subscribed(ALICE).contains("dovecot.lda-dupes.locks") && subscribed(ALICE).contains("Own"));
        check("  Dovecot's files only in the home", !exists(aliceDir.resolve(".dovecot.lda-dupes")) && !exists(aliceDir.resolve(".dovecot.lda-dupes.locks"))
                && !exists(aliceDir.resolve("sieve")) && !exists(aliceDir.resolve("dovecot.sieve"))
                && Files.isRegularFile(aliceDir.resolve("home/.dovecot.lda-dupes")) && Files.isSymbolicLink(aliceDir.resolve("home/dovecot.sieve")));
        check("  the home is vmail's, 0700", "vmail".equals(owner(aliceDir.resolve("home")))
                && "rwx------".equals(mode(aliceDir.resolve("home"))));
        long logBefore = Files.size(MAILLOG);
        deliver(BOB, ALICE, "second");
        Thread.sleep(3000);
        check("the autoreply remembers bob: no second reply", replies(ALICE) == 1
                && newLog(logBefore).stream().anyMatch(l -> l.contains("lmtp(" + ALICE + ")")
                        && l.contains("discarded duplicate vacation response to <" + BOB + ">")));
        check("alice's own script still runs, from the home", count(ALICE, "Own", "home-e2e second") == 1);
        check("carol's false folder with a message stays, the message in it",
                Files.isDirectory(VMAIL.resolve(DOMAIN).resolve("carol/.dovecot.lda-dupes.locks"))
                && count(CAROL, "dovecot.lda-dupes.locks", "home-e2e carol") == 1);

        System.out.println("\n== 4. A mailbox whose rules the panel writes now ==");
        Path daveDir = VMAIL.resolve(DOMAIN).resolve("dave");
        check("the panel's autoreply saved for dave", GENERATOR.saveSieveScript(DAVE, away));
        check("  his home is there before the first delivery, vmail's, 0700", Files.isDirectory(daveDir.resolve("home"))
                && "vmail".equals(owner(daveDir.resolve("home")))
                && "rwx------".equals(mode(daveDir.resolve("home")))
                && "rwx------".equals(mode(daveDir)));
        logBefore = Files.size(MAILLOG);
        deliver(BOB, DAVE, "dave");
        check("  bob gets dave's autoreply", awaitReplies(DAVE, 1));
        List<String> daveLines = newLog(logBefore).stream().filter(l -> l.contains("lmtp(" + DAVE + ")")).toList();
        daveLines.forEach(l -> System.out.println("  " + l.replaceAll("^.*lmtp\\(", "lmtp(")));
        check("  and no error from Dovecot about the duplicate database", daveLines.stream().noneMatch(l -> l.contains("Error")));
        check("  dave's mail where it always was", count(DAVE, "INBOX", "home-e2e dave") == 1 && Files.isDirectory(daveDir.resolve("cur")));

        System.out.println("\n== 5. Second run ==");
        List<String> tree = tree(VMAIL.resolve(DOMAIN));
        String conf = Files.readString(DovecotHome.authSql);
        check("nothing to do", DovecotHome.ensure() == null);
        check("  nothing changed", tree.equals(tree(VMAIL.resolve(DOMAIN))) && conf.equals(Files.readString(DovecotHome.authSql)));
    }

    // ---------------------------------------------------------------- the mail system

    /** The home Dovecot gives the mailbox. */
    static String home(String user) throws Exception {
        for (int i = 0; i < 10; i++) {
            // Right after a reload the authentication process may not answer yet.
            String out = run(30, "doveadm", "user", "-f", "home", "-u", user);
            if (out != null) return out.trim();
            Thread.sleep(1000);
        }
        return "";
    }

    /** The folders the mailbox is subscribed to (what the webmail shows). */
    static List<String> subscribed(String user) throws Exception {
        String out = run(30, "doveadm", "mailbox", "list", "-s", "-u", user);
        return out == null ? List.of() : out.lines().map(String::trim).toList();
    }

    /** The folders IMAP LIST gives, as the webmail sees them (the imap process, logged in as the mailbox). */
    static List<String> imapList(String user) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("doveadm", "exec", "imap", "-u", user).redirectErrorStream(true);
        pb.environment().put("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin");
        Process p = pb.start();
        try (OutputStream o = p.getOutputStream()) { o.write("a LIST \"\" \"*\"\r\nb LOGOUT\r\n".getBytes(StandardCharsets.US_ASCII)); }
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor(30, TimeUnit.SECONDS);
        List<String> names = new ArrayList<>();
        Matcher m = Pattern.compile("(?m)^\\* LIST \\([^)]*\\) \"[^\"]*\" \"?([^\"\\r\\n]+)\"?\\r?$").matcher(out);
        while (m.find()) names.add(m.group(1));
        return names;
    }

    /** Sends a message through Postfix and waits until Postfix says the delivery is over. */
    static void deliver(String from, String to, String token) throws Exception {
        String id = token + "." + System.nanoTime() + "@" + DOMAIN;
        String msg = "From: " + from + "\nTo: " + to + "\nSubject: home-e2e " + token + "\nMessage-ID: <" + id + ">\n\nHome test\n";
        Process p = new ProcessBuilder("/usr/sbin/sendmail", "-f", from, to).redirectErrorStream(true).start();
        try (OutputStream o = p.getOutputStream()) { o.write(msg.getBytes(StandardCharsets.US_ASCII)); }
        p.waitFor(30, TimeUnit.SECONDS);
        String status = awaitStatus(id, to);
        System.out.println("  delivered \"home-e2e " + token + "\" to " + to + ": " + status);
        if (!"sent".equals(status)) check("Postfix delivered it to " + to, false);
    }

    /** Postfix's status for the message with this Message-ID to this recipient, from the maillog; null after 60 s. */
    static String awaitStatus(String messageId, String to) throws Exception {
        Pattern queued = Pattern.compile("postfix/cleanup\\[\\d+\\]: ([0-9A-F]+): message-id=<" + Pattern.quote(messageId) + ">");
        for (int i = 0; i < 120; i++) {
            List<String> lines = newLog(logStart);
            List<String> qids = new ArrayList<>();
            for (String l : lines) { Matcher m = queued.matcher(l); if (m.find()) qids.add(m.group(1)); }
            for (String qid : qids) {
                Pattern done = Pattern.compile(" " + qid + ": to=<" + Pattern.quote(to) + ">.* status=(\\w+)");
                for (String l : lines) { Matcher m = done.matcher(l); if (m.find()) return m.group(1); }
            }
            Thread.sleep(500);
        }
        return null;
    }

    static List<String> newLog(long from) throws Exception {
        List<String> out = new ArrayList<>();
        try (var in = Files.newInputStream(MAILLOG)) {
            in.skipNBytes(Math.min(from, Files.size(MAILLOG)));
            new BufferedReader(new InputStreamReader(in, StandardCharsets.ISO_8859_1)).lines().forEach(out::add);
        }
        return out;
    }

    /** Messages in that folder whose subject contains the text (0 if the folder does not exist). */
    static int count(String user, String folder, String text) throws Exception {
        String out = run(30, "doveadm", "search", "-u", user, "mailbox", folder, "subject", text);
        if (out == null) return 0;
        int n = 0;
        for (String l : out.lines().toList()) {
            if (l.matches("[0-9a-f]{32} \\d+")) n++;
            else if (!l.isBlank()) System.out.println("  doveadm: " + l);
        }
        return n;
    }

    /** The autoreplies bob got from that mailbox. */
    static int replies(String from) throws Exception {
        String out = run(30, "doveadm", "search", "-u", BOB, "mailbox", "INBOX", "subject", "Away", "from", from);
        return out == null ? 0 : (int) out.lines().filter(l -> l.matches("[0-9a-f]{32} \\d+")).count();
    }

    /** Waits up to 30 s for the autoreplies: they come with a second delivery. */
    static boolean awaitReplies(String from, int expected) throws Exception {
        for (int i = 0; i < 60; i++) {
            if (replies(from) >= expected) return replies(from) == expected;
            Thread.sleep(500);
        }
        return false;
    }

    /** Saves and activates a script of the mailbox's own through ManageSieve. */
    static boolean manageSieve(String user, String name, String script) throws Exception {
        String b64 = Base64.getEncoder().encodeToString(("\0" + user + "\0" + password).getBytes(StandardCharsets.UTF_8));
        try (Socket so = new Socket("127.0.0.1", 4190)) {
            so.setSoTimeout(20000);
            BufferedReader in = new BufferedReader(new InputStreamReader(so.getInputStream(), StandardCharsets.UTF_8));
            OutputStream out = so.getOutputStream();
            if (!response(in).startsWith("OK")) return false;
            if (!command(in, out, "AUTHENTICATE \"PLAIN\" \"" + b64 + "\"\r\n").startsWith("OK")) return false;
            byte[] body = script.getBytes(StandardCharsets.UTF_8);
            if (!command(in, out, "PUTSCRIPT \"" + name + "\" {" + body.length + "+}\r\n" + script + "\r\n").startsWith("OK")) return false;
            if (!command(in, out, "SETACTIVE \"" + name + "\"\r\n").startsWith("OK")) return false;
            command(in, out, "LOGOUT\r\n");
        }
        return true;
    }

    static String command(BufferedReader in, OutputStream out, String line) throws Exception {
        out.write(line.getBytes(StandardCharsets.UTF_8));
        out.flush();
        return response(in);
    }

    static String response(BufferedReader in) throws Exception {
        for (String l; (l = in.readLine()) != null; ) {
            if (l.startsWith("OK") || l.startsWith("NO") || l.startsWith("BYE")) {
                if (!l.startsWith("OK")) System.out.println("  ManageSieve: " + l);
                return l;
            }
        }
        return "";
    }

    /** The owner of a file, "" if it is not there. */
    static String owner(Path p) {
        try { return Files.getOwner(p, LinkOption.NOFOLLOW_LINKS).getName(); } catch (Exception e) { return ""; }
    }

    /** The mode of a file as rwx------, "" if it is not there. */
    static String mode(Path p) {
        try { return PosixFilePermissions.toString(Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS)); } catch (Exception e) { return ""; }
    }

    static boolean exists(Path p) {
        return Files.exists(p, LinkOption.NOFOLLOW_LINKS);
    }

    /** Every path under a folder, sorted, with its size: to see that a second run changes nothing. */
    static List<String> tree(Path dir) throws Exception {
        try (Stream<Path> s = Files.walk(dir)) {
            return s.map(p -> p + " " + (Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS) ? p.toFile().length() : -1))
                    .filter(l -> !l.matches(".*/(dovecot\\.index|dovecot\\.list\\.index|dovecot\\.mailbox\\.log|dovecot-uid)[^/]*")).sorted().toList();
        }
    }

    // ---------------------------------------------------------------- setting up and taking down

    static void setUp() throws Exception {
        try (Stream<Path> s = Files.walk(VMAIL, 2)) {
            s.filter(p -> p.getNameCount() == VMAIL.getNameCount() + 2 && Files.isDirectory(p.resolve("home"), LinkOption.NOFOLLOW_LINKS))
             .forEach(homesBefore::add);
        }
        String rootPw = null;
        for (String f : new String[]{"/usr/local/etc/daemoxcp-mail/root-secrets.properties", "/usr/local/etc/daemoxcp-mail/panel-secrets.properties"}) {
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
        password = run(10, "openssl", "rand", "-hex", "16").trim();
        String hash = run(20, "doveadm", "pw", "-s", "BLF-CRYPT", "-p", password);
        if (hash == null || !hash.startsWith("{BLF-CRYPT}")) throw new IllegalStateException("doveadm pw gave no BLF-CRYPT hash");
        StringBuilder sql = new StringBuilder(cleanupSql()).append("INSERT INTO domains (domain, active) VALUES ('" + DOMAIN + "', 1);\n");
        for (String m : new String[]{ALICE, BOB, CAROL, DAVE})
            sql.append("INSERT INTO mailboxes (domain_id, email, password, name, active) SELECT id, '").append(m).append("', '")
               .append(hash.trim()).append("', 'home test', 1 FROM domains WHERE domain='" + DOMAIN + "';\n");
        if (mysql(sql.toString()) == null) throw new IllegalStateException("cannot create the test mailboxes in " + db);
        logStart = Files.size(MAILLOG);
        run(20, "doveadm", "mailbox", "create", "-s", "-u", ALICE, "Own");
        System.out.println("test mailboxes in " + DOMAIN + "; " + run(20, "pkg", "query", "%n-%v", "dovecot-pigeonhole-mysql").trim()
                + "; homes already there: " + homesBefore.size());
    }

    static String cleanupSql() {
        return "DELETE FROM mailboxes WHERE email IN ('" + ALICE + "', '" + BOB + "', '" + CAROL + "', '" + DAVE + "');\n"
             + "DELETE FROM domains WHERE domain='" + DOMAIN + "';\n";
    }

    static void tearDown() throws Exception {
        DovecotHome.vmail = VMAIL;
        try {
            if (savedConf != null && !savedConf.equals(Files.readString(DovecotHome.authSql))) {
                Files.writeString(DovecotHome.authSql, savedConf);
                run(60, "service", "dovecot", "reload");
                System.out.println("configuration put back, Dovecot reloaded");
            }
            // The other mailboxes of the VM: what the migration moved into a home it created goes back to the root.
            Set<Path> homes = new LinkedHashSet<>();
            try (Stream<Path> s = Files.walk(VMAIL, 2)) {
                s.filter(p -> p.getNameCount() == VMAIL.getNameCount() + 2 && !p.startsWith(VMAIL.resolve(DOMAIN))
                        && Files.isDirectory(p.resolve("home"), LinkOption.NOFOLLOW_LINKS) && !homesBefore.contains(p)).forEach(homes::add);
            }
            for (Path m : homes) {
                try (Stream<Path> s = Files.list(m.resolve("home"))) {
                    for (Path f : s.toList())
                        if (!exists(m.resolve(f.getFileName()))) run(30, "mv", f.toString(), m.resolve(f.getFileName()).toString());
                }
                run(10, "rmdir", m.resolve("home").toString());
            }
            if (!homes.isEmpty()) System.out.println("files put back in the root of " + homes.size() + " other mailbox(es)");
            if (Files.exists(work.resolve("root.cnf"))) mysql(cleanupSql());
        } finally {
            List<String> rm = new ArrayList<>(List.of("rm", "-rf", VMAIL.resolve(DOMAIN).toString(), "/var/mail/sieve/" + DOMAIN, work.toString()));
            if (fake != null) rm.add(fake.toString());
            new ProcessBuilder(rm).start().waitFor();
        }
    }

    static String mysql(String sql) throws Exception {
        Path f = work.resolve("statements.sql");
        Files.writeString(f, sql);
        return run(30, "/bin/sh", "-c", "mysql --defaults-extra-file='" + work.resolve("root.cnf") + "' " + db + " < '" + f + "'");
    }

    /** The output of a command, or null if it fails or does not finish in time. */
    static String run(int seconds, String... cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        pb.environment().put("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin");
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!p.waitFor(seconds, TimeUnit.SECONDS)) { p.destroyForcibly(); return null; }
        return p.exitValue() == 0 ? out : null;
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
