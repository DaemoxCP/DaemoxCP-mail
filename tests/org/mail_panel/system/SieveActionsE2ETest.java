package org.mail_panel.system;

import org.mail_panel.integration.SieveGenerator;
import org.mail_panel.integration.SieveGeneratorTest.Rules;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The panel's Sieve rules do what they say, with real deliveries (reperto 216).
 *
 * Until 09/11/2026 SieveGenerator ended every script with an explicit keep: a "move" left the message in the folder AND
 * in INBOX, a forward without a copy kept one, "delete" deleted nothing. Here every rule is written by the panel's own
 * SieveGenerator and saveSieveScript (root, /var/mail/sieve, sievec), a message goes through Postfix's sendmail, and
 * doveadm search says where it landed:
 *  1. move: only in the folder;            2. copy: in the folder and in INBOX;
 *  3. forward without a copy: only at the destination; with a copy: at both;
 *  4. delete: nowhere;                     5. autoresponder: in INBOX, and the reply reaches the sender;
 *  6. reject: not kept, and the sender gets the refusal;
 *  7. the mailbox's own script, saved through ManageSieve on 4190, runs when the panel's rules keep the message (no rule
 *     matches, or a copy) and does not when they move it: Pigeonhole runs the script after a "before" script only while
 *     a keep is in effect;
 *  8. a script the panel wrote before (with the forced keep): the move leaves a copy in INBOX; SieveForcedKeep.repair, as
 *     at boot, fixes and recompiles it, and the move moves.
 *
 * It creates a domain nobody can own (sieve-actions.test: .test is reserved) with three mailboxes in the mail database,
 * and removes all of it at the end. It touches the mail system, so only as root with -De2e.vm=yes, on the VM:
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.SieveActionsE2ETest [database]
 * The MySQL root password comes from the panel's secrets file, as in tests/mail-login-probe.sh.
 */
public class SieveActionsE2ETest {

    static final String DOMAIN = "sieve-actions.test";
    static final String ALICE = "alice@" + DOMAIN, BOB = "bob@" + DOMAIN, CAROL = "carol@" + DOMAIN;
    static final Path MAILLOG = Path.of("/var/log/maillog");

    private static int failures = 0;
    private static String db;
    private static Path work;
    private static long logStart;
    private static final String RUN = Long.toString(System.currentTimeMillis() % 100000000L, 36);
    private static final SieveGenerator GENERATOR = new SieveGenerator();

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm")) || !"root".equals(System.getProperty("user.name"))) {
            System.out.println("Without -De2e.vm=yes, as root, this test does nothing: it delivers real mail.");
            return;
        }
        db = args.length > 0 ? args[0] : "mailserver";
        if (!db.matches("[A-Za-z0-9_]+")) throw new IllegalArgumentException("database name not valid: " + db);
        work = Files.createTempDirectory(Path.of("/var/tmp"), "sieve-actions-e2e");
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
        System.out.println("\n== 1. move ==");
        panelRules(new Rules().filter("move-" + RUN, "move", "SieveMove"));
        String s = deliver(CAROL, ALICE, "move-" + RUN);
        check("in the folder", count(ALICE, "SieveMove", s) == 1);
        check("not in INBOX", count(ALICE, "INBOX", s) == 0);

        System.out.println("\n== 2. copy ==");
        panelRules(new Rules().filter("copy-" + RUN, "copy", "SieveCopy"));
        s = deliver(CAROL, ALICE, "copy-" + RUN);
        check("in the folder", count(ALICE, "SieveCopy", s) == 1);
        check("and in INBOX", count(ALICE, "INBOX", s) == 1);

        System.out.println("\n== 3. forward ==");
        panelRules(new Rules().forward(BOB, false));
        s = deliver(CAROL, ALICE, "forward-" + RUN);
        check("without a copy: at the destination", awaitCount(BOB, "INBOX", s, 1));
        check("  and nothing kept in the mailbox", countAll(ALICE, s) == 0);
        panelRules(new Rules().forward(BOB, true));
        s = deliver(CAROL, ALICE, "forward-copy-" + RUN);
        check("with a copy: at the destination", awaitCount(BOB, "INBOX", s, 1));
        check("  and in INBOX", count(ALICE, "INBOX", s) == 1);

        System.out.println("\n== 4. delete ==");
        panelRules(new Rules().filter("delete-" + RUN, "delete", ""));
        s = deliver(CAROL, ALICE, "delete-" + RUN);
        check("nowhere in the mailbox", countAll(ALICE, s) == 0);

        System.out.println("\n== 5. autoresponder ==");
        String reply = "Away " + RUN;
        panelRules(new Rules().away(reply, "Back on Monday"));
        s = deliver(CAROL, ALICE, "away-" + RUN);
        check("in INBOX", count(ALICE, "INBOX", s) == 1);
        check("the reply reaches the sender", awaitCount(CAROL, "INBOX", reply, 1));

        System.out.println("\n== 6. reject ==");
        panelRules(new Rules().filter("reject-" + RUN, "reject", "Not here"));
        s = deliver(CAROL, ALICE, "reject-" + RUN);
        check("not kept", countAll(ALICE, s) == 0);
        check("the sender gets the refusal", awaitCount(CAROL, "INBOX", s, 1));

        System.out.println("\n== 7. the mailbox's own script, saved through ManageSieve ==");
        String own = "require [\"fileinto\", \"mailbox\"];\r\nif header :contains \"subject\" \"own-" + RUN
                + "\" { fileinto :create \"SieveOwn\"; }\r\n";
        check("ManageSieve: PUTSCRIPT and SETACTIVE", manageSieve(ALICE, "own", own));
        panelRules(new Rules().filter("nothing-matches-" + RUN, "move", "SieveMove"));
        s = deliver(CAROL, ALICE, "own-" + RUN + "-kept");
        check("no panel rule matches: the own script files it", count(ALICE, "SieveOwn", s) == 1);
        check("  and it is not left in INBOX", count(ALICE, "INBOX", s) == 0);
        panelRules(new Rules().filter("own-" + RUN + "-copied", "copy", "SieveCopy"));
        s = deliver(CAROL, ALICE, "own-" + RUN + "-copied");
        check("the panel copies: in its folder, and the own script runs too", count(ALICE, "SieveCopy", s) == 1
                && count(ALICE, "SieveOwn", s) == 1 && count(ALICE, "INBOX", s) == 0);
        panelRules(new Rules().filter("own-" + RUN + "-moved", "move", "SieveMove"));
        s = deliver(CAROL, ALICE, "own-" + RUN + "-moved");
        check("the panel moves: only in its folder, the own script does not run", count(ALICE, "SieveMove", s) == 1
                && countAll(ALICE, s) == 1);
        check("ManageSieve: the own script deactivated", manageSieve(ALICE, "own", null));

        System.out.println("\n== 8. a script written before, fixed as at boot ==");
        Path root = Path.of("/var/mail/sieve");
        String now = GENERATOR.generateSieveScript(0, new Rules().filter("old-" + RUN, "move", "SieveMove"));
        check("written as the panel wrote it before (the forced keep at the end)",
                GENERATOR.saveSieveScript(ALICE, now + SieveGenerator.OLD_FORCED_KEEP));
        Path script = root.resolve(DOMAIN + "/alice/.dovecot.sieve");
        s = deliver(CAROL, ALICE, "old-" + RUN + "-before");
        check("before the repair the move leaves a copy in INBOX (the fault this fixes)",
                count(ALICE, "SieveMove", s) == 1 && count(ALICE, "INBOX", s) == 1);
        List<Path> others = SieveForcedKeep.panelScripts(root).stream().filter(p -> !p.startsWith(root.resolve(DOMAIN))).toList();
        if (!others.isEmpty()) {
            System.out.println("  (repair skipped: " + others.size() + " other panel scripts under " + root + ", not this test's to touch)");
            failures++;
            return;
        }
        Thread.sleep(1100);
        SieveForcedKeep.Outcome o = SieveForcedKeep.repair(root, p -> GENERATOR.compileScript(p.toString()));
        check("the repair fixes it and sievec accepts it", o.fixed() == 1 && o.putBack().isEmpty()
                && Files.readString(script).equals(now));
        check("  the binary is newer than the script", Files.getLastModifiedTime(script.resolveSibling(".dovecot.svbin"))
                .compareTo(Files.getLastModifiedTime(script)) >= 0);
        s = deliver(CAROL, ALICE, "old-" + RUN + "-after");
        check("after the repair the move moves", count(ALICE, "SieveMove", s) == 1 && count(ALICE, "INBOX", s) == 0);
        check("a second repair finds nothing", SieveForcedKeep.repair(root, p -> GENERATOR.compileScript(p.toString())).fixed() == 0);
    }

    // ---------------------------------------------------------------- the mail system

    /** The panel's rules for alice, written and compiled the way the panel does. */
    static void panelRules(Rules rules) throws Exception {
        String script = GENERATOR.generateSieveScript(0, rules);
        boolean saved = GENERATOR.saveSieveScript(ALICE, script);
        boolean compiled = GENERATOR.compileScript("/var/mail/sieve/" + DOMAIN + "/alice/.dovecot.sieve");
        System.out.println(script.substring(SieveGenerator.REQUIRE.length()).stripTrailing().replaceAll("(?m)^", "    | "));
        if (!saved || !compiled) check("the panel's script saved and compiled", false);
    }

    /** Sends a message through Postfix and waits until Postfix says alice's delivery is over; the subject to look for. */
    static String deliver(String from, String to, String token) throws Exception {
        String subject = "sieve-e2e " + token;
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

    /**
     * Postfix's status for the message with this Message-ID to this recipient, from the maillog; null after 60 s. A
     * redirect sends the message again with the same Message-ID, under another queue id: every queue id counts.
     */
    static String awaitStatus(String messageId, String to) throws Exception {
        Pattern queued = Pattern.compile("postfix/cleanup\\[\\d+\\]: ([0-9A-F]+): message-id=<" + Pattern.quote(messageId) + ">");
        for (int i = 0; i < 120; i++) {
            List<String> lines = newLog();
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

    static List<String> newLog() throws Exception {
        List<String> out = new ArrayList<>();
        try (var in = Files.newInputStream(MAILLOG)) {
            in.skipNBytes(Math.min(logStart, Files.size(MAILLOG)));
            new BufferedReader(new InputStreamReader(in, StandardCharsets.ISO_8859_1)).lines().forEach(out::add);
        }
        return out;
    }

    /** Messages in that folder whose subject contains the text (0 if the folder does not exist). */
    static int count(String user, String folder, String text) throws Exception {
        return found(run(30, "doveadm", "search", "-u", user, "mailbox", folder, "subject", text));
    }

    /** The same in every folder of the mailbox. */
    static int countAll(String user, String text) throws Exception {
        return found(run(30, "doveadm", "search", "-u", user, "subject", text));
    }

    /** The "mailbox-guid uid" lines of doveadm search; anything else it says is printed, not counted. */
    static int found(String out) {
        if (out == null) return 0;
        int n = 0;
        for (String l : out.lines().toList()) {
            if (l.matches("[0-9a-f]{32} \\d+")) n++;
            else if (!l.isBlank()) System.out.println("  doveadm: " + l);
        }
        return n;
    }

    /** Waits up to 30 s for a message that comes with a second delivery (a forward, a reply). */
    static boolean awaitCount(String user, String folder, String text, int expected) throws Exception {
        for (int i = 0; i < 60; i++) {
            if (count(user, folder, text) >= expected) return count(user, folder, text) == expected;
            Thread.sleep(500);
        }
        return false;
    }

    /** Saves and activates a script of the mailbox's own through ManageSieve; with null, deactivates it. */
    static boolean manageSieve(String user, String name, String script) throws Exception {
        String b64 = Base64.getEncoder().encodeToString(("\0" + user + "\0" + password).getBytes(StandardCharsets.UTF_8));
        try (Socket so = new Socket("127.0.0.1", 4190)) {
            so.setSoTimeout(20000);
            BufferedReader in = new BufferedReader(new InputStreamReader(so.getInputStream(), StandardCharsets.UTF_8));
            OutputStream out = so.getOutputStream();
            if (!response(in).startsWith("OK")) return false;
            if (!command(in, out, "AUTHENTICATE \"PLAIN\" \"" + b64 + "\"\r\n").startsWith("OK")) return false;
            if (script != null) {
                byte[] body = script.getBytes(StandardCharsets.UTF_8);
                if (!command(in, out, "PUTSCRIPT \"" + name + "\" {" + body.length + "+}\r\n" + script + "\r\n").startsWith("OK")) return false;
                if (!command(in, out, "SETACTIVE \"" + name + "\"\r\n").startsWith("OK")) return false;
            } else if (!command(in, out, "SETACTIVE \"\"\r\n").startsWith("OK")) {
                return false;
            }
            command(in, out, "LOGOUT\r\n");
        }
        return true;
    }

    static String command(BufferedReader in, OutputStream out, String line) throws Exception {
        out.write(line.getBytes(StandardCharsets.UTF_8));
        out.flush();
        return response(in);
    }

    /** The final line of a ManageSieve response (OK, NO or BYE), after the lines that come before it. */
    static String response(BufferedReader in) throws Exception {
        for (String l; (l = in.readLine()) != null; ) {
            if (l.startsWith("OK") || l.startsWith("NO") || l.startsWith("BYE")) {
                if (!l.startsWith("OK")) System.out.println("  ManageSieve: " + l);
                return l;
            }
        }
        return "";
    }

    // ---------------------------------------------------------------- setting up and taking down

    private static String password;
    private static int spoolMode = -1;

    /**
     * /var/mail as the panel leaves it at boot (MailSpoolSticky, reperto 221): sticky, or root writes no rule under it.
     * Its mode before, to put back at the end: the VM is shared.
     */
    static int spoolAsAtBoot() throws Exception {
        Path spool = Path.of("/var/mail");
        int before = (Integer) Files.getAttribute(spool, "unix:mode", java.nio.file.LinkOption.NOFOLLOW_LINKS);
        MailSpoolSticky.ensureAtBoot();
        return before;
    }

    /** /var/mail back to the mode spoolAsAtBoot() found. */
    static void spoolBack(int mode) throws Exception {
        if (mode < 0) return;
        Path spool = Path.of("/var/mail");
        if (((Integer) Files.getAttribute(spool, "unix:mode", java.nio.file.LinkOption.NOFOLLOW_LINKS) & 07777) != (mode & 07777))
            Files.setAttribute(spool, "unix:mode", mode & 07777, java.nio.file.LinkOption.NOFOLLOW_LINKS);
    }

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

        password = run(10, "openssl", "rand", "-hex", "16").trim();
        String hash = run(20, "doveadm", "pw", "-s", "BLF-CRYPT", "-p", password);
        if (hash == null || !hash.startsWith("{BLF-CRYPT}")) throw new IllegalStateException("doveadm pw gave no BLF-CRYPT hash");
        hash = hash.trim();
        StringBuilder sql = new StringBuilder(cleanupSql())
                .append("INSERT INTO domains (domain, active) VALUES ('" + DOMAIN + "', 1);\n");
        for (String m : new String[]{ALICE, BOB, CAROL})
            sql.append("INSERT INTO mailboxes (domain_id, email, password, name, active) SELECT id, '").append(m).append("', '")
               .append(hash).append("', 'sieve test', 1 FROM domains WHERE domain='" + DOMAIN + "';\n");
        if (mysql(sql.toString()) == null) throw new IllegalStateException("cannot create the test mailboxes in " + db);
        spoolMode = spoolAsAtBoot();
        logStart = Files.size(MAILLOG);
        for (String folder : new String[]{"SieveMove", "SieveCopy"})
            run(20, "doveadm", "mailbox", "create", "-u", ALICE, folder);
        System.out.println("test mailboxes " + ALICE + ", " + BOB + ", " + CAROL + " in " + db + "; run " + RUN);
        System.out.println("packages: " + run(20, "pkg", "query", "-g", "%n-%v", "dovecot*").trim().replace('\n', ' '));
    }

    static String cleanupSql() {
        return "DELETE FROM mailboxes WHERE email IN ('" + ALICE + "', '" + BOB + "', '" + CAROL + "');\n"
             + "DELETE FROM domains WHERE domain='" + DOMAIN + "';\n";
    }

    static void tearDown() throws Exception {
        try {
            if (Files.exists(work.resolve("root.cnf"))) mysql(cleanupSql());
        } finally {
            new ProcessBuilder("rm", "-rf", "/var/vmail/" + DOMAIN, "/var/mail/sieve/" + DOMAIN, work.toString()).start().waitFor();
            spoolBack(spoolMode);
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
