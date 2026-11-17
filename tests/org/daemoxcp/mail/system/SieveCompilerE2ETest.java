package org.daemoxcp.mail.system;

import org.daemoxcp.mail.integration.SieveGenerator;
import org.daemoxcp.mail.integration.SieveGeneratorTest.Rules;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The panel's Sieve rules compiled without root, with real deliveries (reperto 218).
 *
 * Until 10/11/2026 SieveGenerator ran Pigeonhole's sievec as root, on the panel's rules and on texts typed into the
 * filters. Here everything goes through the panel's own entry points (SieveGenerator.saveSieveScript, compileScript,
 * validateScript), with the kernel's process accounting on, and:
 *  1. a rule of the panel is saved and compiled: its binary is beside it with the script's owner, group and mode, newer
 *     than the script; a delivery lands where the rule says;
 *  2. Dovecot runs that binary and does not compile again: with the script's text changed and its time put before the
 *     binary's, a delivery still follows the binary; compiled again through the panel, it follows the new text; no
 *     Sieve error or warning in the maillog for these deliveries, while one delivery with the binary taken away does
 *     complain (so the check can fail), and the next one, after the panel compiles again, is quiet;
 *  3. validateScript refuses a text with an error at its line, and accepts the panel's own;
 *  4. vmail, the user that delivers, can rewrite neither the panel's rules nor their binary, nor add a file beside them
 *     (the property of reperto 214, kept);
 *  5. process accounting: every sievec that ran in the test ran as the user sievec, none as root.
 *
 * It creates a domain nobody can own (sieve-compile.test: .test is reserved) with two mailboxes in the mail database,
 * and removes all of it at the end. It turns process accounting on into a file of its own and off at the end (only if it
 * was off). It touches the mail system, so only as root with -De2e.vm=yes, on the VM:
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.SieveCompilerE2ETest [database]
 */
public class SieveCompilerE2ETest {

    static final String DOMAIN = "sieve-compile.test";
    static final String ALICE = "alice@" + DOMAIN, CAROL = "carol@" + DOMAIN;
    static final Path SCRIPT = Path.of("/var/mail/sieve", DOMAIN, "alice", ".dovecot.sieve");
    static final Path BINARY = SCRIPT.resolveSibling(".dovecot.svbin");
    static final Path MAILLOG = Path.of("/var/log/maillog");

    private static int failures = 0;
    private static String db;
    private static Path work;
    private static long logStart;
    private static boolean accounting;
    private static final String RUN = Long.toString(System.currentTimeMillis() % 100000000L, 36);
    private static final SieveGenerator GENERATOR = new SieveGenerator();

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm")) || !"root".equals(System.getProperty("user.name"))) {
            System.out.println("Without -De2e.vm=yes, as root, this test does nothing: it delivers real mail.");
            return;
        }
        db = args.length > 0 ? args[0] : "mailserver";
        if (!db.matches("[A-Za-z0-9_]+")) throw new IllegalArgumentException("database name not valid: " + db);
        work = Files.createTempDirectory(Path.of("/var/tmp"), "sievec-e2e");
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
        System.out.println("\n== 1. A rule of the panel, saved and compiled by the panel ==");
        Rules one = new Rules().filter("compiled-" + RUN, "move", "SieveOne");
        check("saved", GENERATOR.saveSieveScript(ALICE, GENERATOR.generateSieveScript(0, one)));
        check("its binary is beside it", Files.isRegularFile(BINARY));
        check("  with the script's owner, group and mode (" + attrs(BINARY) + ")", attrs(BINARY).equals(attrs(SCRIPT)));
        check("  newer than the script", Files.getLastModifiedTime(BINARY).compareTo(Files.getLastModifiedTime(SCRIPT)) > 0);
        String s = deliver(CAROL, ALICE, "compiled-" + RUN + "-a");
        check("a delivery lands where the rule says", count(ALICE, "SieveOne", s) == 1 && countAll(ALICE, s) == 1);

        System.out.println("\n== 2. Dovecot runs the binary, it does not compile again ==");
        String other = GENERATOR.generateSieveScript(0, new Rules().filter("compiled-" + RUN, "move", "SieveTwo"));
        FileTime binaryTime = Files.getLastModifiedTime(BINARY);
        Files.writeString(SCRIPT, other);
        Files.setLastModifiedTime(SCRIPT, FileTime.fromMillis(binaryTime.toMillis() - 60_000));
        System.out.println("  the script now says SieveTwo, with its time a minute before the binary's");
        s = deliver(CAROL, ALICE, "compiled-" + RUN + "-b");
        check("the delivery follows the binary (SieveOne), not the text (SieveTwo)",
                count(ALICE, "SieveOne", s) == 1 && count(ALICE, "SieveTwo", s) == 0);
        check("compiled again through the panel", GENERATOR.compileScript(SCRIPT.toString())
                && Files.getLastModifiedTime(BINARY).compareTo(Files.getLastModifiedTime(SCRIPT)) > 0);
        s = deliver(CAROL, ALICE, "compiled-" + RUN + "-c");
        check("the next delivery follows the new binary (SieveTwo)", count(ALICE, "SieveTwo", s) == 1 && countAll(ALICE, s) == 1);
        List<String> noise = sieveNoise(0);
        check("no Sieve error, warning or compile in the maillog for these deliveries" + (noise.isEmpty() ? "" : ": " + noise),
                noise.isEmpty());
        int seen = newLog().size();
        Files.delete(BINARY);
        s = deliver(CAROL, ALICE, "compiled-" + RUN + "-d");
        noise = sieveNoise(seen);
        check("  the check can fail: with no binary the delivery complains (" + (noise.isEmpty() ? "nothing" : noise.get(0)) + ")",
                !noise.isEmpty() && count(ALICE, "SieveTwo", s) == 1);
        check("compiled again through the panel", GENERATOR.compileScript(SCRIPT.toString()) && Files.isRegularFile(BINARY));
        seen = newLog().size();
        s = deliver(CAROL, ALICE, "compiled-" + RUN + "-e");
        noise = sieveNoise(seen);
        check("  and the next delivery is quiet again" + (noise.isEmpty() ? "" : ": " + noise),
                noise.isEmpty() && count(ALICE, "SieveTwo", s) == 1);

        System.out.println("\n== 3. validateScript ==");
        SieveGenerator.ValidationResult bad = GENERATOR.validateScript("require \"fileinto\";\nif true { fileinto \"X\" }\n");
        check("a text with an error: refused at its line (" + bad.errorLine + ")", !bad.valid && bad.errorLine == 2);
        check("the panel's own: accepted", GENERATOR.validateScript(other).valid);

        System.out.println("\n== 4. vmail cannot rewrite the panel's rules ==");
        check("not the script", !asVmail("/usr/bin/touch", SCRIPT.toString()));
        check("not the binary", !asVmail("/usr/bin/touch", BINARY.toString()));
        check("not a file of its own beside them", !asVmail("/usr/bin/touch", SCRIPT.resolveSibling("vmail-was-here").toString())
                && !Files.exists(SCRIPT.resolveSibling("vmail-was-here")));
        check("  (and vmail can touch a file of its own: the probe works)",
                asVmail("/usr/bin/touch", "/var/vmail/" + DOMAIN + "/alice/vmail-probe-" + RUN));

        System.out.println("\n== 5. Who ran sievec: process accounting ==");
        if (!accounting) {
            check("process accounting was on for the test", false);
            return;
        }
        ok("accton");
        accounting = false;
        String out = run(30, "lastcomm", "-f", work.resolve("acct").toString(), "sievec");
        List<String> users = new ArrayList<>();
        for (String l : out == null ? List.<String>of() : out.lines().toList()) {
            String[] f = l.trim().split("\\s+");
            if (f.length > 2 && f[0].equals("sievec")) users.add(f[2]);
        }
        System.out.println("  sievec ran " + users.size() + " times, as " + users.stream().distinct().toList());
        check("sievec ran at least three times (two compiles and a validation)", users.size() >= 3);
        check("every time as the user sievec", !users.isEmpty() && users.stream().allMatch("sievec"::equals));
        check("never as root", users.stream().noneMatch("root"::equals));
    }

    // ---------------------------------------------------------------- the mail system

    /**
     * The maillog lines about alice's Sieve, from the line number given on, that speak of an error, a warning or a
     * compile. The domain and the message ids contain "sieve" and "compile" themselves: only the rest of the line counts.
     */
    static List<String> sieveNoise(int fromLine) throws Exception {
        List<String> lines = newLog();
        List<String> out = new ArrayList<>();
        for (String l : lines.subList(Math.min(fromLine, lines.size()), lines.size())) {
            if (!l.contains(ALICE)) continue;
            String rest = l.replace(DOMAIN, "").replaceAll("msgid=<[^>]*>", "");
            if (rest.contains("sieve") && rest.matches("(?i).*(error|warning|fatal|failed|compil).*")) out.add(l);
        }
        return out;
    }

    static boolean asVmail(String... cmd) throws Exception {
        List<String> c = new ArrayList<>(List.of("/usr/sbin/chroot", "-u", "vmail", "-g", "vmail", "-G", "vmail", "/"));
        c.addAll(List.of(cmd));
        return run(20, c.toArray(new String[0])) != null;
    }

    static String attrs(Path p) throws Exception {
        if (!Files.exists(p)) return "missing";
        PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class);
        return a.owner().getName() + ":" + a.group().getName() + " " + PosixFilePermissions.toString(a.permissions());
    }

    /** Sends a message through Postfix and waits until Postfix says the delivery is over; the subject to look for. */
    static String deliver(String from, String to, String token) throws Exception {
        String subject = "sievec-e2e " + token;
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

        String password = run(10, "openssl", "rand", "-hex", "16").trim();
        String hash = run(20, "doveadm", "pw", "-s", "BLF-CRYPT", "-p", password);
        if (hash == null || !hash.startsWith("{BLF-CRYPT}")) throw new IllegalStateException("doveadm pw gave no BLF-CRYPT hash");
        StringBuilder sql = new StringBuilder(cleanupSql())
                .append("INSERT INTO domains (domain, active) VALUES ('" + DOMAIN + "', 1);\n");
        for (String m : new String[]{ALICE, CAROL})
            sql.append("INSERT INTO mailboxes (domain_id, email, password, name, active) SELECT id, '").append(m).append("', '")
               .append(hash.trim()).append("', 'sievec test', 1 FROM domains WHERE domain='" + DOMAIN + "';\n");
        if (mysql(sql.toString()) == null) throw new IllegalStateException("cannot create the test mailboxes in " + db);
        spoolMode = SieveActionsE2ETest.spoolAsAtBoot();
        logStart = Files.size(MAILLOG);
        for (String folder : new String[]{"SieveOne", "SieveTwo"})
            run(20, "doveadm", "mailbox", "create", "-u", ALICE, folder);

        String configured = run(10, "sysctl", "-n", "kern.acct_configured");
        if (configured != null && configured.trim().equals("0")) {
            Path acct = work.resolve("acct");
            Files.createFile(acct, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            accounting = ok("accton", acct.toString());
        } else {
            System.out.println("process accounting is already on (" + configured + "): this test does not touch it");
        }
        System.out.println("test mailboxes " + ALICE + ", " + CAROL + " in " + db + "; run " + RUN + "; accounting " + accounting);
        System.out.println("packages: " + run(20, "pkg", "query", "-g", "%n-%v", "dovecot*").trim().replace('\n', ' '));
    }

    static String cleanupSql() {
        return "DELETE FROM mailboxes WHERE email IN ('" + ALICE + "', '" + CAROL + "');\n"
             + "DELETE FROM domains WHERE domain='" + DOMAIN + "';\n";
    }

    static void tearDown() throws Exception {
        try {
            if (accounting) ok("accton");
            if (Files.exists(work.resolve("root.cnf"))) mysql(cleanupSql());
        } finally {
            new ProcessBuilder("rm", "-rf", "/var/vmail/" + DOMAIN, "/var/mail/sieve/" + DOMAIN, work.toString()).start().waitFor();
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
