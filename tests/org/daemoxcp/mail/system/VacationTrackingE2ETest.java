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
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resetting the memory of the automatic replies, with real deliveries (reperto 219).
 *
 * Until 10/11/2026 the panel's "reset tracking" deleted the compiled binary beside the panel's Sieve rules and restarted
 * Dovecot. The folder of the rules is root's (reperto 214), so Dovecot could not save the binary again, and every
 * following delivery compiled the rules and logged "Error: sieve: binary ...: save: failed to create temporary file ...
 * Permission denied (euid=5000(vmail))"; the restart stopped and started all of Dovecot for nothing. Here, through the
 * panel's own entry points (SieveGenerator.saveSieveScript, VacationTracking.reset and ensureAtBoot):
 *  1. the autoresponder answers a sender once: the second message from the same sender gets no reply;
 *  2. the reset: .dovecot.lda-dupes is gone; the binary is still there, untouched and newer than the script; Dovecot's
 *     master process is the same one (an IMAP session logged in before is no proof: on Dovecot 2.3.21 it outlived the
 *     old reset's restart, measured on 10/11/2026);
 *  3. the autoresponder answers that sender again, once; no Sieve error, warning or compile in the maillog for any of
 *     these deliveries;
 *  4. the boot repair: with the binary taken away (what the old reset did) a delivery complains (so the check of 3 can
 *     fail); ensureAtBoot compiles it again, newer than the script, and the next delivery is quiet; a second
 *     ensureAtBoot leaves it as it is.
 *
 * It creates a domain nobody can own (vacation-reset.test: .test is reserved) with two mailboxes in the mail database,
 * and removes all of it at the end. It touches the mail system, so only as root with -De2e.vm=yes, on the VM:
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.VacationTrackingE2ETest [database]
 */
public class VacationTrackingE2ETest {

    static final String DOMAIN = "vacation-reset.test";
    static final String ALICE = "alice@" + DOMAIN, CAROL = "carol@" + DOMAIN;
    static final Path SCRIPT = Path.of("/var/mail/sieve", DOMAIN, "alice", ".dovecot.sieve");
    static final Path BINARY = SCRIPT.resolveSibling(".dovecot.svbin");
    static final Path DUPLICATES = Path.of("/var/vmail", DOMAIN, "alice", "home", ".dovecot.lda-dupes");
    static final Path MAILLOG = Path.of("/var/log/maillog");
    static final Path MASTER_PID = Path.of("/var/run/dovecot/master.pid");

    private static int failures = 0;
    private static String db;
    private static Path work;
    private static long logStart;
    private static final String RUN = Long.toString(System.currentTimeMillis() % 100000000L, 36);
    private static final String REPLY = "away-" + RUN;
    private static final SieveGenerator GENERATOR = new SieveGenerator();

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm")) || !"root".equals(System.getProperty("user.name"))) {
            System.out.println("Without -De2e.vm=yes, as root, this test does nothing: it delivers real mail.");
            return;
        }
        db = args.length > 0 ? args[0] : "daemoxcp_mail";
        if (!db.matches("[A-Za-z0-9_]+")) throw new IllegalArgumentException("database name not valid: " + db);
        work = Files.createTempDirectory(Path.of("/var/tmp"), "vacation-e2e");
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
        System.out.println("\n== 1. The autoresponder answers a sender once ==");
        check("rules with the autoresponder saved by the panel",
                GENERATOR.saveSieveScript(ALICE, GENERATOR.generateSieveScript(0, new Rules().away(REPLY, "Back on Monday"))));
        check("  compiled, the binary newer than the script", newer(BINARY, SCRIPT));
        String a = deliver("a");
        check("the first message: the reply is sent (" + vacation(a) + ")", "sent".equals(vacation(a)) && replies(1));
        check("  and remembered in " + DUPLICATES, Files.isRegularFile(DUPLICATES));
        String b = deliver("b");
        check("the second message from the same sender: no reply (" + vacation(b) + ")", "discarded".equals(vacation(b)) && replies(1));

        System.out.println("\n== 2. The reset ==");
        String pidBefore = masterPid();
        FileTime binaryTime = Files.getLastModifiedTime(BINARY);
        byte[] binaryBytes = Files.readAllBytes(BINARY);
        String scriptBefore = Files.readString(SCRIPT);
        check("VacationTracking.reset(" + ALICE + ") says yes", VacationTracking.reset(ALICE));
        check("  the memory is gone", !Files.exists(DUPLICATES));
        check("  the binary is still there, untouched", binaryTime.equals(mtime(BINARY))
                && Arrays.equals(Files.readAllBytes(BINARY), binaryBytes));
        check("  and newer than the script, which did not change", newer(BINARY, SCRIPT) && Files.readString(SCRIPT).equals(scriptBefore));
        Thread.sleep(2000);
        String pidAfter = masterPid();
        check("  Dovecot was not restarted: master process " + pidBefore + ", now " + pidAfter,
                pidBefore != null && pidBefore.equals(pidAfter));

        System.out.println("\n== 3. It answers again, once, and nothing complains ==");
        String c = deliver("c");
        check("the same sender after the reset: the reply is sent again (" + vacation(c) + ")", "sent".equals(vacation(c)) && replies(2));
        String d = deliver("d");
        check("and remembered again: the next one gets none (" + vacation(d) + ")", "discarded".equals(vacation(d)) && replies(2));
        check("the binary is still the one of before, newer than the script", binaryTime.equals(mtime(BINARY)) && newer(BINARY, SCRIPT));
        List<String> noise = sieveNoise(0);
        check("no Sieve error, warning or compile in the maillog for these four deliveries" + (noise.isEmpty() ? "" : ": " + noise),
                noise.isEmpty());

        System.out.println("\n== 4. The boot repair of what the old reset left ==");
        int seen = newLog().size();
        Files.deleteIfExists(BINARY);
        System.out.println("  the binary taken away, as the old reset did");
        deliver("e");
        noise = sieveNoise(seen);
        check("  the check can fail: with no binary the delivery complains (" + (noise.isEmpty() ? "nothing" : noise.get(0)) + ")",
                !noise.isEmpty());
        VacationTracking.ensureAtBoot();
        check("ensureAtBoot compiled it again, newer than the script", newer(BINARY, SCRIPT));
        check("  with the script's owner, group and mode", attrs(BINARY).equals(attrs(SCRIPT)));
        seen = newLog().size();
        deliver("f");
        noise = sieveNoise(seen);
        check("  the next delivery is quiet" + (noise.isEmpty() ? "" : ": " + noise), noise.isEmpty());
        FileTime repaired = mtime(BINARY);
        VacationTracking.ensureAtBoot();
        check("a second ensureAtBoot leaves it as it is", repaired != null && repaired.equals(mtime(BINARY)));
    }

    // ---------------------------------------------------------------- the mail system

    static boolean newer(Path binary, Path script) throws Exception {
        return Files.isRegularFile(binary) && Files.getLastModifiedTime(binary).compareTo(Files.getLastModifiedTime(script)) > 0;
    }

    /** The file's time, or null if it is not there. */
    static FileTime mtime(Path p) {
        try {
            return Files.getLastModifiedTime(p);
        } catch (Exception e) {
            return null;
        }
    }

    static String attrs(Path p) throws Exception {
        if (!Files.exists(p)) return "missing";
        var a = Files.readAttributes(p, java.nio.file.attribute.PosixFileAttributes.class);
        return a.owner().getName() + ":" + a.group().getName() + " " + PosixFilePermissions.toString(a.permissions());
    }

    static String masterPid() {
        try {
            return Files.readString(MASTER_PID).trim();
        } catch (Exception e) {
            return null;
        }
    }

    /** Waits until carol has exactly that many replies (a reply is a second delivery, it comes a moment later). */
    static boolean replies(int expected) throws Exception {
        int n = -1;
        for (int i = 0; i < 60; i++) {
            n = SieveActionsE2ETest.found(run(30, "doveadm", "search", "-u", CAROL, "mailbox", "INBOX", "subject", REPLY));
            if (n > expected) break;
            if (n == expected && i >= 4) break;
            Thread.sleep(500);
        }
        System.out.println("  replies at carol: " + n);
        return n == expected;
    }

    /** What Pigeonhole logged for the vacation action on that message: "sent", "discarded", or what it said instead. */
    static String vacation(String messageId) throws Exception {
        Pattern p = Pattern.compile("msgid=<" + Pattern.quote(messageId) + ">: vacation action: (\\w+)");
        for (int i = 0; i < 40; i++) {
            for (String l : newLog()) {
                Matcher m = p.matcher(l);
                if (m.find()) return m.group(1);
            }
            Thread.sleep(500);
        }
        return "nothing logged";
    }

    /**
     * The maillog lines about alice's Sieve, from the line number given on, that speak of an error, a warning or a
     * compile. The domain and the message ids are taken out first: only the rest of the line counts.
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

    /** Sends a message from carol to alice through Postfix and waits until it is delivered; its Message-ID. */
    static String deliver(String token) throws Exception {
        String subject = "vacation-e2e " + RUN + "-" + token;
        String id = "vacation-" + RUN + "-" + token + "." + System.nanoTime() + "@" + DOMAIN;
        String msg = "From: " + CAROL + "\nTo: " + ALICE + "\nSubject: " + subject + "\nMessage-ID: <" + id + ">\n\nAre you there?\n";
        Process p = new ProcessBuilder("/usr/sbin/sendmail", "-f", CAROL, ALICE).redirectErrorStream(true).start();
        try (OutputStream o = p.getOutputStream()) { o.write(msg.getBytes(StandardCharsets.US_ASCII)); }
        p.waitFor(30, TimeUnit.SECONDS);
        String status = awaitStatus(id, ALICE);
        System.out.println("  delivered \"" + subject + "\": " + status);
        if (!"sent".equals(status)) check("Postfix delivered it to " + ALICE, false);
        return id;
    }

    /** The maillog from where the test began. */
    static List<String> newLog() throws Exception {
        List<String> out = new ArrayList<>();
        try (var in = Files.newInputStream(MAILLOG)) {
            in.skipNBytes(Math.min(logStart, Files.size(MAILLOG)));
            new BufferedReader(new InputStreamReader(in, StandardCharsets.ISO_8859_1)).lines().forEach(out::add);
        }
        return out;
    }

    /** Postfix's word on a message: sent, deferred, bounced, or null if it said nothing in a minute. */
    static String awaitStatus(String messageId, String to) throws Exception {
        Pattern queued = Pattern.compile("postfix/cleanup\\[\\d+\\]: ([0-9A-F]+): message-id=<" + Pattern.quote(messageId) + ">");
        for (int i = 0; i < 120; i++) {
            List<String> lines = newLog();
            for (String l : lines) {
                Matcher m = queued.matcher(l);
                if (!m.find()) continue;
                Pattern done = Pattern.compile(" " + m.group(1) + ": to=<" + Pattern.quote(to) + ">.* status=(\\w+)");
                for (String x : lines) { Matcher dm = done.matcher(x); if (dm.find()) return dm.group(1); }
            }
            Thread.sleep(500);
        }
        return null;
    }

    // ---------------------------------------------------------------- setting up and taking down

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
               .append(hash.trim()).append("', 'vacation test', 1 FROM domains WHERE domain='" + DOMAIN + "';\n");
        if (mysql(sql.toString()) == null) throw new IllegalStateException("cannot create the test mailboxes in " + db);
        logStart = Files.size(MAILLOG);
        System.out.println("test mailboxes " + ALICE + ", " + CAROL + " in " + db + "; run " + RUN);
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
            new ProcessBuilder("rm", "-rf", "/var/vmail/" + DOMAIN, "/var/mail/sieve/" + DOMAIN, work.toString()).start().waitFor();
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

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
