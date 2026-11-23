package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.RootOnlyPath;
import org.daemoxcp.mail.util.Shell;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * The processes of Dovecot's mailboxes without the mail group (finding 221).
 *
 * <p>The panel wrote {@code mail_privileged_group = mail} in dovecot.conf, 2.3 and 2.4. With that, every process of
 * a mailbox (imap, pop3, lmtp, managesieve: the ones that talk to the network) keeps the mail group as its saved
 * group and can take it back whenever it wants: measured on the VM, {@code procstat -s} of a vmail imap gives
 * SVGID 6. The mail group writes in /var/mail, where the panel's Sieve rules are.
 *
 * <p>It was not needed: the Dovecot documentation (2.3, wiki MailLocation.mbox, QuickConfiguration,
 * BasicConfiguration) uses it only to create the INBOX and the lock files of mbox mailboxes in /var/mail. The panel
 * keeps the mail in Maildir under /var/vmail. Measured on the VM without the line: IMAP login, SMTP AUTH,
 * ManageSieve and delivery with the panel's rules all fine, and the imap with SVGID 5000 instead of 6. On 2.4 not
 * measured.
 *
 * <p>The installer no longer writes it (DovecotConfig); on servers installed earlier this pass removes it, only if
 * it is the panel's exact line, in a dovecot.conf written by the panel, and if Dovecot does not keep mail in mbox.
 * Afterwards: doveconf must accept the file and no longer give the group, Dovecot must reload, and a real imap of a
 * mailbox must log in and run without the mail group. If a single thing does not add up, the file goes back to how
 * it was and Dovecot reloads. Sessions already open keep the group until they reconnect. At the second startup it
 * finds nothing to do.
 */
public final class DovecotPrivilegedGroup {

    private static final Logger LOGGER = Logger.getLogger(DovecotPrivilegedGroup.class.getName());

    static final Path CONF = Path.of("/usr/local/etc/dovecot/dovecot.conf");
    static final String LINE = "mail_privileged_group = mail\n";
    /** The first line of the dovecot.conf that the panel writes, 2.3 and 2.4 (DovecotConfig). */
    static final List<String> HEADERS = headers();

    /**
     * The first two lines (2.3 and 2.4) with the current signature and with the previous ones (section
     * "dovecotSignature").
     */
    private static List<String> headers() {
        List<String> out = new java.util.ArrayList<>();
        for (String s : PanelMarker.forms("dovecotSignature", org.daemoxcp.mail.scripts.DovecotConfig.SIGNATURE)) {
            out.add("# Dovecot — " + s + "\n");
            out.add("# Dovecot 2.4 — " + s + "\n");
        }
        return List.copyOf(out);
    }
    static final String DOVECONF = "/usr/local/bin/doveconf";
    static final String DOVEADM = "/usr/local/bin/doveadm";
    static final String PROCSTAT = "/usr/bin/procstat";
    static final Path GROUPS = Path.of("/etc/group");
    static final Path VMAIL = Path.of("/var/vmail");

    private DovecotPrivilegedGroup() {}

    // ===================== Pure functions =====================

    /**
     * dovecot.conf without the panel's line, or null if there is nothing to do: it is not the panel's file, the
     * line is not there (already done), it is there twice or written another way (then it is not the panel's, and
     * it stays as it is).
     */
    static String migrated(String conf) {
        if (conf == null || HEADERS.stream().noneMatch(conf::startsWith)) return null;
        String line = "\n" + LINE;
        int at = conf.indexOf(line);
        if (at < 0 || conf.indexOf(line, at + 1) >= 0) return null;
        return conf.substring(0, at + 1) + conf.substring(at + line.length());
    }

    private static final Pattern MBOX = Pattern.compile(
            "(?m)^\\s*(mail_location\\s*=\\s*mbox:|mail_driver\\s*=\\s*mbox\\s*$|mail_inbox_path\\s*=)|INBOX=/var/mail");

    /** True if, according to `doveconf -n`, Dovecot keeps mail in mbox: there the mail group is needed for /var/mail. */
    static boolean usesMbox(String doveconfN) {
        return doveconfN != null && MBOX.matcher(doveconfN).find();
    }

    /** The group's number from the text of /etc/group, or -1. */
    static int gidOf(String groupFile, String name) {
        if (groupFile == null) return -1;
        for (String l : groupFile.split("\n")) {
            String[] f = l.split(":", -1);
            if (f.length >= 3 && f[0].equals(name) && f[2].matches("\\d{1,9}")) return Integer.parseInt(f[2]);
        }
        return -1;
    }

    /**
     * True if the `procstat -s` line (PID COMM EUID RUID SVUID EGID RGID SVGID UMASK FLAGS GROUPS) has the group
     * among the effective, real, saved or supplementary ones.
     */
    static boolean keepsGroup(String procstatLine, int gid) {
        String[] t = procstatLine.trim().split("\\s+");
        if (t.length < 11) return true;
        String g = Integer.toString(gid);
        if (t[5].equals(g) || t[6].equals(g) || t[7].equals(g)) return true;
        for (String x : t[t.length - 1].split(",")) if (x.equals(g)) return true;
        return false;
    }

    // ===================== At startup =====================

    /** At the start of the root part. */
    public static void ensureAtBoot() {
        try {
            String r = ensure();
            if (r == null) return;
            if (r.startsWith("DONE")) LOGGER.info("[DovecotPrivilegedGroup] " + r);
            else LOGGER.warning("[DovecotPrivilegedGroup] " + r);
        } catch (Throwable t) {
            LOGGER.warning("[DovecotPrivilegedGroup] failed: " + t);
        }
    }

    /** Null if there was nothing to do; otherwise how it went (DONE, ROLLED_BACK, or why it stays as it is). */
    static synchronized String ensure() throws Exception {
        if (!Files.isRegularFile(CONF, LinkOption.NOFOLLOW_LINKS) || !Files.isExecutable(Path.of(DOVECONF))) return null;
        String before = new String(RootOnlyPath.read(CONF, 1 << 20), StandardCharsets.UTF_8);
        String after = migrated(before);
        if (after == null) return null;
        Shell.Result n = Shell.run(Duration.ofSeconds(15), DOVECONF, "-n");
        if (!n.success()) return "left as it is: doveconf does not accept the configuration as it is (" + first(n.outputTrim()) + ")";
        if (usesMbox(n.output())) return "left as it is: Dovecot keeps mail in mbox, where the group mail is needed for /var/mail";
        PosixFileAttributes like = Files.readAttributes(CONF, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        write(after, like);
        if (!Shell.run(Duration.ofSeconds(15), DOVECONF, "-n").success())
            return putBack(before, like, false, "doveconf refuses the configuration without the line");
        Shell.Result g = Shell.run(Duration.ofSeconds(15), DOVECONF, "-h", "mail_privileged_group");
        if (!g.success() || !g.outputTrim().isEmpty())
            return putBack(before, like, false, "doveconf still gives mail_privileged_group = " + first(g.outputTrim()));
        String done = "DONE: Dovecot's mail processes no longer keep the group mail (" + LINE.trim() + " served only mbox"
                + " INBOXes in /var/mail; the mail is Maildir under " + VMAIL + ")";
        if (!running()) return done + "; Dovecot is not running, it reads it at the start";
        if (!reload()) return putBack(before, like, true, "Dovecot did not reload");
        String mailbox = SieveStorage.someMailbox(VMAIL);
        if (mailbox == null) return done + "; Dovecot reloaded, no mailbox to try a login with";
        String why = verify(mailbox, gidOf(Files.readString(GROUPS), "mail"));
        if (why != null) return putBack(before, like, true, why);
        return done + "; Dovecot reloaded, an imap of " + mailbox + " logs in without it; sessions already open keep it until"
                + " they reconnect";
    }

    /**
     * After the reload: a real imap of the mailbox logs in, and runs without the group. Retries for 10 s: auth
     * restarts.
     */
    static String verify(String mailbox, int gid) throws Exception {
        if (gid < 0) return "the group mail is not in " + GROUPS;
        String last = "";
        for (int i = 0; i < 10; i++) {
            String[] p = userProcess(mailbox);
            if (p[0] != null) return keepsGroup(p[0], gid) ? "an imap of " + mailbox + " still has the group mail: " + p[0].trim() : null;
            last = p[1];
            Thread.sleep(1000);
        }
        return "doveadm exec imap -u " + mailbox + " does not log in after the reload (" + first(last) + ")";
    }

    /**
     * A real imap of the mailbox, as Dovecot starts it with its configuration: {@code doveadm exec imap -u},
     * which becomes imap (same pid). As soon as it says PREAUTH, its `procstat -s` line; then LOGOUT.
     * {line or null, exit code}.
     */
    static String[] userProcess(String mailbox) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(DOVEADM, "exec", "imap", "-u", mailbox).redirectErrorStream(true);
        Process p = pb.start();
        StringBuilder out = new StringBuilder();
        CountDownLatch in = new CountDownLatch(1);
        Thread reader = Thread.ofVirtual().start(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                for (String l; (l = r.readLine()) != null; ) {
                    synchronized (out) { if (out.length() < 4096) out.append(l).append('\n'); }
                    if (l.startsWith("* PREAUTH")) in.countDown();
                }
            } catch (IOException ignored) {
                // the process has ended
            }
        });
        String line = null;
        try {
            if (in.await(15, TimeUnit.SECONDS)) {
                Shell.Result s = Shell.run(Duration.ofSeconds(10), PROCSTAT, "-s", Long.toString(p.pid()));
                String[] rows = s.outputTrim().split("\n");
                if (s.success() && rows.length >= 2) line = rows[rows.length - 1];
            }
            try (OutputStream o = p.getOutputStream()) {
                o.write("a LOGOUT\r\n".getBytes(StandardCharsets.US_ASCII));
            } catch (IOException ignored) {
                // already exited
            }
            if (!p.waitFor(10, TimeUnit.SECONDS)) p.destroyForcibly();
            reader.join(Duration.ofSeconds(5));
        } finally {
            if (p.isAlive()) p.destroyForcibly();
        }
        synchronized (out) { return new String[]{line, out.toString()}; }
    }

    // ===================== The pieces =====================

    static boolean running() {
        return Shell.run(Duration.ofSeconds(15), "service", "dovecot", "status").success();
    }

    static boolean reload() throws InterruptedException {
        boolean ok = Shell.run(Duration.ofSeconds(60), "service", "dovecot", "reload").success();
        Thread.sleep(1000);
        return ok;
    }

    private static void write(String content, PosixFileAttributes like) throws IOException {
        RootOnlyPath.replace(CONF.getParent(), CONF.getFileName().toString(), content.getBytes(StandardCharsets.UTF_8),
                like.owner(), like.group(), like.permissions());
    }

    private static String putBack(String before, PosixFileAttributes like, boolean reload, String why) throws Exception {
        write(before, like);
        if (reload && running()) reload();
        return "ROLLED_BACK: " + why + "; " + CONF + " put back as it was";
    }

    private static String first(String s) {
        int i = s.indexOf('\n');
        String t = i < 0 ? s : s.substring(0, i);
        return t.length() > 200 ? t.substring(0, 200) : t;
    }
}
