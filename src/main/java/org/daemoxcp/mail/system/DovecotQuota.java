package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.DovecotConfig;
import org.daemoxcp.mail.util.Shell;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The mailbox quotas, really enforced: before, they were saved with each mailbox (quota_mb) and Dovecot did not
 * read them.
 *
 * <p>In 2.4 (DovecotConfig):
 * <ul>
 *   <li>conf.d/{@value DovecotConfig#QUOTA_FILE_NAME}: the quota plugin, imap_quota, a root with the count driver,
 *       and the quota-status service that Postfix queries;</li>
 *   <li>a userdb sql before userdb static, in auth-sql.conf.ext, that gives the limit of each mailbox
 *       (quota_storage_size = quota_mb in MB; 0 = no limit). Dovecot's MySQL user reads quota_mb (MailDbUsers,
 *       which runs before);</li>
 *   <li>in Postfix, after reject_unauth_destination, {@value #POLICY}: a full mailbox answers 452 to the
 *       recipient, and with Dovecot not answering, mail goes through as before (default_action=DUNNO) and LMTP
 *       checks the quota.</li>
 * </ul>
 *
 * <p>On servers installed earlier, at startup and after MailDbUsers: the two Dovecot files are written, doveconf
 * -n, restart (a reload does not create the new socket), and the tests: Dovecot runs, authentication goes through,
 * LMTP and IMAP are there, quota-status answers DUNNO to a recipient that does not exist, and doveadm user gives a
 * mailbox its limit. If one does not add up, the files go back to how they were and Dovecot restarts. Then Postfix,
 * with postfix check and reload, and main.cf put back as it was if they fail. A configuration that the panel does
 * not recognise stays as it is, and the log says so. In 2.3 nothing: the quotas need 2.4, which the Updates page
 * installs. At the second startup it does nothing.
 */
public final class DovecotQuota {

    private static final Logger LOGGER = Logger.getLogger(DovecotQuota.class.getName());

    static final Path AUTH_SQL = Path.of(DovecotAuthWorker.CONF_D, "auth-sql.conf.ext");
    static final Path QUOTA = Path.of(DovecotAuthWorker.CONF_D, DovecotConfig.QUOTA_FILE_NAME);
    static final Path SOCKET = Path.of("/var/spool/postfix/private/quota-status");
    static final String POSTCONF = "/usr/local/sbin/postconf";
    static final String POSTFIX = "/usr/local/sbin/postfix";
    /** In Postfix's rules, after reject_unauth_destination. */
    public static final String POLICY = "check_policy_service { unix:private/quota-status, default_action=DUNNO }";

    private static final Pattern UNAUTH = Pattern.compile("\\breject_unauth_destination\\b");

    private DovecotQuota() {}

    enum Action { NOTHING, APPLY, NOT_24, LEFT_ALONE }

    record Decision(Action action, String authSql, String reason) {}

    /**
     * auth-sql.conf.ext with the quota userdb before userdb static; the same text if it is already there; null if
     * the file is not the one the panel writes (another userdb sql, no userdb static or more than one, static not at
     * the start of a line).
     */
    static String withQuotaUserdb(String authSql) {
        if (authSql == null || !authSql.contains("passdb sql {")) return null;
        if (authSql.contains(DovecotConfig.QUOTA_USERDB)) return authSql;
        // The block written by an earlier version of the panel (its first line, then a single userdb sql up to
        // userdb static): it is replaced with the current one.
        int mark = authSql.indexOf(DovecotConfig.QUOTA_USERDB_MARK);
        if (mark >= 0) {
            int stat = authSql.indexOf("userdb static {", mark);
            if (stat < 0 || (mark > 0 && authSql.charAt(mark - 1) != '\n')) return null;
            String old = authSql.substring(mark, stat);
            if (old.indexOf("userdb sql {") < 0 || old.indexOf("userdb sql {") != old.lastIndexOf("userdb sql {")
                    || authSql.indexOf("userdb sql", stat) >= 0 || authSql.substring(0, mark).contains("userdb sql")) return null;
            return authSql.substring(0, mark) + DovecotConfig.QUOTA_USERDB + authSql.substring(stat);
        }
        if (authSql.contains("userdb sql")) return null;
        int i = authSql.indexOf("userdb static {");
        if (i < 0 || authSql.indexOf("userdb static {", i + 1) >= 0) return null;
        int line = authSql.lastIndexOf('\n', i) + 1;
        if (line != i) return null;
        return authSql.substring(0, line) + DovecotConfig.QUOTA_USERDB + authSql.substring(line);
    }

    /** A pure function: the Dovecot version, auth-sql.conf.ext and the quota file as they are now (null if missing). */
    static Decision decide(String version, String authSql, String quotaFile) {
        if (version == null || !version.trim().startsWith("2.4")) return new Decision(Action.NOT_24, null, "Dovecot is not 2.4");
        // The blocks written in Italian by earlier versions count as the current ones (EnglishComments).
        authSql = org.daemoxcp.mail.system.EnglishComments.english(authSql);
        quotaFile = org.daemoxcp.mail.system.EnglishComments.english(quotaFile);
        String wanted = withQuotaUserdb(authSql);
        if (wanted == null)
            return new Decision(Action.LEFT_ALONE, null, AUTH_SQL.getFileName() + " is not the one the panel writes (or has its own userdb sql): quotas left as they are");
        if (wanted.equals(authSql) && DovecotConfig.QUOTA_FILE.equals(quotaFile)) return new Decision(Action.NOTHING, null, "already in place");
        return new Decision(Action.APPLY, wanted, "quotas not applied yet");
    }

    /**
     * Postfix's rules with the query to quota-status after reject_unauth_destination; the same if it is already
     * there; null if it is not known where.
     */
    static String withPolicy(String restrictions) {
        if (restrictions == null) return null;
        if (restrictions.contains("private/quota-status")) return restrictions;
        Matcher m = UNAUTH.matcher(restrictions);
        if (!m.find()) return null;
        int end = m.end();
        if (m.find()) return null;
        return restrictions.substring(0, end) + ", " + POLICY + restrictions.substring(end);
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(DovecotAuthWorker.DOVECONF))) return;
            Shell.Result v = Shell.run(Duration.ofSeconds(15), "dovecot", "--version");
            if (!v.success()) return;
            Decision d = decide(v.outputTrim(), read(AUTH_SQL), read(QUOTA));
            switch (d.action()) {
                case NOT_24 -> { return; }
                case LEFT_ALONE -> { LOGGER.warning("[DovecotQuota] " + d.reason()); return; }
                case APPLY -> { if (!applyDovecot(d.authSql())) return; }
                case NOTHING -> { }
            }
            ensurePostfix();
        } catch (Throwable t) {
            LOGGER.warning("[DovecotQuota] ensureAtBoot exception: " + t.getMessage());
        }
    }

    private static String read(Path f) throws IOException {
        return Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS) ? Files.readString(f, StandardCharsets.UTF_8) : null;
    }

    /** The two Dovecot files, the doveconf test, the restart and the checks; if they fail, everything as it was. */
    static boolean applyDovecot(String authSql) throws Exception {
        if (!DovecotAuthWorker.running()) {
            LOGGER.info("[DovecotQuota] Dovecot is not running: quotas left as they are, retrying at the next start");
            return false;
        }
        int before = DovecotAuthWorker.lookup();
        if (!DovecotAuthWorker.LOOKUP_OK.contains(before)) {
            LOGGER.warning("[DovecotQuota] authentication already fails before any change (doveadm auth lookup exit " + before + "): quotas left as they are");
            return false;
        }
        byte[] authBefore = Files.readAllBytes(AUTH_SQL);
        PosixFileAttributes authAttrs = Files.readAttributes(AUTH_SQL, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        byte[] quotaBefore = Files.exists(QUOTA, LinkOption.NOFOLLOW_LINKS) ? Files.readAllBytes(QUOTA) : null;
        String problem;
        try {
            writeLike(AUTH_SQL, authSql, authAttrs);
            writeConf(QUOTA, DovecotConfig.QUOTA_FILE);
            Shell.Result check = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n");
            if (!check.success()) {
                putBack(authBefore, authAttrs, quotaBefore, false);
                LOGGER.warning("[DovecotQuota] ROLLED_BACK: doveconf refuses the quota configuration (" + firstLine(check.outputTrim()) + "): nothing changed");
                return false;
            }
            DovecotSockets.restart();
            problem = verifyDovecot();
        } catch (Exception e) {
            problem = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        if (problem != null) {
            putBack(authBefore, authAttrs, quotaBefore, true);
            String after = DovecotSockets.verifyRunning();
            LOGGER.warning("[DovecotQuota] ROLLED_BACK: " + problem + "; the files back as they were and Dovecot restarted"
                    + (after == null ? " (running again)" : " (" + after + ")"));
            return false;
        }
        LOGGER.info("[DovecotQuota] DONE: Dovecot applies each mailbox's quota (" + QUOTA + ", userdb sql in " + AUTH_SQL
                + "); restarted, authentication, LMTP, IMAP and quota-status checked");
        return true;
    }

    /** After the restart, up to 20 s. null if it works. */
    static String verifyDovecot() throws InterruptedException {
        String last = "unreachable";
        for (int i = 0; i < 40; i++) {
            last = DovecotSockets.verifyRunning();
            if (last == null) {
                String answer = askQuotaStatus("daemoxcp-mail-probe@invalid");
                last = "action=DUNNO".equals(answer) ? null : "quota-status answers '" + answer + "' instead of action=DUNNO";
                if (last == null) last = checkLimit();
                if (last == null) return null;
            }
            Thread.sleep(500);
        }
        return last;
    }

    /**
     * A mailbox with its limit: doveadm user must give quota_storage_size = quota_mb M. null if it works or
     * there is no mailbox.
     */
    static String checkLimit() {
        try {
            if (org.daemoxcp.mail.Main.mailDatabase == null) return null;
            for (var m : org.daemoxcp.mail.Main.mailDatabase.getAllMailboxes()) {
                if (!m.active || m.email == null || m.email.isEmpty()) continue;
                Shell.Result r = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVEADM, "user", "-f", "quota_storage_size", m.email);
                String want = m.quotaMb + "M";
                return r.success() && r.outputTrim().equals(want) ? null
                        : "doveadm user gives " + m.email + " the limit '" + r.outputTrim() + "' instead of " + want;
            }
        } catch (Exception e) {
            return "the mailboxes cannot be read to check a limit: " + e.getMessage();
        }
        return null;
    }

    /**
     * A query to quota-status as Postfix makes it (policy protocol: name=value lines, then an empty one). The
     * answer is the action=... line, or a text that says why there is none.
     */
    static String askQuotaStatus(String recipient) {
        try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            ch.connect(UnixDomainSocketAddress.of(SOCKET));
            ch.write(ByteBuffer.wrap(("request=smtpd_access_policy\nprotocol_state=RCPT\nprotocol_name=ESMTP\nrecipient="
                    + recipient + "\nsize=0\n\n").getBytes(StandardCharsets.US_ASCII)));
            ByteBuffer buf = ByteBuffer.allocate(4096);
            long deadline = System.nanoTime() + 5_000_000_000L;
            StringBuilder out = new StringBuilder();
            ch.configureBlocking(false);
            while (System.nanoTime() < deadline && !out.toString().contains("\n\n")) {
                buf.clear();
                int n = ch.read(buf);
                if (n < 0) break;
                if (n == 0) { Thread.sleep(20); continue; }
                buf.flip();
                out.append(StandardCharsets.US_ASCII.decode(buf));
            }
            String s = out.toString().trim();
            return s.isEmpty() ? "(no answer)" : s.lines().findFirst().orElse(s);
        } catch (Exception e) {
            return "(" + e.getClass().getSimpleName() + ")";
        }
    }

    /** The quota-status query in smtpd_recipient_restrictions, if quota-status answers and the rules are the panel's. */
    static void ensurePostfix() throws Exception {
        if (!Files.isExecutable(Path.of(POSTCONF))) return;
        String now = postconf("-h", "smtpd_recipient_restrictions");
        String wanted = withPolicy(now);
        if (wanted == null) {
            LOGGER.warning("[DovecotQuota] smtpd_recipient_restrictions has no single reject_unauth_destination: Postfix left as it is"
                    + " (a full mailbox is refused at delivery, not before)");
            return;
        }
        if (wanted.equals(now)) return;
        if (!"action=DUNNO".equals(askQuotaStatus("daemoxcp-mail-probe@invalid"))) {
            LOGGER.warning("[DovecotQuota] quota-status does not answer: Postfix left as it is, retrying at the next start");
            return;
        }
        Path mainCf = Path.of(postconf("-h", "config_directory"), "main.cf");
        byte[] before = Files.readAllBytes(mainCf);
        PosixFileAttributes attrs = Files.readAttributes(mainCf, PosixFileAttributes.class);
        boolean checkedBefore = Shell.run(Duration.ofSeconds(60), POSTFIX, "check").success();
        String problem = null;
        Shell.Result r = Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", "smtpd_recipient_restrictions = " + wanted);
        if (!r.success()) problem = "postconf -e failed (exit " + r.exitCode() + "): " + r.outputTrim();
        if (problem == null && !postconf("-h", "smtpd_recipient_restrictions").equals(wanted))
            problem = "smtpd_recipient_restrictions is not what was written";
        if (problem == null) {
            Shell.Result check = Shell.run(Duration.ofSeconds(60), POSTFIX, "check");
            if (checkedBefore && !check.success()) problem = "postfix check failed (exit " + check.exitCode() + "): " + check.outputTrim();
        }
        if (problem == null) {
            Shell.Result reload = Shell.run(Duration.ofSeconds(60), POSTFIX, "reload");
            if (!reload.success()) problem = "postfix reload failed (exit " + reload.exitCode() + "): " + reload.outputTrim();
        }
        if (problem != null) {
            Files.write(mainCf, before);
            restoreAttributes(mainCf, attrs);
            Shell.run(Duration.ofSeconds(60), POSTFIX, "reload");
            LOGGER.warning("[DovecotQuota] ROLLED_BACK (Postfix): " + problem + "; main.cf back as it was");
            return;
        }
        LOGGER.info("[DovecotQuota] DONE: Postfix asks quota-status before accepting a recipient (" + POLICY + ")");
    }

    // ===================== how much each mailbox uses, for the "Mailboxes" page =====================

    /**
     * Whether the quotas are enforced on this server, or why not (in English: the page puts it inside a text of
     * its own).
     */
    public static String notApplied() {
        try {
            Shell.Result v = Shell.run(Duration.ofSeconds(15), "dovecot", "--version");
            if (!v.success()) return "Dovecot is not installed";
            if (!v.outputTrim().startsWith("2.4")) return "quotas need Dovecot 2.4, this server has " + v.outputTrim().split(" ")[0];
            Decision d = decide(v.outputTrim(), read(AUTH_SQL), read(QUOTA));
            if (d.action() == Action.NOTHING) return null;
            return d.action() == Action.LEFT_ALONE ? d.reason() : "the panel applies them at its next start";
        } catch (Exception e) {
            return e.getClass().getSimpleName();
        }
    }

    /**
     * How much each mailbox uses and its limit, from {@code doveadm -f tab quota get -A}: email, used and limit in
     * KB (0 = no limit), percentage. With applied false and the reason, if the quotas are not enforced.
     */
    public static JSONObject usage() {
        JSONObject r = new JSONObject().put("success", true);
        String why = notApplied();
        r.put("applied", why == null);
        if (why != null) return r.put("reason", why).put("mailboxes", new JSONArray());
        Shell.Result q = Shell.run(Duration.ofSeconds(60), DovecotAuthWorker.DOVEADM, "-f", "tab", "quota", "get", "-A");
        if (!q.success()) return r.put("success", false).put("error", org.daemoxcp.mail.i18n.I18n.tr("server.quota.readFailed", java.util.Map.of("code", String.valueOf(q.exitCode()))));
        return r.put("mailboxes", parseUsage(q.outputTrim()));
    }

    /** The text of doveadm -f tab quota get -A: only the STORAGE lines, with the header to find the columns. */
    static JSONArray parseUsage(String tab) {
        JSONArray out = new JSONArray();
        if (tab == null || tab.isBlank()) return out;
        String[] lines = tab.split("\n");
        String[] head = lines[0].split("\t");
        int user = -1, type = -1, value = -1, limit = -1, pct = -1;
        for (int i = 0; i < head.length; i++) {
            switch (head[i].trim().toLowerCase(java.util.Locale.ROOT)) {
                case "username" -> user = i;
                case "type" -> type = i;
                case "value" -> value = i;
                case "limit" -> limit = i;
                case "%" -> pct = i;
                default -> { }
            }
        }
        if (user < 0 || type < 0 || value < 0 || limit < 0) return out;
        for (int i = 1; i < lines.length; i++) {
            String[] c = lines[i].split("\t", -1);
            if (c.length <= Math.max(Math.max(user, type), Math.max(value, limit))) continue;
            if (!"STORAGE".equalsIgnoreCase(c[type].trim())) continue;
            long used = number(c[value]), lim = number(c[limit]);
            JSONObject m = new JSONObject().put("email", c[user].trim()).put("used_kb", Math.max(used, 0)).put("limit_kb", Math.max(lim, 0));
            m.put("percent", lim > 0 ? (int) Math.min(100, Math.round(100.0 * Math.max(used, 0) / lim)) : (pct >= 0 && pct < c.length ? (int) number(c[pct]) : 0));
            out.put(m);
        }
        return out;
    }

    private static long number(String s) {
        try {
            String t = s == null ? "" : s.trim();
            return t.isEmpty() || t.equals("-") ? 0 : Long.parseLong(t);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    // ===================== file =====================

    private static void writeConf(Path file, String content) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.writeString(tmp, content);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Shell.run(Duration.ofSeconds(10), "chown", "root:wheel", tmp.toString());
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /** Atomic write with the previous owner, group and permissions (auth-sql.conf.ext has the database password). */
    private static void writeLike(Path file, String content, PosixFileAttributes attrs) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.createFile(tmp);
        restoreAttributes(tmp, attrs);
        Files.writeString(tmp, content);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(byte[] authBefore, PosixFileAttributes authAttrs, byte[] quotaBefore, boolean restart) throws Exception {
        Files.write(AUTH_SQL, authBefore);
        restoreAttributes(AUTH_SQL, authAttrs);
        if (quotaBefore != null) Files.write(QUOTA, quotaBefore);
        else Files.deleteIfExists(QUOTA);
        if (restart) {
            DovecotSockets.restart();
            if (!DovecotAuthWorker.running()) Shell.run(Duration.ofSeconds(60), "service", "dovecot", "start");
        }
    }

    private static void restoreAttributes(Path f, PosixFileAttributes attrs) throws IOException {
        PosixFileAttributeView view = Files.getFileAttributeView(f, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        view.setPermissions(attrs.permissions());
        view.setOwner(attrs.owner());
        view.setGroup(attrs.group());
    }

    private static String postconf(String... args) {
        String[] cmd = new String[args.length + 1];
        cmd[0] = POSTCONF;
        System.arraycopy(args, 0, cmd, 1, args.length);
        Shell.Result r = Shell.run(Duration.ofSeconds(15), cmd);
        return r.success() ? r.outputTrim() : "";
    }

    private static String firstLine(String s) {
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
