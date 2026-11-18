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
 * Le quote delle caselle, applicate davvero: prima si salvavano con ogni casella (quota_mb) e Dovecot non le leggeva.
 *
 * <p>Nella 2.4 (DovecotConfig):
 * <ul>
 *   <li>conf.d/{@value DovecotConfig#QUOTA_FILE_NAME}: il plugin quota, imap_quota, una radice col driver count, e il
 *       servizio quota-status che Postfix interroga;</li>
 *   <li>un userdb sql prima di userdb static, in auth-sql.conf.ext, che da' il limite di ogni casella
 *       (quota_storage_size = quota_mb in MB; 0 = nessun limite). L'utente MySQL di Dovecot legge quota_mb (MailDbUsers,
 *       che gira prima);</li>
 *   <li>in Postfix, dopo reject_unauth_destination, {@value #POLICY}: una casella piena risponde 452 al destinatario,
 *       e con Dovecot che non risponde la posta passa come prima (default_action=DUNNO) e la quota la controlla LMTP.</li>
 * </ul>
 *
 * <p>Sui server installati prima, all'avvio e dopo MailDbUsers: si scrivono i due file di Dovecot, doveconf -n, riavvio
 * (un reload non crea il socket nuovo), e le prove: Dovecot gira, l'autenticazione passa, LMTP e IMAP ci sono,
 * quota-status risponde DUNNO a un destinatario che non c'e', e doveadm user da' a una casella il suo limite. Se una non
 * torna, i file tornano com'erano e Dovecot riparte. Poi Postfix, con postfix check e reload, e main.cf rimesso com'era se
 * non vanno. Una configurazione che il pannello non riconosce resta com'e', e lo dice il registro. Nella 2.3 niente: le
 * quote vogliono la 2.4, che la pagina Aggiornamenti installa. Al secondo avvio non fa niente.
 */
public final class DovecotQuota {

    private static final Logger LOGGER = Logger.getLogger(DovecotQuota.class.getName());

    static final Path AUTH_SQL = Path.of(DovecotAuthWorker.CONF_D, "auth-sql.conf.ext");
    static final Path QUOTA = Path.of(DovecotAuthWorker.CONF_D, DovecotConfig.QUOTA_FILE_NAME);
    static final Path SOCKET = Path.of("/var/spool/postfix/private/quota-status");
    static final String POSTCONF = "/usr/local/sbin/postconf";
    static final String POSTFIX = "/usr/local/sbin/postfix";
    /** Nelle regole di Postfix, dopo reject_unauth_destination. */
    public static final String POLICY = "check_policy_service { unix:private/quota-status, default_action=DUNNO }";

    private static final Pattern UNAUTH = Pattern.compile("\\breject_unauth_destination\\b");

    private DovecotQuota() {}

    enum Action { NOTHING, APPLY, NOT_24, LEFT_ALONE }

    record Decision(Action action, String authSql, String reason) {}

    /**
     * auth-sql.conf.ext col userdb delle quote prima di userdb static; lo stesso testo se c'e' gia'; null se il file non e'
     * quello che scrive il pannello (un altro userdb sql, nessun userdb static o piu' d'uno, static non a inizio riga).
     */
    static String withQuotaUserdb(String authSql) {
        if (authSql == null || !authSql.contains("passdb sql {")) return null;
        if (authSql.contains(DovecotConfig.QUOTA_USERDB)) return authSql;
        if (authSql.contains("userdb sql")) return null;
        int i = authSql.indexOf("userdb static {");
        if (i < 0 || authSql.indexOf("userdb static {", i + 1) >= 0) return null;
        int line = authSql.lastIndexOf('\n', i) + 1;
        if (line != i) return null;
        return authSql.substring(0, line) + DovecotConfig.QUOTA_USERDB + authSql.substring(line);
    }

    /** Funzione pura: la versione di Dovecot, auth-sql.conf.ext e il file delle quote come sono adesso (null se mancano). */
    static Decision decide(String version, String authSql, String quotaFile) {
        if (version == null || !version.trim().startsWith("2.4")) return new Decision(Action.NOT_24, null, "Dovecot is not 2.4");
        String wanted = withQuotaUserdb(authSql);
        if (wanted == null)
            return new Decision(Action.LEFT_ALONE, null, AUTH_SQL.getFileName() + " is not the one the panel writes (or has its own userdb sql): quotas left as they are");
        if (wanted.equals(authSql) && DovecotConfig.QUOTA_FILE.equals(quotaFile)) return new Decision(Action.NOTHING, null, "already in place");
        return new Decision(Action.APPLY, wanted, "quotas not applied yet");
    }

    /** Le regole di Postfix con la domanda a quota-status dopo reject_unauth_destination; le stesse se c'e'; null se non si sa dove. */
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

    /** I due file di Dovecot, la prova di doveconf, il riavvio e le verifiche; se non tornano, tutto com'era. */
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

    /** Dopo il riavvio, fino a 20 s. null se va. */
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

    /** Una casella col suo limite: doveadm user deve dare quota_storage_size = quota_mb M. null se va o non c'e' una casella. */
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
     * Una domanda a quota-status come la fa Postfix (protocollo delle policy: righe nome=valore, poi una vuota). La
     * risposta e' la riga action=..., o un testo che dice perche' non c'e'.
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

    /** La domanda a quota-status in smtpd_recipient_restrictions, se quota-status risponde e le regole sono quelle del pannello. */
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

    // ===================== quanto usa ogni casella, per la pagina Caselle =====================

    /** Se le quote si applicano su questo server, o perche' no (in inglese: la pagina lo mette dentro un suo testo). */
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
     * Quanto usa ogni casella e il suo limite, da {@code doveadm -f tab quota get -A}: email, usato e limite in KB (0 =
     * nessun limite), percentuale. Con applied false e il perche', se le quote non si applicano.
     */
    public static JSONObject usage() {
        JSONObject r = new JSONObject().put("success", true);
        String why = notApplied();
        r.put("applied", why == null);
        if (why != null) return r.put("reason", why).put("mailboxes", new JSONArray());
        Shell.Result q = Shell.run(Duration.ofSeconds(60), DovecotAuthWorker.DOVEADM, "-f", "tab", "quota", "get", "-A");
        if (!q.success()) return r.put("success", false).put("error", "doveadm quota get failed (exit " + q.exitCode() + ")");
        return r.put("mailboxes", parseUsage(q.outputTrim()));
    }

    /** Il testo di doveadm -f tab quota get -A: solo le righe STORAGE, con l'intestazione per trovare le colonne. */
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

    /** Scrittura atomica con proprietario, gruppo e permessi di prima (auth-sql.conf.ext ha la password del database). */
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
