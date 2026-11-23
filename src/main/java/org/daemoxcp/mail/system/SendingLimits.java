package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.util.Shell;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
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
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * The sending limits of the mailboxes, enforced: before, they were saved (rate_limits) and nobody read them.
 *
 * <p>The panel acts as a policy service for Postfix (smtpd_data_restrictions, {@value #POLICY}). For every message
 * that a mailbox sends after authenticating (sasl_username: port 587, 465, the webmail) Postfix asks, at the DATA
 * command, with the number of recipients:
 * <ul>
 *   <li>more recipients than the per-message maximum: 550 5.5.3;</li>
 *   <li>over the maximum of the last hour or of the last 24 hours: 450 4.7.1, temporary (the sender sees why and
 *       tries again later; the message is not lost);</li>
 *   <li>otherwise DUNNO, and the recipients are counted: each one counts as one message.</li>
 * </ul>
 * Incoming mail (without authentication) is not counted and passes. A mailbox's limit is its own, if it exists and
 * is active; otherwise the global one, if it has been saved; otherwise none. With the panel stopped Postfix gets no
 * answer and lets the mail through (default_action=DUNNO): the limits come back with the panel.
 *
 * <p>The socket is in the Postfix queue, 0600 owned by postfix, like the LMTP and quota-status ones. Requests are
 * read with tight limits (lines, attributes): the one talking is Postfix, but the process is the panel's root part.
 * The counts are kept in memory and on disk ({@link #STATE}, every minute and at exit): a restart does not reset
 * them.
 *
 * <p>At the start of the root part: the service, then Postfix (smtpd_data_restrictions with the query at the top) if
 * the service answers, with postfix check and reload, and main.cf put back as it was if they fail.
 */
public final class SendingLimits {

    private static final Logger LOGGER = Logger.getLogger(SendingLimits.class.getName());

    static final Path SOCKET = Path.of("/var/spool/postfix/private/daemoxcp-sending-limits");
    static final Path STATE = Path.of("/var/db/daemoxcp-mail/sending-counts.txt");
    static final String POSTCONF = "/usr/local/sbin/postconf";
    static final String POSTFIX = "/usr/local/sbin/postfix";
    /** In smtpd_data_restrictions. */
    public static final String POLICY = "check_policy_service { unix:private/daemoxcp-sending-limits, default_action=DUNNO }";

    static final int MAX_LINE = 2048;
    static final int MAX_ATTRIBUTES = 100;
    private static final Pattern NAME = Pattern.compile("[a-z_]{1,64}");

    private SendingLimits() {}

    // ===================== the decision: tested without Postfix =====================

    /** The limit of a mailbox. maxRecipients 0 = no per-message maximum. */
    public record Limit(int perHour, int perDay, int maxRecipients) {}

    /**
     * How many messages each mailbox has sent, with the instant: the last hour and the last 24 hours are
     * counted from here.
     */
    static final class Counter {
        private final Map<String, ArrayDeque<long[]>> sent = new HashMap<>();
        private boolean dirty;

        synchronized int since(String user, long from) {
            ArrayDeque<long[]> q = sent.get(user);
            if (q == null) return 0;
            int n = 0;
            for (long[] e : q) if (e[0] > from) n += (int) e[1];
            return n;
        }

        synchronized void add(String user, long at, int count) {
            ArrayDeque<long[]> q = sent.computeIfAbsent(user, k -> new ArrayDeque<>());
            q.addLast(new long[]{at, count});
            dirty = true;
        }

        /** Drop whatever is older than 24 hours. */
        synchronized void prune(long now) {
            sent.values().forEach(q -> q.removeIf(e -> e[0] <= now - 86_400));
            sent.values().removeIf(ArrayDeque::isEmpty);
        }

        synchronized Map<String, int[]> usage(long now) {
            Map<String, int[]> out = new LinkedHashMap<>();
            for (String u : sent.keySet()) out.put(u, new int[]{since(u, now - 3_600), since(u, now - 86_400)});
            return out;
        }

        synchronized String dump(long now) {
            prune(now);
            StringBuilder sb = new StringBuilder();
            sent.forEach((u, q) -> q.forEach(e -> sb.append(u).append(' ').append(e[0]).append(' ').append(e[1]).append('\n')));
            dirty = false;
            return sb.toString();
        }

        synchronized boolean dirty() {
            return dirty;
        }

        /** The lines of {@link #dump}: "mailbox instant count". A line that is not like that is skipped. */
        synchronized void load(String text, long now) {
            if (text == null) return;
            for (String line : text.split("\n")) {
                String[] p = line.trim().split(" ");
                if (p.length != 3 || p[0].isEmpty() || p[0].length() > 254) continue;
                try {
                    long at = Long.parseLong(p[1]);
                    int n = Integer.parseInt(p[2]);
                    if (at > now - 86_400 && at <= now + 60 && n > 0 && n <= 100_000) add(p[0], at, n);
                } catch (NumberFormatException ignored) { }
            }
            dirty = false;
        }
    }

    /**
     * The answer to a Postfix request (the attributes already read): the part after "action=". It counts the
     * recipients only when it answers DUNNO to a message that has a limit.
     */
    static String decide(Map<String, String> a, Function<String, Limit> limits, Counter counter, long now) {
        if (!"smtpd_access_policy".equals(a.get("request"))) return "DUNNO";
        if (!"DATA".equals(a.get("protocol_state"))) return "DUNNO";
        String user = a.getOrDefault("sasl_username", "").trim().toLowerCase(Locale.ROOT);
        if (user.isEmpty()) return "DUNNO";
        Limit l = limits.apply(user);
        if (l == null) return "DUNNO";
        int n;
        try {
            n = Math.max(1, Integer.parseInt(a.getOrDefault("recipient_count", "1").trim()));
        } catch (NumberFormatException e) {
            n = 1;
        }
        if (l.maxRecipients() > 0 && n > l.maxRecipients())
            return "550 5.5.3 Too many recipients: at most " + l.maxRecipients() + " per message from " + user;
        synchronized (counter) {
            if (counter.since(user, now - 3_600) + n > l.perHour())
                return "450 4.7.1 Sending limit reached: at most " + l.perHour() + " messages per hour from " + user + ". Try again later.";
            if (counter.since(user, now - 86_400) + n > l.perDay())
                return "450 4.7.1 Sending limit reached: at most " + l.perDay() + " messages per day from " + user + ". Try again later.";
            counter.add(user, now, n);
        }
        return "DUNNO";
    }

    /**
     * The limit that applies to each mailbox, from the rate_limits rows: the mailbox's own if active, otherwise
     * the global one (if there is one), otherwise none.
     */
    static Function<String, Limit> limitsOf(List<MailDatabase.RateLimit> rows) {
        Map<String, Limit> own = new HashMap<>();
        Limit global = null;
        for (MailDatabase.RateLimit r : rows) {
            Limit l = new Limit(r.maxPerHour, r.maxPerDay, Math.max(0, r.maxRecipients));
            if ("global".equalsIgnoreCase(r.targetType)) global = l;
            else if ("mailbox".equalsIgnoreCase(r.targetType) && r.enabled && r.targetName != null)
                own.put(r.targetName.trim().toLowerCase(Locale.ROOT), l);
        }
        final Limit g = global;
        return user -> own.getOrDefault(user, g);
    }

    /**
     * A request: name=value lines up to an empty line. null if the connection ends or the request is not
     * acceptable.
     */
    static Map<String, String> read(BufferedReader in) throws IOException {
        Map<String, String> a = new HashMap<>();
        while (true) {
            String line = readLine(in);
            if (line == null) return null;
            if (line.isEmpty()) return a.isEmpty() ? null : a;
            int eq = line.indexOf('=');
            if (eq < 1) return null;
            String name = line.substring(0, eq);
            if (!NAME.matcher(name).matches() || a.size() >= MAX_ATTRIBUTES) return null;
            a.put(name, line.substring(eq + 1));
        }
    }

    /** A line, at most {@value #MAX_LINE} characters: a longer one closes the connection (null). */
    private static String readLine(BufferedReader in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') return sb.toString();
            if (c == '\r') continue;
            if (sb.length() >= MAX_LINE) return null;
            sb.append((char) c);
        }
        return null;
    }

    // ===================== the service =====================

    private static final Counter COUNTER = new Counter();
    private static volatile Function<String, Limit> limits = u -> null;
    private static volatile long limitsAt;
    private static volatile ServerSocketChannel server;

    /** The limits are read again from the database every 30 seconds, and right after a save (invalidate). */
    static Function<String, Limit> currentLimits() {
        long now = System.nanoTime();
        if (now - limitsAt > 30_000_000_000L) {
            try {
                if (Main.mailDatabase != null) limits = limitsOf(Main.mailDatabase.getRateLimits());
            } catch (Exception e) {
                LOGGER.warning("[SendingLimits] cannot read the limits: " + e.getMessage() + " (the previous ones stay)");
            }
            limitsAt = now;
        }
        return limits;
    }

    /** After a change from the page: the next request reads them again. */
    public static void invalidate() {
        limitsAt = 0;
    }

    /** The service, once per process. True if it is listening. */
    public static synchronized boolean start() {
        if (server != null) return true;
        try {
            if (!Files.isDirectory(SOCKET.getParent())) return false;
            try {
                if (Files.exists(STATE)) COUNTER.load(Files.readString(STATE, StandardCharsets.UTF_8), Instant.now().getEpochSecond());
            } catch (IOException e) {
                LOGGER.warning("[SendingLimits] cannot read " + STATE + ": counting starts again");
            }
            // A socket left over from an earlier startup: the panel's lock (PanelInstanceLock) says it is not
            // another instance's.
            if (Files.exists(SOCKET, LinkOption.NOFOLLOW_LINKS) && !Files.isDirectory(SOCKET, LinkOption.NOFOLLOW_LINKS)) Files.delete(SOCKET);
            ServerSocketChannel ch = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
            ch.bind(UnixDomainSocketAddress.of(SOCKET));
            Shell.Result own = Shell.run(Duration.ofSeconds(10), "chown", "postfix:postfix", SOCKET.toString());
            Files.setPosixFilePermissions(SOCKET, PosixFilePermissions.fromString("rw-------"));
            if (!own.success()) LOGGER.warning("[SendingLimits] chown postfix of the socket failed: " + own.outputTrim());
            server = ch;
            Thread t = new Thread(SendingLimits::acceptLoop, "sending-limits");
            t.setDaemon(true);
            t.start();
            ScheduledExecutorService saver = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread s = new Thread(r, "sending-limits-save");
                s.setDaemon(true);
                return s;
            });
            saver.scheduleWithFixedDelay(SendingLimits::save, 60, 60, TimeUnit.SECONDS);
            Runtime.getRuntime().addShutdownHook(new Thread(SendingLimits::save, "sending-limits-exit"));
            return true;
        } catch (Exception e) {
            LOGGER.warning("[SendingLimits] the policy service did not start: " + e.getMessage());
            return false;
        }
    }

    private static void acceptLoop() {
        while (server != null && server.isOpen()) {
            try {
                SocketChannel c = server.accept();
                Thread.ofVirtual().name("sending-limits-client").start(() -> serve(c));
            } catch (IOException e) {
                if (server == null || !server.isOpen()) return;
            }
        }
    }

    /** A Postfix connection: several requests one after the other, as long as Postfix keeps it open. */
    static void serve(SocketChannel c) {
        try (c; BufferedReader in = new BufferedReader(new InputStreamReader(Channels.newInputStream(c), StandardCharsets.US_ASCII), 4096);
             OutputStream out = Channels.newOutputStream(c)) {
            Map<String, String> a;
            while ((a = read(in)) != null) {
                String action = decide(a, currentLimits(), COUNTER, Instant.now().getEpochSecond());
                if (!action.equals("DUNNO"))
                    LOGGER.info("[SendingLimits] " + a.getOrDefault("sasl_username", "") + ": " + action);
                out.write(("action=" + action + "\n\n").getBytes(StandardCharsets.US_ASCII));
                out.flush();
            }
        } catch (IOException ignored) {
            // Postfix closed: close here too
        }
    }

    static void save() {
        try {
            if (!COUNTER.dirty()) return;
            String text = COUNTER.dump(Instant.now().getEpochSecond());
            Path tmp = STATE.resolveSibling("." + STATE.getFileName() + ".tmp");
            Files.deleteIfExists(tmp);
            Files.createFile(tmp, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            Files.writeString(tmp, text, StandardCharsets.UTF_8);
            Files.move(tmp, STATE, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            LOGGER.warning("[SendingLimits] cannot save the counts: " + e.getMessage());
        }
    }

    /** A test query, like Postfix: without authentication the answer must be DUNNO. */
    static String ask(Map<String, String> attributes) {
        try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            ch.connect(UnixDomainSocketAddress.of(SOCKET));
            StringBuilder req = new StringBuilder();
            attributes.forEach((k, v) -> req.append(k).append('=').append(v).append('\n'));
            req.append('\n');
            ch.write(ByteBuffer.wrap(req.toString().getBytes(StandardCharsets.US_ASCII)));
            BufferedReader in = new BufferedReader(new InputStreamReader(Channels.newInputStream(ch), StandardCharsets.US_ASCII));
            String line = in.readLine();
            return line == null ? "(no answer)" : line;
        } catch (Exception e) {
            return "(" + e.getClass().getSimpleName() + ")";
        }
    }

    // ===================== Postfix =====================

    /** smtpd_data_restrictions with the query at the top; the same text if it is already there. */
    static String withPolicy(String restrictions) {
        String r = restrictions == null ? "" : restrictions.trim();
        if (r.contains("private/daemoxcp-sending-limits")) return r;
        return r.isEmpty() ? POLICY : POLICY + ", " + r;
    }

    /** The query in smtpd_data_restrictions, if the service answers. */
    public static void ensurePostfix() {
        try {
            if (!Files.isExecutable(Path.of(POSTCONF)) || server == null) return;
            String now = postconf("-h", "smtpd_data_restrictions");
            String wanted = withPolicy(now);
            if (wanted.equals(now)) return;
            Map<String, String> probe = new LinkedHashMap<>();
            probe.put("request", "smtpd_access_policy");
            probe.put("protocol_state", "DATA");
            probe.put("recipient_count", "1");
            if (!"action=DUNNO".equals(ask(probe))) {
                LOGGER.warning("[SendingLimits] the policy service does not answer: Postfix left as it is");
                return;
            }
            Path mainCf = Path.of(postconf("-h", "config_directory"), "main.cf");
            byte[] before = Files.readAllBytes(mainCf);
            PosixFileAttributes attrs = Files.readAttributes(mainCf, PosixFileAttributes.class);
            boolean checkedBefore = Shell.run(Duration.ofSeconds(60), POSTFIX, "check").success();
            String problem = null;
            Shell.Result r = Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", "smtpd_data_restrictions = " + wanted);
            if (!r.success()) problem = "postconf -e failed (exit " + r.exitCode() + "): " + r.outputTrim();
            if (problem == null && !postconf("-h", "smtpd_data_restrictions").equals(wanted)) problem = "smtpd_data_restrictions is not what was written";
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
                PosixFileAttributeView view = Files.getFileAttributeView(mainCf, PosixFileAttributeView.class);
                view.setOwner(attrs.owner());
                view.setGroup(attrs.group());
                view.setPermissions(attrs.permissions());
                Shell.run(Duration.ofSeconds(60), POSTFIX, "reload");
                LOGGER.warning("[SendingLimits] ROLLED_BACK: " + problem + "; main.cf back as it was");
                return;
            }
            LOGGER.info("[SendingLimits] DONE: Postfix asks the panel before each message a mailbox sends (smtpd_data_restrictions = " + wanted + ")");
        } catch (Throwable t) {
            LOGGER.warning("[SendingLimits] ensurePostfix exception: " + t.getMessage());
        }
    }

    // ===================== the page =====================

    /**
     * Whether the limits are enforced (the service listens, Postfix asks), the reason if not, and how much each
     * mailbox has sent.
     */
    public static JSONObject status() {
        JSONObject r = new JSONObject();
        String why = null;
        if (server == null || !server.isOpen()) why = org.daemoxcp.mail.i18n.I18n.tr("server.limits.notRunning");
        else if (!postconf("-h", "smtpd_data_restrictions").contains("private/daemoxcp-sending-limits"))
            why = org.daemoxcp.mail.i18n.I18n.tr("server.limits.notAsked");
        r.put("applied", why == null);
        if (why != null) r.put("reason", why);
        JSONObject usage = new JSONObject();
        COUNTER.usage(Instant.now().getEpochSecond()).forEach((u, n) -> usage.put(u, new JSONObject().put("hour", n[0]).put("day", n[1])));
        return r.put("usage", usage);
    }

    private static String postconf(String... args) {
        String[] cmd = new String[args.length + 1];
        cmd[0] = POSTCONF;
        System.arraycopy(args, 0, cmd, 1, args.length);
        Shell.Result r = Shell.run(Duration.ofSeconds(15), cmd);
        return r.success() ? r.outputTrim() : "";
    }
}
