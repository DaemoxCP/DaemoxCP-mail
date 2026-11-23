package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The counts of mail sent and received, read from the Postfix log: before, the email_statistics table existed, the
 * "Statistics" page read it, and nobody wrote it.
 *
 * <p>Every minute the root part reads the new lines of /var/log/maillog (from the position saved in {@link #STATE};
 * after the midnight rotation, the rest of the old file: from maillog.0 until newsyslog has compressed it, then from
 * maillog.0.bz2) and counts, per day (UTC, r13), mailbox and domain:
 * <ul>
 *   <li>received: the successful deliveries to a mailbox (lmtp, status=sent);</li>
 *   <li>sent: the successful deliveries, to anyone, of a message sent by an authenticated mailbox
 *       (sasl_username), one per recipient;</li>
 *   <li>bounced: the permanently failed deliveries, for the mailbox that had sent or, for incoming mail, the
 *       mailbox that was to receive;</li>
 *   <li>spam and virus: the messages Rspamd rejected (milter-reject), for the mailbox they were addressed to.</li>
 * </ul>
 * Only the panel's mailboxes are counted: an external address never ends up in the table. At the first read it
 * starts from the end of the file: the counts begin from when this version runs, without counting twice what was
 * there. The rows of email_statistics older than {@value #KEEP_DAYS} days are removed once a day.
 */
public final class MailLogStats {

    private static final Logger LOGGER = Logger.getLogger(MailLogStats.class.getName());

    static final Path LOG = Path.of("/var/log/maillog");
    static final Path ROTATED = Path.of("/var/log/maillog.0.bz2");
    /** The old file just rotated, before newsyslog compresses it (flag J: it waits about 10 s, then bzip2). */
    static final Path ROTATED_PLAIN = Path.of("/var/log/maillog.0");
    /** How long to wait for the old file, whole or compressed, before giving up on its remainder. */
    static final Duration ROTATION_WAIT = Duration.ofMinutes(10);
    static final Path STATE = Path.of("/var/db/daemoxcp-mail/maillog-position.txt");
    static final int KEEP_DAYS = 400;
    static final long MAX_READ = 64L * 1024 * 1024;

    private MailLogStats() {}

    // ===================== the lines: tested without the real log =====================

    /** A count: the day (UTC), the type (sent, received, spam, virus, bounced), the address, the bytes. */
    record Event(LocalDate day, String type, String address, long bytes) {}

    private static final Pattern LINE = Pattern.compile(
            "^(?<ts>[A-Z][a-z]{2} [ 0-9]\\d \\d\\d:\\d\\d:\\d\\d|\\d{4}-\\d\\d-\\d\\dT\\S+) \\S+ "
            + "postfix(?:/[a-z0-9_.-]+)*/(?<daemon>[a-z0-9_-]+)\\[\\d+\\]: (?<qid>[0-9A-Za-z]{6,}): (?<msg>.*)$");
    private static final Pattern ADDRESS = Pattern.compile("to=<([^>]*)>");
    private static final Pattern STATUS = Pattern.compile("status=([a-z]+)");
    private static final Pattern SIZE = Pattern.compile("size=(\\d+)");
    private static final Pattern SASL = Pattern.compile("sasl_username=([^,\\s]+)");
    private static final DateTimeFormatter BSD = DateTimeFormatter.ofPattern("MMM d HH:mm:ss yyyy", Locale.ENGLISH);

    /**
     * The lines one after the other: for every queued message it remembers who sent it (authenticated) and how big
     * it is.
     */
    static final class Parser {
        private final ZoneId zone;
        private final LinkedHashMap<String, String[]> queue = new LinkedHashMap<>(16, 0.75f, false);

        Parser(ZoneId zone) {
            this.zone = zone;
        }

        /** The counts of a line (often none). now is used to give the year to syslog dates, which lack it. */
        List<Event> line(String line, ZonedDateTime now) {
            Matcher m = LINE.matcher(line);
            if (!m.matches()) return List.of();
            String daemon = m.group("daemon"), qid = m.group("qid"), msg = m.group("msg");
            String[] q = queue.get(qid);
            switch (daemon) {
                case "smtpd" -> {
                    Matcher s = SASL.matcher(msg);
                    if (s.find()) info(qid)[0] = s.group(1).trim().toLowerCase(Locale.ROOT);
                    return milterReject(msg, m.group("ts"), now);
                }
                case "qmgr" -> {
                    if (msg.equals("removed")) { queue.remove(qid); return List.of(); }
                    Matcher s = SIZE.matcher(msg);
                    if (msg.startsWith("from=<") && s.find()) info(qid)[1] = s.group(1);
                    return List.of();
                }
                case "cleanup" -> { return milterReject(msg, m.group("ts"), now); }
                case "lmtp", "smtp", "virtual", "local" -> {
                    if (!msg.startsWith("to=<")) return List.of();
                    Matcher a = ADDRESS.matcher(msg), st = STATUS.matcher(msg);
                    if (!a.find() || !st.find()) return List.of();
                    String rcpt = a.group(1).trim().toLowerCase(Locale.ROOT), status = st.group(1);
                    String sender = q == null ? null : q[0];
                    long bytes = q == null || q[1] == null ? 0 : Long.parseLong(q[1]);
                    LocalDate day = day(m.group("ts"), now);
                    if (day == null) return List.of();
                    boolean local = daemon.equals("lmtp") || daemon.equals("virtual") || daemon.equals("local");
                    List<Event> out = new ArrayList<>(2);
                    if (status.equals("sent")) {
                        if (local) out.add(new Event(day, "received", rcpt, bytes));
                        if (sender != null) out.add(new Event(day, "sent", sender, bytes));
                    } else if (status.equals("bounced")) {
                        if (sender != null) out.add(new Event(day, "bounced", sender, bytes));
                        else if (local) out.add(new Event(day, "bounced", rcpt, bytes));
                    }
                    return out;
                }
                default -> { return List.of(); }
            }
        }

        /** Rspamd rejected the message: spam, or virus if it says so. Counted for the mailbox it was addressed to. */
        private List<Event> milterReject(String msg, String ts, ZonedDateTime now) {
            int at = msg.indexOf("milter-reject:");
            if (at < 0) return List.of();
            Matcher a = ADDRESS.matcher(msg);
            LocalDate day = day(ts, now);
            if (!a.find() || day == null) return List.of();
            String type = msg.substring(at).toLowerCase(Locale.ROOT).contains("virus") ? "virus" : "spam";
            return List.of(new Event(day, type, a.group(1).trim().toLowerCase(Locale.ROOT), 0));
        }

        private String[] info(String qid) {
            String[] i = queue.computeIfAbsent(qid, k -> new String[2]);
            // Queue entries that do not end with "removed" (lost lines, a restart) must not grow without end.
            if (queue.size() > 50_000) queue.remove(queue.keySet().iterator().next());
            return i;
        }

        /**
         * The UTC day of a syslog date (without a year: the year of now, or the one before if it would fall in the
         * future).
         */
        LocalDate day(String ts, ZonedDateTime now) {
            try {
                if (Character.isDigit(ts.charAt(0))) return OffsetDateTime.parse(ts).withOffsetSameInstant(ZoneOffset.UTC).toLocalDate();
                ZonedDateTime local = now.withZoneSameInstant(zone);
                LocalDateTime t = LocalDateTime.parse(ts.replaceAll(" +", " ") + " " + local.getYear(), BSD);
                if (t.isAfter(local.toLocalDateTime().plusDays(1))) t = t.minusYears(1);
                return t.atZone(zone).withZoneSameInstant(ZoneOffset.UTC).toLocalDate();
            } catch (DateTimeParseException | IndexOutOfBoundsException e) {
                return null;
            }
        }

        int queued() {
            return queue.size();
        }
    }

    /** The counts summed by day, type and address: one write per group instead of per message. */
    static Map<List<Object>, long[]> aggregate(List<Event> events) {
        Map<List<Object>, long[]> out = new LinkedHashMap<>();
        for (Event e : events) {
            long[] v = out.computeIfAbsent(List.of(e.day(), e.type(), e.address()), k -> new long[2]);
            v[0]++;
            v[1] += e.bytes();
        }
        return out;
    }

    // ===================== reading the log =====================

    private static final Parser PARSER = new Parser(systemZone());
    private static volatile LocalDate lastCleanup;

    /** The system time zone (the one syslog uses): /etc/localtime, not the JVM's if someone has changed it. */
    static ZoneId systemZone() {
        try {
            Path target = Files.readSymbolicLink(Path.of("/etc/localtime"));
            String s = target.toString();
            int i = s.indexOf("zoneinfo/");
            if (i >= 0) return ZoneId.of(s.substring(i + "zoneinfo/".length()));
        } catch (Exception ignored) { }
        return ZoneId.systemDefault();
    }

    public static void start() {
        ScheduledExecutorService s = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "mail-log-stats");
            t.setDaemon(true);
            return t;
        });
        s.scheduleWithFixedDelay(MailLogStats::collectSafely, 30, 60, TimeUnit.SECONDS);
    }

    private static void collectSafely() {
        try {
            collect();
        } catch (Throwable t) {
            LOGGER.warning("[MailLogStats] " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    /** One read: the new lines, the counts into the database, the saved position. */
    static synchronized void collect() throws Exception {
        if (Main.mailDatabase == null || !Files.isRegularFile(LOG, LinkOption.NOFOLLOW_LINKS)) return;
        long inode = ((Number) Files.getAttribute(LOG, "unix:ino")).longValue();
        long size = Files.size(LOG);
        long[] saved = readState();
        if (saved == null) {
            // The first time it starts from the end: what was there is not counted (nor counted twice, if the state
            // is lost).
            writeState(inode, size);
            LOGGER.info("[MailLogStats] Counting sent and received mail from now on (" + LOG + ")");
            return;
        }
        List<String> lines = new ArrayList<>();
        long offset = saved[1];
        if (saved[0] == inode && size < offset) {
            // The same file, emptied in place: there is no old file to finish (before, yesterday's .bz2 was read
            // from that position: lines already counted or from other days).
            offset = 0;
        } else if (saved[0] != inode) {
            // The file has rotated. The rest of the old one, if it is already there (whole or compressed); if not, it
            // is tried again at the next round, without touching the position: measured on the VM on 2026-11-21,
            // newsyslog leaves maillog.0 whole for about 10 s and only afterwards compresses it, and at 00:00:02 on the
            // production server the .bz2 was not there yet.
            List<String> rest = rotatedRest(ROTATED_PLAIN, ROTATED, saved[0], offset);
            Instant now = Instant.now();
            if (rest == null) {
                if (rotationWaitSince == null) rotationWaitSince = now;
                if (!gaveUpWaiting(rotationWaitSince, now)) return;
                LOGGER.warning("[MailLogStats] " + LOG + " was turned over and after " + ROTATION_WAIT.toMinutes()
                        + " minutes neither " + ROTATED_PLAIN + " nor " + ROTATED + " is there: the rest of the old file is not counted");
                rest = List.of();
            }
            rotationWaitSince = null;
            lines.addAll(rest);
            offset = 0;
        }
        long end = Math.min(size, offset + MAX_READ);
        long consumed = readLines(LOG, offset, end, lines);
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        List<Event> events = new ArrayList<>();
        for (String l : lines) events.addAll(PARSER.line(l, now));
        write(aggregate(events));
        writeState(inode, offset + consumed);
        cleanupOnceADay();
    }

    /** The complete lines between from and to (a last half line stays for next time). How many bytes it consumed. */
    static long readLines(Path file, long from, long to, List<String> out) throws IOException {
        if (to <= from) return 0;
        byte[] buf = new byte[(int) (to - from)];
        try (RandomAccessFile f = new RandomAccessFile(file.toFile(), "r")) {
            f.seek(from);
            f.readFully(buf);
        }
        int last = -1;
        for (int i = buf.length - 1; i >= 0; i--) if (buf[i] == '\n') { last = i; break; }
        if (last < 0) return 0;
        String text = new String(buf, 0, last, StandardCharsets.UTF_8);
        for (String l : text.split("\n", -1)) if (!l.isEmpty()) out.add(l);
        return last + 1;
    }

    /** Since when the old file has been awaited after a rotation (null: not waiting). */
    private static volatile Instant rotationWaitSince;

    /** Waiting for the old file stops after {@link #ROTATION_WAIT}. */
    static boolean gaveUpWaiting(Instant since, Instant now) {
        return !now.isBefore(since.plus(ROTATION_WAIT));
    }

    /**
     * The rest of yesterday's file after the bytes already read, or null if it is not there yet: it is tried again
     * at the next round.
     * <ul>
     *   <li>plain is there and is exactly the file that was being read (same inode): from there, even if bzip2 is
     *       already writing a half-done .bz2;</li>
     *   <li>plain is gone and the .bz2 is there: bzip2 has finished (it removes the original only at the end), from
     *       the .bz2;</li>
     *   <li>otherwise null.</li>
     * </ul>
     */
    static List<String> rotatedRest(Path plain, Path bz2, long oldInode, long skip) {
        if (Files.isRegularFile(plain, LinkOption.NOFOLLOW_LINKS)) {
            try {
                if (((Number) Files.getAttribute(plain, "unix:ino", LinkOption.NOFOLLOW_LINKS)).longValue() != oldInode) return null;
                List<String> out = new ArrayList<>();
                long size = Files.size(plain);
                if (size > skip) readLines(plain, skip, Math.min(size, skip + MAX_READ), out);
                return out;
            } catch (IOException | UnsupportedOperationException | IllegalArgumentException e) {
                return null;
            }
        }
        if (!Files.isRegularFile(bz2, LinkOption.NOFOLLOW_LINKS)) return null;
        return bz2Rest(bz2, skip);
    }

    /** The rest of a compressed file, after the bytes already read. */
    static List<String> bz2Rest(Path rotated, long skip) {
        List<String> out = new ArrayList<>();
        try {
            Process p = new ProcessBuilder("/usr/bin/bzcat", rotated.toString()).redirectErrorStream(false).start();
            try (InputStream in = p.getInputStream()) {
                long left = skip;
                while (left > 0) { long n = in.skip(left); if (n <= 0) break; left -= n; }
                BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                String l;
                long bytes = 0;
                while ((l = r.readLine()) != null && bytes < MAX_READ) { out.add(l); bytes += l.length() + 1; }
            }
            p.waitFor(60, TimeUnit.SECONDS);
            p.destroy();
        } catch (Exception e) {
            LOGGER.warning("[MailLogStats] cannot read " + rotated + ": " + e.getMessage());
        }
        return out;
    }

    /**
     * The counts into the table: mailbox, domain and server total, as the page sums them. Only the panel's
     * mailboxes.
     */
    static void write(Map<List<Object>, long[]> groups) throws Exception {
        if (groups.isEmpty()) return;
        Map<String, MailDatabase.Mailbox> boxes = new HashMap<>();
        for (MailDatabase.Mailbox b : Main.mailDatabase.getAllMailboxes())
            if (b.email != null) boxes.put(b.email.toLowerCase(Locale.ROOT), b);
        for (Map.Entry<List<Object>, long[]> g : groups.entrySet()) {
            LocalDate day = (LocalDate) g.getKey().get(0);
            String type = (String) g.getKey().get(1);
            MailDatabase.Mailbox b = boxes.get((String) g.getKey().get(2));
            if (b == null) continue;
            int n = (int) g.getValue()[0];
            long bytes = g.getValue()[1];
            Main.mailDatabase.incrementEmailStatOn(day, b.id, b.domainId, type, n, bytes);
            Main.mailDatabase.incrementEmailStatOn(day, null, b.domainId, type, n, bytes);
            Main.mailDatabase.incrementEmailStatOn(day, null, null, type, n, bytes);
        }
    }

    private static void cleanupOnceADay() {
        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        if (today.equals(lastCleanup)) return;
        lastCleanup = today;
        int n = Main.mailDatabase.deleteEmailStatsBefore(today.minusDays(KEEP_DAYS));
        if (n > 0) LOGGER.info("[MailLogStats] " + n + " statistics rows older than " + KEEP_DAYS + " days removed");
    }

    private static long[] readState() {
        try {
            if (!Files.isRegularFile(STATE, LinkOption.NOFOLLOW_LINKS)) return null;
            String[] p = Files.readString(STATE).trim().split(" ");
            return p.length == 2 ? new long[]{Long.parseLong(p[0]), Long.parseLong(p[1])} : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static void writeState(long inode, long offset) throws IOException {
        Path tmp = STATE.resolveSibling("." + STATE.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.createFile(tmp, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(tmp, inode + " " + offset + "\n");
        Files.move(tmp, STATE, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
