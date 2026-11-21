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
 * I conteggi di posta mandata e ricevuta, letti dal registro di Postfix: prima la tabella email_statistics c'era, la
 * pagina Statistiche la leggeva, e nessuno la scriveva.
 *
 * <p>Ogni minuto la parte root legge le righe nuove di /var/log/maillog (dalla posizione salvata in {@link #STATE};
 * dopo la rotazione di mezzanotte, il resto del file vecchio: da maillog.0 finche' newsyslog non l'ha compresso, poi da
 * maillog.0.bz2) e conta, per giorno (UTC, r13), casella e dominio:
 * <ul>
 *   <li>ricevuti: le consegne riuscite a una casella (lmtp, status=sent);</li>
 *   <li>mandati: le consegne riuscite, a chiunque, di un messaggio mandato da una casella autenticata
 *       (sasl_username), una per destinatario;</li>
 *   <li>respinti (bounced): le consegne fallite per sempre, della casella che aveva mandato o, per la posta in arrivo,
 *       della casella che doveva ricevere;</li>
 *   <li>spam e virus: i messaggi che Rspamd ha rifiutato (milter-reject), della casella a cui erano diretti.</li>
 * </ul>
 * Si contano solo le caselle del pannello: un indirizzo esterno non finisce mai nella tabella. Alla prima lettura si
 * parte dalla fine del file: i conteggi cominciano da quando gira questa versione, senza contare due volte quello che
 * c'era. Le righe di email_statistics piu' vecchie di {@value #KEEP_DAYS} giorni si tolgono una volta al giorno.
 */
public final class MailLogStats {

    private static final Logger LOGGER = Logger.getLogger(MailLogStats.class.getName());

    static final Path LOG = Path.of("/var/log/maillog");
    static final Path ROTATED = Path.of("/var/log/maillog.0.bz2");
    /** Il file vecchio appena girato, prima che newsyslog lo comprima (flag J: aspetta circa 10 s, poi bzip2). */
    static final Path ROTATED_PLAIN = Path.of("/var/log/maillog.0");
    /** Quanto si aspetta il file vecchio, intero o compresso, prima di lasciar perdere il suo resto. */
    static final Duration ROTATION_WAIT = Duration.ofMinutes(10);
    static final Path STATE = Path.of("/var/db/daemoxcp-mail/maillog-position.txt");
    static final int KEEP_DAYS = 400;
    static final long MAX_READ = 64L * 1024 * 1024;

    private MailLogStats() {}

    // ===================== le righe: si provano senza il registro vero =====================

    /** Un conteggio: il giorno (UTC), il tipo (sent, received, spam, virus, bounced), l'indirizzo, i byte. */
    record Event(LocalDate day, String type, String address, long bytes) {}

    private static final Pattern LINE = Pattern.compile(
            "^(?<ts>[A-Z][a-z]{2} [ 0-9]\\d \\d\\d:\\d\\d:\\d\\d|\\d{4}-\\d\\d-\\d\\dT\\S+) \\S+ "
            + "postfix(?:/[a-z0-9_.-]+)*/(?<daemon>[a-z0-9_-]+)\\[\\d+\\]: (?<qid>[0-9A-Za-z]{6,}): (?<msg>.*)$");
    private static final Pattern ADDRESS = Pattern.compile("to=<([^>]*)>");
    private static final Pattern STATUS = Pattern.compile("status=([a-z]+)");
    private static final Pattern SIZE = Pattern.compile("size=(\\d+)");
    private static final Pattern SASL = Pattern.compile("sasl_username=([^,\\s]+)");
    private static final DateTimeFormatter BSD = DateTimeFormatter.ofPattern("MMM d HH:mm:ss yyyy", Locale.ENGLISH);

    /** Le righe una dopo l'altra: ricorda di ogni messaggio in coda chi l'ha mandato (autenticato) e quanto e' grande. */
    static final class Parser {
        private final ZoneId zone;
        private final LinkedHashMap<String, String[]> queue = new LinkedHashMap<>(16, 0.75f, false);

        Parser(ZoneId zone) {
            this.zone = zone;
        }

        /** I conteggi di una riga (spesso nessuno). now serve a dare l'anno alle date di syslog, che non lo hanno. */
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

        /** Rspamd ha rifiutato il messaggio: spam, o virus se lo dice. Della casella a cui era diretto. */
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
            // Le code che non finiscono con «removed» (righe perse, un riavvio) non devono crescere senza fine.
            if (queue.size() > 50_000) queue.remove(queue.keySet().iterator().next());
            return i;
        }

        /** Il giorno UTC di una data di syslog (senza anno: l'anno di now, o quello prima se cadrebbe nel futuro). */
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

    /** I conteggi sommati per giorno, tipo e indirizzo: una scrittura per gruppo invece che per messaggio. */
    static Map<List<Object>, long[]> aggregate(List<Event> events) {
        Map<List<Object>, long[]> out = new LinkedHashMap<>();
        for (Event e : events) {
            long[] v = out.computeIfAbsent(List.of(e.day(), e.type(), e.address()), k -> new long[2]);
            v[0]++;
            v[1] += e.bytes();
        }
        return out;
    }

    // ===================== la lettura del registro =====================

    private static final Parser PARSER = new Parser(systemZone());
    private static volatile LocalDate lastCleanup;

    /** Il fuso del sistema (quello di syslog): /etc/localtime, non quello della JVM se qualcuno l'ha cambiato. */
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

    /** Una lettura: le righe nuove, i conteggi nel database, la posizione salvata. */
    static synchronized void collect() throws Exception {
        if (Main.mailDatabase == null || !Files.isRegularFile(LOG, LinkOption.NOFOLLOW_LINKS)) return;
        long inode = ((Number) Files.getAttribute(LOG, "unix:ino")).longValue();
        long size = Files.size(LOG);
        long[] saved = readState();
        if (saved == null) {
            // La prima volta si parte dalla fine: quello che c'era non si conta (ne' due volte, se lo stato si perde).
            writeState(inode, size);
            LOGGER.info("[MailLogStats] Counting sent and received mail from now on (" + LOG + ")");
            return;
        }
        List<String> lines = new ArrayList<>();
        long offset = saved[1];
        if (saved[0] == inode && size < offset) {
            // Lo stesso file, svuotato sul posto: non c'e' un file vecchio da finire (prima si leggeva il .bz2 di ieri
            // da quella posizione, righe gia' contate o d'altri giorni).
            offset = 0;
        } else if (saved[0] != inode) {
            // Il file e' girato. Il resto di quello vecchio, se c'e' gia' (intero o compresso); se no si riprova al giro
            // dopo, senza toccare la posizione: misurato sulla VM il 21/11/2026, newsyslog lascia maillog.0 intero per
            // circa 10 s e solo dopo lo comprime, e alle 00:00:02 del server vero il .bz2 non c'era ancora.
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

    /** Le righe complete fra from e to (l'ultima riga a meta' resta per la prossima volta). Quanti byte ha consumato. */
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

    /** Da quando si aspetta il file vecchio dopo una rotazione (null: non si aspetta). */
    private static volatile Instant rotationWaitSince;

    /** Si smette di aspettare il file vecchio dopo {@link #ROTATION_WAIT}. */
    static boolean gaveUpWaiting(Instant since, Instant now) {
        return !now.isBefore(since.plus(ROTATION_WAIT));
    }

    /**
     * Il resto del file di ieri dopo i byte gia' letti, o null se non c'e' ancora: si riprova al giro dopo.
     * <ul>
     *   <li>plain c'e' ed e' proprio il file che si leggeva (stesso inode): da li', anche se bzip2 sta gia' scrivendo un
     *       .bz2 a meta';</li>
     *   <li>plain non c'e' piu' e c'e' il .bz2: bzip2 ha finito (toglie l'originale solo alla fine), dal .bz2;</li>
     *   <li>altrimenti null.</li>
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

    /** Il resto di un file compresso, dopo i byte gia' letti. */
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

    /** I conteggi nella tabella: casella, dominio e totale del server, come li somma la pagina. Solo le caselle del pannello. */
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
