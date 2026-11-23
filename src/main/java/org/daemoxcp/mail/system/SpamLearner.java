package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.PanelSecrets;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * The root part of the panel hands over to Rspamd the messages that users have moved into Junk or out of it
 * (SpamLearning), every minute, and deletes them.
 *
 * The controller password ("enable", the only one that makes it learn) stays in root's secrets and travels only from
 * here to 127.0.0.1:11334, in the Password header. The collection folder belongs to vmail: here no link is followed
 * (a link to a root file would become text fed to Rspamd), and only a real, complete file counts (the names that
 * start with a dot are those the program is still writing). A message that is empty, larger than
 * SpamLearning.MAX_BYTES or older than a week is deleted without being handed over; so is one that Rspamd rejects
 * as a message (400, 413). If Rspamd does not answer, or does not accept the password, the messages stay and it
 * tries again on the next round. Nothing of the content is written to the log: only how many.
 */
public final class SpamLearner {

    private static final Logger LOGGER = Logger.getLogger(SpamLearner.class.getName());

    static final Duration MAX_AGE = Duration.ofDays(7);
    static final int PER_ROUND = 200;
    static final String CONTROLLER = "http://127.0.0.1:11334/";

    private SpamLearner() {}

    /** How Rspamd answered: the HTTP code, -1 if it did not answer. */
    @FunctionalInterface
    interface Teacher {
        int learn(String kind, byte[] message);
    }

    /** The round: how many learned, how many discarded, and whether it stopped because Rspamd was not there. */
    record Round(int learned, int dropped, boolean stopped, int lastStatus) {}

    /** One round on any collection folder. Pure with respect to Teacher; now for the age of the messages. */
    static Round round(Path spool, Teacher teacher, Instant now) throws IOException {
        int learned = 0, dropped = 0;
        for (String kind : SpamLearning.KINDS) {
            Path dir = spool.resolve(kind);
            if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) continue;
            for (Path f : waiting(dir)) {
                BasicFileAttributes a = Files.readAttributes(f, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!a.isRegularFile() || a.size() == 0 || a.size() > SpamLearning.MAX_BYTES
                        || a.lastModifiedTime().toInstant().isBefore(now.minus(MAX_AGE))) {
                    if (a.isDirectory()) continue;
                    Files.deleteIfExists(f);
                    dropped++;
                    continue;
                }
                byte[] message = read(f, (int) a.size());
                if (message == null) { Files.deleteIfExists(f); dropped++; continue; }
                int status = teacher.learn(kind, message);
                if (status >= 200 && status < 300) { Files.deleteIfExists(f); learned++; }
                else if (status == 400 || status == 413) { Files.deleteIfExists(f); dropped++; }
                else return new Round(learned, dropped, true, status);
            }
        }
        return new Round(learned, dropped, false, 0);
    }

    /** The complete messages of a folder, oldest first (the name starts with the time), at most PER_ROUND. */
    static List<Path> waiting(Path dir) throws IOException {
        List<Path> out = new ArrayList<>();
        try (DirectoryStream<Path> s = Files.newDirectoryStream(dir)) {
            for (Path p : s) if (!p.getFileName().toString().startsWith(".")) out.add(p);
        }
        out.sort(null);
        return out.size() > PER_ROUND ? out.subList(0, PER_ROUND) : out;
    }

    /** The file without following links, at most expected bytes; null if it changed while being read. */
    static byte[] read(Path f, int expected) throws IOException {
        try (SeekableByteChannel c = Files.newByteChannel(f, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            ByteBuffer b = ByteBuffer.allocate(expected);
            while (b.hasRemaining() && c.read(b) > 0) { }
            if (b.hasRemaining() || c.read(ByteBuffer.allocate(1)) > 0) return null;
            return b.array();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * HTTP/1.1: over plain http the Java client first tries to upgrade to HTTP/2 (h2c), and the Rspamd controller
     * received the request without the body ("got zero length body", 400: measured on the VM on 2026-11-20).
     */
    private static final HttpClient HTTP = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(5)).build();

    /** The Rspamd controller on the machine itself, with the password from root's secrets. */
    static Teacher rspamd(String password) {
        return (kind, message) -> {
            try {
                HttpRequest r = HttpRequest.newBuilder(URI.create(CONTROLLER + ("spam".equals(kind) ? "learnspam" : "learnham")))
                        .timeout(Duration.ofSeconds(60)).header("Password", password)
                        .POST(HttpRequest.BodyPublishers.ofByteArray(message)).build();
                return HTTP.send(r, HttpResponse.BodyHandlers.discarding()).statusCode();
            } catch (IOException e) {
                return -1;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
        };
    }

    private static volatile Instant lastWarning = Instant.EPOCH;

    static void tick() {
        try {
            Path spool = Path.of(SpamLearning.SPOOL);
            if (!Files.isDirectory(spool, LinkOption.NOFOLLOW_LINKS)) return;
            if (nothingWaiting(spool)) return;
            String password = PanelSecrets.reread(PanelSecrets.RSPAMD_CONTROLLER_PASSWORD);
            if (password == null || password.isEmpty()) {
                warn("the Rspamd controller password is not in the root secrets: the users' moves wait");
                return;
            }
            Round r = round(spool, rspamd(password), Instant.now());
            if (r.learned() > 0 || r.dropped() > 0)
                LOGGER.info("[SpamLearning] Rspamd learned " + r.learned() + " message(s) from the users' moves"
                        + (r.dropped() > 0 ? "; " + r.dropped() + " dropped (empty, too big, too old or refused)" : ""));
            if (r.stopped()) warn("Rspamd's controller answered " + r.lastStatus() + ": the users' moves wait for the next round");
        } catch (Throwable t) {
            warn(t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private static boolean nothingWaiting(Path spool) throws IOException {
        for (String kind : SpamLearning.KINDS) {
            Path dir = spool.resolve(kind);
            if (Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS) && !waiting(dir).isEmpty()) return false;
        }
        return true;
    }

    /** At most one warning an hour: a stopped Rspamd must not fill the log. */
    private static void warn(String what) {
        Instant now = Instant.now();
        if (now.isBefore(lastWarning.plus(Duration.ofHours(1)))) return;
        lastWarning = now;
        LOGGER.warning("[SpamLearning] " + what);
    }

    /** In the root part, once: one round a minute. */
    public static void start() {
        ScheduledExecutorService s = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "spam-learner");
            t.setDaemon(true);
            return t;
        });
        s.scheduleWithFixedDelay(SpamLearner::tick, 90, 60, TimeUnit.SECONDS);
    }
}
