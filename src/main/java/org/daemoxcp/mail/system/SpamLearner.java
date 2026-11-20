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
 * La parte root del pannello consegna a Rspamd i messaggi che gli utenti hanno spostato nella Junk o fuori (SpamLearning),
 * ogni minuto, e li cancella.
 *
 * La password del controller («enable», l'unica che fa imparare) resta nei segreti di root e viaggia solo da qui a
 * 127.0.0.1:11334, nell'intestazione Password. La cartella di raccolta e' di vmail: qui nessun collegamento si segue
 * (un collegamento verso un file di root diventerebbe testo dato in pasto a Rspamd), e conta solo un file vero, intero
 * (i nomi che cominciano col punto sono quelli che il programma sta ancora scrivendo). Un messaggio vuoto, piu' grande
 * di SpamLearning.MAX_BYTES o piu' vecchio di una settimana si cancella senza consegnarlo; uno che Rspamd rifiuta come
 * messaggio (400, 413) anche. Se Rspamd non risponde, o non accetta la password, i messaggi restano e si riprova al giro
 * dopo. Del contenuto non si scrive niente nel registro: solo quanti.
 */
public final class SpamLearner {

    private static final Logger LOGGER = Logger.getLogger(SpamLearner.class.getName());

    static final Duration MAX_AGE = Duration.ofDays(7);
    static final int PER_ROUND = 200;
    static final String CONTROLLER = "http://127.0.0.1:11334/";

    private SpamLearner() {}

    /** Come Rspamd ha risposto: il codice HTTP, -1 se non ha risposto. */
    @FunctionalInterface
    interface Teacher {
        int learn(String kind, byte[] message);
    }

    /** Il giro: quanti imparati, quanti scartati, e se ci si e' fermati perche' Rspamd non c'era. */
    record Round(int learned, int dropped, boolean stopped, int lastStatus) {}

    /** Un giro su una cartella di raccolta qualsiasi. Puro rispetto a Teacher; now per l'eta' dei messaggi. */
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

    /** I messaggi interi di una cartella, i piu' vecchi prima (il nome comincia con l'ora), al massimo PER_ROUND. */
    static List<Path> waiting(Path dir) throws IOException {
        List<Path> out = new ArrayList<>();
        try (DirectoryStream<Path> s = Files.newDirectoryStream(dir)) {
            for (Path p : s) if (!p.getFileName().toString().startsWith(".")) out.add(p);
        }
        out.sort(null);
        return out.size() > PER_ROUND ? out.subList(0, PER_ROUND) : out;
    }

    /** Il file senza seguire collegamenti, al massimo expected byte; null se e' cambiato sotto le mani. */
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
     * HTTP/1.1: su http in chiaro il client di Java prova prima a passare a HTTP/2 (h2c), e il controller di Rspamd
     * riceveva la richiesta senza il corpo («got zero length body», 400: misurato sulla VM il 20/11/2026).
     */
    private static final HttpClient HTTP = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(5)).build();

    /** Il controller di Rspamd sulla macchina stessa, con la password dei segreti di root. */
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

    /** Al massimo un avviso all'ora: Rspamd fermo non deve riempire il registro. */
    private static void warn(String what) {
        Instant now = Instant.now();
        if (now.isBefore(lastWarning.plus(Duration.ofHours(1)))) return;
        lastWarning = now;
        LOGGER.warning("[SpamLearning] " + what);
    }

    /** Nella parte root, una volta: un giro al minuto. */
    public static void start() {
        ScheduledExecutorService s = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "spam-learner");
            t.setDaemon(true);
            return t;
        });
        s.scheduleWithFixedDelay(SpamLearner::tick, 90, 60, TimeUnit.SECONDS);
    }
}
