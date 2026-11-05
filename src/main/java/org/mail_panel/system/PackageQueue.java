package org.mail_panel.system;

import java.nio.ByteBuffer;
import org.mail_panel.i18n.I18n;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Un lavoro alla volta sui pacchetti, e l'elenco per riproteggerli scritto davvero prima di
 * sbloccarli.
 *
 * Aggiornamento guidato, manutenzione, aggiornamento dei non protetti, Roundcube, la JVM, il
 * passaggio di Python, la migrazione di MySQL, il ricollegamento delle librerie, la pulizia del
 * client MySQL, l'installazione dei componenti, la protezione e la rimozione dei pacchetti: tutti
 * cambiano i pacchetti o le loro protezioni, e due insieme si pestano i piedi. Il secondo
 * sovrascriveva l'elenco su disco del primo; il primo, finendo, lo cancellava mentre il secondo
 * aveva ancora pacchetti sbloccati; e un'interruzione in quel momento li lasciava sbloccati senza
 * che l'avvio lo sapesse. Un "pkg upgrade" dei non protetti, partito mentre la manutenzione aveva
 * tolto la protezione a Dovecot, aggiornava anche Dovecot. E il piano calcolato da uno non vale
 * piu' se l'altro cambia i pacchetti nel frattempo.
 *
 * Il turno si prende nella richiesta, PRIMA di avviare il lavoro: quindi prima dei controlli, del
 * piano e di ogni sblocco. Si rilascia quando il lavoro finisce, qualunque cosa succeda. Chi lo
 * trova preso non parte, e sa chi lo tiene.
 *
 * Il turno vale fra PROCESSI, non solo fra i thread di un pannello. Il servizio (--web) e il
 * menu a schermo sono due JVM, e il menu ha la sua reinstallazione completa: con il turno solo
 * in memoria, il menu non vedeva una manutenzione in corso nel servizio, e il servizio non
 * vedeva una reinstallazione partita dal menu. Peggio, ogni avvio del jar (anche solo
 * --access-code) riproteggeva "dopo un crash" l'elenco di un lavoro vivo in un altro processo, e
 * glielo cancellava. Per questo chi tiene il turno tiene anche un blocco del sistema operativo
 * su un file accanto all'elenco: il blocco muore col processo, l'elenco no, ed e' proprio la
 * differenza fra "un lavoro e' in corso" e "un lavoro si e' interrotto".
 */
public final class PackageQueue {

    private static final Logger LOGGER = Logger.getLogger(PackageQueue.class.getName());

    private PackageQueue() {}

    /**
     * L'elenco dei pacchetti che un lavoro in corso ha sbloccato. Il finally di un lavoro non gira
     * se il processo muore (riavvio del pannello, kill, crash della JVM): questo file e' l'unica
     * cosa che sopravvive, e all'avvio il pannello riprotegge cio' che c'e' scritto.
     */
    public static final String STATE_PATH = "/var/db/mail-panel-maintenance-locks";

    /** Dove sta l'elenco. E' una variabile solo perche' le prove non scrivano in /var/db. */
    static Path list = Path.of(STATE_PATH);

    private record Turn(String id, String description, long start) {}

    private static final AtomicReference<Turn> IN_PROGRESS = new AtomicReference<>();

    /**
     * Il file del turno fra processi, accanto all'elenco: /var/db/mail-panel-package-turn. Chi
     * tiene il turno ne tiene il blocco (fcntl, attraverso FileChannel.tryLock) e ci scrive chi
     * e': pid, lavoro, da quando. Il file resta sempre; e' il blocco che dice se il turno e'
     * preso, e il sistema lo toglie da solo quando il processo muore, anche con kill -9.
     *
     * Si ricava da 'list' perche' le prove, spostando l'elenco, spostino anche questo.
     */
    static Path turnFile() {
        return list.resolveSibling("mail-panel-package-turn");
    }

    /**
     * Il canale e il blocco del turno fra processi, se questo processo lo tiene. Un canale solo
     * per tutto: in Java (e in fcntl) chiudere UN qualunque canale sullo stesso file toglie i
     * blocchi del processo su quel file, quindi il file del turno non si apre mai altrove
     * mentre lo si tiene.
     */
    private static FileChannel turnChannel;
    private static FileLock turnLock;

    /**
     * Prende il turno per il lavoro 'id'. null se l'ha preso; altrimenti il motivo per cui il
     * lavoro non puo' partire, da mostrare cosi' com'e'.
     *
     * Non lo prende nemmeno se su disco c'e' l'elenco di un lavoro che non si e' chiuso: quei
     * pacchetti potrebbero essere ancora sbloccati, e un "pkg upgrade" o un "pkg install" li
     * cambierebbe come se niente fosse.
     */
    public static String take(String id, String description) {
        return take(id, description, true);
    }

    /**
     * Come prendi, ma anche con l'elenco di un lavoro interrotto su disco. Solo per rimettere o
     * togliere protezioni: rimetterle e' proprio il rimedio a quell'elenco.
     */
    public static String takeForLocks(String id, String description) {
        return take(id, description, false);
    }

    private static String take(String id, String description, boolean notWithOpenList) {
        Turn fresh = new Turn(id, description, System.currentTimeMillis());
        while (!IN_PROGRESS.compareAndSet(null, fresh)) {
            String holder = holder();
            if (holder != null) return busy(holder);
            // Rilasciato fra i due passi: si riprova.
        }
        // In questo processo il turno e' nostro; adesso fra i processi. Prima di guardare
        // l'elenco: se c'e' ed e' di un lavoro vivo in un altro processo, la risposta giusta e'
        // "c'e' un lavoro in corso", non "c'e' un lavoro interrotto".
        String elsewhere = lockAcrossProcesses(fresh);
        if (elsewhere != null) {
            IN_PROGRESS.compareAndSet(fresh, null);
            return elsewhere;
        }
        if (notWithOpenList && statePresent()) {
            release(id);
            return I18n.tr("server.turn.openList", java.util.Map.of("file", String.valueOf(list)));
        }
        return null;
    }

    /** Rilascia il turno, ma solo se e' di 'id': un lavoro non puo' liberare quello di un altro. */
    public static void release(String id) {
        Turn t = IN_PROGRESS.get();
        if (t != null && t.id().equals(id)) {
            // Prima il blocco fra processi, poi il turno in memoria: al contrario, un altro
            // thread di questo processo prenderebbe il turno e chiederebbe un blocco che questa
            // JVM tiene ancora.
            unlockAcrossProcesses();
            IN_PROGRESS.compareAndSet(t, null);
        }
    }

    /**
     * Prende il blocco del file del turno, senza aspettare. null se l'ha preso (e ci ha scritto
     * chi e'); altrimenti il motivo per cui il lavoro non puo' partire: il turno e' di un altro
     * processo, e il messaggio dice di chi; o il file non si apre, e allora non si parte, perche'
     * senza quel blocco due processi potrebbero sbloccare insieme.
     */
    private static synchronized String lockAcrossProcesses(Turn t) {
        // Non deve succedere (il turno in memoria e' appena stato preso): ma aprire e chiudere
        // un secondo canale toglierebbe il blocco a chi lo tiene, quindi non si apre niente.
        if (turnChannel != null) return busy(t.description());
        Path f = turnFile();
        FileChannel c = null;
        try {
            c = FileChannel.open(f, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
            FileLock l = c.tryLock();
            if (l == null) {
                String who = readHolder(c);
                c.close();
                return I18n.tr("server.turn.otherProcess", java.util.Map.of("who",
                        who.isEmpty() ? I18n.tr("server.turn.otherProcessUnknown") : who));
            }
            String me = "pid " + ProcessHandle.current().pid() + ": " + t.description() + " (since "
                    + java.time.Instant.ofEpochMilli(t.start()).truncatedTo(java.time.temporal.ChronoUnit.SECONDS) + " UTC)\n";
            c.truncate(0);
            ByteBuffer b = ByteBuffer.wrap(me.getBytes(StandardCharsets.UTF_8));
            long at = 0;
            while (b.hasRemaining()) at += c.write(b, at);
            c.force(false);
            turnChannel = c;
            turnLock = l;
            return null;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot lock " + f, e);
            if (c != null) {
                try { c.close(); } catch (Exception x) { LOGGER.log(Level.FINE, "close " + f, x); }
            }
            return I18n.tr("server.turn.cannotLock", java.util.Map.of("file", String.valueOf(f), "err", String.valueOf(e)));
        }
    }

    /** Chi tiene il turno in un altro processo, da quello che ha scritto nel file ("" se niente). */
    private static String readHolder(FileChannel c) {
        try {
            ByteBuffer b = ByteBuffer.allocate(512);
            int n = c.read(b, 0);
            if (n <= 0) return "";
            String s = new String(b.array(), 0, n, StandardCharsets.UTF_8).trim();
            // Lo ha scritto il pannello, ma finisce in un messaggio: niente a capo, niente controllo.
            return s.replaceAll("[\\p{Cntrl}]+", " ");
        } catch (Exception e) {
            return "";
        }
    }

    /** Toglie il blocco del turno fra processi, se lo tiene questo processo, e svuota il file. */
    private static synchronized void unlockAcrossProcesses() {
        if (turnChannel == null) return;
        try { turnChannel.truncate(0); }
        catch (Exception e) { LOGGER.log(Level.FINE, "Cannot empty " + turnFile(), e); }
        try { turnLock.release(); }
        catch (Exception e) { LOGGER.log(Level.WARNING, "Cannot release the lock on " + turnFile(), e); }
        try { turnChannel.close(); }
        catch (Exception e) { LOGGER.log(Level.WARNING, "Cannot close " + turnFile(), e); }
        turnChannel = null;
        turnLock = null;
    }

    /** Chi tiene il turno adesso ("manutenzione, in corso da 3 minuti"), o null se e' libero. */
    public static String holder() {
        Turn t = IN_PROGRESS.get();
        if (t == null) return null;
        long min = (System.currentTimeMillis() - t.start()) / 60000;
        return t.description() + ", " + (min < 1 ? I18n.tr("server.turn.justStarted")
                : min == 1 ? I18n.tr("server.turn.running.one")
                : I18n.tr("server.turn.running.other", java.util.Map.of("n", String.valueOf(min))));
    }

    /**
     * Mentre un lavoro cambia i pacchetti, un piano calcolato adesso vedrebbe protezioni tolte e
     * versioni che stanno cambiando: null se si puo' calcolare, altrimenti il motivo.
     */
    public static String planNotNow() {
        String holder = holder();
        return holder == null ? null
             : I18n.tr("server.turn.busyPlan", java.util.Map.of("who", String.valueOf(holder)));
    }

    /** Il messaggio per chi trova il turno preso. */
    static String busy(String holder) {
        return I18n.tr("server.turn.busy", java.util.Map.of("who", String.valueOf(holder)));
    }

    /**
     * Avvia in un thread il lavoro che ha GIA' preso il turno 'id', e rilascia il turno quando il
     * lavoro finisce, anche con un errore. Se il thread non parte, lo rilascia subito.
     */
    public static void start(String id, String name, Runnable work) {
        try {
            // La lingua di chi ha chiesto il lavoro segue il lavoro nel suo thread (messaggi e log)
            Thread t = new Thread(I18n.withCurrent(() -> {
                try { work.run(); }
                finally { release(id); }
            }), name);
            t.setDaemon(true);   // come prima: un lavoro non tiene acceso un pannello che si sta spegnendo
            t.start();
        } catch (RuntimeException | Error e) {
            release(id);
            throw e;
        }
    }

    /**
     * Scrive su disco l'elenco dei pacchetti che si stanno per sbloccare, PRIMA di sbloccarli, e
     * dice se ci e' riuscito: null se l'elenco e' scritto e forzato su disco, altrimenti il motivo.
     * Se non e' null, chi chiama NON deve sbloccare niente.
     *
     * Prima un errore di scrittura (disco pieno, /var/db non scrivibile) finiva in un avviso e il
     * lavoro sbloccava lo stesso: se poi il processo moriva, l'avvio non aveva nessun elenco da cui
     * riproteggere. Il file si crea solo se non esiste (CREATE_NEW, atomico): se esiste, e'
     * l'elenco di un lavoro interrotto che l'avvio non e' riuscito a chiudere, e sovrascriverlo
     * perderebbe proprio i pacchetti da riproteggere.
     */
    public static String writeState(List<String> packages) {
        return writeState(list, packages);
    }

    static String writeState(Path f, List<String> packages) {
        boolean created = false;
        try (FileChannel c = FileChannel.open(f, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            created = true;
            ByteBuffer b = ByteBuffer.wrap((String.join("\n", packages) + "\n").getBytes(StandardCharsets.US_ASCII));
            while (b.hasRemaining()) c.write(b);
            c.force(true);
            return null;
        } catch (FileAlreadyExistsException e) {
            return I18n.tr("server.turn.listExists", java.util.Map.of("file", String.valueOf(f)));
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot write " + f, e);
            // Un elenco scritto a meta' non deve restare: l'avvio lo leggerebbe come vero.
            if (created) {
                try { Files.deleteIfExists(f); }
                catch (Exception x) { LOGGER.log(Level.WARNING, "Cannot remove " + f, x); }
            }
            return I18n.tr("server.turn.cannotWrite", java.util.Map.of("file", String.valueOf(f), "err", String.valueOf(e)));
        }
    }

    /** Cancella l'elenco. Lo fa solo il lavoro che l'ha scritto, dopo aver riprotetto tutto. */
    public static void deleteState() {
        try { Files.deleteIfExists(list); }
        catch (Exception e) { LOGGER.log(Level.WARNING, "Cannot remove " + list, e); }
    }

    /** Se c'e' un elenco di un lavoro non concluso. */
    public static boolean statePresent() {
        return Files.exists(list);
    }
}
