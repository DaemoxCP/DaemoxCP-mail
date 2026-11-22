package org.daemoxcp.mail.system;

import java.nio.ByteBuffer;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
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
 * Il turno vale fra PROCESSI, non solo dentro questo. Fino al 06/11/2026 era un AtomicReference:
 * misurato sulla VM, un secondo processo Java lo prendeva mentre il primo lo teneva, e ogni avvio
 * del jar (anche il menu da console aperto mentre il pannello web aggiorna) riproteggeva i
 * pacchetti di un lavoro in corso e ne cancellava l'elenco, facendo fallire il suo pkg upgrade
 * («is locked and may not be modified»). Adesso chi prende il turno tiene anche un lock fcntl su
 * TURN_LOCK_PATH: il sistema lo toglie da solo quando il processo muore, quindi un lavoro
 * interrotto non lascia il turno preso per sempre.
 */
public final class PackageQueue {

    private static final Logger LOGGER = Logger.getLogger(PackageQueue.class.getName());

    private PackageQueue() {}

    /**
     * L'elenco dei pacchetti che un lavoro in corso ha sbloccato. Il finally di un lavoro non gira
     * se il processo muore (riavvio del pannello, kill, crash della JVM): questo file e' l'unica
     * cosa che sopravvive, e all'avvio il pannello riprotegge cio' che c'e' scritto.
     */
    public static final String STATE_PATH = "/var/db/daemoxcp-mail-maintenance-locks";

    /** Dove sta l'elenco. E' una variabile solo perche' le prove non scrivano in /var/db. */
    static Path list = Path.of(STATE_PATH);

    private record Turn(String id, String description, long start) {}

    private static final AtomicReference<Turn> IN_PROGRESS = new AtomicReference<>();

    /** Il lock del turno fra processi. Dentro c'e' scritto chi lo tiene, per dirlo a chi lo trova preso. */
    public static final String TURN_LOCK_PATH = "/var/db/daemoxcp-mail/package-turn.lock";

    /** Dove sta il lock. E' una variabile solo perche' le prove non scrivano in /var/db. */
    static Path turnLock = Path.of(TURN_LOCK_PATH);

    /**
     * Il lavoro che tiene il turno, scritto su disco quando lo prende e tolto quando lo rilascia: chi e',
     * quando e' partito, da quale processo, e com'erano pacchetti e servizi all'inizio. Se il processo muore
     * a meta' resta, ed e' da qui che il pannello in servizio capisce che cosa il lavoro ha cambiato e lo
     * completa (InterruptedJobRecovery): anche un lavoro che non aveva sbloccato niente, e che quindi non
     * lasciava l'elenco. Sta accanto al lock del turno, cosi' le prove che spostano il lock spostano anche lui.
     */
    static Path running() {
        return turnLock.resolveSibling("package-job-running.json");
    }

    /**
     * Com'erano pacchetti e servizi all'inizio di un lavoro ({"inventory": {nome: versione}, "services": {nome:
     * acceso}}): lo fornisce UpdateManager, che sa chiederlo al sistema. Vuoto finche' nessuno lo imposta.
     */
    static volatile java.util.function.Supplier<JSONObject> snapshot = JSONObject::new;

    /**
     * Il canale e il lock di chi tiene il turno in QUESTO processo. Si toccano solo da chi tiene
     * IN_PROGRESS: un secondo canale aperto e chiuso sullo stesso file, nello stesso processo,
     * toglierebbe il lock fcntl (e' la regola di POSIX, la ricorda anche la documentazione di
     * FileChannel), quindi qui se ne apre uno solo per volta.
     */
    private static FileChannel lockChannel;
    private static FileLock fileLock;

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
        // Poi il turno fra processi: un altro pannello (o un menu da console) puo' tenerlo.
        String other = takeFileLock(fresh);
        if (other != null) {
            IN_PROGRESS.compareAndSet(fresh, null);
            return other;
        }
        if (notWithOpenList && statePresent()) {
            release(id);
            // L'elenco dell'aggiornamento della Java c'e' per disegno finche' lo script lavora: non e' un lavoro che non
            // e' finito, e riavviare il pannello sarebbe il consiglio sbagliato (reperto 210).
            if (jobRecord().optBoolean("expectsRestart")) return I18n.tr("server.turn.javaRunning");
            return I18n.tr("server.turn.openList", java.util.Map.of("file", String.valueOf(list)));
        }
        // Un lavoro vero (non il ripristino delle protezioni) lascia la sua traccia finche' tiene il turno.
        if (notWithOpenList) writeRunning(fresh);
        return null;
    }

    private static void writeRunning(Turn t) {
        JSONObject r = new JSONObject()
                .put("id", t.id())
                .put("description", t.description())
                .put("startedUtc", java.time.Instant.ofEpochMilli(t.start()).truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
                .put("startedEpoch", t.start() / 1000)
                .put("pid", ProcessHandle.current().pid())
                .put("expectsRestart", false);
        try {
            JSONObject snap = snapshot.get();
            if (snap != null) for (String k : snap.keySet()) r.put(k, snap.get(k));
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Cannot take the snapshot of packages and services for " + t.id(), e);
        }
        writeJson(running(), r);
    }

    private static void writeJson(Path f, JSONObject r) {
        try {
            Files.createDirectories(f.getParent());
            Path tmp = f.resolveSibling(f.getFileName() + ".tmp");
            Files.writeString(tmp, r.toString(2) + "\n", StandardCharsets.UTF_8);
            Files.move(tmp, f, java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot write " + f, e);
        }
    }

    /**
     * Chi tiene il turno, per il registro: l'id del lavoro e il pid, in inglese per tutti. La descrizione resta fuori:
     * e' nella lingua del pannello e serve a chi legge la pagina, e i registri sono in inglese (EnglishLogsTest; visto
     * sulla VM il 22/11/2026, «aggiornamento di …» nel registro di un pannello in italiano).
     */
    public static String holderForLog() {
        Turn t = IN_PROGRESS.get();
        if (t != null) return "job " + t.id() + " in this process";
        JSONObject r = runningRecord();
        if (!r.optString("id", "").isEmpty()) return "job " + r.optString("id") + ", pid " + r.optLong("pid", 0);
        try {
            // Il lock comincia con «pid N, »: quello si', il resto e' la descrizione.
            String who = new String(Files.readAllBytes(turnLock), StandardCharsets.UTF_8).trim();
            int comma = who.indexOf(',');
            if (who.startsWith("pid ") && comma > 4) return "another panel process, " + who.substring(0, comma);
        } catch (Exception ignored) {
            // Senza il file si dice solo che e' un altro processo.
        }
        return "another panel process";
    }

    /** La traccia del lavoro che tiene (o teneva) il turno, o un oggetto vuoto se non c'e'. */
    public static JSONObject runningRecord() {
        try { return new JSONObject(Files.readString(running())); }
        catch (Exception e) { return new JSONObject(); }
    }

    /** Toglie la traccia: chi ha completato un lavoro interrotto, o il lavoro stesso quando rilascia il turno. */
    static void deleteRunning() {
        try { Files.deleteIfExists(running()); }
        catch (Exception e) { LOGGER.log(Level.WARNING, "Cannot remove " + running(), e); }
    }

    /**
     * Il lock fra processi, per il turno appena preso in questo processo. null se preso; altrimenti
     * il messaggio per chi lo trova preso (o per chi non puo' nemmeno aprire il file: senza il
     * lock non si parte, perche' un turno che non vale fra processi e' quello che si e' rotto).
     */
    private static String takeFileLock(Turn t) {
        FileChannel c = null;
        try {
            Files.createDirectories(turnLock.getParent());
            c = FileChannel.open(turnLock, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
            FileLock l;
            try { l = c.tryLock(); }
            catch (OverlappingFileLockException e) { l = null; }   // non succede: c'e' IN_PROGRESS davanti
            if (l == null) {
                String who = new String(Files.readAllBytes(turnLock), StandardCharsets.UTF_8).trim();
                c.close();
                return busy(I18n.tr("server.turn.otherProcess", java.util.Map.of("who", who.isEmpty() ? "?" : who)));
            }
            String who = "pid " + ProcessHandle.current().pid() + ", " + t.description()
                    + " (" + java.time.Instant.ofEpochMilli(t.start()).truncatedTo(java.time.temporal.ChronoUnit.SECONDS) + ")";
            c.truncate(0);
            c.write(ByteBuffer.wrap((who + "\n").getBytes(StandardCharsets.UTF_8)), 0);
            lockChannel = c;
            fileLock = l;
            return null;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot take the package turn lock " + turnLock, e);
            if (c != null) try { c.close(); } catch (Exception ignored) { }
            return I18n.tr("server.turn.lockFileError", java.util.Map.of("file", String.valueOf(turnLock), "err", org.daemoxcp.mail.util.ErrorText.detail("PackageQueue", e)));
        }
    }

    /** Rilascia il turno, ma solo se e' di 'id': un lavoro non puo' liberare quello di un altro. */
    public static void release(String id) {
        Turn t = IN_PROGRESS.get();
        if (t == null || !t.id().equals(id)) return;
        // Il lavoro e' finito (bene o male, ma dentro il suo finally): la sua traccia non serve piu'.
        if (id.equals(runningRecord().optString("id"))) deleteRunning();
        // Prima il lock fra processi, poi il turno di questo processo: al contrario, un altro
        // thread potrebbe prendere il turno e trovare il file ancora bloccato da noi.
        try {
            if (fileLock != null) fileLock.release();
            if (lockChannel != null) lockChannel.close();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot release the package turn lock " + turnLock, e);
        } finally {
            fileLock = null;
            lockChannel = null;
        }
        IN_PROGRESS.compareAndSet(t, null);
    }

    /** L'id del lavoro che tiene il turno adesso, o null se e' libero (reperto 206: la pagina lo segue). */
    public static String holderId() {
        Turn t = IN_PROGRESS.get();
        return t == null ? null : t.id();
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
        String error = writeState(list, packages);
        if (error == null) writeJobRecord(packages, false);
        return error;
    }

    /**
     * Come writeState, per un lavoro che passa i pacchetti a uno script fuori dal pannello e si
     * aspetta di essere riavviato da lui (l'aggiornamento della JVM): al riavvio l'elenco c'e' per
     * disegno, e non va scambiato per un lavoro interrotto.
     */
    public static String writeStateForRestart(List<String> packages) {
        String error = writeState(list, packages);
        if (error == null) {
            writeJobRecord(packages, true);
            // Anche la traccia del turno: al riavvio voluto il processo e' morto per disegno, non interrotto.
            JSONObject r = runningRecord();
            if (!r.isEmpty()) writeJson(running(), r.put("expectsRestart", true));
        }
        return error;
    }

    /** Accanto all'elenco: quale lavoro l'ha scritto, quando, e da quale processo. */
    static Path jobRecordPath() {
        return list.resolveSibling(list.getFileName() + ".job.json");
    }

    /**
     * Chi ha scritto l'elenco, per dire all'avvio QUALE lavoro si e' interrotto. Se non si scrive
     * non si ferma niente: l'elenco basta a riproteggere, questo serve solo a spiegare.
     */
    private static void writeJobRecord(List<String> packages, boolean expectsRestart) {
        Turn t = IN_PROGRESS.get();
        JSONObject r = new JSONObject()
                .put("description", t == null ? "" : t.description())
                .put("turnId", t == null ? "" : t.id())
                .put("startedUtc", java.time.Instant.ofEpochMilli(t == null ? System.currentTimeMillis() : t.start())
                        .truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
                .put("pid", ProcessHandle.current().pid())
                .put("expectsRestart", expectsRestart)
                .put("packages", new JSONArray(packages));
        try {
            Path tmp = jobRecordPath().resolveSibling(jobRecordPath().getFileName() + ".tmp");
            Files.writeString(tmp, r.toString(2) + "\n", StandardCharsets.UTF_8);
            Files.move(tmp, jobRecordPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot write " + jobRecordPath(), e);
        }
    }

    /** Il lavoro che ha scritto l'elenco, o un oggetto vuoto se non si sa (elenco di un pannello di prima). */
    public static JSONObject jobRecord() {
        try { return new JSONObject(Files.readString(jobRecordPath())); }
        catch (Exception e) { return new JSONObject(); }
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
        try { Files.deleteIfExists(jobRecordPath()); }
        catch (Exception e) { LOGGER.log(Level.WARNING, "Cannot remove " + jobRecordPath(), e); }
    }

    /** Se c'e' un elenco di un lavoro non concluso. */
    public static boolean statePresent() {
        return Files.exists(list);
    }
}
