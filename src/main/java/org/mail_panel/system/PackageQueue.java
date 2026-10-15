package org.mail_panel.system;

import java.nio.ByteBuffer;
import org.mail_panel.i18n.I18n;
import java.nio.channels.FileChannel;
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

    private record Turno(String id, String descrizione, long inizio) {}

    private static final AtomicReference<Turno> IN_CORSO = new AtomicReference<>();

    /**
     * Prende il turno per il lavoro 'id'. null se l'ha preso; altrimenti il motivo per cui il
     * lavoro non puo' partire, da mostrare cosi' com'e'.
     *
     * Non lo prende nemmeno se su disco c'e' l'elenco di un lavoro che non si e' chiuso: quei
     * pacchetti potrebbero essere ancora sbloccati, e un "pkg upgrade" o un "pkg install" li
     * cambierebbe come se niente fosse.
     */
    public static String prendi(String id, String descrizione) {
        return prendi(id, descrizione, true);
    }

    /**
     * Come prendi, ma anche con l'elenco di un lavoro interrotto su disco. Solo per rimettere o
     * togliere protezioni: rimetterle e' proprio il rimedio a quell'elenco.
     */
    public static String prendiPerLeProtezioni(String id, String descrizione) {
        return prendi(id, descrizione, false);
    }

    private static String prendi(String id, String descrizione, boolean nonConElencoAperto) {
        Turno nuovo = new Turno(id, descrizione, System.currentTimeMillis());
        while (!IN_CORSO.compareAndSet(null, nuovo)) {
            String chi = chi();
            if (chi != null) return occupato(chi);
            // Rilasciato fra i due passi: si riprova.
        }
        if (nonConElencoAperto && statoPresente()) {
            rilascia(id);
            return I18n.tr("server.turn.openList", java.util.Map.of("file", String.valueOf(list)));
        }
        return null;
    }

    /** Rilascia il turno, ma solo se e' di 'id': un lavoro non puo' liberare quello di un altro. */
    public static void rilascia(String id) {
        Turno t = IN_CORSO.get();
        if (t != null && t.id().equals(id)) IN_CORSO.compareAndSet(t, null);
    }

    /** Chi tiene il turno adesso ("manutenzione, in corso da 3 minuti"), o null se e' libero. */
    public static String chi() {
        Turno t = IN_CORSO.get();
        if (t == null) return null;
        long min = (System.currentTimeMillis() - t.inizio()) / 60000;
        return t.descrizione() + ", " + (min < 1 ? I18n.tr("server.turn.justStarted")
                : min == 1 ? I18n.tr("server.turn.running.one")
                : I18n.tr("server.turn.running.other", java.util.Map.of("n", String.valueOf(min))));
    }

    /**
     * Mentre un lavoro cambia i pacchetti, un piano calcolato adesso vedrebbe protezioni tolte e
     * versioni che stanno cambiando: null se si puo' calcolare, altrimenti il motivo.
     */
    public static String pianoNonAdesso() {
        String chi = chi();
        return chi == null ? null
             : I18n.tr("server.turn.busyPlan", java.util.Map.of("who", String.valueOf(chi)));
    }

    /** Il messaggio per chi trova il turno preso. */
    static String occupato(String chi) {
        return I18n.tr("server.turn.busy", java.util.Map.of("who", String.valueOf(chi)));
    }

    /**
     * Avvia in un thread il lavoro che ha GIA' preso il turno 'id', e rilascia il turno quando il
     * lavoro finisce, anche con un errore. Se il thread non parte, lo rilascia subito.
     */
    public static void avvia(String id, String nome, Runnable lavoro) {
        try {
            // La lingua di chi ha chiesto il lavoro segue il lavoro nel suo thread (messaggi e log)
            Thread t = new Thread(I18n.withCurrent(() -> {
                try { lavoro.run(); }
                finally { rilascia(id); }
            }), nome);
            t.setDaemon(true);   // come prima: un lavoro non tiene acceso un pannello che si sta spegnendo
            t.start();
        } catch (RuntimeException | Error e) {
            rilascia(id);
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
    public static String scriviStato(List<String> pacchetti) {
        return scriviStato(list, pacchetti);
    }

    static String scriviStato(Path f, List<String> pacchetti) {
        boolean creato = false;
        try (FileChannel c = FileChannel.open(f, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            creato = true;
            ByteBuffer b = ByteBuffer.wrap((String.join("\n", pacchetti) + "\n").getBytes(StandardCharsets.US_ASCII));
            while (b.hasRemaining()) c.write(b);
            c.force(true);
            return null;
        } catch (FileAlreadyExistsException e) {
            return I18n.tr("server.turn.listExists", java.util.Map.of("file", String.valueOf(f)));
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot write " + f, e);
            // Un elenco scritto a meta' non deve restare: l'avvio lo leggerebbe come vero.
            if (creato) {
                try { Files.deleteIfExists(f); }
                catch (Exception x) { LOGGER.log(Level.WARNING, "Cannot remove " + f, x); }
            }
            return I18n.tr("server.turn.cannotWrite", java.util.Map.of("file", String.valueOf(f), "err", String.valueOf(e)));
        }
    }

    /** Cancella l'elenco. Lo fa solo il lavoro che l'ha scritto, dopo aver riprotetto tutto. */
    public static void cancellaStato() {
        try { Files.deleteIfExists(list); }
        catch (Exception e) { LOGGER.log(Level.WARNING, "Cannot remove " + list, e); }
    }

    /** Se c'e' un elenco di un lavoro non concluso. */
    public static boolean statoPresente() {
        return Files.exists(list);
    }
}
