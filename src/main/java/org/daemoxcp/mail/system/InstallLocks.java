package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * L'installazione completa su un server dove il pannello e' gia' partito: i pacchetti protetti
 * si sbloccano prima, con l'elenco salvato, e si riproteggono alla fine, anche se fallisce.
 *
 * Perche' esiste: misurato il 05/11/2026 sulla VM FreeBSD 15.1 (reperto 126). All'avvio il
 * pannello protegge con pkg lock i pacchetti dello stack di posta (39 su quella macchina,
 * UpdateManager.applyLockPolicy). La reinstallazione dal menu lanciava lo script senza
 * toccarli: la fase 1 fermava dovecot, rspamd, clamav, redis, nginx e php-fpm e cancellava le
 * loro configurazioni, la fase 2 si fermava su «mysql84-server-8.4.11_4 is locked and may not be
 * modified», lo script usciva 1 e la posta restava spenta (dovecot e nginx non ripartivano
 * nemmeno a mano, senza configurazione). Rilanciata dopo pkg unlock -a -y, riusciva.
 *
 * Lo sblocco segue le regole dei lavori sui pacchetti (PackageQueue): il turno prima di tutto,
 * anche contro un altro processo del pannello; l'elenco su disco PRIMA di sbloccare, cosi' se il
 * processo muore a meta' il prossimo avvio riprotegge; e se qualcosa non va prima dello script
 * si rimette tutto com'era e non si ferma niente. Si sbloccano TUTTI i pacchetti protetti, non
 * solo quelli dello stack: pkg install puo' dover aggiornare anche una dipendenza, e una
 * dipendenza bloccata ferma la fase 2 nello stesso modo. Alla fine si riprotegge esattamente
 * quell'elenco, cioe' lo stato di prima, comprese le protezioni messe a mano.
 */
public final class InstallLocks {

    private static final Logger LOGGER = Logger.getLogger(InstallLocks.class.getName());

    private InstallLocks() {}

    /** Il prefisso del turno della reinstallazione completa, scritto nel record del lavoro (turnId). */
    public static final String REINSTALL_TURN_PREFIX = "reinstall-";

    /** I comandi di pkg che servono qui. Nelle prove un finto, per i guasti che pkg vero non da'. */
    interface Pkg {
        /** I pacchetti protetti, un nome-versione per riga ("" se nessuno), o null se pkg non risponde. */
        String lockList();
        boolean unlock(String name);
        boolean lock(String name);
        boolean installed(String name);
    }

    /**
     * La lettura dei protetti e' "pkg query -e '%k = 1' '%n-%v'", non "pkg lock -l -q".
     * Misurato sulla VM il 05/11/2026 (pkg 2.8.4, su una copia del database): quando non c'e'
     * nessun pacchetto protetto, "pkg lock -l -q" esce con 1 e non scrive niente, cioe' come un
     * errore; la query esce 0 con l'elenco o vuota, e 1 solo col database rotto. Con lock -l, su
     * un server senza protezioni (un'installazione da zero) la reinstallazione si sarebbe
     * rifiutata dicendo che pkg non risponde.
     */
    static Pkg real() {
        return new Pkg() {
            public String lockList() {
                Shell.Result r = Shell.run(Duration.ofSeconds(60), "pkg", "query", "-e", "%k = 1", "%n-%v");
                return r.success() ? r.outputTrim() : null;
            }
            public boolean unlock(String name) { return valid(name) && Shell.run(Duration.ofSeconds(30), "pkg", "unlock", "-y", name).success(); }
            public boolean lock(String name) { return valid(name) && Shell.run(Duration.ofSeconds(30), "pkg", "lock", "-y", name).success(); }
            public boolean installed(String name) { return valid(name) && Shell.run(Duration.ofSeconds(15), "pkg", "info", "-e", name).success(); }
            private boolean valid(String name) { return UpdateManager.isValidName(name); }
        };
    }

    /**
     * Il turno preso e i pacchetti sbloccati. Si chiude con {@link #finish}, sempre: e' li' che
     * si riprotegge e si rilascia il turno.
     */
    public static final class Held {
        final String turnId;
        final List<String> unlocked;
        private boolean finished;

        Held(String turnId, List<String> unlocked) {
            this.turnId = turnId;
            this.unlocked = List.copyOf(unlocked);
        }

        /** I pacchetti sbloccati, da riproteggere alla fine. */
        public List<String> unlocked() { return unlocked; }
    }

    /**
     * L'esito della preparazione: o il turno preso ({@code held} non null, e {@code report} dice
     * che cosa e' stato sbloccato), o il rifiuto ({@code refusal} non null): in quel caso non e'
     * stato cambiato niente, o e' stato rimesso com'era, e lo script non deve partire.
     */
    public record Start(Held held, String refusal, String report) {}

    /** Prende il turno e sblocca i pacchetti protetti, prima che lo script fermi qualcosa. */
    public static Start prepare(String description) {
        return prepare(description, real(), () -> null);
    }

    /**
     * Come {@link #prepare(String)}, con un passo in mezzo: {@code onTurn} gira col turno gia' preso
     * e PRIMA di qualunque sblocco. E' il posto della via di ritorno (PackageWayBack): un boot
     * environment fatto qui ha i pacchetti protetti com'erano e nessun elenco di sblocchi aperto,
     * quindi ripartire da li' e' ripartire dal server di prima. Se {@code onTurn} restituisce un
     * motivo, non si sblocca niente, il turno si rilascia e il motivo e' il rifiuto.
     */
    public static Start prepare(String description, java.util.function.Supplier<String> onTurn) {
        return prepare(description, real(), onTurn);
    }

    static Start prepare(String description, Pkg pkg) {
        return prepare(description, pkg, () -> null);
    }

    static Start prepare(String description, Pkg pkg, java.util.function.Supplier<String> onTurn) {
        // "reinstall-": lo riconosce l'avviso di un lavoro interrotto (PackageRecovery), che per la
        // reinstallazione dice anche che la posta puo' essere spenta e dov'e' la via di ritorno.
        // "install-" lo usa gia' l'installazione di un pacchetto dalla pagina web.
        String id = REINSTALL_TURN_PREFIX + System.nanoTime();
        // take, non takeForLocks: con l'elenco di un lavoro interrotto su disco i pacchetti
        // potrebbero essere gia' sbloccati, e un elenco nuovo non si potrebbe nemmeno scrivere.
        String refusal = PackageQueue.take(id, description);
        if (refusal != null) return new Start(null, refusal, "");
        String notNow;
        try {
            notNow = onTurn.get();
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "The step before the unlock failed", e);
            notNow = String.valueOf(e.getMessage());
        }
        if (notNow != null) {
            PackageQueue.release(id);
            return new Start(null, notNow, "");
        }
        boolean listWritten = false;
        List<String> locked = List.of();
        try {
            String before = pkg.lockList();
            if (before == null) {
                PackageQueue.release(id);
                return new Start(null, I18n.tr("server.reinstall.cannotRead"), "");
            }
            locked = new ArrayList<>(UpdateManager.lockedNames(before));
            if (locked.isEmpty()) return new Start(new Held(id, locked), null, I18n.tr("server.reinstall.noLocks"));

            // Prima l'elenco su disco, poi lo sblocco: se l'elenco non si scrive, non si sblocca.
            String stateError = PackageQueue.writeState(locked);
            if (stateError != null) {
                PackageQueue.release(id);
                return new Start(null, I18n.tr("server.reinstall.noList", java.util.Map.of("err", stateError)), "");
            }
            listWritten = true;
            for (String n : locked) pkg.unlock(n);

            // L'uscita di pkg unlock non basta: si rilegge. Un pacchetto rimasto protetto
            // fermerebbe la fase 2 a servizi gia' spenti, cioe' proprio il difetto da evitare.
            String after = pkg.lockList();
            Set<String> still = after == null ? new TreeSet<>(locked) : stillAmong(locked, after);
            if (!still.isEmpty()) {
                String back = relock(locked, pkg);
                PackageQueue.release(id);
                return new Start(null, I18n.tr("server.reinstall.unlockFailed", java.util.Map.of(
                        "list", String.join(", ", still), "back", back)), "");
            }
            return new Start(new Held(id, locked), null, I18n.tr("server.reinstall.unlocked", java.util.Map.of(
                    "n", String.valueOf(locked.size()), "file", String.valueOf(PackageQueue.list))));
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Preparing the installation failed", e);
            String back = "";
            try { if (listWritten) back = " " + relock(locked, pkg); }
            catch (RuntimeException x) { LOGGER.log(Level.WARNING, "Locking the packages again failed", x); }
            finally { PackageQueue.release(id); }
            return new Start(null, I18n.tr("server.reinstall.noList", java.util.Map.of("err", String.valueOf(e))) + back, "");
        }
    }

    /**
     * Riprotegge i pacchetti sbloccati da {@link #prepare}, rimette in pari la traccia dei blocchi
     * (la nota e le annotazioni: reinstallare un pacchetto gli cancella l'annotazione) e rilascia
     * il turno. Da chiamare in un finally. Non lancia: restituisce cosa e' successo.
     */
    public static String finish(Held held) {
        return finish(held, real(), true);
    }

    static String finish(Held held, Pkg pkg, boolean refreshTrace) {
        if (held == null || held.finished) return "";
        held.finished = true;
        try {
            return held.unlocked.isEmpty() ? "" : relock(held.unlocked, pkg);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Locking the packages again failed", e);
            return I18n.tr("server.reinstall.relockUnknown", java.util.Map.of("file", String.valueOf(PackageQueue.list)));
        } finally {
            if (refreshTrace) UpdateManager.refreshLockTrace();
            PackageQueue.release(held.turnId);
        }
    }

    /**
     * Riprotegge 'names', poi rilegge le protezioni e chiude l'elenco su disco solo se ogni
     * pacchetto ancora installato e' di nuovo protetto. Uno che l'installazione ha tolto non si
     * puo' proteggere, e non tiene aperto l'elenco: lo stesso criterio del ripristino all'avvio.
     */
    static String relock(List<String> names, Pkg pkg) {
        List<String> gone = new ArrayList<>(), kept = new ArrayList<>();
        for (String n : names) {
            if (!pkg.installed(n)) { gone.add(n); continue; }
            kept.add(n);
            pkg.lock(n);
        }
        String after = pkg.lockList();
        if (after == null)
            return I18n.tr("server.reinstall.relockUnknown", java.util.Map.of("file", String.valueOf(PackageQueue.list)));
        Set<String> nowLocked = UpdateManager.lockedNames(after);
        List<String> notLocked = new ArrayList<>();
        for (String n : kept) if (!nowLocked.contains(n)) notLocked.add(n);
        if (!notLocked.isEmpty())
            return I18n.tr("server.reinstall.relockFailed", java.util.Map.of(
                    "list", String.join(", ", notLocked), "file", String.valueOf(PackageQueue.list)));
        PackageQueue.deleteState();
        return gone.isEmpty()
                ? I18n.tr("server.reinstall.relocked", java.util.Map.of("n", String.valueOf(kept.size())))
                : I18n.tr("server.reinstall.relockedGone", java.util.Map.of(
                        "n", String.valueOf(kept.size()), "list", String.join(", ", gone)));
    }

    /** Quali di 'names' risultano ancora protetti nell'elenco dei protetti. */
    private static Set<String> stillAmong(List<String> names, String lockOutput) {
        Set<String> now = UpdateManager.lockedNames(lockOutput), r = new TreeSet<>();
        for (String n : names) if (now.contains(n)) r.add(n);
        return r;
    }
}
