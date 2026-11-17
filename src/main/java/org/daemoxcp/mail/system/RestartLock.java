package org.daemoxcp.mail.system;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.daemoxcp.mail.util.Shell;

/**
 * Il riavvio programmato: fino a quando la macchina non riparte il pannello non cambia niente.
 *
 * <p>Il committente, il 09/11/2026, programmando il riavvio del server vero: «quando metto lo schedule per il
 * riavvio, non devi farmi fare niente nel pannello finche' non si riavvia, sennò potrebbero succedere cose
 * spiacevoli». Un lavoro avviato un minuto prima dello spegnimento resta a meta' (un pkg che sostituisce le
 * librerie, un file di configurazione riscritto senza il reload), e nessuno lo vede fino al riavvio dopo.
 *
 * <p>Come: ogni richiesta che puo' cambiare qualcosa ({@code Access.changes}) viene rifiutata finche' esiste il
 * processo {@code shutdown} (programmato dal pannello o da SSH: lo stesso processo). Restano le letture, annullare il
 * riavvio, riavviare subito e lo stato del riavvio ({@link #exempt}). Lo sa solo la root: la parte web non vede i
 * processi degli altri utenti ({@code security.bsd.see_other_uids=0}) e lo chiede alla root.
 *
 * <p>L'ora: quella scritta dal pannello quando lo programma ({@link #AT}, valida solo se il processo e' lo stesso), o
 * ricavata dal comando ({@code shutdown -r +N}: avviato da tanti secondi, piu' N minuti). Per gli altri formati si
 * sa che c'e', non quando.
 */
public final class RestartLock {

    private RestartLock() {}

    private static final Logger LOGGER = Logger.getLogger(RestartLock.class.getName());

    /** Dove il pannello scrive il processo e l'ora del riavvio che programma: "pid millisecondi". */
    static Path AT = Path.of("/var/db/mailpanel/reboot-at");

    /** Lo stato. known falso: non si e' potuto leggere (pgrep non ha risposto). at 0: l'ora non si sa. */
    public record State(boolean scheduled, long at, boolean known) {
        public static final State NONE = new State(false, 0, true);
        public static final State UNKNOWN = new State(false, 0, false);
    }

    /** Quello che resta possibile col riavvio programmato, per rotta: annullarlo, riavviare subito, il suo stato. */
    private static final Map<String, Set<String>> EXEMPT = Map.of(
            "/api/updates", Set.of("reboot_cancel", "reboot_now", "reboot_state"));

    public static boolean exempt(String route, String action) {
        // Map.of non accetta null nemmeno in lettura: senza rotta o senza azione non c'e' eccezione che tenga.
        if (route == null || action == null) return false;
        Set<String> s = EXEMPT.get(route);
        return s != null && s.contains(action);
    }

    private static volatile State cached;
    private static volatile long cachedAt;
    /** Pochi secondi: una pagina che salva tre cose di fila non lancia tre pgrep. */
    private static final long TTL_MS = 3000;

    /** Lo stato adesso (solo la root). */
    public static State current() {
        long now = System.currentTimeMillis();
        State c = cached;
        if (c != null && now - cachedAt < TTL_MS) return c;
        State s = read(now);
        cached = s;
        cachedAt = now;
        return s;
    }

    /** Dopo averlo programmato o annullato: la prossima richiesta rilegge. */
    public static void forget() {
        cachedAt = 0;
    }

    private static State read(long now) {
        Shell.Result r = Shell.run(Duration.ofSeconds(10), "/bin/pgrep", "-x", "shutdown");
        String out = r.output() == null ? "" : r.output().trim();
        // pgrep: 0 trovato, 1 nessuno; il resto e' un errore, e "non so" non vale "nessun riavvio".
        if (r.exitCode() == 1 && out.isEmpty()) return State.NONE;
        if (!r.success()) return State.UNKNOWN;
        String pid = out.split("\\s+")[0];
        if (!pid.matches("[0-9]{1,7}")) return State.UNKNOWN;
        long at = recordedAt(pid);
        if (at == 0) {
            Shell.Result p = Shell.run(Duration.ofSeconds(10), "/bin/ps", "-o", "etimes=", "-o", "command=", "-p", pid);
            if (p.success() && p.output() != null) at = atFromPs(p.output().trim(), now);
        }
        return new State(true, at, true);
    }

    /** L'ora scritta dal pannello, se e' di questo processo. */
    private static long recordedAt(String pid) {
        try {
            if (!Files.isRegularFile(AT)) return 0;
            String[] f = Files.readString(AT, StandardCharsets.UTF_8).trim().split("\\s+");
            if (f.length == 2 && f[0].equals(pid) && f[1].matches("[0-9]{1,15}")) return Long.parseLong(f[1]);
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "reboot-at unreadable", e);
        }
        return 0;
    }

    /**
     * Da una riga di ps ("secondi comando"): l'ora per "shutdown -r +N" e "shutdown -r now", 0 per gli altri
     * formati (un'ora assoluta: si sa che c'e' un riavvio, non quando).
     */
    static long atFromPs(String line, long now) {
        String[] f = line.trim().split("\\s+");
        if (f.length < 2 || !f[0].matches("[0-9]{1,10}")) return 0;
        long started = now - Long.parseLong(f[0]) * 1000;
        for (int i = 2; i < f.length; i++) {
            String a = f[i];
            if (a.startsWith("-")) continue;
            if (a.equals("now")) return started;
            if (a.matches("\\+[0-9]{1,5}")) return started + Long.parseLong(a.substring(1)) * 60_000;
            return 0;
        }
        return 0;
    }

    /** Il pannello l'ha appena programmato: processo e ora, per dirla giusta in ogni pagina. */
    public static void record(String pid, long at) {
        try {
            if (pid == null || !pid.matches("[0-9]{1,7}")) return;
            Files.writeString(AT, pid + " " + at + "\n", StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "reboot-at not written: the time of the restart will be read from ps", e);
        }
        forget();
    }

    /** Annullato: l'ora non vale piu'. */
    public static void cleared() {
        try {
            Files.deleteIfExists(AT);
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "reboot-at not removed", e);
        }
        forget();
    }
}
