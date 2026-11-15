package org.mail_panel.system;

import org.mail_panel.integration.SieveGenerator;
import org.mail_panel.security.SafeNames;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.logging.Logger;

/**
 * La memoria delle risposte automatiche di una casella, e come si azzera senza rompere niente (reperto 219).
 *
 * <p>Pigeonhole ricorda a chi ha gia' risposto nel database dei duplicati di Dovecot, il file .dovecot.lda-dupes nella
 * home della casella. La documentazione di Pigeonhole (2.3, «Sieve Usage», sulla risposta automatica): «List of
 * autoreplied senders is stored in '.dovecot.lda-dupes' file in user's home directory», e per provare di nuovo «try
 * deleting this file». Per azzerarla basta togliere quel file:
 * <ul>
 *   <li>il compilato .dovecot.svbin accanto alle regole del pannello e' il codice dello script, non sa niente delle
 *       risposte date. Fino al 10/11/2026 il reset lo toglieva «per forzare la ricompilazione», ma la cartella e' di
 *       root (reperto 214) e Dovecot, che consegna come vmail, non lo puo' salvare: da li' in poi ogni consegna a quella
 *       casella ricompilava le regole e scriveva nel maillog «Error: sieve: binary ...: save: failed to create temporary
 *       file ... Permission denied (euid=5000(vmail))», finche' il pannello non risalvava le regole (misurato sulla VM il
 *       10/11/2026). Le regole non cambiano: ricompilarle non serve;</li>
 *   <li>Dovecot non tiene la memoria in memoria: LMTP la rilegge dal file a ogni consegna. Il reset faceva {@code
 *       service dovecot restart}, che ferma e riavvia tutto Dovecot (processo principale, autenticazione, LMTP, l'ascolto
 *       di IMAP), e non serviva: subito dopo il reset, senza riavvio, la consegna seguente riceve di nuovo la risposta
 *       (misurato). Una sessione IMAP gia' entrata al riavvio sopravviveva (Dovecot 2.3.21, misurato);</li>
 *   <li>.dovecot.sieve.db, che il reset toglieva in /var/mail/sieve, non lo scrive e non lo legge nessuno: nessuna
 *       libreria di Dovecot 2.3.21 e Pigeonhole 0.5.21 contiene quel nome (misurato), .dovecot.lda-dupes si'.</li>
 * </ul>
 *
 * <p>La casella viene da MySQL, dove col pannello separato scrive anche la parte web, e root ne fa un percorso: deve
 * avere la forma di un indirizzo, e il file restare sotto /var/vmail (come in SieveGenerator.saveSieveScript).
 *
 * <p>All'avvio {@link #ensureAtBoot()} rimette il compilato alle regole del pannello che non l'hanno, o l'hanno piu'
 * vecchio dello script: e' quello che lasciava il reset di prima.
 */
public final class VacationTracking {

    private static final Logger LOGGER = Logger.getLogger(VacationTracking.class.getName());

    /**
     * La radice delle caselle. La home di Dovecot di ognuna e' la sua cartella home/ (home=/var/vmail/%d/%n/home,
     * reperto 217, DovecotHome); prima era la radice stessa.
     */
    static final Path HOMES = Path.of("/var/vmail");
    /** Il database dei duplicati di Dovecot, dove Pigeonhole ricorda le risposte automatiche date. */
    public static final String DUPLICATES = ".dovecot.lda-dupes";

    static final Path PANEL_RULES = Path.of("/var/mail/sieve");
    static final String BINARY = ".dovecot.svbin";

    private VacationTracking() {}

    /**
     * Azzera la memoria delle risposte automatiche della casella: la prossima consegna da un mittente gia' servito
     * riceve di nuovo la risposta. Non tocca le regole ne' il compilato, e non riavvia Dovecot. Falso se l'indirizzo
     * non ha la forma di un indirizzo.
     */
    public static boolean reset(String email) throws IOException {
        return reset(HOMES, email);
    }

    static boolean reset(Path homes, String email) throws IOException {
        Path duplicates = duplicatesOf(homes, email);
        if (duplicates == null) return false;
        Files.deleteIfExists(duplicates);
        // Prima del reperto 217 la memoria stava nella radice della casella: se DovecotHome non l'ha ancora portata nella
        // home (o Dovecot l'ha riscritta li' prima della migrazione), si toglie anche quella.
        Files.deleteIfExists(duplicates.getParent().resolveSibling(DUPLICATES));
        return true;
    }

    /** homes/dominio/nome/home/.dovecot.lda-dupes, o null se l'indirizzo non e' un indirizzo. Pura. */
    static Path duplicatesOf(Path homes, String email) {
        if (!SafeNames.address(email)) return null;
        int at = email.indexOf('@');
        return SafeNames.under(homes, email.substring(at + 1), email.substring(0, at), DovecotHome.DIR, DUPLICATES);
    }

    // ===================== All'avvio: il compilato che il reset di prima toglieva =====================

    /** Vero se accanto allo script non c'e' un compilato vero strettamente piu' nuovo, come Pigeonhole lo vuole. */
    static boolean stale(Path script) throws IOException {
        Path binary = script.resolveSibling(BINARY);
        if (!Files.isRegularFile(binary, LinkOption.NOFOLLOW_LINKS)) return true;
        FileTime b = Files.getLastModifiedTime(binary, LinkOption.NOFOLLOW_LINKS);
        FileTime s = Files.getLastModifiedTime(script, LinkOption.NOFOLLOW_LINKS);
        return b.compareTo(s) <= 0;
    }

    /** Il risultato di un giro: gli script ricompilati, e quelli che non si sono potuti ricompilare. */
    record Outcome(List<Path> compiled, List<Path> notCompiled) {}

    /**
     * Ricompila con compile (vero se il compilato e' al suo posto) ogni regola del pannello sotto root senza un compilato
     * piu' nuovo. Le altre non si toccano: al secondo giro non c'e' niente da fare.
     */
    static Outcome repair(Path root, Predicate<Path> compile) throws IOException {
        List<Path> compiled = new ArrayList<>(), notCompiled = new ArrayList<>();
        for (Path script : SieveForcedKeep.panelScripts(root)) {
            if (!stale(script)) continue;
            if (compile.test(script) && !stale(script)) compiled.add(script);
            else notCompiled.add(script);
        }
        return new Outcome(compiled, notCompiled);
    }

    /** All'avvio della parte root, dopo SieveForcedKeep (che ricompila gia' quello che cambia). */
    public static void ensureAtBoot() {
        try {
            if (SieveCompiler.sievec() == null) return;
            SieveGenerator compiler = new SieveGenerator();
            Outcome o = repair(PANEL_RULES, p -> compiler.compileScript(p.toString()));
            if (!o.compiled().isEmpty())
                LOGGER.info("[VacationTracking] DONE: " + o.compiled().size() + " Sieve script(s) of the panel compiled again:"
                        + " their binary was missing or older, and Dovecot compiled them at each delivery");
            for (Path p : o.notCompiled())
                LOGGER.warning("[VacationTracking] NOT COMPILED: " + p + " (Dovecot compiles it at each delivery)");
        } catch (Throwable t) {
            LOGGER.warning("[VacationTracking] failed: " + t);
        }
    }
}
