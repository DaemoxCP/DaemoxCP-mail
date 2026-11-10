package org.mail_panel.system;

import org.mail_panel.integration.SieveGenerator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * Il keep esplicito che il pannello metteva in fondo alle sue regole Sieve, tolto dagli script gia' scritti (reperto 216).
 *
 * Fino al 09/11/2026 SieveGenerator chiudeva ogni script con «# Default action» e «keep;». Il messaggio restava cosi'
 * sempre nella INBOX: «Sposta» lo lasciava nella cartella E nella INBOX, «Inoltra» senza copia ne teneva una, «Elimina»
 * non eliminava niente. Adesso SieveGenerator non lo scrive piu'; qui si toglie dagli script che aveva gia' scritto, in
 * /var/mail/sieve/dominio/nome/.dovecot.sieve, e si ricompilano con sievec (la cartella e' di root: Dovecot, che consegna
 * come vmail, non potrebbe salvare il compilato da solo). sievec gira con l'utente sievec, non da root, e root installa
 * solo il compilato (SieveCompiler, reperto 218).
 *
 * Si tocca solo uno script del pannello: un file vero (un collegamento lo fa ManageSieve, non il pannello), che comincia
 * con una delle due righe require che il pannello ha scritto (prima e dopo l'aggiunta di "date") e finisce con quella coda
 * esatta. Si toglie solo la coda: il resto resta byte per byte, e il risultato e' quello che SieveGenerator scrive adesso
 * per le stesse regole. Il file nuovo ha proprietario e permessi del vecchio; se sievec lo rifiuta, torna com'era. Al
 * secondo avvio non trova niente da fare.
 */
public final class SieveForcedKeep {

    private static final Logger LOGGER = Logger.getLogger(SieveForcedKeep.class.getName());

    static final Path PANEL_RULES = Path.of("/var/mail/sieve");
    static final String SCRIPT = ".dovecot.sieve";

    /** La riga require che il pannello scriveva prima di aggiungere "date" (stessa coda, stesso resto). */
    static final String REQUIRE_WITHOUT_DATE = SieveGenerator.REQUIRE.replace(", \"date\"];", "];");

    private SieveForcedKeep() {}

    /** Lo script senza il keep forzato, o null se non e' uno script del pannello con quella coda. Funzione pura. */
    static String fixed(String script) {
        if (script == null || !script.endsWith(SieveGenerator.OLD_FORCED_KEEP)) return null;
        if (!script.startsWith(SieveGenerator.REQUIRE) && !script.startsWith(REQUIRE_WITHOUT_DATE)) return null;
        return script.substring(0, script.length() - SieveGenerator.OLD_FORCED_KEEP.length());
    }

    /** Gli script del pannello: radice/dominio/nome/.dovecot.sieve, solo file veri (Files.walk non segue i collegamenti). */
    static List<Path> panelScripts(Path root) {
        List<Path> out = new ArrayList<>();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) return out;
        try (Stream<Path> s = Files.walk(root, 3)) {
            s.filter(p -> root.relativize(p).getNameCount() == 3 && p.getFileName().toString().equals(SCRIPT)
                    && Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)).sorted().forEach(out::add);
        } catch (IOException e) {
            LOGGER.warning("[SieveForcedKeep] cannot read " + root + ": " + e.getMessage());
        }
        return out;
    }

    /** Il risultato di un giro: quanti script sistemati, e quelli rimasti com'erano perche' sievec non li accettava. */
    record Outcome(int fixed, List<Path> putBack) {}

    /**
     * Toglie la coda da ogni script del pannello sotto root e lo ricompila con compile (vero se sievec l'ha accettato).
     * Se compile dice di no, lo script torna com'era e si ricompila quello.
     */
    static Outcome repair(Path root, Predicate<Path> compile) throws IOException {
        int done = 0;
        List<Path> putBack = new ArrayList<>();
        for (Path script : panelScripts(root)) {
            String before = Files.readString(script, StandardCharsets.UTF_8);
            String after = fixed(before);
            if (after == null) continue;
            replace(script, after);
            if (compile.test(script)) {
                done++;
            } else {
                replace(script, before);
                compile.test(script);
                putBack.add(script);
            }
        }
        return new Outcome(done, putBack);
    }

    /** Riscrive il file in un colpo solo (copia accanto con gli stessi attributi, poi rename): chi consegna non lo vede a meta'. */
    private static void replace(Path script, String content) throws IOException {
        Path tmp = script.resolveSibling(SCRIPT + ".forced-keep");
        Files.copy(script, tmp, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.move(tmp, script, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /** All'avvio della parte root. */
    public static void ensureAtBoot() {
        try {
            SieveGenerator compiler = new SieveGenerator();
            Outcome o = repair(PANEL_RULES, p -> compiler.compileScript(p.toString()));
            if (o.fixed() > 0)
                LOGGER.info("[SieveForcedKeep] DONE: " + o.fixed() + " Sieve script(s) of the panel without the forced keep at"
                        + " the end, recompiled: move, forward without a copy and delete now do what they say");
            for (Path p : o.putBack())
                LOGGER.warning("[SieveForcedKeep] LEFT AS IT WAS: sievec refuses " + p + " without the forced keep");
        } catch (Throwable t) {
            LOGGER.warning("[SieveForcedKeep] failed: " + t);
        }
    }
}
