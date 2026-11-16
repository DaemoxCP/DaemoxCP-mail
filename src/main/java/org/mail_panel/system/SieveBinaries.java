package org.mail_panel.system;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Le regole Sieve del pannello compilate dal Pigeonhole che c'e' adesso (reperto 241).
 *
 * <p>Il compilato (.svbin) accanto a ogni regola del pannello lo fa il pannello con sievec (SieveCompiler, reperto 218):
 * Dovecot consegna come vmail e nella cartella di root non lo puo' scrivere. Quando Pigeonhole cambia formato, come nel
 * passaggio dalla 2.3 alla 2.4 (intestazione 02 contro 03, misurato sulla VM), il compilato di prima non vale piu':
 * Dovecot ricompila la regola in memoria a ogni messaggio, la posta arriva e le regole funzionano, ma a ogni messaggio
 * scrive due errori nel registro («binary ... save: failed to create temporary file», «The LDA Sieve plugin does not
 * have permission to save global Sieve script binaries»). Il testo delle regole non cambia, quindi SieveRulesRefresh
 * non riscriveva niente, e ne' il passaggio a Dovecot 2.4 ne' il riavvio del pannello se ne accorgevano.
 *
 * <p>Qui ogni regola del pannello (/var/mail/sieve/dominio/nome/.dovecot.sieve che comincia con le righe require del
 * pannello: uno script fatto a mano resta com'e') si compila col sievec installato, e il compilato si sostituisce solo
 * se e' diverso. Il compilato e' deterministico (misurato: due compilazioni della 2.4.5 uguali byte per byte), quindi
 * al secondo giro non si scrive niente. Si fa all'avvio della parte root dopo SieveRulesRefresh; nel passaggio a
 * Dovecot 2.4 appena la 2.4 e' partita; e di nuovo se il passaggio torna alla 2.3. Le cartelle si percorrono senza
 * seguire collegamenti; compilare e scrivere e' SieveCompiler (sievec come utente sievec, RootOnlyPath). Nel log solo
 * i conteggi, mai gli indirizzi.
 */
public final class SieveBinaries {

    private static final Logger LOGGER = Logger.getLogger(SieveBinaries.class.getName());

    private SieveBinaries() {}

    static final Path ROOT = Path.of("/var/mail/sieve");
    static final String SCRIPT = ".dovecot.sieve";
    /** Un file di regole del pannello e' piccolo: piu' grande non e' suo. */
    static final long MAX_SCRIPT = 64 << 10;

    /** Quello che serve, per provarlo senza sievec ne' /var/mail. */
    interface Compiler {
        /** Le regole del pannello; vuoto se Pigeonhole non c'e'. */
        List<Path> scripts() throws IOException;
        /** Compila e sostituisce il compilato solo se e' diverso (SieveCompiler.refresh). */
        SieveCompiler.Outcome refresh(Path script);
    }

    /** Quante ricompilate, quante gia' giuste, e lo stato di quelle che non si sono compilate. */
    public record Result(int recompiled, int unchanged, List<String> failed) {}

    /** Puro rispetto a {@link Compiler}. */
    static Result run(Compiler c) {
        List<Path> scripts;
        try {
            scripts = c.scripts();
        } catch (IOException e) {
            return new Result(0, 0, List.of("the rules could not be listed: " + e.getClass().getSimpleName()));
        }
        int recompiled = 0, unchanged = 0;
        List<String> failed = new ArrayList<>();
        for (Path s : scripts) {
            SieveCompiler.Outcome o = c.refresh(s);
            switch (o.status()) {
                case COMPILED -> recompiled++;
                case UNCHANGED -> unchanged++;
                default -> failed.add(o.status().name().toLowerCase());
            }
        }
        return new Result(recompiled, unchanged, failed);
    }

    /** Le regole del pannello sul server, col sievec installato. */
    public static Result refreshNow() {
        return run(real());
    }

    /** All'avvio della parte root, dopo SieveRulesRefresh. */
    public static void ensureAtBoot() {
        try {
            Result r = refreshNow();
            if (r.recompiled() > 0)
                LOGGER.info("[SieveBinaries] DONE: " + r.recompiled() + " Sieve rule file(s) of the panel compiled again by the"
                        + " Pigeonhole installed now (the compiled ones were of another version: Dovecot compiled them again at"
                        + " every message and logged errors); " + r.unchanged() + " already right");
            if (!r.failed().isEmpty())
                LOGGER.warning("[SieveBinaries] " + r.failed().size() + " Sieve rule file(s) of the panel not compiled ("
                        + String.join(", ", r.failed()) + "): Dovecot compiles them at every message");
        } catch (Throwable t) {
            LOGGER.warning("[SieveBinaries] failed: " + t);
        }
    }

    // ===================== Il server vero =====================

    static Compiler real() {
        return new Compiler() {
            @Override public List<Path> scripts() throws IOException {
                if (SieveCompiler.sievec() == null) return List.of();
                return panelScripts(ROOT);
            }
            @Override public SieveCompiler.Outcome refresh(Path script) {
                return SieveCompiler.refresh(script);
            }
        };
    }

    /** dominio/nome/.dovecot.sieve sotto root, senza seguire collegamenti, solo quelli che il pannello ha scritto. */
    static List<Path> panelScripts(Path root) throws IOException {
        List<Path> out = new ArrayList<>();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) return out;
        try (DirectoryStream<Path> domains = Files.newDirectoryStream(root)) {
            for (Path d : domains) {
                if (!Files.isDirectory(d, LinkOption.NOFOLLOW_LINKS)) continue;
                try (DirectoryStream<Path> names = Files.newDirectoryStream(d)) {
                    for (Path n : names) {
                        if (!Files.isDirectory(n, LinkOption.NOFOLLOW_LINKS)) continue;
                        Path s = n.resolve(SCRIPT);
                        if (!Files.isRegularFile(s, LinkOption.NOFOLLOW_LINKS) || Files.size(s) > MAX_SCRIPT) continue;
                        if (SieveRulesRefresh.panelScript(Files.readString(s, StandardCharsets.UTF_8))) out.add(s);
                    }
                }
            }
        }
        out.sort(null);
        return out;
    }
}
