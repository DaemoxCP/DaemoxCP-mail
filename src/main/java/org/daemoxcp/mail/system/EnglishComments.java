package org.daemoxcp.mail.system;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * I commenti che il pannello scriveva in italiano nei file del server, e il loro passaggio all'inglese (22/11/2026).
 *
 * <p>Fino ad oggi i commenti delle configurazioni e degli script che il pannello scrive sul server (Dovecot, Postfix,
 * pf, rspamd, redis, clamd, nginx, php-fpm, fail2ban, gli script d'installazione) erano in italiano: chi amministra il
 * server e non lo legge non capiva perche' una riga c'e'. Il codice adesso li scrive in inglese. Quelli di prima stanno
 * in legacy-names.json, sezione "italianComments", riga per riga accanto alla traduzione, e non nel codice (la scelta
 * del 30/10/2026, LegacyNames).
 *
 * <p>All'avvio, nei file del pannello, le righe di commento in italiano diventano quelle in inglese: lo stesso
 * passaggio del nome del prodotto (PanelMarker.productCommentsAtBoot), con gli stessi controlli. Si cambiano SOLO le
 * righe di commento, e lo si verifica prima di scrivere; scrittura atomica con permessi, proprietario e flag di prima;
 * nessun reload, perche' un commento non cambia quello che il servizio fa. Prima della traduzione passano le sezioni
 * dei commenti di prima ancora (productComments: il nome di prima del prodotto; damagedComments: le parole rovinate
 * dalle rinomine fatte sul testo), cosi' anche una riga di quelle arriva all'inglese in un passaggio solo.
 *
 * <p>Il codice che riconosce un suo blocco dal commento (RedisSocket, ClamdSocket, RspamdController, LmtpSocket,
 * DovecotQuota, PfPolicy) legge il file attraverso {@link #english}: riconosce cosi' anche il blocco scritto in
 * italiano, se il passaggio all'avvio non e' riuscito, invece di aggiungerne un secondo o di crederlo di qualcun altro.
 *
 * <p>Lo script Sieve dello spam non passa da qui: SpecialFolders lo riscrive e lo ricompila da se' quando non e' quello
 * di adesso, e un sorgente piu' nuovo del suo compilato farebbe ricompilare Dovecot a ogni consegna.
 */
public final class EnglishComments {

    private static final Logger LOGGER = Logger.getLogger(EnglishComments.class.getName());

    static final String SECTION = "italianComments";

    /** Le sezioni che si applicano, nell'ordine: le forme piu' vecchie prima, la traduzione per ultima. */
    static final List<String> CHAIN = List.of("productComments", "damagedComments", SECTION);

    /** I file con commenti del pannello oltre a quelli del passaggio del nome (PanelMarker.serviceFiles). */
    static final List<String> MORE_FILES = List.of(
            "/usr/local/etc/mysql/my.cnf", "/etc/sysctl.conf", "/etc/pf.conf",
            org.daemoxcp.mail.security.Fail2banManager.PERMABAN_FILE);

    /** E le cartelle: quelle dei file di Postfix e di Dovecot, e il sito della webmail dell'installazione a pezzi. */
    static final List<String> MORE_FOLDERS = List.of(
            "/usr/local/etc/postfix", "/usr/local/etc/dovecot", "/usr/local/etc/nginx/sites-enabled");

    private EnglishComments() {}

    /** Il testo con le righe di commento di prima in inglese; le altre righe restano come sono. Pura. */
    public static String english(String content) {
        if (content == null) return null;
        String s = content;
        for (String section : CHAIN) s = PanelMarker.current(s, section);
        return s;
    }

    record Report(List<String> done, List<String> problems) {}

    /**
     * Le copie di un file, del pannello o di chi amministra: ConfigBackups («file.bak.MILLISECONDI»), Fail2banManager
     * («.bak.AAAAMMGG-HHMMSS»), BanActionRepair («.before-pf-»), quelle di prima ancora («.prima-di-pf-»), e .pre-2.4,
     * .orig, .old, .sample. Una copia conserva il file com'era: non si traduce. Visto sul server vero il 22/11/2026, dove
     * jail.d e pf.anchors ne hanno una ventina.
     */
    static final java.util.regex.Pattern COPY = java.util.regex.Pattern.compile(
            ".*(\\.bak(\\..*)?|\\.before-.*|\\.prima-di-.*|\\.pre-2\\.4|\\.orig|\\.old|\\.sample|~)");

    static boolean copy(Path p) {
        Path name = p.getFileName();
        return name != null && COPY.matcher(name.toString()).matches();
    }

    /** I file dati con le righe di commento in inglese; quelli senza niente da cambiare, e le copie, non si toccano. */
    static Report migrate(Collection<Path> files) {
        List<String> done = new ArrayList<>(), problems = new ArrayList<>();
        for (Path p : files) {
            if (copy(p) || !PanelMarker.stale(p, EnglishComments::english)) continue;
            PanelMarker.rewrite(p, EnglishComments::english, done, problems);
        }
        return new Report(done, problems);
    }

    /** All'avvio, da root (Main, dopo il passaggio del nome del prodotto). Un file che non riesce si riprova al prossimo. */
    public static void atBoot() {
        try {
            Set<Path> files = new LinkedHashSet<>(PanelMarker.serviceFiles(MORE_FILES, MORE_FOLDERS));
            files.addAll(CommentRepair.files());
            String jar = UpdateManager.jarPath();
            if (!jar.isEmpty()) {
                Path parent = Path.of(jar).toAbsolutePath().getParent();
                if (parent != null) files.add(parent.resolve("run.sh"));
            }
            Report r = migrate(files);
            if (!r.done().isEmpty())
                LOGGER.info("[EnglishComments] DONE: the comments in English in " + String.join(", ", r.done()));
            if (!r.problems().isEmpty())
                LOGGER.warning("[EnglishComments] PARTIAL, retrying at the next start: " + String.join("; ", r.problems()));
        } catch (Throwable t) {
            LOGGER.warning("[EnglishComments] failed: " + t);
        }
    }
}
