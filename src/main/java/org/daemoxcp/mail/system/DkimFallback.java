package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.security.DkimManager;
import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Rspamd firma solo i domini che hanno la loro chiave DKIM: try_fallback = false in local.d/dkim_signing.conf.
 *
 * <p>Misurato sul server vero il 21/11/2026: ogni notte alle 03:01 e alle 04:15 (i rapporti di periodic per root, da
 * sendmail, che passano da Rspamd con non_smtpd_milters) Rspamd scriveva «cannot load dkim key
 * /var/db/rspamd/dkim/...: cannot stat key file». Il dominio di quei messaggi, il nome della macchina, non e' un dominio
 * di posta e non ha chiave; con try_fallback a true, il valore predefinito, Rspamd la cerca nel percorso predefinito,
 * che non esiste. Sulla VM installata dal README il file non c'era proprio: lo stesso errore per ogni messaggio locale o
 * autenticato di un dominio senza chiave. Quello che si firma non cambia: senza chiave non si firmava comunque.
 *
 * <p>Il file lo scrive DkimManager, coi domini e le loro chiavi; qui solo la riga in piu':
 * <ul>
 *   <li>il file non c'e': lo scrive DkimManager dal database (su un server nuovo, nessun dominio con DKIM);</li>
 *   <li>il file e' del pannello (l'intestazione di DkimManager o quella dell'installatore RspamdScript) e non dice
 *       try_fallback: la riga dopo allow_username_mismatch, il resto byte per byte com'era;</li>
 *   <li>try_fallback c'e' gia', con qualunque valore, o il file l'ha scritto qualcun altro: com'e'.</li>
 * </ul>
 * Solo sul Rspamd del pannello, quello dietro Postfix come milter. Poi rspamadm configtest, reload e la prova: rspamadm
 * configdump dkim_signing dice try_fallback = false e Rspamd analizza. Se qualcosa non torna il file torna com'era (o
 * si toglie) e si ricarica. Al secondo avvio non fa niente.
 */
public final class DkimFallback {

    private static final Logger LOGGER = Logger.getLogger(DkimFallback.class.getName());

    static final Path FILE = Path.of(DkimManager.CONFIG_PATH);
    /** L'intestazione che scrive l'installatore RspamdScript. */
    static final String SCRIPT_HEADER = "# DKIM Signing\n# Keys are generated per-domain by the panel\n";
    static final Pattern ANY_FALLBACK = Pattern.compile("(?m)^\\s*try_fallback\\s*=");
    static final Pattern ALLOW_LINE = Pattern.compile("(?m)^allow_username_mismatch = true;\\n");
    static final Pattern FALLBACK_FALSE = Pattern.compile("(?m)^\\s*try_fallback\\s*=\\s*false\\s*;");

    private DkimFallback() {}

    enum Action { NOTHING, WRITE, INSERT, LEFT_ALONE }

    /**
     * Che cosa fare. installed: c'e' rspamadm; proxy: il worker-proxy.inc di local.d (null se non c'e'); current: il
     * file di adesso (null se non c'e'). Funzione pura.
     */
    static Action decide(boolean installed, String proxy, String current) {
        if (!installed || proxy == null || !HeaderFromCheck.MILTER.matcher(proxy).find()) return Action.NOTHING;
        if (current == null) return Action.WRITE;
        if (ANY_FALLBACK.matcher(current).find()) return Action.NOTHING;
        boolean ours = current.startsWith(DkimManager.CONFIG_HEADER) || current.startsWith(SCRIPT_HEADER);
        return ours && ALLOW_LINE.matcher(current).find() ? Action.INSERT : Action.LEFT_ALONE;
    }

    /** Il file con la riga dopo allow_username_mismatch, tutto il resto com'era. Funzione pura. */
    static String inserted(String current) {
        var m = ALLOW_LINE.matcher(current);
        if (!m.find()) return null;
        return current.substring(0, m.end()) + DkimManager.NO_FALLBACK + "\n" + current.substring(m.end());
    }

    /** configdump dice try_fallback = false. Funzione pura. */
    static boolean dumpSaysNoFallback(String dump) {
        return dump != null && FALLBACK_FALSE.matcher(dump).find();
    }

    public static void ensureAtBoot() {
        try {
            boolean installed = Files.isExecutable(Path.of(RspamdController.RSPAMADM));
            String proxy = Files.isRegularFile(HeaderFromCheck.PROXY, LinkOption.NOFOLLOW_LINKS)
                    ? Files.readString(HeaderFromCheck.PROXY, StandardCharsets.UTF_8) : null;
            String current = Files.isRegularFile(FILE, LinkOption.NOFOLLOW_LINKS) ? Files.readString(FILE, StandardCharsets.UTF_8)
                    : Files.exists(FILE, LinkOption.NOFOLLOW_LINKS) ? "" : null;
            switch (decide(installed, proxy, current)) {
                case NOTHING -> { }
                case LEFT_ALONE -> LOGGER.info("[DkimFallback] " + FILE + " was not written by the panel and does not say"
                        + " try_fallback: left as it is (Rspamd looks for a key under /var/db/rspamd/dkim for domains without one)");
                case WRITE -> {
                    if (Main.mailDatabase == null) {
                        LOGGER.info("[DkimFallback] no database yet: " + FILE + " is written at the next start");
                        return;
                    }
                    apply(new DkimManager(Main.mailDatabase).rspamdConfigText(), null, "no " + FILE + ": written with no domain"
                            + " signed without its own key");
                }
                case INSERT -> apply(inserted(current), current, NO_FALLBACK_REASON);
            }
        } catch (Throwable t) {
            LOGGER.warning("[DkimFallback] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static final String NO_FALLBACK_REASON = "Rspamd looked for a key under /var/db/rspamd/dkim for every domain without one"
            + " (the server's own name in root's reports) and logged «cannot load dkim key»";

    static boolean apply(String wanted, String previous, String reason) throws Exception {
        if (wanted == null) return false;
        if (!Shell.run(Duration.ofSeconds(30), "service", "rspamd", "status").success()) {
            LOGGER.info("[DkimFallback] Rspamd is not running: " + FILE + " left as it is, retrying at the next start");
            return false;
        }
        write(wanted);
        Shell.Result test = Shell.run(Duration.ofSeconds(60), RspamdController.RSPAMADM, "configtest");
        if (!test.success()) {
            putBack(previous, false);
            LOGGER.warning("[DkimFallback] ROLLED_BACK: rspamadm configtest refuses " + FILE + ": nothing changed");
            return false;
        }
        HeaderFromCheck.reload();
        String problem = "Rspamd does not answer a scan";
        for (int i = 0; i < 30 && problem != null; i++) {
            Thread.sleep(1000);
            String dump = Shell.run(Duration.ofSeconds(60), RspamdController.RSPAMADM, "configdump", "dkim_signing").output();
            if (!dumpSaysNoFallback(dump)) problem = "rspamadm configdump dkim_signing does not say " + DkimManager.NO_FALLBACK;
            else problem = HeaderFromCheck.scan("<" + HeaderFromCheck.PROBE_USER + ">") == null ? "Rspamd does not answer a scan" : null;
        }
        if (problem != null) {
            putBack(previous, true);
            LOGGER.warning("[DkimFallback] ROLLED_BACK: " + problem + "; " + FILE + " put back");
            return false;
        }
        LOGGER.info("[DkimFallback] DONE: Rspamd signs only the domains that have their own DKIM key (" + DkimManager.NO_FALLBACK
                + " in " + FILE + "; " + reason + ")");
        return true;
    }

    private static void write(String content) throws Exception {
        Files.createDirectories(FILE.getParent());
        Path tmp = FILE.resolveSibling("." + FILE.getFileName() + ".tmp");
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Files.move(tmp, FILE, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(String previous, boolean reload) throws Exception {
        if (previous != null) write(previous);
        else Files.deleteIfExists(FILE);
        if (reload) HeaderFromCheck.reload();
    }
}
