package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * All'avvio del servizio, da root e prima di tutto il resto: il pannello passa dal nome di prima (FreeBSD Mail Panel,
 * "mailpanel" sul disco) a DaemoxCP Mail (17/11/2026), su un server installato prima.
 *
 * <p>Il nome sta in molti posti del server, e ognuno ha la sua migrazione, con i suoi controlli e il suo ritorno
 * indietro. Qui c'e' solo l'ordine, che conta:
 * <ol>
 *   <li>i file e le cartelle che legge soltanto il pannello (sezione "productFiles"): i segreti, i registri delle
 *       reinstallazioni, il database SQLite, la nota della manutenzione. Si spostano e basta; e i file delle cartelle
 *       di prima che finiscono in una di adesso gia' presente (sezione "mergedFolders", mergeFolders);</li>
 *   <li>le cartelle dei dati, che leggono anche php-fpm, nginx e pf (DataFolderRename);</li>
 *   <li>le righe di commento col nome di prima nei file di configurazione (PanelMarker.productComments): dopo, il
 *       codice che riconosce i suoi blocchi dal commento trova quello di adesso;</li>
 *   <li>l'utente di sistema della parte web, prima che la parte root la accenda (PanelUserRename);</li>
 *   <li>il servizio rc.d e il jar (PanelServiceRename);</li>
 *   <li>la jail di fail2ban degli accessi (AuthJailRename) e la superficie pubblica sulla 443 (PublicSurfaceRename).</li>
 * </ol>
 * Il database e gli utenti di MySQL vengono dopo, quando il pannello ha aperto la sua configurazione (MysqlRename, da
 * Main). Un passo che non riesce lascia le cose come stavano e lo dice nel registro; quelli dopo non dipendono da lui,
 * e al prossimo avvio si riprova. Su un server gia' passato, o installato con questa versione, non c'e' niente da
 * fare e nessun passo tocca niente.
 *
 * <p>Solo nel processo del servizio (--web) o del menu, da root: un comando da console (--access-code, --create-admin,
 * --reinstall) che spostasse le cartelle sotto un servizio ancora acceso con la versione di prima lo romperebbe.
 */
public final class ProductRename {

    private static final Logger LOGGER = Logger.getLogger(ProductRename.class.getName());

    private ProductRename() {}

    /** Vero per il processo che puo' fare il passaggio: root, e il servizio (--web) o il menu (senza argomenti). */
    public static boolean applies(String[] args) {
        if (!"root".equals(System.getProperty("user.name"))) return false;
        if (args.length == 0) return true;
        for (String a : args) if ("--web".equals(a)) return true;
        return false;
    }

    public static void atServiceStart() {
        step("files", ProductRename::files);
        step("DataFolderRename", DataFolderRename::ensureAtBoot);
        step("PanelMarker", PanelMarker::productCommentsAtBoot);
        step("PanelUserRename", PanelUserRename::ensureAtBoot);
        step("PanelServiceRename", PanelServiceRename::ensureAtBoot);
        step("AuthJailRename", AuthJailRename::ensureAtBoot);
        step("PublicSurfaceRename", PublicSurfaceRename::ensureAtBoot);
    }

    private static void step(String name, Runnable r) {
        try {
            r.run();
        } catch (Throwable t) {
            LOGGER.warning("[ProductRename] " + name + " failed: " + t);
        }
    }

    /** I file del solo pannello: spostati se c'e' il nome di prima e non quello di adesso. Non segue i collegamenti. */
    static void files() {
        moveFiles(LegacyNames.pairs("productFiles"));
        mergeFolders(LegacyNames.pairs("mergedFolders"));
    }

    static void moveFiles(List<String[]> pairs) {
        for (String[] p : pairs) {
            if (p[0].equals(p[1])) continue;
            Path from = Path.of(p[0]), to = Path.of(p[1]);
            if (!Files.exists(from, LinkOption.NOFOLLOW_LINKS)) continue;
            if (Files.exists(to, LinkOption.NOFOLLOW_LINKS)) {
                LOGGER.warning("[ProductRename] LEFT: both " + from + " and " + to + " exist: the old one left in place");
                continue;
            }
            try {
                if (to.getParent() != null) Files.createDirectories(to.getParent());
                Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
                LOGGER.info("[ProductRename] DONE: " + from + " -> " + to);
            } catch (IOException e) {
                LOGGER.warning("[ProductRename] LEFT: " + from + " could not be moved to " + to + ": " + e.getMessage());
            }
        }
    }

    /**
     * Le cartelle di prima il cui nome di adesso e' gia' di un'altra (sezione "mergedFolders"): /usr/local/etc/mailpanel,
     * dove lo script del solo MySQL lasciava mysql.json, e /usr/local/etc/mail-panel, i segreti, diventano entrambe
     * /usr/local/etc/daemoxcp-mail. Ogni file passa nella cartella di adesso col suo nome, proprietario e permessi; uno
     * che li' c'e' gia' resta dov'e', e allora resta anche la cartella. Vuota, la cartella di prima si toglie.
     * Una cartella di adesso che manca non si crea: chi deve crearla (PanelSecrets) le da' i permessi giusti.
     */
    static void mergeFolders(List<String[]> pairs) {
        for (String[] p : pairs) {
            if (p[0].equals(p[1])) continue;
            Path from = Path.of(p[0]), to = Path.of(p[1]);
            if (!Files.isDirectory(from, LinkOption.NOFOLLOW_LINKS)) continue;
            if (!Files.isDirectory(to, LinkOption.NOFOLLOW_LINKS)) {
                LOGGER.warning("[ProductRename] LEFT: " + from + " stays: " + to + " is not there yet");
                continue;
            }
            List<Path> children;
            try (Stream<Path> s = Files.list(from)) {
                children = s.toList();
            } catch (IOException e) {
                LOGGER.warning("[ProductRename] LEFT: " + from + " cannot be read: " + e.getMessage());
                continue;
            }
            boolean left = false;
            for (Path child : children) {
                Path target = to.resolve(child.getFileName().toString());
                if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                    LOGGER.warning("[ProductRename] LEFT: both " + child + " and " + target + " exist: the old one left in place");
                    left = true;
                    continue;
                }
                try {
                    Files.move(child, target, StandardCopyOption.ATOMIC_MOVE);
                    LOGGER.info("[ProductRename] DONE: " + child + " -> " + target);
                } catch (IOException e) {
                    LOGGER.warning("[ProductRename] LEFT: " + child + " could not be moved to " + target + ": " + e.getMessage());
                    left = true;
                }
            }
            if (left) continue;
            try {
                Files.delete(from);
                LOGGER.info("[ProductRename] DONE: " + from + " removed, its files are in " + to);
            } catch (IOException e) {
                LOGGER.warning("[ProductRename] LEFT: " + from + " could not be removed: " + e.getMessage());
            }
        }
    }
}
