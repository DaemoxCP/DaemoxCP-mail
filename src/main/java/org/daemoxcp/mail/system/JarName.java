package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Logger;

/**
 * Dalla 0.9.0 il jar si chiama daemoxcp-mail.jar, senza la versione, e cosi' lo chiamano il README e i comandi da
 * console. Sui server installati prima il file si chiama ancora daemoxcp-mail-1.0.jar, e il servizio (rc.conf, lo
 * script di avvio) e upgrade-panel.sh usano quel percorso: il file vero resta dov'e', e accanto nasce il collegamento
 * daemoxcp-mail.jar che punta a lui. Cosi' "java -jar daemoxcp-mail.jar --access-code" vale su ogni server, e
 * upgrade-panel.sh, che sostituisce il file vero, non lascia mai il collegamento indietro.
 *
 * All'avvio della parte root, idempotente: al secondo avvio non scrive niente.
 */
public final class JarName {

    private static final Logger LOGGER = Logger.getLogger(JarName.class.getName());

    public enum Outcome { NOTHING, LINKED, RELINKED, BLOCKED }

    private JarName() {}

    public static void ensureAtBoot() {
        try {
            String jar = PanelSeparation.jarPath();
            if (jar == null) return;
            Outcome o = ensure(Path.of(jar));
            if (o == Outcome.LINKED || o == Outcome.RELINKED)
                LOGGER.info("[JarName] DONE: " + Product.JAR_FILE + " -> " + Path.of(jar).getFileName() + " (servers installed before 0.9.0)");
            else if (o == Outcome.BLOCKED)
                LOGGER.warning("[JarName] " + Path.of(jar).resolveSibling(Product.JAR_FILE) + " is a file of its own, not this panel's"
                        + " jar: left alone, so the console commands with " + Product.JAR_FILE + " would run that one");
        } catch (Throwable t) {
            LOGGER.warning("[JarName] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /** Il collegamento accanto al jar che gira, se serve. Pura sul filesystem: le prove la chiamano su una cartella loro. */
    static Outcome ensure(Path jar) throws java.io.IOException {
        if (jar == null || !Files.isRegularFile(jar) || jar.getFileName().toString().equals(Product.JAR_FILE)) return Outcome.NOTHING;
        Path link = jar.resolveSibling(Product.JAR_FILE);
        Path target = jar.getFileName();
        if (Files.isSymbolicLink(link)) {
            if (Files.readSymbolicLink(link).equals(target)) return Outcome.NOTHING;
            Files.delete(link);
            Files.createSymbolicLink(link, target);
            return Outcome.RELINKED;
        }
        if (Files.exists(link)) return Outcome.BLOCKED;
        Files.createSymbolicLink(link, target);
        return Outcome.LINKED;
    }
}
