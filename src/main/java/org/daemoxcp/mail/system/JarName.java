package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Logger;

/**
 * Since 0.9.0 the jar is called daemoxcp-mail.jar, without the version, and that is what the README and the
 * console commands call it. On servers installed before, the file is still called daemoxcp-mail-1.0.jar, and the
 * service (rc.conf, the start script) and upgrade-panel.sh use that path: the real file stays where it is, and next
 * to it the link daemoxcp-mail.jar pointing to it is created. That way "java -jar daemoxcp-mail.jar --access-code"
 * works on every server, and upgrade-panel.sh, which replaces the real file, never leaves the link behind.
 *
 * At the start of the root part, idempotent: at the second start it writes nothing.
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

    /** The link next to the running jar, if needed. Pure on the filesystem: the tests call it on a folder of their own. */
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
