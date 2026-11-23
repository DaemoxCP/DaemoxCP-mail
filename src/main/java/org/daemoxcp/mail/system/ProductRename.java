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
 * At service startup, as root and before everything else: the panel moves from the previous name (FreeBSD Mail
 * Panel, "mailpanel" on disk) to DaemoxCP Mail (2026-11-17), on a server installed earlier.
 *
 * <p>The name is in many places on the server, and each one has its own migration, with its own checks and its
 * own way back. Here there is only the order, which matters:
 * <ol>
 *   <li>the files and folders that only the panel reads (section "productFiles"): the secrets, the logs of the
 *       reinstallations, the SQLite database, the maintenance note. They are simply moved; and the files of the
 *       previous folders that end up in a current one already present (section "mergedFolders",
 *       mergeFolders);</li>
 *   <li>the data folders, which php-fpm, nginx and pf read too (DataFolderRename);</li>
 *   <li>the comment lines with the previous name in the configuration files (PanelMarker.productComments):
 *       afterwards, the code that recognizes its blocks by the comment finds the current one;</li>
 *   <li>the system user of the web part, before the root part starts it (PanelUserRename);</li>
 *   <li>the rc.d service and the jar (PanelServiceRename);</li>
 *   <li>the fail2ban jail for logins (AuthJailRename) and the public surface on 443 (PublicSurfaceRename).</li>
 * </ol>
 * The MySQL database and users come later, when the panel has opened its configuration (MysqlRename, from
 * Main). A step that fails leaves things as they were and says so in the log; the ones after it do not depend on
 * it, and at the next startup it is tried again. On a server already moved over, or installed with this version,
 * there is nothing to do and no step touches anything.
 *
 * <p>Only in the service process (--web) or the menu one, as root: a console command (--access-code,
 * --create-admin, --reinstall) that moved the folders from under a service still running with the previous
 * version would break it.
 */
public final class ProductRename {

    private static final Logger LOGGER = Logger.getLogger(ProductRename.class.getName());

    private ProductRename() {}

    /** True for the process that can do the move: root, and the service (--web) or the menu (no arguments). */
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

    /** The panel-only files: moved if the previous name exists and the current one does not. Does not follow links. */
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
     * The previous folders whose current name already belongs to another one (section "mergedFolders"):
     * /usr/local/etc/mailpanel, where the MySQL-only script left mysql.json, and /usr/local/etc/mail-panel, the
     * secrets, both become /usr/local/etc/daemoxcp-mail. Every file moves into the current folder with its name,
     * owner and permissions; one that is already there stays where it is, and then the folder stays too. Once
     * empty, the previous folder is removed. A current folder that is missing is not created: whoever has to
     * create it (PanelSecrets) gives it the right permissions.
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
