package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * At startup: the file and folder names that the panel used to write in Italian.
 *
 * <p>The names in the code have moved to English (r26), but a server that is already running has
 * the old ones on disk. Without this step the panel would no longer find them and would lose its
 * state: its own log, the log of the last restart, the state of the version jump, the copies
 * taken before every change to postfix, nginx and fail2ban.
 *
 * <p>Every step checks first: repeating it changes nothing. If BOTH names exist the old one is
 * left where it is and a warning is logged, because deciding which of the two counts is not a
 * migration's job: it must not destroy anything.
 *
 * <p>The old and new names live in the data file (LegacyNames, sections "files" and
 * "vmailFolders"), not here. The order is the file's order, and it matters where a folder
 * contains a file to rename: first the folder, then the file inside it, otherwise the second step
 * would look for a path that no longer exists.
 *
 * <p>The package branch file keeps the "zz" prefix: pkg reads /usr/local/etc/pkg/repos in
 * alphabetical order and for every field the last one wins, so the new name must stay
 * alphabetically last. The chosen name is the same as the web panel's, so the two stop calling
 * the same thing by two different names.
 *
 * <p>NOT here are the names that nginx and fail2ban read too: the file of the public surface on
 * 443, its access log, the fail2ban filter and jail (and with the jail the pf anchor and table),
 * and the folder of its files (`/var/db/daemoxcp-mail/pubblico`, which nginx reads for
 * mta-sts.txt). They must all be moved together, with nginx and fail2ban reloaded and a way back
 * if either of them refuses: PublicSurfaceRename moves them. The folder was here until
 * 2026-10-31, and that was wrong: on the production server nginx would have looked for it under
 * the old name.
 */
public final class PathMigration {

    private static final Logger LOGGER = Logger.getLogger(PathMigration.class.getName());

    private PathMigration() {}

    public static void run() {
        for (String[] p : LegacyNames.pairs("files")) rename(p[0], p[1]);
        migrateArchive(AddressTransform.vmail);
    }

    /**
     * The mail archive of the mailboxes removed or turned into aliases, under /var/vmail.
     * Kept apart, so that it can be tested on any folder without touching the others.
     */
    static void migrateArchive(Path vmail) {
        for (String[] p : LegacyNames.pairs("vmailFolders"))
            rename(vmail.resolve(p[0]).toString(), vmail.resolve(p[1]).toString());
    }

    /** Moves oldName to newName if the first exists and the second does not. Does not follow links. */
    private static void rename(String oldName, String newName) {
        // If the two names are the same there is nothing to move. The guard exists because a
        // rename pass over the code can ALSO change the old name in here, and the result
        // would be a false warning instead of a visible error.
        if (oldName.equals(newName)) return;
        Path from = Path.of(oldName);
        Path to = Path.of(newName);
        if (!Files.exists(from, LinkOption.NOFOLLOW_LINKS)) return;
        if (Files.exists(to, LinkOption.NOFOLLOW_LINKS)) {
            LOGGER.warning("Both " + oldName + " and " + newName + " exist: leaving the old one in place");
            return;
        }
        try {
            Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
            LOGGER.info("Renamed " + oldName + " to " + newName);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Could not rename " + oldName + " to " + newName, e);
        }
    }
}
