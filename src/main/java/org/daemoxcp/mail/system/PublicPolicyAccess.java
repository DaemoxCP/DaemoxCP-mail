package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.logging.Logger;

/**
 * The MTA-STS policy is read by nginx, which runs as www: folder 0755 and file 0644, set explicitly, not left
 * to the umask.
 *
 * The panel's service runs with umask 077. On a freshly installed server the policy folder was created 0700
 * and the file 0600, owned by root: nginx answered 403 to /.well-known/mta-sts.txt, and "Set up everything"
 * stopped at the configuration of port 443 saying only that the policy did not match (finding 250, measured on
 * the clean VM on 2026-11-16, following the installation guide). The production server did not show it: its
 * folder had been created earlier.
 *
 * The content is public by construction: anyone reads it at https://mta-sts.domain/.well-known/mta-sts.txt,
 * and it contains nothing secret. The folder stays owned by root: nobody else writes in it.
 *
 * Never through a link: the permissions are changed without following links (a link in place of the folder or
 * of the file is left as it is and reported), and the file is written alongside and renamed into place.
 */
public final class PublicPolicyAccess {

    private static final Logger LOGGER = Logger.getLogger(PublicPolicyAccess.class.getName());

    static final Set<PosixFilePermission> DIR = PosixFilePermissions.fromString("rwxr-xr-x");
    static final Set<PosixFilePermission> FILE = PosixFilePermissions.fromString("rw-r--r--");

    enum Outcome { NOTHING, DONE, LEFT }

    record Report(Outcome outcome, String detail) {}

    private PublicPolicyAccess() {}

    /** Writes the policy: a new file alongside, with the right permissions, then renamed into place. */
    static void write(Path dir, Path file, String text) throws IOException {
        Files.createDirectories(dir);
        PosixFileAttributes d = attributes(dir);
        if (d == null || !d.isDirectory())
            throw new IOException(dir + " is not a directory (or is a link): left as it is");
        if (!DIR.equals(d.permissions())) setPermissions(dir, DIR);
        Path next = dir.resolve("." + file.getFileName() + ".new");
        Files.deleteIfExists(next);
        Files.writeString(next, text, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        setPermissions(next, FILE);
        Files.move(next, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    /**
     * The servers on which the policy was already written with the service's umask: folder and file set to the
     * right permissions. Nothing to do if they are missing or already right.
     */
    static Report repair(Path dir, Path file) throws IOException {
        PosixFileAttributes d = attributes(dir);
        if (d == null) return new Report(Outcome.NOTHING, "");
        if (!d.isDirectory()) return new Report(Outcome.LEFT, dir + " is not a directory (or is a link): left as it is");
        StringBuilder done = new StringBuilder();
        if (!DIR.equals(d.permissions())) {
            done.append(dir).append(' ').append(PosixFilePermissions.toString(d.permissions())).append(" -> rwxr-xr-x");
            setPermissions(dir, DIR);
        }
        PosixFileAttributes f = attributes(file);
        if (f != null) {
            if (!f.isRegularFile()) {
                return new Report(Outcome.LEFT, (done.isEmpty() ? "" : done + "; ")
                        + file + " is not a regular file (or is a link): left as it is");
            }
            if (!FILE.equals(f.permissions())) {
                if (!done.isEmpty()) done.append("; ");
                done.append(file).append(' ').append(PosixFilePermissions.toString(f.permissions())).append(" -> rw-r--r--");
                setPermissions(file, FILE);
            }
        }
        return done.isEmpty() ? new Report(Outcome.NOTHING, "") : new Report(Outcome.DONE, done.toString());
    }

    public static void ensureAtBoot() {
        try {
            Report r = repair(Path.of(WebProtection.PUBLIC_DIR), Path.of(WebProtection.POLICY_FILE));
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[PublicPolicyAccess] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[PublicPolicyAccess] failed: " + t);
        }
    }

    /** The attributes without following a link, or null if the path does not exist. */
    private static PosixFileAttributes attributes(Path p) throws IOException {
        if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) return null;
        return Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    }

    private static void setPermissions(Path p, Set<PosixFilePermission> perms) throws IOException {
        Files.getFileAttributeView(p, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).setPermissions(perms);
    }
}
