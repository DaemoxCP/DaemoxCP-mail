package org.mail_panel.system;

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
 * La politica MTA-STS la legge nginx, che gira come www: cartella 0755 e file 0644, scritti e non lasciati all'umask.
 *
 * Il servizio del pannello gira con umask 077. Su un server installato da poco la cartella della politica nasceva 0700
 * e il file 0600, di root: nginx rispondeva 403 a /.well-known/mta-sts.txt, e «Set up everything» si fermava alla
 * configurazione della porta 443 dicendo solo che la politica non tornava (reperto 250, misurato sulla VM pulita il
 * 16/11/2026, seguendo la guida d'installazione). Il server vero non lo mostrava: la sua cartella era nata prima.
 *
 * Il contenuto e' pubblico per costruzione: lo legge chiunque su https://mta-sts.dominio/.well-known/mta-sts.txt, e
 * non contiene niente di segreto. La cartella resta di root: nessun altro ci scrive.
 *
 * Mai attraverso un collegamento: i permessi si cambiano senza seguirli (un collegamento al posto della cartella o del
 * file si lascia com'e' e si dice), e il file si scrive accanto e si rinomina al suo posto.
 */
public final class PublicPolicyAccess {

    private static final Logger LOGGER = Logger.getLogger(PublicPolicyAccess.class.getName());

    static final Set<PosixFilePermission> DIR = PosixFilePermissions.fromString("rwxr-xr-x");
    static final Set<PosixFilePermission> FILE = PosixFilePermissions.fromString("rw-r--r--");

    enum Outcome { NOTHING, DONE, LEFT }

    record Report(Outcome outcome, String detail) {}

    private PublicPolicyAccess() {}

    /** Scrive la politica: un file nuovo accanto, coi permessi giusti, poi rinominato al suo posto. */
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
     * I server su cui la politica e' gia' stata scritta con l'umask del servizio: cartella e file ai permessi giusti.
     * Niente da fare se mancano o sono gia' giusti.
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

    /** Gli attributi senza seguire un collegamento, o null se il percorso non c'e'. */
    private static PosixFileAttributes attributes(Path p) throws IOException {
        if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) return null;
        return Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    }

    private static void setPermissions(Path p, Set<PosixFilePermission> perms) throws IOException {
        Files.getFileAttributeView(p, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).setPermissions(perms);
    }
}
