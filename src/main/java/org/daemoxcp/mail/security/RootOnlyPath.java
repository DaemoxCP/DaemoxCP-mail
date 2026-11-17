package org.daemoxcp.mail.security;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Dove root scrive solo se nessun altro puo' cambiare il percorso (reperto 221).
 *
 * <p>Le regole Sieve del pannello stanno in /var/mail/sieve, di root, ma /var/mail e' root:mail 0775 (FreeBSD, mtree): con
 * il gruppo mail si rinominava /var/mail/sieve intera e se ne metteva un'altra al suo posto, misurato sulla VM. E il
 * pannello scriveva le regole da root seguendo i collegamenti (SafeNames.under guarda solo il testo del percorso): un
 * .dovecot.sieve che era un collegamento faceva riscrivere a root il file a cui puntava (di nobody, 0600). Insieme: chi
 * aveva il gruppo mail (postfix, clamav, dma che e' setgid mail e lo lancia chiunque, e i processi delle caselle di
 * Dovecot con mail_privileged_group) faceva riscrivere a root un file qualunque.
 *
 * <p>Qui le regole per root:
 * <ul>
 *   <li>ogni cartella da / a quella in cui si scrive e' una cartella vera (mai un collegamento) di root, o dell'utente
 *       del processo; nessun altro ci scrive. Sopra quella in cui si scrive basta il bit sticky (come /tmp, e /var/mail
 *       dal reperto 221): chi scrive li' non puo' rinominare ne' togliere quello che e' di root. Cosi' nessun altro puo'
 *       cambiare il percorso fra il controllo e la scrittura, e i passi dopo per percorso sono sicuri;</li>
 *   <li>il file si scrive nuovo accanto, con un nome a caso che non c'e' (CREATE_NEW: un nome gia' presente, anche un
 *       collegamento, non si apre), proprietario, gruppo e permessi dati senza seguire collegamenti, poi rename sul nome
 *       vero: un collegamento li' viene sostituito, mai seguito, e Dovecot vede il file tutto o niente;</li>
 *   <li>se una cartella non passa, non si scrive niente: il motivo va nel registro di chi chiama.</li>
 * </ul>
 * Misurato sulla VM (OpenJDK 25 su FreeBSD 15.1): CREATE_NEW su un collegamento da' FileAlreadyExists, il rename sopra un
 * collegamento lascia intatto il file a cui puntava, "unix:mode" legge e scrive il bit sticky.
 */
public final class RootOnlyPath {

    private RootOnlyPath() {}

    private static final int TYPE = 0170000, FOLDER = 0040000, LINK = 0120000, STICKY = 01000, OTHERS_WRITE = 022;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Set<PosixFilePermission> FOLDER_MODE = PosixFilePermissions.fromString("rwxr-xr-x");

    /** L'utente del processo: root per la parte root. Una cartella sua non la cambia nessun altro. */
    private static final int SELF = selfUid();

    private static int selfUid() {
        try {
            return (int) new com.sun.security.auth.module.UnixSystem().getUid();
        } catch (Throwable t) {
            return 0;
        }
    }

    /**
     * Null se da / fino a dir ogni cartella e' una cartella vera di root (o del processo) che nessun altro puo' cambiare;
     * altrimenti il motivo. Sopra dir chi scrive e' ammesso solo col bit sticky; dir stessa no.
     */
    public static String problem(Path dir) {
        return chain(dir, false);
    }

    /** Come problem(), ma anche dir puo' essere sticky: ci si fanno solo cartelle, controllate una per una dopo. */
    static String chain(Path dir, boolean lastMayBeSticky) {
        Path d = dir.toAbsolutePath().normalize();
        List<Path> levels = new ArrayList<>();
        Path p = d.getRoot();
        levels.add(p);
        for (Path name : d) {
            p = p.resolve(name.toString());
            levels.add(p);
        }
        for (int i = 0; i < levels.size(); i++) {
            boolean last = i == levels.size() - 1;
            String why = level(levels.get(i), !last || lastMayBeSticky);
            if (why != null) return why;
        }
        return null;
    }

    /** Una cartella sola: vera, di root o del processo, scritta da altri solo se sticky e se e' ammesso. */
    static String level(Path p, boolean stickyAllowed) {
        Map<String, Object> a;
        try {
            a = Files.readAttributes(p, "unix:mode,uid,owner", LinkOption.NOFOLLOW_LINKS);
        } catch (IOException | UnsupportedOperationException e) {
            return "cannot read " + p + ": " + e.getMessage();
        }
        int mode = (Integer) a.get("mode");
        int uid = (Integer) a.get("uid");
        if ((mode & TYPE) == LINK) return p + " is a link";
        if ((mode & TYPE) != FOLDER) return p + " is not a folder";
        if (uid != 0 && uid != SELF) return p + " belongs to " + a.get("owner") + ", not to root";
        if ((mode & OTHERS_WRITE) != 0 && !(stickyAllowed && (mode & STICKY) != 0))
            return p + " can be written by others (" + String.format("%04o", mode & 07777) + ")";
        return null;
    }

    private static String name(String n) {
        if (n == null || n.isEmpty() || n.contains("/") || n.equals(".") || n.equals(".."))
            throw new IllegalArgumentException("invalid path piece");
        return n;
    }

    /**
     * Le cartelle sotto base, fatte se mancano (del processo, rwxr-xr-x, il gruppo da quella sopra come fa BSD), e
     * controllate una per una: un nome gia' presente che non e' una cartella vera di root fa fallire tutto. Base deve
     * passare il controllo, e puo' essere sticky (come /var/mail).
     *
     * @return l'ultima cartella
     * @throws IOException col motivo, se una cartella non passa
     */
    public static Path folders(Path base, String... names) throws IOException {
        Path cur = base.toAbsolutePath().normalize();
        String why = chain(cur, true);
        if (why != null) throw new IOException(why);
        for (String n : names) {
            Path next = cur.resolve(name(n));
            try {
                Files.createDirectory(next);
                Files.getFileAttributeView(next, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).setPermissions(FOLDER_MODE);
            } catch (FileAlreadyExistsException e) {
                // c'e' gia': il controllo qui sotto dice se va bene
            }
            why = level(next, false);
            if (why != null) throw new IOException(why);
            cur = next;
        }
        return cur;
    }

    /**
     * Mette in dir/name il contenuto, in un colpo solo e senza seguire collegamenti: file nuovo accanto con un nome a
     * caso, proprietario, gruppo e permessi dati (null: quelli del processo, il gruppo della cartella, rw-------), poi
     * rename sul nome. dir deve passare {@link #problem(Path)}.
     *
     * @throws IOException col motivo; dir/name resta com'era
     */
    public static void replace(Path dir, String name, byte[] content, UserPrincipal owner, GroupPrincipal group,
                               Set<PosixFilePermission> mode) throws IOException {
        String why = problem(dir);
        if (why != null) throw new IOException(why);
        Path target = dir.resolve(name(name));
        Path tmp = dir.resolve(name + ".panel-" + Long.toHexString(RANDOM.nextLong() & Long.MAX_VALUE));
        try {
            try (FileChannel c = FileChannel.open(tmp, Set.<OpenOption>of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
                ByteBuffer b = ByteBuffer.wrap(content);
                while (b.hasRemaining()) c.write(b);
                c.force(true);
            }
            PosixFileAttributeView v = Files.getFileAttributeView(tmp, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (owner != null) v.setOwner(owner);
            if (group != null) v.setGroup(group);
            if (mode != null) v.setPermissions(mode);
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            try { Files.deleteIfExists(tmp); } catch (IOException ignored) { /* resta, col suo nome a caso */ }
            throw e;
        }
    }

    /**
     * Un file vero (mai un collegamento) di una cartella che passa {@link #problem(Path)}, fino a max byte.
     *
     * @throws IOException col motivo
     */
    public static byte[] read(Path file, int max) throws IOException {
        Path f = file.toAbsolutePath().normalize();
        String why = problem(f.getParent());
        if (why != null) throw new IOException(why);
        if (!Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)) throw new IOException(f + " is not a regular file");
        try (InputStream in = Files.newInputStream(f, LinkOption.NOFOLLOW_LINKS)) {
            byte[] b = in.readNBytes(max + 1);
            if (b.length > max) throw new IOException(f + " is larger than " + max + " bytes");
            return b;
        }
    }
}
