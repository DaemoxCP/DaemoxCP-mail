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
 * Where root writes only if nobody else can change the path (finding 221).
 *
 * <p>The panel's Sieve rules are in /var/mail/sieve, owned by root, but /var/mail is root:mail 0775 (FreeBSD, mtree): with
 * the mail group one could rename the whole /var/mail/sieve and put another one in its place, measured on the VM. And the
 * panel wrote the rules as root following links (SafeNames.under looks only at the text of the path): a
 * .dovecot.sieve that was a link made root rewrite the file it pointed to (owned by nobody, 0600). Together: whoever
 * had the mail group (postfix, clamav, dma which is setgid mail and anyone can run, and the Dovecot mailbox
 * processes with mail_privileged_group) could make root rewrite any file.
 *
 * <p>Here the rules for root:
 * <ul>
 *   <li>every folder from / to the one being written into is a real folder (never a link) owned by root, or by the user
 *       of the process; nobody else writes in it. Above the one being written into the sticky bit is enough (like /tmp,
 *       and /var/mail since finding 221): whoever writes there cannot rename or remove what belongs to root. So nobody
 *       else can change the path between the check and the write, and the later steps by path are safe;</li>
 *   <li>the file is written new next to it, with a random name that does not exist (CREATE_NEW: a name already present,
 *       even a link, is not opened), owner, group and permissions set without following links, then rename onto the
 *       real name: a link there is replaced, never followed, and Dovecot sees the file whole or not at all;</li>
 *   <li>if a folder does not pass, nothing is written: the reason goes into the caller's log.</li>
 * </ul>
 * Measured on the VM (OpenJDK 25 on FreeBSD 15.1): CREATE_NEW on a link gives FileAlreadyExists, the rename over a
 * link leaves the file it pointed to intact, "unix:mode" reads and writes the sticky bit.
 */
public final class RootOnlyPath {

    private RootOnlyPath() {}

    private static final int TYPE = 0170000, FOLDER = 0040000, LINK = 0120000, STICKY = 01000, OTHERS_WRITE = 022;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Set<PosixFilePermission> FOLDER_MODE = PosixFilePermissions.fromString("rwxr-xr-x");

    /** The user of the process: root for the root part. A folder of its own cannot be changed by anyone else. */
    private static final int SELF = selfUid();

    private static int selfUid() {
        try {
            return (int) new com.sun.security.auth.module.UnixSystem().getUid();
        } catch (Throwable t) {
            return 0;
        }
    }

    /**
     * Null if from / down to dir every folder is a real folder owned by root (or by the process) that nobody else can
     * change; otherwise the reason. Above dir, others writing is allowed only with the sticky bit; in dir itself it is
     * not.
     */
    public static String problem(Path dir) {
        return chain(dir, false);
    }

    /** Like problem(), but dir can be sticky too: only folders are made in it, checked one by one afterwards. */
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

    /** A single folder: real, owned by root or by the process, writable by others only if sticky and if that is allowed. */
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
     * The folders under base, made if missing (owned by the process, rwxr-xr-x, the group from the one above as BSD
     * does), and checked one by one: a name already present that is not a real folder owned by root makes everything
     * fail. Base must pass the check, and can be sticky (like /var/mail).
     *
     * @return the last folder
     * @throws IOException with the reason, if a folder does not pass
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
                // already there: the check below says whether it is fine
            }
            why = level(next, false);
            if (why != null) throw new IOException(why);
            cur = next;
        }
        return cur;
    }

    /**
     * Puts the content into dir/name, in one go and without following links: a new file next to it with a random
     * name, owner, group and permissions set (null: those of the process, the folder's group, rw-------), then
     * rename onto the name. dir must pass {@link #problem(Path)}.
     *
     * @throws IOException with the reason; dir/name stays as it was
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
            try { Files.deleteIfExists(tmp); } catch (IOException ignored) { /* stays, with its random name */ }
            throw e;
        }
    }

    /**
     * A real file (never a link) in a folder that passes {@link #problem(Path)}, up to max bytes.
     *
     * @throws IOException with the reason
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
