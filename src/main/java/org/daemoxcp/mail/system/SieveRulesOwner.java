package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * The folder of the panel's Sieve rules owned by root again (finding 225).
 *
 * <p>On the production server (2026-11-10) /var/mail/sieve was vmail:vmail 755, and so were the domain's
 * folder, global and two of the three mailbox folders; the panel's rules were partly owned by vmail (755),
 * partly root:vmail (644), plus the Dovecot log (vmail, 600). The installation of 2026-10-11 had left it like
 * that, and no migration gave it back to root: finding 220 had fixed only the script that gave it to vmail.
 * Since finding 221 root writes the rules only where nobody else can change the path (RootOnlyPath): with the
 * folder owned by vmail it refuses, and the panel would have answered "not written" at every save of those
 * mailboxes, and left their rules with the forced keep (SieveForcedKeep). Seen in the snapshot taken before
 * the switch, which stopped there.
 *
 * <p>Here, at the start of the root part and before MailSpoolSticky (which would otherwise report the folder as
 * a problem):
 * <ul>
 *   <li>the whole tree is examined without following links. If there is a link, a file with more than one
 *       name (a hard link: vmail could make one to a root file on the same disk, for example /var/mail/root,
 *       and make it readable by everyone), something that is not a file or a folder, or something that is not
 *       owned by root or vmail, nothing is changed: it says what and why;</li>
 *   <li>otherwise, from top to bottom, the folders and the rule files (.dovecot.sieve and its compiled
 *       .dovecot.svbin) become root's: those that were vmail's become root:mail, folders 0755 and rules 0644
 *       (Dovecot, which delivers as vmail, still reads them); those already root's only lose write for others.
 *       Each entry is re-read right before touching it: the folder above is already root's, so vmail can no
 *       longer swap it. The other files (the Dovecot log, .dovecot.sieve.log) stay as they are;</li>
 *   <li>afterwards everything is re-read; if something does not add up, every entry goes back to how it was.</li>
 * </ul>
 * Nothing is widened: a root folder keeps its mode minus write for others. At the second startup there is
 * nothing to do. The rules with the forced keep are fixed right after by SieveForcedKeep, which recompiles them.
 */
public final class SieveRulesOwner {

    private static final Logger LOGGER = Logger.getLogger(SieveRulesOwner.class.getName());

    /** The rules folder: not final, the tests move it. */
    static Path rules = Path.of("/var/mail/sieve");
    static final String MAIL_USER = "vmail";
    static final String GROUP = "mail";
    /** The panel's files in a mailbox folder: the rules and their compiled file. */
    static final Set<String> PANEL_FILES = Set.of(".dovecot.sieve", ".dovecot.svbin");
    static final int MAX_ENTRIES = 100_000;

    private static final int TYPE = 0170000, FOLDER = 0040000, REGULAR = 0100000, LINK = 0120000, OTHERS_WRITE = 022;

    private SieveRulesOwner() {}

    /** An entry of the tree as it was before: to know what to change and to put it back. */
    record Entry(Path path, boolean folder, boolean panelFile, String owner, int uid, int gid, int mode) {

        /** This entry is to be handled: a folder or a rules file owned by vmail, or writable by others. */
        boolean needsChange() {
            return (folder || panelFile) && (uid != 0 || (mode & OTHERS_WRITE) != 0);
        }

        /**
         * The mode it must have: taken from vmail, the one Dovecot reads; already root's, its own without write
         * for others.
         */
        int wantedMode() {
            if (uid != 0) return folder ? 0755 : 0644;
            return mode & ~OTHERS_WRITE;
        }
    }

    /** At the start of the root part. */
    public static void ensureAtBoot() {
        try {
            String r = ensure(rules, MAIL_USER, GROUP);
            if (r == null) return;
            if (r.startsWith("DONE")) LOGGER.info("[SieveRulesOwner] " + r);
            else LOGGER.warning("[SieveRulesOwner] " + r);
        } catch (Throwable t) {
            LOGGER.warning("[SieveRulesOwner] failed: " + t);
        }
    }

    /**
     * Null if there was nothing to do; "DONE: ..." if done; "ROLLED_BACK: ..." if put back as it was; otherwise
     * why it stays as it is (and nothing has been changed).
     */
    static synchronized String ensure(Path root, String mailUser, String groupName) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return null;
        List<Entry> tree = new ArrayList<>();
        String why = scan(root, mailUser, tree);
        if (why != null) return "left as it is, nothing changed: " + why;
        List<Entry> todo = tree.stream().filter(Entry::needsChange).toList();
        if (todo.isEmpty()) return null;
        String parent = parentProblem(root.toAbsolutePath().getParent());
        if (parent != null) return "left as it is, nothing changed: " + parent;

        UserPrincipalLookupService look = root.getFileSystem().getUserPrincipalLookupService();
        UserPrincipal rootUser = look.lookupPrincipalByName("root");
        GroupPrincipal group = look.lookupPrincipalByGroupName(groupName);
        List<Entry> changed = new ArrayList<>();
        try {
            // The tree is in top-down order (first the folder, then what it contains).
            for (Entry e : todo) {
                String again = check(e.path(), mailUser, e.folder());
                if (again != null) throw new IOException(again);
                Map<String, Object> now = Files.readAttributes(e.path(), "unix:uid,gid,mode", LinkOption.NOFOLLOW_LINKS);
                if ((Integer) now.get("uid") != e.uid() || ((Integer) now.get("mode") & 07777) != e.mode())
                    throw new IOException(e.path() + " changed while it was being looked at");
                changed.add(e);
                PosixFileAttributeView v = Files.getFileAttributeView(e.path(), PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
                if (e.uid() != 0) {
                    v.setOwner(rootUser);
                    v.setGroup(group);
                }
                Files.setAttribute(e.path(), "unix:mode", e.wantedMode(), LinkOption.NOFOLLOW_LINKS);
            }
            String wrong = verify(todo);
            if (wrong != null) throw new IOException(wrong);
        } catch (IOException | RuntimeException ex) {
            String back = putBack(changed);
            return "ROLLED_BACK: " + ex.getMessage() + (back == null ? "; every entry is as it was" : "; " + back);
        }
        long folders = todo.stream().filter(Entry::folder).count();
        long files = todo.size() - folders;
        long fromMailUser = todo.stream().filter(e -> e.uid() != 0).count();
        long others = tree.stream().filter(e -> !e.folder() && !e.panelFile()).count();
        return "DONE: " + root + " is root's again: " + folders + " folder(s) and " + files + " rule file(s) changed ("
                + fromMailUser + " belonged to " + mailUser + ", given to it by the installation of before; the others"
                + " could be written by others), folders 0755 and rules 0644 now, still readable by Dovecot: root writes"
                + " the panel's rules there again. " + others + " other file(s), Dovecot's own, left as they were";
    }

    /**
     * The tree from top to bottom, without following links. The reason if something is wrong: a link, a file
     * with more than one name, something that is not a file or a folder, owned by another user; null if it can
     * proceed.
     */
    static String scan(Path root, String mailUser, List<Entry> out) throws IOException {
        String why = check(root, mailUser, true);
        if (why != null) return why;
        List<Path> folders = new ArrayList<>();
        folders.add(root);
        out.add(entry(root, true, false));
        for (int i = 0; i < folders.size(); i++) {
            Path dir = folders.get(i);
            List<Path> children;
            try (Stream<Path> s = Files.list(dir)) {
                children = s.sorted().toList();
            }
            for (Path child : children) {
                if (out.size() >= MAX_ENTRIES) return root + " has more than " + MAX_ENTRIES + " entries";
                Map<String, Object> a = Files.readAttributes(child, "unix:mode", LinkOption.NOFOLLOW_LINKS);
                boolean folder = ((Integer) a.get("mode") & TYPE) == FOLDER;
                why = check(child, mailUser, folder);
                if (why != null) return why;
                if (folder) folders.add(child);
                out.add(entry(child, folder, !folder && PANEL_FILES.contains(child.getFileName().toString())));
            }
        }
        // From top to bottom: each folder before what it contains (listing by folder already guarantees it for the
        // direct children; sorting by depth handles the levels below).
        out.sort((x, y) -> Integer.compare(x.path().getNameCount(), y.path().getNameCount()));
        return null;
    }

    /** A single entry, re-read without following links: null if it is as expected. */
    static String check(Path p, String mailUser, boolean folder) throws IOException {
        Map<String, Object> a = Files.readAttributes(p, "unix:mode,uid,owner,nlink", LinkOption.NOFOLLOW_LINKS);
        int type = (Integer) a.get("mode") & TYPE;
        if (type == LINK) return p + " is a link";
        if (folder && type != FOLDER) return p + " is not a folder any more";
        if (!folder && type != REGULAR) return p + " is not a file or a folder";
        String owner = String.valueOf(((UserPrincipal) a.get("owner")).getName());
        if ((Integer) a.get("uid") != 0 && !owner.equals(mailUser)) return p + " belongs to " + owner + ", not to root or " + mailUser;
        if (!folder && (Integer) a.get("nlink") != 1)
            return p + " has " + a.get("nlink") + " names (hard links): it could be a file of somebody else";
        return null;
    }

    private static Entry entry(Path p, boolean folder, boolean panelFile) throws IOException {
        Map<String, Object> a = Files.readAttributes(p, "unix:mode,uid,gid,owner", LinkOption.NOFOLLOW_LINKS);
        return new Entry(p, folder, panelFile, String.valueOf(((UserPrincipal) a.get("owner")).getName()),
                (Integer) a.get("uid"), (Integer) a.get("gid"), (Integer) a.get("mode") & 07777);
    }

    /** The folder that contains the rules folder (/var/mail): real and owned by root, or nothing is touched. */
    static String parentProblem(Path parent) throws IOException {
        if (parent == null) return "no folder above the rules";
        Map<String, Object> a = Files.readAttributes(parent, "unix:mode,uid", LinkOption.NOFOLLOW_LINKS);
        if (((Integer) a.get("mode") & TYPE) != FOLDER) return parent + " is not a real folder";
        if ((Integer) a.get("uid") != 0) return parent + " does not belong to root";
        return null;
    }

    /** Every changed entry is as it must be: root's, with the intended mode. The reason if not. */
    static String verify(List<Entry> todo) throws IOException {
        for (Entry e : todo) {
            Map<String, Object> a = Files.readAttributes(e.path(), "unix:mode,uid", LinkOption.NOFOLLOW_LINKS);
            int mode = (Integer) a.get("mode");
            if ((mode & TYPE) == LINK) return e.path() + " is a link now";
            if ((Integer) a.get("uid") != 0) return e.path() + " read back as not root's";
            if ((mode & 07777) != e.wantedMode())
                return e.path() + " read back as " + String.format("%04o", mode & 07777) + " instead of " + String.format("%04o", e.wantedMode());
        }
        return null;
    }

    /**
     * The changed entries put back as they were, from bottom to top. Null if all are back; otherwise those that
     * are not. An entry already as it was is skipped: it is the one on which the change failed (for example a
     * file with the schg flag), which cannot even be put back.
     */
    static String putBack(List<Entry> changed) {
        List<String> failed = new ArrayList<>();
        for (int i = changed.size() - 1; i >= 0; i--) {
            Entry e = changed.get(i);
            try {
                Map<String, Object> now = Files.readAttributes(e.path(), "unix:uid,gid,mode", LinkOption.NOFOLLOW_LINKS);
                if ((Integer) now.get("uid") == e.uid() && (Integer) now.get("gid") == e.gid()
                        && ((Integer) now.get("mode") & 07777) == e.mode()) continue;
                Files.setAttribute(e.path(), "unix:mode", e.mode(), LinkOption.NOFOLLOW_LINKS);
                Files.setAttribute(e.path(), "unix:uid", e.uid(), LinkOption.NOFOLLOW_LINKS);
                Files.setAttribute(e.path(), "unix:gid", e.gid(), LinkOption.NOFOLLOW_LINKS);
            } catch (IOException | RuntimeException ex) {
                failed.add(e.path() + " (" + ex.getMessage() + ")");
            }
        }
        return failed.isEmpty() ? null : "NOT put back: " + String.join(", ", failed);
    }
}
