package org.mail_panel.system;

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
 * La cartella delle regole Sieve del pannello di nuovo di root (reperto 225).
 *
 * <p>Sul server vero (10/11/2026) /var/mail/sieve era di vmail:vmail 755, e cosi' la cartella del dominio, global e due
 * delle tre cartelle delle caselle; le regole del pannello in parte di vmail (755), in parte di root:vmail (644), piu' il
 * registro di Dovecot (vmail, 600). Cosi' l'aveva lasciata l'installazione dell'11/10/2026, e nessuna migrazione la
 * restituiva a root: il reperto 220 aveva corretto solo lo script che la dava a vmail. Dal reperto 221 root scrive le
 * regole solo dove nessun altro puo' cambiare il percorso (RootOnlyPath): con la cartella di vmail rifiuta, e il pannello
 * avrebbe risposto «non scritte» a ogni salvataggio di quelle caselle, e lasciato le loro regole col keep forzato
 * (SieveForcedKeep). Visto nella fotografia prima del passaggio, che si e' fermato li'.
 *
 * <p>Qui, all'avvio della parte root e prima di MailSpoolSticky (che altrimenti segnalerebbe la cartella come un
 * problema):
 * <ul>
 *   <li>si guarda tutto l'albero senza seguire collegamenti. Se c'e' un collegamento, un file con piu' nomi (un
 *       collegamento fisico: vmail poteva darne uno a un file di root dello stesso disco, per esempio /var/mail/root, e
 *       renderlo leggibile a tutti), qualcosa che non e' un file o una cartella, o qualcosa che non e' di root o di
 *       vmail, non si cambia niente: si dice cosa e perche';</li>
 *   <li>altrimenti, dall'alto in basso, le cartelle e i file delle regole (.dovecot.sieve e il suo compilato
 *       .dovecot.svbin) diventano di root: quelli che erano di vmail root:mail, cartelle 0755 e regole 0644 (Dovecot,
 *       che consegna come vmail, li legge ancora); quelli gia' di root perdono solo la scrittura per gli altri. Ogni voce
 *       si rilegge subito prima di toccarla: la cartella sopra e' gia' di root, quindi vmail non la puo' piu' scambiare.
 *       Gli altri file (il registro di Dovecot, .dovecot.sieve.log) restano come sono;</li>
 *   <li>dopo si rilegge tutto; se qualcosa non torna, ogni voce torna com'era.</li>
 * </ul>
 * Niente si allarga: una cartella di root resta col suo modo meno la scrittura per gli altri. Al secondo avvio non c'e'
 * niente da fare. Le regole col keep forzato le sistema subito dopo SieveForcedKeep, che le ricompila.
 */
public final class SieveRulesOwner {

    private static final Logger LOGGER = Logger.getLogger(SieveRulesOwner.class.getName());

    /** La cartella delle regole: non final, le prove la spostano. */
    static Path rules = Path.of("/var/mail/sieve");
    static final String MAIL_USER = "vmail";
    static final String GROUP = "mail";
    /** I file del pannello in una cartella di casella: le regole e il loro compilato. */
    static final Set<String> PANEL_FILES = Set.of(".dovecot.sieve", ".dovecot.svbin");
    static final int MAX_ENTRIES = 100_000;

    private static final int TYPE = 0170000, FOLDER = 0040000, REGULAR = 0100000, LINK = 0120000, OTHERS_WRITE = 022;

    private SieveRulesOwner() {}

    /** Una voce dell'albero com'era prima: per sapere cosa cambiare e per rimetterla. */
    record Entry(Path path, boolean folder, boolean panelFile, String owner, int uid, int gid, int mode) {

        /** Tocca a questa voce: una cartella o un file delle regole di vmail, o scrivibile da altri. */
        boolean needsChange() {
            return (folder || panelFile) && (uid != 0 || (mode & OTHERS_WRITE) != 0);
        }

        /** Il modo che deve avere: preso a vmail, quello che Dovecot legge; gia' di root, il suo senza la scrittura degli altri. */
        int wantedMode() {
            if (uid != 0) return folder ? 0755 : 0644;
            return mode & ~OTHERS_WRITE;
        }
    }

    /** All'avvio della parte root. */
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
     * Null se non c'era niente da fare; "DONE: ..." se fatto; "ROLLED_BACK: ..." se tornato com'era; altrimenti perche'
     * resta com'e' (e niente e' stato cambiato).
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
            // L'albero e' in ordine dall'alto in basso (prima la cartella, poi quello che contiene).
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
     * L'albero dall'alto in basso, senza seguire collegamenti. Il motivo se qualcosa non va: un collegamento, un file con
     * piu' nomi, qualcosa che non e' un file o una cartella, di un altro utente; null se si puo' procedere.
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
        // Dall'alto in basso: ogni cartella prima di quello che contiene (l'elenco per cartelle lo garantisce gia' per i
        // figli diretti; si ordina per profondita' per i livelli sotto).
        out.sort((x, y) -> Integer.compare(x.path().getNameCount(), y.path().getNameCount()));
        return null;
    }

    /** Una voce sola, riletta senza seguire collegamenti: null se e' come ci si aspetta. */
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

    /** La cartella che contiene quella delle regole (/var/mail): vera e di root, o non si tocca niente. */
    static String parentProblem(Path parent) throws IOException {
        if (parent == null) return "no folder above the rules";
        Map<String, Object> a = Files.readAttributes(parent, "unix:mode,uid", LinkOption.NOFOLLOW_LINKS);
        if (((Integer) a.get("mode") & TYPE) != FOLDER) return parent + " is not a real folder";
        if ((Integer) a.get("uid") != 0) return parent + " does not belong to root";
        return null;
    }

    /** Ogni voce cambiata e' come deve essere: di root, col modo voluto. Il motivo se no. */
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
     * Le voci cambiate com'erano, dal basso in alto. Null se tutte tornate; altrimenti quelle che non tornano. Una voce
     * gia' com'era si salta: e' quella su cui il cambio e' fallito (per esempio un file col flag schg), che non si puo'
     * nemmeno rimettere.
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
