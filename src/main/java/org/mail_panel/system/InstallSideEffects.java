package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Logger;

/**
 * Cio' che un aggiornamento di pacchetti cambia FUORI dai file che pkg installa: la
 * configurazione viva e gli indirizzi in ascolto.
 *
 * I lavori dell'updater confrontavano pacchetti, versioni, protezioni e servizi attivi.
 * Nessuna di queste cose vede uno script di installazione che riscrive un file di
 * configurazione. Misurato sulla VM FreeBSD 15.1 il 24/10/2026 (reperto 42): aggiornando
 * postfix-mysql 3.11.7_1,1 -> 3.11.7_3,1 lo script ha scritto {@code inet_protocols = ipv4}
 * in /usr/local/etc/postfix/main.cf mentre postfix ascoltava in IPv4 e IPv6. Al riavvio IPv6
 * sparisce, e per ogni controllo che c'era il lavoro e' riuscito: configurazione valida,
 * servizio attivo, pid cambiato. Un server di posta con un record AAAA smette di ricevere in
 * IPv6 e il pannello dice «in servizio».
 *
 * Le domande sono due, e nessuna dipende dal pacchetto:
 *
 *  - quali file della configurazione sono cambiati senza essere file di un pacchetto che il
 *    lavoro ha cambiato. Su FreeBSD la configurazione viva non e' di nessun pacchetto: pkg
 *    installa main.cf.sample, main.cf e' dell'amministratore. Un file che nessun pacchetto
 *    aggiornato possiede, e che e' cambiato durante l'installazione, l'ha cambiato uno script.
 *  - quali indirizzi erano in ascolto prima e non lo sono piu' dopo.
 *
 * Elencare a mano i file "importanti" di ogni servizio sarebbe invecchiato al primo
 * pacchetto nuovo, ed e' lo stesso errore che questa classe deve prendere: si guarda tutta la
 * configurazione e si chiede a pkg di chi e' ogni file.
 */
final class InstallSideEffects {

    private static final Logger LOGGER = Logger.getLogger(InstallSideEffects.class.getName());

    private InstallSideEffects() {}

    /**
     * Dove sta la configurazione viva: tutta /usr/local/etc, tutta /etc, e la configurazione
     * del caricatore. A queste si aggiungono, una per una, le cartelle in cui un pacchetto
     * installato tiene i suoi .sample fuori da /usr/local/etc (Roundcube, in
     * /usr/local/www/roundcube/config): la configurazione sta dove sta il suo esempio.
     *
     * Di /etc prima si guardavano solo i file di rc.conf, e uno script che scrivesse in
     * /etc/periodic.conf non si sarebbe visto. Misurato sulla VM il 24/10/2026: 574 file, 3 MB,
     * nessuno di un pacchetto. Quello che ci cambia da solo, sempre misurato sulla VM negli
     * ultimi due giorni, ha una regola sua e non da' allarme: gli utenti che un pacchetto crea
     * (vedi {@link #ACCOUNT_FILES}), i file rigenerati da un altro (vedi {@link #isDerived}), e
     * resolv.conf (vedi {@link #EXCLUDED}).
     */
    static final List<String> CONFIG_ROOTS = List.of(
            "/usr/local/etc", "/etc", "/boot/loader.conf", "/boot/loader.conf.local", "/boot/loader.conf.d");

    /**
     * Cio' che si scrive da solo, in qualunque momento, e che nessun pacchetto installa:
     *  - la cartella del pannello: la scrive il pannello stesso (la configurazione del
     *    firewall, i segreti);
     *  - /etc/resolv.conf: lo riscrivono dhclient e resolvconf a ogni rinnovo dell'indirizzo.
     *    Misurato: riscritto all'avvio della VM. Dentro un aggiornamento sarebbe un allarme
     *    contro uno script che non c'entra, e un allarme ferma i riavvii del guidato.
     * Un loro cambiamento durante l'aggiornamento non dice niente sugli script di installazione.
     */
    static final List<String> EXCLUDED = List.of("/usr/local/etc/mail-panel", "/etc/resolv.conf");

    /**
     * Gli elenchi di utenti e gruppi. Un pacchetto che ha bisogno di un utente lo crea nel suo
     * script di pre-installazione («===> Creating users», misurato nell'uscita di postfix): una
     * RIGA AGGIUNTA qui e' un pacchetto che fa il suo mestiere, e si dice senza allarme. Una
     * riga tolta o cambiata no: e' un utente esistente toccato da uno script.
     */
    static final Set<String> ACCOUNT_FILES = Set.of("/etc/passwd", "/etc/group", "/etc/master.passwd");

    /**
     * La versione di prima dei file che uno script ha cambiato, per poterla rimettere. Sotto
     * /var/db/mailpanel, accanto alla nota dei blocchi, e non accanto ai file: in cartelle come
     * /usr/local/etc/newsyslog.conf.d o /usr/local/etc/periodic si legge, o si ESEGUE, ogni
     * file che c'e', e una copia messa li' diventerebbe configurazione anche lei.
     */
    static final Path BEFORE_UPDATE_DIR = Paths.get("/var/db/mailpanel/config-before-update");

    /** Quante copie si tengono: le piu' vecchie si tolgono. Contengono anche password, come i file da cui vengono. */
    static final int BEFORE_UPDATE_KEPT = 10;

    /** Il contenuto si tiene, per mostrare che cosa e' cambiato, solo fino a questa misura. */
    static final int MAX_KEPT_BYTES = 256 * 1024;

    /** Righe mostrate per file, per lato: il resto si conta e si dice. */
    static final int MAX_SHOWN_LINES = 12;

    /** Quanto si aspetta, al massimo, un indirizzo che manca: un demone appena riavviato puo' metterci qualche secondo ad aprirlo. */
    static final int LISTEN_GRACE_SECONDS = 60;

    /**
     * Lo stato di un file: l'impronta del contenuto, i permessi con proprietario e gruppo, e il
     * contenuto stesso se e' abbastanza piccolo. Il contenuto serve a dire che cosa e' cambiato;
     * si mostra solo se il file e' leggibile da tutti (vedi {@link #configChanges}).
     */
    record FileState(String sha256, String permissions, boolean worldReadable, byte[] content) {}

    /** La configurazione in un istante: percorso -> stato, e percorso -> pacchetto che lo possiede. */
    record ConfigSnapshot(Map<String, FileState> files, Map<String, String> owners) {}

    // ===================== la configurazione =====================

    /** La configurazione di questa macchina, adesso. */
    static ConfigSnapshot configSnapshot() {
        Map<String, String> owners = owners(Shell.runShell(Duration.ofSeconds(60),
                "pkg query -a '%n\t%Fp' 2>/dev/null").output(), CONFIG_ROOTS);
        List<Path> recursive = new ArrayList<>();
        for (String r : CONFIG_ROOTS) recursive.add(Paths.get(r));
        return configSnapshot(recursive, sampleDirsOutside(owners, CONFIG_ROOTS), owners);
    }

    /**
     * La fotografia di un insieme di cartelle, senza chiedere niente a pkg: cosi' si prova.
     *
     * @param recursive file o cartelle da guardare per intero
     * @param flat      cartelle da guardare senza scendere nelle sottocartelle
     * @param owners    percorso -> pacchetto, da {@link #owners(String)}
     */
    static ConfigSnapshot configSnapshot(List<Path> recursive, List<Path> flat, Map<String, String> owners) {
        Map<String, FileState> files = new TreeMap<>();
        for (Path root : recursive) collect(root, Integer.MAX_VALUE, files);
        for (Path dir : flat) collect(dir, 1, files);
        return new ConfigSnapshot(files, owners);
    }

    private static void collect(Path root, int depth, Map<String, FileState> into) {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return;
        // walkFileTree e non Files.walk: con Files.walk un file che sparisce mentre si scorre
        // la cartella (un temporaneo di qualcuno) interrompe TUTTA la fotografia, e
        // /usr/local/etc resterebbe fuori per un file solo. Qui quel file si salta e basta.
        // Senza FOLLOW_LINKS: un collegamento verso / non fa fotografare il disco intero.
        try {
            Files.walkFileTree(root, Set.of(), depth, new java.nio.file.SimpleFileVisitor<>() {
                @Override
                public java.nio.file.FileVisitResult preVisitDirectory(Path d, java.nio.file.attribute.BasicFileAttributes a) {
                    return excluded(d.toString()) ? java.nio.file.FileVisitResult.SKIP_SUBTREE
                                                  : java.nio.file.FileVisitResult.CONTINUE;
                }

                @Override
                public java.nio.file.FileVisitResult visitFile(Path p, java.nio.file.attribute.BasicFileAttributes a) {
                    if (a.isRegularFile() && !excluded(p.toString())) {
                        FileState st = state(p);
                        if (st != null) into.put(p.toString(), st);
                    }
                    return java.nio.file.FileVisitResult.CONTINUE;
                }

                @Override
                public java.nio.file.FileVisitResult visitFileFailed(Path p, IOException e) {
                    return java.nio.file.FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            LOGGER.warning("configuration snapshot: could not read " + root + ": " + e.getMessage());
        }
    }

    static boolean excluded(String path) {
        for (String e : EXCLUDED) if (path.equals(e) || path.startsWith(e + "/")) return true;
        return false;
    }

    /** Lo stato di un file, o null se non si e' potuto leggere. */
    static FileState state(Path p) {
        try {
            PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            Set<PosixFilePermission> perm = a.permissions();
            String permissions = PosixFilePermissions.toString(perm) + " " + a.owner().getName() + ":" + a.group().getName();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] kept = null;
            if (a.size() <= MAX_KEPT_BYTES) {
                kept = Files.readAllBytes(p);
                md.update(kept);
            } else {
                try (InputStream in = Files.newInputStream(p, LinkOption.NOFOLLOW_LINKS)) {
                    byte[] buf = new byte[65536];
                    for (int n; (n = in.read(buf)) > 0; ) md.update(buf, 0, n);
                }
            }
            return new FileState(HexFormat.of().formatHex(md.digest()), permissions,
                    perm.contains(PosixFilePermission.OTHERS_READ), kept);
        } catch (IOException | UnsupportedOperationException | java.security.NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * Di chi e' ogni file, da {@code pkg query -a '%n\t%Fp'}: percorso -> nome del pacchetto.
     * Si tengono solo i file che possono interessare: quelli sotto le radici, e quelli delle
     * cartelle in cui un pacchetto tiene un .sample o un .dist. Questi ultimi tutti, non solo
     * gli esempi: accanto a config.inc.php.sample Roundcube installa defaults.inc.php, e un
     * file del pacchetto preso per configurazione di nessuno darebbe l'allarme a ogni suo
     * aggiornamento.
     */
    static Map<String, String> owners(String pkgQueryOutput, List<String> roots) {
        List<String[]> all = new ArrayList<>();
        Set<String> sampleDirs = new TreeSet<>();
        for (String line : (pkgQueryOutput == null ? "" : pkgQueryOutput).split("\n")) {
            int tab = line.indexOf('\t');
            if (tab <= 0) continue;
            String name = line.substring(0, tab).trim(), path = line.substring(tab + 1).trim();
            if (!UpdateManager.isValidName(name) || !path.startsWith("/")) continue;
            all.add(new String[]{path, name});
            if (isSample(path) && !underRoots(path, roots)) sampleDirs.add(parentOf(path));
        }
        Map<String, String> r = new TreeMap<>();
        for (String[] e : all)
            if (underRoots(e[0], roots) || sampleDirs.contains(parentOf(e[0]))) r.put(e[0], e[1]);
        return r;
    }

    private static String parentOf(String path) {
        int s = path.lastIndexOf('/');
        return s <= 0 ? "/" : path.substring(0, s);
    }

    private static boolean isSample(String path) {
        return path.endsWith(".sample") || path.endsWith(".dist");
    }

    private static boolean underRoots(String path, List<String> roots) {
        for (String r : roots) if (path.equals(r) || path.startsWith(r + "/")) return true;
        return false;
    }

    /** Le cartelle che contengono un .sample o un .dist di un pacchetto, fuori dalle radici. */
    static List<Path> sampleDirsOutside(Map<String, String> owners, List<String> roots) {
        Set<String> dirs = new TreeSet<>();
        for (String p : owners.keySet())
            if (isSample(p) && !underRoots(p, roots)) dirs.add(parentOf(p));
        List<Path> r = new ArrayList<>();
        for (String d : dirs) r.add(Paths.get(d));
        return r;
    }

    /**
     * Che cosa e' cambiato fra le due fotografie, e se e' cosa da segnalare.
     *
     * Quattro casi, e solo l'ultimo fa scattare l'allarme:
     *  - "package": il file e' di un pacchetto che il lavoro ha cambiato. E' l'aggiornamento
     *    stesso, si conta e basta.
     *  - "newDefault": il file vivo non e' di nessuno ed e' adesso identico al .sample nuovo
     *    del suo pacchetto. Non era mai stato modificato e pkg l'ha sostituito con il
     *    predefinito nuovo, che e' cio' che fa con un esempio intatto.
     *  - "commentsOnly": cambiato da uno script, ma solo in righe di commento o vuote. Si dice,
     *    non cambia niente di quello che il servizio legge. Misurato: lo script di postfix
     *    aggiunge a master.cf quattro voci commentate.
     *  - "script": cambiato, creato, tolto o con altri permessi, senza che nessun pacchetto del
     *    lavoro lo possieda. E' il main.cf del reperto 42.
     *
     * @param changedPackages i pacchetti che il lavoro ha installato, aggiornato, reinstallato
     *        o tolto: quelli del piano e quelli cambiati fuori dal piano
     * @return un oggetto per ogni file cambiato: path, happened (changed, created, removed,
     *         permissions), owner, kind, alarm; per i file che si possono mostrare
     *         removedLines e addedLines, per gli altri hidden con il motivo
     */
    static JSONArray configChanges(ConfigSnapshot before, ConfigSnapshot after, Set<String> changedPackages) {
        JSONArray r = new JSONArray();
        Set<String> paths = new TreeSet<>(before.files().keySet());
        paths.addAll(after.files().keySet());
        for (String p : paths) {
            FileState b = before.files().get(p), a = after.files().get(p);
            if (b != null && a != null && b.sha256().equals(a.sha256()) && b.permissions().equals(a.permissions()))
                continue;
            String happened = b == null ? "created" : a == null ? "removed"
                    : !b.sha256().equals(a.sha256()) ? "changed" : "permissions";
            String owner = after.owners().getOrDefault(p, before.owners().get(p));
            JSONObject c = new JSONObject().put("path", p).put("happened", happened)
                    .put("owner", owner == null ? "" : owner);
            if (b != null && a != null && !b.permissions().equals(a.permissions()))
                c.put("permissionsFrom", b.permissions()).put("permissionsTo", a.permissions());

            String kind;
            if (owner != null && changedPackages.contains(owner)) kind = "package";
            else if (owner == null && isDerived(p, before, after)) kind = "derived";
            else if (owner == null && a != null && isNewDefault(p, a, after, changedPackages)) kind = "newDefault";
            else if (owner == null && a == null && sampleWentWithPackage(p, before, after, changedPackages)) kind = "package";
            else kind = "script";

            // Che cosa e' cambiato dentro, quando lo si puo' sapere. Il contenuto si legge
            // per decidere se sono solo commenti anche quando non lo si puo' mostrare.
            if (!"package".equals(kind) && !"newDefault".equals(kind) && !"derived".equals(kind)) {
                byte[] oldC = b == null ? new byte[0] : b.content();
                byte[] newC = a == null ? new byte[0] : a.content();
                if (oldC != null && newC != null && isText(oldC) && isText(newC)) {
                    List<List<String>> d = lineDiff(new String(oldC, StandardCharsets.UTF_8),
                                                    new String(newC, StandardCharsets.UTF_8));
                    // Con i permessi cambiati no: un file reso illeggibile al demone, o leggibile a
                    // tutti, conta anche se dentro sono cambiati solo i commenti.
                    if ("changed".equals(happened) && !c.has("permissionsFrom")
                            && (!d.get(0).isEmpty() || !d.get(1).isEmpty())
                            && allComments(d.get(0)) && allComments(d.get(1)))
                        kind = "commentsOnly";
                    else if ("changed".equals(happened) && !c.has("permissionsFrom")
                            && ACCOUNT_FILES.contains(p) && d.get(0).isEmpty() && !d.get(1).isEmpty())
                        kind = "accounts";
                    boolean readable = (b == null || b.worldReadable()) && (a == null || a.worldReadable());
                    if ("changed".equals(happened) && d.get(0).isEmpty() && d.get(1).isEmpty()) {
                        // Stesse righe, altro ordine: in un file di configurazione l'ordine
                        // puo' contare (le regole di nginx, le mappe di postfix), quindi resta
                        // un allarme, ma non c'e' una riga da mostrare.
                        c.put("hidden", "sameLines");
                    } else if (readable) {
                        c.put("removedLines", shown(d.get(0))).put("removedCount", d.get(0).size());
                        c.put("addedLines", shown(d.get(1))).put("addedCount", d.get(1).size());
                    } else {
                        // Un file che non tutti possono leggere puo' contenere una password
                        // (le mappe MySQL di postfix, la connessione SQL di dovecot): il suo
                        // contenuto non finisce nel log del lavoro, nemmeno oscurato.
                        c.put("hidden", "notWorldReadable");
                    }
                } else if (!"permissions".equals(happened)) {
                    c.put("hidden", oldC == null || newC == null ? "tooLarge" : "binary");
                }
            }
            c.put("kind", kind).put("alarm", "script".equals(kind));
            r.put(c);
        }
        return r;
    }

    /**
     * Un file che si rigenera da un altro, e che quindi cambia quando cambia la sua fonte:
     * l'allarme, se c'e', lo da' la fonte.
     *  - X.db, X.lmdb, X.cdb accanto a X: le mappe di postmap e newaliases (/etc/aliases.db),
     *    /etc/login.conf.db;
     *  - /etc/pwd.db e /etc/spwd.db, che pwd_mkdb ricava da /etc/master.passwd;
     *  - /etc/ssl/cert.pem, /etc/ssl/certs e /etc/ssl/untrusted, che certctl ricava
     *    dall'archivio dei certificati. Misurato: circa 190 file rigenerati sulla VM negli
     *    ultimi due giorni, nessuno scritto da una persona.
     */
    static boolean isDerived(String p, ConfigSnapshot before, ConfigSnapshot after) {
        if (p.equals("/etc/pwd.db") || p.equals("/etc/spwd.db") || p.equals("/etc/ssl/cert.pem")
                || p.startsWith("/etc/ssl/certs/") || p.startsWith("/etc/ssl/untrusted/")) return true;
        for (String ext : new String[]{".db", ".lmdb", ".cdb"}) {
            if (!p.endsWith(ext)) continue;
            String source = p.substring(0, p.length() - ext.length());
            if (before.files().containsKey(source) || after.files().containsKey(source)) return true;
        }
        return false;
    }

    /**
     * Mette da parte la versione di prima dei file indicati, sotto {@code dir} con il loro
     * percorso intero, con gli stessi permessi, proprietario e gruppo: cosi' {@code cp -p} la
     * rimette com'era. La cartella e' leggibile solo da root, perche' fra quei file ci sono le
     * mappe con le password.
     *
     * @return percorso -> dove e' la copia, oppure il motivo per cui non c'e' ("created": non
     *         c'era prima; "tooLarge": non se ne teneva il contenuto; "error: ...")
     */
    static Map<String, String> saveBefore(ConfigSnapshot before, List<String> paths, Path dir) {
        Map<String, String> r = new LinkedHashMap<>();
        for (String p : paths) {
            FileState b = before.files().get(p);
            if (b == null) { r.put(p, "created"); continue; }
            if (b.content() == null) { r.put(p, "tooLarge"); continue; }
            try {
                Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
                Path copy = dir.resolve(p.substring(1));
                Files.createDirectories(copy.getParent());
                Files.write(copy, b.content());
                String[] perm = b.permissions().split(" ", 2);
                Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString(perm[0]));
                String[] og = perm.length > 1 ? perm[1].split(":", 2) : new String[0];
                var lookup = copy.getFileSystem().getUserPrincipalLookupService();
                if (og.length == 2) {
                    Files.setOwner(copy, lookup.lookupPrincipalByName(og[0]));
                    Files.getFileAttributeView(copy, java.nio.file.attribute.PosixFileAttributeView.class)
                         .setGroup(lookup.lookupPrincipalByGroupName(og[1]));
                }
                r.put(p, copy.toString());
            } catch (IOException | RuntimeException e) {
                r.put(p, "error: " + e.getMessage());
            }
        }
        return r;
    }

    /** Toglie le copie piu' vecchie, tenendo le ultime {@code kept}: i nomi sono date UTC, quindi l'ordine e' quello dei nomi. */
    static void pruneBefore(Path root, int kept) {
        try (var s = Files.list(root)) {
            List<Path> dirs = new ArrayList<>(s.filter(Files::isDirectory).sorted().toList());
            for (int i = 0; i < dirs.size() - kept; i++) {
                try (var w = Files.walk(dirs.get(i))) {
                    for (Path x : w.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(x);
                }
            }
        } catch (IOException | RuntimeException e) {
            LOGGER.warning("could not prune " + root + ": " + e.getMessage());
        }
    }

    /** Il file vivo e' identico al .sample del suo pacchetto, cioe' e' il predefinito nuovo. */
    private static boolean isNewDefault(String p, FileState a, ConfigSnapshot after, Set<String> changedPackages) {
        for (String suffix : new String[]{".sample", ".dist"}) {
            FileState sample = after.files().get(p + suffix);
            String sampleOwner = after.owners().get(p + suffix);
            if (sample != null && sampleOwner != null && changedPackages.contains(sampleOwner)
                    && sample.sha256().equals(a.sha256())) return true;
        }
        return false;
    }

    /** Il file vivo se n'e' andato insieme al .sample del pacchetto che il lavoro ha tolto. */
    private static boolean sampleWentWithPackage(String p, ConfigSnapshot before, ConfigSnapshot after,
                                                 Set<String> changedPackages) {
        for (String suffix : new String[]{".sample", ".dist"}) {
            String owner = before.owners().get(p + suffix);
            if (owner != null && changedPackages.contains(owner) && !after.files().containsKey(p + suffix))
                return true;
        }
        return false;
    }

    static boolean isText(byte[] b) {
        for (byte x : b) if (x == 0) return false;
        return true;
    }

    /**
     * Le righe tolte e quelle aggiunte, contate come multinsieme: [tolte, aggiunte], ognuna
     * nell'ordine del proprio file. Per un file di configurazione e' la risposta che serve
     * («+ inet_protocols = ipv4») senza il costo di una diff vera, che su due file di qualche
     * migliaio di righe vorrebbe una tabella da milioni di celle.
     */
    static List<List<String>> lineDiff(String oldText, String newText) {
        Map<String, Integer> count = new LinkedHashMap<>();
        String[] o = lines(oldText), n = lines(newText);
        for (String l : o) count.merge(l, 1, Integer::sum);
        List<String> added = new ArrayList<>();
        for (String l : n) {
            Integer k = count.get(l);
            if (k != null && k > 0) count.put(l, k - 1);
            else added.add(l);
        }
        List<String> removed = new ArrayList<>();
        Map<String, Integer> left = new LinkedHashMap<>(count);
        for (String l : o) {
            Integer k = left.get(l);
            if (k != null && k > 0) { removed.add(l); left.put(l, k - 1); }
        }
        return List.of(removed, added);
    }

    /** Le righe di un testo. Il pezzo vuoto dopo l'ultimo a capo non e' una riga del file. */
    private static String[] lines(String text) {
        if (text.isEmpty()) return new String[0];
        String t = text.endsWith("\n") ? text.substring(0, text.length() - 1) : text;
        return t.split("\n", -1);
    }

    /** Commento o riga vuota, nelle due grafie dei file di /usr/local/etc: # e ; (php.ini). */
    static boolean allComments(List<String> lines) {
        for (String l : lines) {
            String t = l.trim();
            if (!t.isEmpty() && !t.startsWith("#") && !t.startsWith(";")) return false;
        }
        return true;
    }

    /** Le righe da mostrare: al massimo MAX_SHOWN_LINES, accorciate, con le credenziali oscurate. */
    private static JSONArray shown(List<String> lines) {
        JSONArray r = new JSONArray();
        for (int i = 0; i < lines.size() && i < MAX_SHOWN_LINES; i++) {
            String l = UpdateManager.oscuraCredenziali(lines.get(i)).replace('\t', ' ');
            r.put(l.length() > 160 ? l.substring(0, 160) + "..." : l);
        }
        return r;
    }

    // ===================== gli indirizzi in ascolto =====================

    /**
     * Gli indirizzi TCP in ascolto adesso: "tcp6 *:25" -> "master". Null se non si e' potuto
     * chiedere, che non e' "nessuno in ascolto".
     *
     * Solo TCP. In UDP {@code sockstat -l} elenca anche i socket con cui rspamd fa le sue
     * domande DNS, legati a *:* e diversi a ogni riavvio: misurati 25 su 63 righe sulla VM.
     * Confrontarli darebbe un allarme a ogni aggiornamento di rspamd.
     */
    static Map<String, String> listening() {
        Shell.Result r = Shell.runShell(Duration.ofSeconds(20), "sockstat -46lq -P tcp 2>/dev/null");
        return r.success() ? parseSockstat(r.output()) : null;
    }

    /**
     * Da {@code sockstat -46lq}: USER COMMAND PID FD PROTO LOCAL FOREIGN. La chiave e'
     * protocollo e indirizzo locale, non il pid: il pid cambia a ogni riavvio, l'indirizzo
     * deve restare.
     */
    static Map<String, String> parseSockstat(String out) {
        Map<String, String> r = new TreeMap<>();
        for (String line : (out == null ? "" : out).split("\n")) {
            String[] t = line.trim().split("\\s+");
            if (t.length < 6 || !t[4].startsWith("tcp")) continue;
            r.putIfAbsent(t[4] + " " + t[5], t[1]);
        }
        return r;
    }

    /** Gli indirizzi persi e quelli comparsi: {lost: [...], gained: [...]}, ognuno {address, command}. */
    static JSONObject compareListening(Map<String, String> before, Map<String, String> after) {
        JSONArray lost = new JSONArray(), gained = new JSONArray();
        for (Map.Entry<String, String> e : before.entrySet())
            if (!after.containsKey(e.getKey()))
                lost.put(new JSONObject().put("address", e.getKey()).put("command", e.getValue()));
        for (Map.Entry<String, String> e : after.entrySet())
            if (!before.containsKey(e.getKey()))
                gained.put(new JSONObject().put("address", e.getKey()).put("command", e.getValue()));
        return new JSONObject().put("lost", lost).put("gained", gained);
    }

    // ===================== un lavoro =====================

    /**
     * Le due fotografie di un lavoro e i problemi che il confronto ha trovato. Un lavoro ne
     * crea una, la fotografa subito prima di pkg upgrade e la interroga dopo; alla fine mette
     * {@link #problems()} nel proprio esito.
     *
     * Sta in un punto solo perche' la chiedono tre lavori (aggiornamento guidato, manutenzione
     * completa, aggiornamento dei non protetti), e la stessa decisione scritta tre volte e' gia'
     * diventata, in questa area, tre decisioni diverse.
     */
    static final class Watch {
        private boolean taken;
        private boolean changedByScript;
        private ConfigSnapshot configBefore;
        private Map<String, String> listeningBefore;
        private final List<String> problems = new ArrayList<>();

        /** Subito prima di pkg upgrade: la configurazione e gli indirizzi come li ha lasciati l'amministratore. */
        void takeBefore() {
            taken = true;
            try {
                configBefore = configSnapshot();
            } catch (RuntimeException e) {
                LOGGER.warning("configuration snapshot failed: " + e);
            }
            listeningBefore = listening();
        }

        /**
         * Dopo pkg upgrade: che cosa e' cambiato nella configurazione, fuori dai file dei
         * pacchetti. Si chiama anche quando pkg e' uscito diverso da zero: e' proprio il caso in
         * cui una macchina puo' essere rimasta a meta'.
         *
         * @param plan          il piano firmato, per sapere quali pacchetti il lavoro ha cambiato
         * @param outsidePlan   i pacchetti cambiati fuori dal piano (gia' segnalati a parte)
         * @param restartFollows true se il lavoro riavvia i servizi subito dopo (l'aggiornamento
         *                      guidato): allora la modifica entra in vigore fra poco, non al
         *                      prossimo riavvio
         */
        void checkConfig(UpdateManager.Job job, JSONObject plan, JSONArray outsidePlan, boolean restartFollows) {
            // Un lavoro che si e' fermato prima di pkg upgrade non ha cambiato niente: non c'e'
            // un prima da confrontare, e un «non ho potuto controllare» sarebbe falso.
            if (!taken) return;
            job.scrivi("  " + I18n.tr("server.drift.configHeader"));
            if (configBefore == null) {
                job.scrivi("    ?   " + I18n.tr("server.drift.configUnknown"));
                return;
            }
            JSONArray changes;
            try {
                changes = configChanges(configBefore, configSnapshot(), changedPackages(plan, outsidePlan));
            } catch (RuntimeException e) {
                LOGGER.warning("configuration comparison failed: " + e);
                job.scrivi("    ?   " + I18n.tr("server.drift.configUnknown"));
                return;
            }
            int packageFiles = 0, derivedFiles = 0;
            List<String> alarmed = new ArrayList<>();
            for (int i = 0; i < changes.length(); i++) {
                JSONObject c = changes.getJSONObject(i);
                String kind = c.getString("kind");
                if ("package".equals(kind)) { packageFiles++; continue; }
                if ("derived".equals(kind)) { derivedFiles++; continue; }
                String mark = c.getBoolean("alarm") ? "NO  " : "--  ";
                job.scrivi("    " + mark + c.getString("path") + ": "
                        + I18n.tr("server.drift.happened." + c.getString("happened"))
                        + ", " + I18n.tr("server.drift.kind." + kind));
                if (c.has("permissionsFrom"))
                    job.scrivi("          " + I18n.tr("server.drift.permissions",
                            Map.of("from", c.getString("permissionsFrom"), "to", c.getString("permissionsTo"))));
                writeLines(job, c, "removedLines", "removedCount", "- ");
                writeLines(job, c, "addedLines", "addedCount", "+ ");
                if (c.has("hidden"))
                    job.scrivi("          " + I18n.tr("server.drift.hidden." + c.getString("hidden")));
                if (c.getBoolean("alarm")) alarmed.add(c.getString("path"));
            }
            if (alarmed.isEmpty() && changes.length() == packageFiles + derivedFiles) {
                job.scrivi("    ok  " + I18n.tr("server.drift.configClean", Map.of("n", String.valueOf(packageFiles))));
                if (derivedFiles > 0)
                    job.scrivi("    " + I18n.tr("server.drift.derivedFiles", Map.of("n", String.valueOf(derivedFiles))));
                return;
            }
            if (packageFiles > 0)
                job.scrivi("    " + I18n.tr("server.drift.packageFiles", Map.of("n", String.valueOf(packageFiles))));
            if (derivedFiles > 0)
                job.scrivi("    " + I18n.tr("server.drift.derivedFiles", Map.of("n", String.valueOf(derivedFiles))));
            if (alarmed.isEmpty()) return;
            changedByScript = true;
            writeSaved(job, saveBefore(configBefore, alarmed, BEFORE_UPDATE_DIR.resolve(
                    java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                            .withZone(java.time.ZoneOffset.UTC).format(java.time.Instant.now()))));
            pruneBefore(BEFORE_UPDATE_DIR, BEFORE_UPDATE_KEPT);
            job.scrivi("  " + I18n.tr(restartFollows ? "server.drift.configNoteHeld" : "server.drift.configNoteLater"));
            problems.add(I18n.tr("server.drift.configProblem", Map.of("files", String.join(", ", alarmed))));
            // Fuori dal log del lavoro, che vive in memoria: una configurazione cambiata che
            // nessuno ha approvato deve restare scritta. Solo i percorsi, nessun contenuto (r19).
            LOGGER.warning("configuration changed by an installation script: " + alarmed);
        }

        /**
         * Alla fine del lavoro: gli indirizzi che erano in ascolto prima ci sono ancora?
         * Uno che manca si aspetta fino a {@link #LISTEN_GRACE_SECONDS}, perche' un demone
         * appena riavviato puo' metterci qualche secondo ad aprirlo.
         */
        void checkListening(UpdateManager.Job job) {
            if (!taken) return;
            job.scrivi("  " + I18n.tr("server.drift.listenHeader"));
            if (listeningBefore == null) {
                job.scrivi("    ?   " + I18n.tr("server.drift.listenUnknown"));
                return;
            }
            Map<String, String> now = listening();
            long deadline = System.currentTimeMillis() + LISTEN_GRACE_SECONDS * 1000L;
            while ((now == null || !compareListening(listeningBefore, now).getJSONArray("lost").isEmpty())
                    && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
                now = listening();
            }
            if (now == null) {
                job.scrivi("    ?   " + I18n.tr("server.drift.listenUnknown"));
                return;
            }
            JSONObject cmp = compareListening(listeningBefore, now);
            JSONArray lost = cmp.getJSONArray("lost"), gained = cmp.getJSONArray("gained");
            List<String> lostNames = new ArrayList<>();
            for (int i = 0; i < lost.length(); i++) {
                JSONObject l = lost.getJSONObject(i);
                lostNames.add(l.getString("address"));
                job.scrivi("    NO  " + l.getString("address") + " (" + l.getString("command") + "): "
                        + I18n.tr("server.drift.lost"));
            }
            for (int i = 0; i < gained.length(); i++) {
                JSONObject g = gained.getJSONObject(i);
                job.scrivi("    +   " + g.getString("address") + " (" + g.getString("command") + "): "
                        + I18n.tr("server.drift.gained"));
            }
            if (lost.isEmpty()) {
                job.scrivi("    ok  " + I18n.tr("server.drift.listenSame", Map.of("n", String.valueOf(listeningBefore.size()))));
                return;
            }
            problems.add(I18n.tr("server.drift.listenProblem", Map.of("list", String.join(", ", lostNames))));
            LOGGER.warning("listening addresses lost after an update: " + lostNames);
        }

        /** I problemi da mettere nell'esito del lavoro; vuoti se il confronto non ha trovato niente. */
        List<String> problems() { return new ArrayList<>(problems); }

        /**
         * True se uno script ha cambiato la configurazione fuori dai file dei pacchetti (un
         * allarme, non un predefinito rimesso o dei commenti). L'aggiornamento guidato lo
         * chiede prima di riavviare: vedi runAggiornamentoGuidato.
         */
        boolean configChangedByScript() { return changedByScript; }

        /** Dove e' la versione di prima di ogni file, e come la si rimette. */
        private static void writeSaved(UpdateManager.Job job, Map<String, String> saved) {
            String dir = null;
            for (Map.Entry<String, String> e : saved.entrySet()) {
                String v = e.getValue();
                if (v.equals("created")) job.scrivi("    " + I18n.tr("server.drift.savedCreated", Map.of("path", e.getKey())));
                else if (v.equals("tooLarge")) job.scrivi("    " + I18n.tr("server.drift.savedTooLarge", Map.of("path", e.getKey())));
                else if (v.startsWith("error: ")) job.scrivi("    " + I18n.tr("server.drift.savedError",
                        Map.of("path", e.getKey(), "error", v.substring(7))));
                else {
                    if (dir == null) {
                        dir = v.substring(0, v.length() - e.getKey().length());
                        job.scrivi("  " + I18n.tr("server.drift.savedHeader", Map.of("dir", dir)));
                    }
                    job.scrivi("      cp -p " + v + " " + e.getKey());
                }
            }
        }

        private static void writeLines(UpdateManager.Job job, JSONObject c, String key, String countKey, String sign) {
            JSONArray lines = c.optJSONArray(key);
            if (lines == null) return;
            for (int i = 0; i < lines.length(); i++) job.scrivi("          " + sign + lines.getString(i));
            int more = c.optInt(countKey) - lines.length();
            if (more > 0) job.scrivi("          " + I18n.tr("server.drift.moreLines", Map.of("n", String.valueOf(more))));
        }
    }

    /** I pacchetti che il lavoro ha cambiato: le righe del piano e quelli cambiati fuori dal piano. */
    static Set<String> changedPackages(JSONObject plan, JSONArray outsidePlan) {
        Set<String> r = new TreeSet<>();
        JSONArray changes = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; changes != null && i < changes.length(); i++) {
            String n = changes.getJSONObject(i).optString("nome");
            if (!n.isEmpty()) r.add(n);
        }
        for (int i = 0; outsidePlan != null && i < outsidePlan.length(); i++) {
            String n = outsidePlan.getJSONObject(i).optString("name");
            if (!n.isEmpty()) r.add(n);
        }
        return r;
    }
}
