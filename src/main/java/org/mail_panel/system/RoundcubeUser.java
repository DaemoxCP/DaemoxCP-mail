package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Roundcube col suo utente: l'utente e il gruppo "roundcube", un pool di php-fpm suo con un
 * socket suo, e i file della webmail che appartengono a lui e a nessun altro.
 *
 * <p>Prima Roundcube girava nel pool "www" di php-fpm, cioe' con lo stesso utente dei processi
 * di nginx. Un difetto in uno dei due consegnava all'altro tutto quello che poteva toccare: la
 * configurazione di Roundcube (la password del database, la des_key), quella del plugin SSO (la
 * chiave che apre i gettoni con la password master di Dovecot), le sessioni della webmail. Adesso
 * nginx puo' solo aprire il socket (listen.group = www), e quei file li legge solo roundcube.
 *
 * <p>Tre cose misurate sulla VM FreeBSD 15.1 il 31/10/2026 decidono come e' fatto:
 * <ul>
 *   <li>il post-install di php84 ricopia www.conf.default in www.conf se www.conf manca: togliere
 *       il file farebbe ripartire, al primo aggiornamento di PHP, un pool che gira come www. Quindi
 *       www.conf resta, con soli commenti: php-fpm lo accetta (php-fpm -t), purche' i commenti
 *       comincino con ";" -- con "#" lo rifiuta e non parte;</li>
 *   <li>il post-install di roundcube-php84 fa "chown www:www" di logs e temp a ogni installazione
 *       e aggiornamento: la proprieta' si riafferma a ogni avvio e dopo l'aggiornamento della
 *       webmail fatto dal pannello ({@link #repairOwnership()});</li>
 *   <li>la rotazione che il pacchetto installa (newsyslog.conf.d/roundcube.conf) ricrea i log come
 *       www:www: dopo la prima rotazione Roundcube non potrebbe piu' scriverli.</li>
 * </ul>
 *
 * <p>All'avvio ({@link #ensureAtBoot()}), sui server installati prima: crea utente e gruppo,
 * scrive il pool roundcube portandosi dietro i valori pm.* di quello www, lascia www.conf senza
 * pool, sistema la proprieta' dei file, sposta fastcgi_pass di nginx sul socket nuovo. Controlla con
 * php-fpm -t e nginx -t, ricarica, guarda che i processi del pool girino come roundcube e che la
 * webmail risponda con la sua pagina di accesso. Al primo passo che fallisce rimette tutto com'era
 * e ricarica: al prossimo avvio ci riprova. Non sceglie per nessuno: un www.conf che non e' quello
 * del pannello, un pool www che serve anche un altro sito, una webmail che gia' non risponde,
 * lasciano tutto com'e' e lo scrivono nel log.
 */
public final class RoundcubeUser {

    private static final Logger LOGGER = Logger.getLogger(RoundcubeUser.class.getName());

    public static final String USER = "roundcube";
    public static final String GROUP = "roundcube";
    /** Il gruppo dei processi di nginx: puo' aprire il socket del pool, e nient'altro. */
    public static final String WEB_GROUP = "www";
    public static final String POOL = "roundcube";
    public static final String SOCKET = "/var/run/php-fpm-roundcube.sock";
    /** Il socket del pool www, come lo scrivevano gli script d'installazione di prima. */
    public static final String OLD_SOCKET = "/var/run/php-fpm.sock";

    public static final String FPM_DIR = "/usr/local/etc/php-fpm.d";
    public static final String ROUNDCUBE_DIR = "/usr/local/www/roundcube";
    public static final String SESSIONS_DIR = "/var/db/mailpanel/php_sessions";
    public static final String PHP_ERRORS_LOG = "/var/log/php_errors.log";
    public static final String NEWSYSLOG_DIR = "/usr/local/etc/newsyslog.conf.d";
    public static final String SSO_KEY = "/var/db/mailpanel/roundcube_sso.key";
    /** La rotazione che installa il pacchetto di Roundcube, e il campione da cui la copia. */
    static final String ROUNDCUBE_ROTATION_SAMPLE = "/usr/local/share/examples/roundcube/newsyslog.conf";
    /** Le copie dei file prima della migrazione, per chi vuole guardarle: fuori da php-fpm.d. */
    static final String BACKUP_DIR = "/var/db/mailpanel/service-users-backup";

    /** Le righe del pool che il pannello sceglie; le altre (pm.*) si portano da quello di prima. */
    private static final Set<String> OWN_KEYS = Set.of("user", "group", "listen",
            "listen.owner", "listen.group", "listen.mode");

    private static final String DEFAULT_PM = """
            pm = dynamic
            pm.max_children = 10
            pm.start_servers = 3
            pm.min_spare_servers = 2
            pm.max_spare_servers = 5
            """;

    private RoundcubeUser() {}

    // ===================== i file che scrive il pannello =====================

    /** Il pool di Roundcube: utente suo, socket suo, nginx nel gruppo che lo apre. */
    public static String poolConf(String otherLines) {
        String rest = otherLines == null || otherLines.isBlank() ? DEFAULT_PM : otherLines;
        if (!rest.endsWith("\n")) rest += "\n";
        return "; " + PanelMarker.WRITTEN + "\n"
             + "; Il pool di Roundcube, col suo utente: non quello di nginx (www), non root.\n"
             + "; nginx apre il socket perche' sta nel gruppo www (listen.group); i file della\n"
             + "; webmail li legge solo roundcube.\n"
             + "[" + POOL + "]\n"
             + "user = " + USER + "\n"
             + "group = " + GROUP + "\n"
             + "listen = " + SOCKET + "\n"
             + "listen.owner = " + USER + "\n"
             + "listen.group = " + WEB_GROUP + "\n"
             + "listen.mode = 0660\n"
             + PhpHardening.LIMIT_COMMENT + PhpHardening.LIMIT
             + rest;
    }

    /** www.conf senza pool: c'e' solo perche' il pacchetto di PHP non lo ricrei. */
    public static String wwwPlaceholder() {
        return "; " + PanelMarker.WRITTEN + "\n"
             + "; Qui c'era il pool \"www\", con cui Roundcube girava come l'utente di nginx.\n"
             + "; Adesso Roundcube ha il suo pool, in " + POOL + ".conf, col suo utente.\n"
             + "; Il file resta, senza pool, di proposito: se www.conf manca, installare o\n"
             + "; aggiornare php84 ricopia qui www.conf.default, e php-fpm farebbe ripartire\n"
             + "; un pool che gira come www. I commenti cominciano con ';': php-fpm rifiuta '#'.\n";
    }

    /** La rotazione dei log di Roundcube, come quella del pacchetto ma col proprietario giusto. */
    static String roundcubeRotation() {
        return "# " + PanelMarker.WRITTEN + "\n"
             + "# La rotazione dei log di Roundcube: quella del pacchetto li ricreava come www:www,\n"
             + "# e dopo la prima rotazione la webmail non avrebbe piu' potuto scriverli.\n"
             + "# logfilename                 [owner:group] mode count size when  flags [/pid_file] [sig_num]\n"
             + ROUNDCUBE_DIR + "/logs/errors.log    " + USER + ":" + GROUP + "  640  10    1000 *     XCBN\n"
             + ROUNDCUBE_DIR + "/logs/sendmail.log  " + USER + ":" + GROUP + "  640  10    1000 *     XCBN\n";
    }

    /**
     * Il pezzo degli script d'installazione che da' a Roundcube il suo utente e il suo pool. Va
     * messo dove prima si scriveva www.conf; la proprieta' dei file la fa {@link #shellOwnership()},
     * dopo che i file ci sono.
     */
    public static String shellPool() {
        return "\n# Roundcube col suo utente e il suo pool di php-fpm, non quello di nginx (www).\n"
             + "pw groupshow " + GROUP + " >/dev/null 2>&1 || pw groupadd " + GROUP + "\n"
             + "pw usershow " + USER + " >/dev/null 2>&1 || pw useradd " + USER + " -g " + GROUP
             + " -d /nonexistent -s /usr/sbin/nologin -c \"Roundcube webmail\"\n"
             + "mkdir -p " + FPM_DIR + "\n"
             + "cat > " + FPM_DIR + "/" + POOL + ".conf << 'ROUNDCUBE_POOL'\n" + poolConf(null) + "ROUNDCUBE_POOL\n"
             + "cat > " + FPM_DIR + "/www.conf << 'WWW_PLACEHOLDER'\n" + wwwPlaceholder() + "WWW_PLACEHOLDER\n";
    }

    /** Il pezzo degli script d'installazione che da' a roundcube i suoi file. */
    public static String shellOwnership() {
        StringBuilder b = new StringBuilder("\n# I file di Roundcube: suoi, e di nessun altro.\n");
        for (Ownership o : ownershipPlan(Places.real())) {
            String p = o.path().toString();
            b.append("if [ -e ").append(p).append(" ]; then ");
            if (o.contents()) b.append("chown -R ");
            else b.append("chown ");
            b.append(o.user()).append(':').append(o.group()).append(' ').append(p)
             .append("; chmod ").append(octal(o.mode())).append(' ').append(p).append("; fi\n");
        }
        // La rotazione del pacchetto, se e' ancora quella del pacchetto.
        b.append("if [ -f ").append(ROUNDCUBE_ROTATION_SAMPLE).append(" ] && cmp -s ")
         .append(ROUNDCUBE_ROTATION_SAMPLE).append(' ').append(NEWSYSLOG_DIR).append("/roundcube.conf; then\n")
         .append("cat > ").append(NEWSYSLOG_DIR).append("/roundcube.conf << 'ROUNDCUBE_ROTATION'\n")
         .append(roundcubeRotation()).append("ROUNDCUBE_ROTATION\nfi\n");
        return b.toString();
    }

    /** La riga di newsyslog del registro degli errori di PHP: lo scrivono i processi di roundcube. */
    public static String phpErrorsRotationLine() {
        return PHP_ERRORS_LOG + "    " + USER + ":" + GROUP + "    640    7    1024    *    JC";
    }

    /**
     * Dove nginx deve passare le richieste PHP di Roundcube: il socket nuovo se il pool roundcube
     * c'e', quello di prima se la migrazione non e' ancora riuscita (rigenerare nginx.conf col
     * socket nuovo, senza il pool, spegnerebbe la webmail).
     */
    public static String fastcgiPass() {
        return "unix:" + (migrated(Places.real()) ? SOCKET : OLD_SOCKET);
    }

    /** L'utente con cui gira il PHP di Roundcube: roundcube dopo la migrazione, www prima. */
    public static String runtimeUser() {
        return migrated(Places.real()) ? USER : WEB_GROUP;
    }

    /** Il gruppo che legge le configurazioni della webmail: roundcube dopo la migrazione, www prima. */
    public static String runtimeGroup() {
        return migrated(Places.real()) ? GROUP : WEB_GROUP;
    }

    static boolean migrated(Places at) {
        try {
            Path pool = at.fpmDir().resolve(POOL + ".conf");
            return Files.isRegularFile(pool, LinkOption.NOFOLLOW_LINKS)
                    && PanelMarker.writtenByPanel(Files.readString(pool, StandardCharsets.UTF_8));
        } catch (IOException e) {
            return false;
        }
    }

    // ===================== la proprieta' dei file =====================

    /**
     * Un file o una cartella con proprietario, gruppo e permessi. contents: anche quello che c'e'
     * dentro (senza seguire i link), coi permessi degli altri tolti.
     */
    record Ownership(Path path, String user, String group, String mode, boolean contents) {}

    /** Dove stanno i file: fissi sul server, cartelle temporanee nella prova. */
    record Places(Path fpmDir, Path roundcubeDir, Path sessionsDir, Path phpErrorsLog,
                  Path newsyslogDir, Path rotationSample, Path ssoKey, Path backupDir) {
        static Places real() {
            return new Places(Path.of(FPM_DIR), Path.of(ROUNDCUBE_DIR), Path.of(SESSIONS_DIR),
                    Path.of(PHP_ERRORS_LOG), Path.of(NEWSYSLOG_DIR), Path.of(ROUNDCUBE_ROTATION_SAMPLE),
                    Path.of(SSO_KEY), Path.of(BACKUP_DIR));
        }
    }

    /**
     * Di chi devono essere i file della webmail. Le configurazioni le scrive root (il pannello) e
     * roundcube le legge col gruppo: non le puo' cambiare. Il codice del plugin SSO e' di root. La
     * chiave SSO la legge solo il pannello: il plugin ha il segreto nella sua configurazione.
     */
    static List<Ownership> ownershipPlan(Places at) {
        Path rc = at.roundcubeDir();
        Path sso = rc.resolve("plugins/mailpanel_sso");
        List<Ownership> l = new ArrayList<>();
        l.add(new Ownership(rc.resolve("config/config.inc.php"), "root", GROUP, "rw-r-----", false));
        l.add(new Ownership(sso, "root", "wheel", "rwxr-xr-x", false));
        l.add(new Ownership(sso.resolve("mailpanel_sso.php"), "root", "wheel", "rw-r--r--", false));
        l.add(new Ownership(sso.resolve("config.inc.php"), "root", GROUP, "rw-r-----", false));
        l.add(new Ownership(rc.resolve("temp"), USER, GROUP, "rwx------", true));
        l.add(new Ownership(rc.resolve("logs"), USER, GROUP, "rwxr-x---", true));
        l.add(new Ownership(at.sessionsDir(), USER, GROUP, "rwx------", true));
        l.add(new Ownership(at.phpErrorsLog(), USER, GROUP, "rw-r-----", false));
        l.add(new Ownership(at.ssoKey(), "root", "wheel", "rw-------", false));
        return l;
    }

    private static String octal(String mode) {
        int v = 0;
        for (char c : mode.toCharArray()) v = (v << 1) | (c == '-' ? 0 : 1);
        return String.format("%o", v);
    }

    /** Quello che c'era prima su un file: per rimetterlo. */
    private record Snapshot(Path path, String user, String group, Set<PosixFilePermission> perms) {}

    /**
     * Mette proprietario, gruppo e permessi giusti, e ricorda quelli di prima in {@code undo}.
     * Non segue mai i link: logs, temp e le sessioni erano scrivibili da www, e un link messo li'
     * dentro da chi aveva preso www, seguito da root, avrebbe dato a roundcube un file qualunque.
     * Ritorna i percorsi cambiati.
     */
    static List<String> apply(List<Ownership> plan, Deque<Snapshot> undo) throws IOException {
        List<String> changed = new ArrayList<>();
        for (Ownership o : plan) {
            if (!Files.exists(o.path(), LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(o.path())) continue;
            if (set(o.path(), o.user(), o.group(), PosixFilePermissions.fromString(o.mode()), undo))
                changed.add(o.path().toString());
            if (!o.contents() || !Files.isDirectory(o.path(), LinkOption.NOFOLLOW_LINKS)) continue;
            List<Path> inside;
            try (Stream<Path> s = Files.walk(o.path())) {
                inside = s.filter(p -> !p.equals(o.path())).toList();
            }
            for (Path p : inside) {
                if (Files.isSymbolicLink(p)) continue;
                Set<PosixFilePermission> perms = Files.readAttributes(p, PosixFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS).permissions();
                perms.remove(PosixFilePermission.OTHERS_READ);
                perms.remove(PosixFilePermission.OTHERS_WRITE);
                perms.remove(PosixFilePermission.OTHERS_EXECUTE);
                if (set(p, o.user(), o.group(), perms, undo)) changed.add(p.toString());
            }
        }
        return changed;
    }

    private static boolean set(Path p, String user, String group, Set<PosixFilePermission> perms,
                               Deque<Snapshot> undo) throws IOException {
        PosixFileAttributeView v = Files.getFileAttributeView(p, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        PosixFileAttributes a = v.readAttributes();
        if (a.owner().getName().equals(user) && a.group().getName().equals(group) && a.permissions().equals(perms))
            return false;
        undo.push(new Snapshot(p, a.owner().getName(), a.group().getName(), a.permissions()));
        UserPrincipalLookupService names = p.getFileSystem().getUserPrincipalLookupService();
        UserPrincipal u = names.lookupPrincipalByName(user);
        GroupPrincipal g = names.lookupPrincipalByGroupName(group);
        if (!a.owner().getName().equals(user)) v.setOwner(u);
        if (!a.group().getName().equals(group)) v.setGroup(g);
        if (!a.permissions().equals(perms)) v.setPermissions(perms);
        return true;
    }

    private static List<String> restore(Deque<Snapshot> undo) {
        List<String> problems = new ArrayList<>();
        while (!undo.isEmpty()) {
            Snapshot s = undo.pop();
            try {
                PosixFileAttributeView v = Files.getFileAttributeView(s.path(), PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
                UserPrincipalLookupService names = s.path().getFileSystem().getUserPrincipalLookupService();
                // Solo quello che e' cambiato: un file che non si e' potuto cambiare non si tocca di nuovo.
                PosixFileAttributes a = v.readAttributes();
                if (!a.owner().getName().equals(s.user())) v.setOwner(names.lookupPrincipalByName(s.user()));
                if (!a.group().getName().equals(s.group())) v.setGroup(names.lookupPrincipalByGroupName(s.group()));
                if (!a.permissions().equals(s.perms())) v.setPermissions(s.perms());
            } catch (IOException e) {
                problems.add(s.path() + ": " + e.getMessage());
            }
        }
        return problems;
    }

    /**
     * La proprieta' riaffermata, senza toccare i servizi: dopo un aggiornamento di Roundcube (il
     * post-install del pacchetto rimette logs e temp a www:www) e a ogni avvio. Solo se la
     * migrazione c'e' gia': prima, i file sono ancora di www perche' li legge il pool www.
     */
    public static List<String> repairOwnership() {
        Places at = Places.real();
        if (!migrated(at)) return List.of();
        List<String> changed = new ArrayList<>();
        try {
            changed.addAll(apply(ownershipPlan(at), new ArrayDeque<>()));
            Deque<FileEdit> edits = new ArrayDeque<>();
            for (FileEdit e : rotationEdits(at)) { e.apply(); edits.push(e); changed.add(e.path().toString()); }
        } catch (IOException e) {
            LOGGER.warning("[RoundcubeUser] cannot repair the ownership of the webmail files: " + e.getMessage());
        }
        return changed;
    }

    // ===================== le rotazioni dei log =====================

    /** Un file riscritto, con il testo di prima per rimetterlo. */
    record FileEdit(Path path, String before, String after) {
        void apply() throws IOException { write(path, after); }
        void undo() throws IOException {
            if (before == null) Files.deleteIfExists(path); else write(path, before);
        }
    }

    /**
     * Le due rotazioni che ricreano i log col proprietario: quella degli errori di PHP (la scrive
     * l'installazione del pannello) e quella di Roundcube (la copia il pacchetto dal suo campione).
     * Quella del pacchetto si riscrive solo se e' ancora uguale al campione: se qualcuno l'ha
     * cambiata, e' sua, e lo dice il controllo degli utenti dei servizi.
     */
    static List<FileEdit> rotationEdits(Places at) throws IOException {
        List<FileEdit> l = new ArrayList<>();
        Path php = at.newsyslogDir().resolve("php-errors.conf");
        if (Files.isRegularFile(php, LinkOption.NOFOLLOW_LINKS)) {
            String before = Files.readString(php, StandardCharsets.UTF_8);
            String after = before.replaceAll("(?m)^(" + Pattern.quote(at.phpErrorsLog().toString()) + "\\s+)www:www(\\s)",
                    "$1" + USER + ":" + GROUP + "$2");
            if (!after.equals(before)) l.add(new FileEdit(php, before, after));
        }
        Path rc = at.newsyslogDir().resolve("roundcube.conf");
        if (Files.isRegularFile(rc, LinkOption.NOFOLLOW_LINKS) && Files.isRegularFile(at.rotationSample())) {
            String before = Files.readString(rc, StandardCharsets.UTF_8);
            if (before.equals(Files.readString(at.rotationSample(), StandardCharsets.UTF_8)))
                l.add(new FileEdit(rc, before, roundcubeRotation().replace(ROUNDCUBE_DIR, at.roundcubeDir().toString())));
        }
        return l;
    }

    // ===================== il pool di prima =====================

    /** Un pool letto da un file di php-fpm.d: il nome e le sue righe chiave = valore, in ordine. */
    record Pool(String name, Map<String, String> values, List<String> lines) {
        String get(String k) { return values.get(k); }
    }

    /** I pool di un file di php-fpm (righe ";" di commento, sezioni [nome]). */
    static List<Pool> pools(String content) {
        List<Pool> out = new ArrayList<>();
        Pool cur = null;
        for (String raw : content.split("\n")) {
            String t = raw.trim();
            if (t.isEmpty() || t.startsWith(";")) continue;
            if (t.startsWith("[") && t.endsWith("]")) {
                cur = new Pool(t.substring(1, t.length() - 1).trim(), new LinkedHashMap<>(), new ArrayList<>());
                out.add(cur);
                continue;
            }
            if (cur == null) continue;
            int eq = t.indexOf('=');
            if (eq < 0) continue;
            String k = t.substring(0, eq).trim(), v = t.substring(eq + 1).trim();
            cur.values().put(k, v);
            cur.lines().add(k + " = " + v);
        }
        return out;
    }

    /** Il valore di listen come lo scrive nginx in fastcgi_pass: un percorso diventa unix:percorso. */
    static String nginxForm(String listen) {
        return listen.startsWith("/") ? "unix:" + listen : listen;
    }

    // ===================== nginx =====================

    /** Un blocco server di nginx che passa a php-fpm: il file, il nome e la porta su cui risponde. */
    record Site(Path file, String name, String port, boolean roundcube) {}

    /** I file della configurazione di nginx com'e' davvero, dall'uscita di nginx -T. */
    static Map<Path, String> configFiles(String dump) {
        Map<Path, String> out = new LinkedHashMap<>();
        Matcher m = Pattern.compile("(?m)^# configuration file (.+):$").matcher(dump == null ? "" : dump);
        Path cur = null;
        int from = 0;
        while (m.find()) {
            if (cur != null) out.put(cur, dump.substring(from, m.start()));
            cur = Path.of(m.group(1).trim());
            from = m.end() + 1;
        }
        if (cur != null) out.put(cur, dump.substring(Math.min(from, dump.length())));
        return out;
    }

    /** Il testo senza i commenti di nginx (da # a fine riga, fuori dalle virgolette). */
    static String withoutComments(String c) {
        StringBuilder b = new StringBuilder();
        boolean inQuote = false;
        char q = 0;
        for (int i = 0; i < c.length(); i++) {
            char ch = c.charAt(i);
            if (inQuote) {
                b.append(ch);
                if (ch == q) inQuote = false;
            } else if (ch == '"' || ch == '\'') {
                inQuote = true; q = ch; b.append(ch);
            } else if (ch == '#') {
                while (i < c.length() && c.charAt(i) != '\n') i++;
                if (i < c.length()) b.append('\n');
            } else b.append(ch);
        }
        return b.toString();
    }

    private static final Pattern SERVER_OPEN = Pattern.compile("(?:^|[;{}\\s])server\\s*\\{");

    /** I blocchi server { ... } di un file, gia' senza commenti. */
    static List<String> serverBlocks(String c) {
        List<String> out = new ArrayList<>();
        Matcher m = SERVER_OPEN.matcher(c);
        int pos = 0;
        while (m.find(pos)) {
            int open = c.indexOf('{', m.start() + 1);
            int depth = 0, i = open;
            for (; i < c.length(); i++) {
                if (c.charAt(i) == '{') depth++;
                else if (c.charAt(i) == '}' && --depth == 0) break;
            }
            out.add(c.substring(open, Math.min(i + 1, c.length())));
            pos = Math.min(i + 1, c.length());
        }
        return out;
    }

    /** I siti che passano le richieste a {@code pass}, e se sono la webmail. */
    static List<Site> sitesPassingTo(Map<Path, String> files, String pass, Path roundcubeDir) {
        Pattern passes = Pattern.compile("fastcgi_pass\\s+" + Pattern.quote(pass) + "\\s*;");
        Pattern root = Pattern.compile("(?m)\\broot\\s+" + Pattern.quote(roundcubeDir.toString()) + "(/public_html)?/?\\s*;");
        Pattern name = Pattern.compile("(?m)\\bserver_name\\s+([^\\s;]+)");
        Pattern listen = Pattern.compile("(?m)\\blisten\\s+([^\\s;]+)");
        List<Site> out = new ArrayList<>();
        for (Map.Entry<Path, String> f : files.entrySet()) {
            for (String b : serverBlocks(withoutComments(f.getValue()))) {
                if (!passes.matcher(b).find()) continue;
                Matcher n = name.matcher(b), l = listen.matcher(b);
                String port = l.find() ? l.group(1).replaceFirst("^.*:", "") : "";
                out.add(new Site(f.getKey(), n.find() ? n.group(1) : "", port, root.matcher(b).find()));
            }
        }
        return out;
    }

    /** Lo stesso file con fastcgi_pass spostato da {@code from} al socket del pool roundcube. */
    static String repointed(String content, String from) {
        return content.replaceAll("fastcgi_pass(\\s+)" + Pattern.quote(from) + "(\\s*);",
                Matcher.quoteReplacement("fastcgi_pass") + "$1" + Matcher.quoteReplacement("unix:" + SOCKET) + "$2;");
    }

    // ===================== la migrazione all'avvio =====================

    enum Outcome { NOTHING, REPAIRED, NOT_INSTALLED, NOT_OURS, OTHER_SITES, NOT_SERVED, NGINX_UNREADABLE,
                   NOT_ANSWERING, DONE, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Quello che serve da php-fpm, nginx e dal sistema, separato per provarlo senza i servizi veri. */
    interface Services {
        /** L'uscita di nginx -T, o null se nginx non risponde. */
        String nginxDump();
        Shell.Result nginxTest();
        Shell.Result nginxReload();
        Shell.Result phpFpmTest();
        Shell.Result phpFpmReload();
        /** Crea gruppo e utente se mancano; falso se non ci riesce. */
        boolean ensureUser();
        /** Gli utenti dei processi di ogni pool di php-fpm in esecuzione: pool -> utenti. */
        Map<String, Set<String>> poolUsers();
        /** La webmail risponde con la sua pagina di accesso, su quel nome e quella porta. */
        boolean webmailAnswers(String name, String port);
        /** Una pausa fra un controllo e l'altro (nella prova non aspetta). */
        void pause();
    }

    public static void ensureAtBoot() {
        try {
            Report r = migrate(Places.real(), new RealServices());
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[RoundcubeUser] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE || r.outcome() == Outcome.REPAIRED) LOGGER.info(line);
            else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[RoundcubeUser] failed: " + t);
        }
    }

    static Report migrate(Places at, Services sv) throws IOException {
        if (!Files.isDirectory(at.roundcubeDir()))
            return new Report(Outcome.NOTHING, "");
        Path poolFile = at.fpmDir().resolve(POOL + ".conf");
        Path wwwFile = at.fpmDir().resolve("www.conf");

        // Gia' migrato: solo la proprieta' dei file, che un aggiornamento di Roundcube rimette a www.
        if (Files.exists(poolFile, LinkOption.NOFOLLOW_LINKS)) {
            if (!migrated(at))
                return new Report(Outcome.NOT_OURS, poolFile + " exists and was not written by the panel: nothing changed");
            List<String> changed = new ArrayList<>(apply(ownershipPlan(at), new ArrayDeque<>()));
            for (FileEdit e : rotationEdits(at)) { e.apply(); changed.add(e.path().toString()); }
            String www = wwwPoolBack(at, wwwFile, sv);
            if (www != null && !www.startsWith("replaced"))
                return new Report(Outcome.NOT_OURS, www + (changed.isEmpty() ? "" : "; ownership put back on " + String.join(", ", changed)));
            if (www != null) changed.add(wwwFile + " (" + www + ")");
            return changed.isEmpty() ? new Report(Outcome.NOTHING, "")
                    : new Report(Outcome.REPAIRED, "put back: " + String.join(", ", changed));
        }

        if (!Files.isRegularFile(wwwFile, LinkOption.NOFOLLOW_LINKS))
            return new Report(Outcome.NOT_INSTALLED, wwwFile + " is missing: no php-fpm pool for the webmail, nothing changed");
        String wwwBefore = Files.readString(wwwFile, StandardCharsets.UTF_8);
        List<Pool> pools = pools(wwwBefore);
        if (pools.size() != 1 || !"www".equals(pools.get(0).name()) || !"www".equals(pools.get(0).get("user"))
                || pools.get(0).get("listen") == null)
            return new Report(Outcome.NOT_OURS, wwwFile + " is not the panel's www pool (one pool [www], user = www): nothing changed");
        Pool www = pools.get(0);
        String oldPass = nginxForm(www.get("listen"));

        String dump = sv.nginxDump();
        if (dump == null)
            return new Report(Outcome.NGINX_UNREADABLE, "nginx -T failed: nothing changed, retrying at the next start");
        Map<Path, String> nginxFiles = configFiles(dump);
        List<Site> sites = sitesPassingTo(nginxFiles, oldPass, at.roundcubeDir());
        List<Site> webmail = sites.stream().filter(Site::roundcube).toList();
        if (sites.size() > webmail.size())
            return new Report(Outcome.OTHER_SITES, "the www pool (" + oldPass + ") also serves sites that are not the webmail: nothing changed");
        if (webmail.isEmpty())
            return new Report(Outcome.NOT_SERVED, "no nginx server passes the webmail to " + oldPass + ": nothing changed");

        // Prima della migrazione la webmail deve rispondere: altrimenti dopo non si saprebbe dire
        // se l'ha rotta lei.
        for (Site s : webmail)
            if (!sv.webmailAnswers(s.name(), s.port()))
                return new Report(Outcome.NOT_ANSWERING, "the webmail does not answer now on " + s.name() + ":" + s.port()
                        + ": nothing changed, retrying at the next start");

        if (!sv.ensureUser())
            return new Report(Outcome.ROLLED_BACK, "cannot create the user " + USER + ": nothing changed");

        // Il pool nuovo si porta dietro le righe di quello di prima che non riguardano chi e dove.
        StringBuilder rest = new StringBuilder();
        for (String l : www.lines()) {
            String k = l.substring(0, l.indexOf('=')).trim();
            if (!OWN_KEYS.contains(k)) rest.append(l).append('\n');
        }

        Deque<FileEdit> edits = new ArrayDeque<>();
        Deque<Snapshot> owners = new ArrayDeque<>();
        boolean fpmReloaded = false, nginxReloaded = false;
        try {
            backup(at, wwwFile, nginxFiles.keySet());
            FileEdit pool = new FileEdit(poolFile, null, poolConf(rest.toString()));
            pool.apply(); edits.push(pool);
            FileEdit placeholder = new FileEdit(wwwFile, wwwBefore, wwwPlaceholder());
            placeholder.apply(); edits.push(placeholder);
            for (FileEdit e : rotationEdits(at)) { e.apply(); edits.push(e); }
            apply(ownershipPlan(at), owners);

            Shell.Result t = sv.phpFpmTest();
            if (!t.success()) return rollBack(edits, owners, sv, false, false, "php-fpm -t refused the new pool: " + t.outputTrim());

            Map<Path, String> touched = new LinkedHashMap<>();
            for (Site s : webmail) touched.putIfAbsent(s.file(), null);
            for (Path f : touched.keySet()) {
                String before = Files.readString(f, StandardCharsets.UTF_8);
                FileEdit e = new FileEdit(f, before, repointed(before, oldPass));
                e.apply(); edits.push(e);
            }
            t = sv.nginxTest();
            if (!t.success()) return rollBack(edits, owners, sv, false, false, "nginx -t refused the new socket: " + t.outputTrim());

            fpmReloaded = true;
            t = sv.phpFpmReload();
            if (!t.success()) return rollBack(edits, owners, sv, true, false, "php-fpm reload failed: " + t.outputTrim());
            String pools2 = waitForPool(sv);
            if (pools2 != null) return rollBack(edits, owners, sv, true, false, pools2);

            nginxReloaded = true;
            t = sv.nginxReload();
            if (!t.success()) return rollBack(edits, owners, sv, true, true, "nginx reload failed: " + t.outputTrim());
            for (Site s : webmail) {
                boolean ok = false;
                for (int i = 0; i < 10 && !ok; i++) {
                    ok = sv.webmailAnswers(s.name(), s.port());
                    if (!ok) sv.pause();
                }
                if (!ok) return rollBack(edits, owners, sv, true, true,
                        "the webmail does not answer on " + s.name() + ":" + s.port() + " after the switch");
            }
        } catch (IOException | RuntimeException e) {
            return rollBack(edits, owners, sv, fpmReloaded, nginxReloaded, "unexpected error: " + e);
        }
        return new Report(Outcome.DONE, "Roundcube runs in the pool " + POOL + " as " + USER + ", nginx passes to "
                + SOCKET + " (" + webmail.size() + " site" + (webmail.size() == 1 ? "" : "s") + "), "
                + owners.size() + " ownerships changed; copies of the old files in " + at.backupDir());
    }

    /**
     * Dopo la migrazione www.conf deve restare senza pool. Se ne ha uno di nuovo e il file e'
     * identico a www.conf.default, l'ha ricopiato il pacchetto di PHP (manca il segnaposto: l'ha
     * tolto qualcuno, e un aggiornamento l'ha rimesso): torna il segnaposto, con php-fpm -t e reload.
     * Se e' diverso l'ha scritto qualcuno, e non si tocca. null: niente da dire.
     */
    private static String wwwPoolBack(Places at, Path wwwFile, Services sv) throws IOException {
        if (!Files.isRegularFile(wwwFile, LinkOption.NOFOLLOW_LINKS)) {
            new FileEdit(wwwFile, null, wwwPlaceholder()).apply();
            return "replaced: it was missing";
        }
        String w = Files.readString(wwwFile, StandardCharsets.UTF_8);
        if (pools(w).isEmpty()) return null;
        Path sample = at.fpmDir().resolve("www.conf.default");
        if (!Files.isRegularFile(sample) || !w.equals(Files.readString(sample, StandardCharsets.UTF_8)))
            return wwwFile + " defines a pool again and is not the package's www.conf.default: left as it is, php-fpm runs it";
        FileEdit e = new FileEdit(wwwFile, w, wwwPlaceholder());
        e.apply();
        Shell.Result t = sv.phpFpmTest();
        if (!t.success()) {
            e.undo();
            return "php-fpm -t refused " + wwwFile + " without its pool: put back (" + t.outputTrim() + ")";
        }
        Shell.Result r = sv.phpFpmReload();
        if (!r.success()) {
            e.undo();
            sv.phpFpmReload();
            return "php-fpm reload failed without the www pool: put back (" + r.outputTrim() + ")";
        }
        return "replaced: the PHP package had copied www.conf.default back, with a pool that runs as www";
    }

    /** Aspetta che il pool roundcube giri come roundcube e che nessun pool www sia rimasto. null se va. */
    private static String waitForPool(Services sv) {
        Map<String, Set<String>> users = Map.of();
        for (int i = 0; i < 20; i++) {
            users = sv.poolUsers();
            if (Set.of(USER).equals(users.get(POOL)) && !users.containsKey("www")) return null;
            sv.pause();
        }
        return "after the reload php-fpm runs " + users + " instead of " + POOL + "=[" + USER + "] alone";
    }

    private static Report rollBack(Deque<FileEdit> edits, Deque<Snapshot> owners, Services sv,
                                   boolean reloadFpm, boolean reloadNginx, String why) {
        List<String> problems = new ArrayList<>(restore(owners));
        while (!edits.isEmpty()) {
            FileEdit e = edits.pop();
            try { e.undo(); } catch (IOException x) { problems.add(e.path() + ": " + x.getMessage()); }
        }
        if (reloadFpm) {
            Shell.Result r = sv.phpFpmReload();
            if (!r.success()) problems.add("php-fpm reload: " + r.outputTrim());
        }
        if (reloadNginx) {
            Shell.Result r = sv.nginxReload();
            if (!r.success()) problems.add("nginx reload: " + r.outputTrim());
        }
        return new Report(Outcome.ROLLED_BACK, why + "; everything put back"
                + (problems.isEmpty() ? "" : " EXCEPT: " + String.join("; ", problems)));
    }

    /** Le copie di www.conf e dei file di nginx, per chi vuole vedere com'erano: non servono a rimettere. */
    private static void backup(Places at, Path www, Iterable<Path> nginx) {
        try {
            Path dir = at.backupDir().resolve("roundcube-" + java.time.LocalDate.now(java.time.ZoneOffset.UTC));
            Files.createDirectories(dir);
            try { Files.setPosixFilePermissions(at.backupDir(), PosixFilePermissions.fromString("rwx------")); }
            catch (UnsupportedOperationException ignored) {}
            Files.copy(www, dir.resolve("www.conf"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            for (Path p : nginx)
                if (Files.isRegularFile(p))
                    Files.copy(p, dir.resolve(p.toString().replace('/', '_')), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            LOGGER.warning("[RoundcubeUser] cannot keep a copy of the old files: " + e.getMessage());
        }
    }

    /** Scrive un file nuovo come root, leggibile da tutti (pool, rotazioni, nginx), o lo riscrive al suo posto. */
    private static void write(Path p, String content) throws IOException {
        Files.writeString(p, content, StandardCharsets.UTF_8);
    }

    // ===================== i servizi veri =====================

    private static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(20);

        @Override public String nginxDump() {
            if (Shell.resolve("nginx") == null) return null;
            Shell.Result r = Shell.run(SHORT, "nginx", "-T");
            return r.success() ? r.output() : null;
        }
        @Override public Shell.Result nginxTest() { return Shell.run(SHORT, "nginx", "-t"); }
        // "one": funzionano anche se nginx_enable non e' YES in rc.conf.
        @Override public Shell.Result nginxReload() { return Shell.run(SHORT, "service", "nginx", "onereload"); }
        @Override public Shell.Result phpFpmTest() { return Shell.run(SHORT, "php-fpm", "-t"); }
        @Override public Shell.Result phpFpmReload() { return Shell.run(SHORT, "service", "php_fpm", "onereload"); }

        @Override public boolean ensureUser() {
            if (!Shell.run(SHORT, "pw", "groupshow", GROUP).success()
                    && !Shell.run(SHORT, "pw", "groupadd", GROUP).success()) return false;
            if (!Shell.run(SHORT, "pw", "usershow", USER).success()
                    && !Shell.run(SHORT, "pw", "useradd", USER, "-g", GROUP, "-d", "/nonexistent",
                                  "-s", "/usr/sbin/nologin", "-c", "Roundcube webmail").success()) return false;
            return Shell.run(SHORT, "pw", "usershow", USER).success();
        }

        @Override public Map<String, Set<String>> poolUsers() {
            // Un -o per colonna: su FreeBSD "-o user=,pid=" fa di ",pid=" l'intestazione di user.
            return ServiceUsers.poolUsers(Shell.run(SHORT, "ps", "-axww", "-o", "user=", "-o", "pid=", "-o", "ppid=",
                    "-o", "command=").output());
        }

        @Override public boolean webmailAnswers(String name, String port) {
            if (!name.matches("[A-Za-z0-9.-]+") || !port.matches("[0-9]+")) return false;
            Shell.Result r = Shell.run(SHORT, "curl", "-sk", "-m", "15", "--resolve", name + ":" + port + ":127.0.0.1",
                    "https://" + name + ":" + port + "/");
            return r.success() && r.output().contains("rcmloginuser");
        }

        @Override public void pause() {
            try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }
}
