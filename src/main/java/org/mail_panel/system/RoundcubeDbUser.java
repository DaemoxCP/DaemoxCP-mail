package org.mail_panel.system;

import org.mail_panel.integration.RoundcubeSsoManager;
import org.mail_panel.security.PanelSecrets;
import org.mail_panel.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Roundcube entra in MySQL col suo utente, "roundcube", che puo' toccare solo il database della
 * webmail, e non piu' con quello del pannello.
 *
 * <p>Prima db_dsnw in config.inc.php usava l'utente del pannello (mailpanel), che ha tutti i
 * privilegi anche sul database della posta: caselle e hash delle loro password, domini,
 * amministratori, passkey, sessioni del pannello. Chi prendeva la webmail -- un difetto nel PHP di
 * Roundcube o in un suo plugin -- leggeva la password nella configurazione e con quella leggeva e
 * scriveva tutto. Adesso la webmail ha un utente suo, con i privilegi sul solo database di
 * Roundcube; la password la genera il pannello e la tiene nel file dei segreti
 * ({@link PanelSecrets#ROUNDCUBE_DB_PASSWORD}).
 *
 * <p>Gli script d'installazione creano l'utente da subito ({@link #shellAccountSql}). Sui server
 * installati prima ci pensa l'avvio ({@link #ensureAtBoot}), dopo il plugin SSO:
 * <ol>
 *   <li>guarda che la webmail risponda adesso e che la sua sessione arrivi nel database, e prova
 *       un accesso vero con l'SSO del pannello: se gia' adesso qualcosa non va, dopo non si
 *       saprebbe dire chi l'ha rotta;</li>
 *   <li>crea l'utente roundcube coi privilegi sul solo database della webmail, ed entra con lui;</li>
 *   <li>riscrive db_dsnw (scrittura atomica, stesso proprietario e permessi) e ricarica php-fpm,
 *       perche' opcache puo' tenere la configurazione di prima;</li>
 *   <li>verifica: la pagina d'accesso risponde, la sua sessione e' nel database, MySQL ha visto
 *       entrare roundcube, l'accesso vero riesce;</li>
 *   <li>solo allora toglie all'utente del pannello i privilegi sul database della webmail, e
 *       verifica di nuovo: se nella webmail qualcos'altro entrava come il pannello, si vede qui.</li>
 * </ol>
 * Al primo controllo che fallisce rimette tutto com'era -- privilegi, configurazione, l'utente
 * roundcube tolto o com'era -- e ricarica: al prossimo avvio ci riprova. Non sceglie per nessuno:
 * un db_dsnw con un altro utente o un altro server, un utente roundcube che c'e' gia' e la webmail
 * non usa, un'altra configurazione della webmail che entra come il pannello, una webmail che gia'
 * non risponde, lasciano tutto com'e' e lo scrivono nel log.
 *
 * <p>L'accesso vero e' quello del pulsante «Apri webmail» del pannello: l'utente master di Dovecot,
 * che in Roundcube compare come "casella*admin", mai la password di una persona. Se l'SSO non
 * entra gia' prima (sul banco del server vero master-users ha l'hash vuoto), la verifica si fa
 * senza, con gli altri controlli, e il log lo dice.
 */
public final class RoundcubeDbUser {

    private static final Logger LOGGER = Logger.getLogger(RoundcubeDbUser.class.getName());

    /** L'utente MySQL della webmail. */
    public static final String USER = "roundcube";
    /** Il database della webmail come lo creano gli script d'installazione. */
    public static final String DATABASE = "roundcubemail";
    /** Roundcube si collega a 127.0.0.1, cioe' in TCP: l'account e' per quell'indirizzo. */
    public static final String HOST = "127.0.0.1";
    public static final String ROUNDCUBE_DIR = "/usr/local/www/roundcube";
    /** Dove il pannello mette i file di passaggio con un segreto (cartelle 700 che durano un comando). */
    static final String WORK_DIR = "/var/db/mailpanel";

    /** La chiave fra apici o virgolette, tutte e due valide in PHP: prima le virgolette non si vedevano. */
    private static final Pattern DSN = Pattern.compile(
            "db_dsnw['\"]?\\]?\\s*=\\s*['\"]([a-z]+)://([^:]+):([^@]*)@([^/]+)/([A-Za-z0-9_]+)");
    private static final Pattern LOCAL_HOST = Pattern.compile("(127\\.0\\.0\\.1|localhost)(:[0-9]{1,5})?");
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9_]{1,64}");
    /** Le password che genera il pannello: solo lettere e cifre (PanelSecrets.newAlphanumericPassword). */
    private static final Pattern GENERATED = Pattern.compile("[A-Za-z0-9]{16,128}");
    private static final Pattern SESSION_ID = Pattern.compile("[A-Za-z0-9]{8,128}");
    /** Un altro collegamento a MySQL dentro la configurazione della webmail (db_dsnr, plugin). */
    private static final Pattern ANY_DSN = Pattern.compile("['\"]([a-z]+)://([^:'\"@/]+):[^@'\"]*@[^'\"]+['\"]");

    private RoundcubeDbUser() {}

    // ===================== db_dsnw =====================

    /**
     * Il collegamento letto da db_dsnw: line e' la riga, userStart e passwordEnd le posizioni nella
     * riga di "utente:password", cioe' il pezzo che la migrazione sostituisce.
     */
    public record Dsn(String driver, String user, String password, String host, String db,
                      int line, int userStart, int passwordEnd) {
        /** L'host dell'account MySQL: quello del DSN senza la porta. */
        String accountHost() {
            int c = host.indexOf(':');
            return c < 0 ? host : host.substring(0, c);
        }
    }

    /**
     * Il db_dsnw che Roundcube usa davvero. Riga per riga, non su tutto il testo, per due motivi
     * che una ricerca globale sbaglia entrambi: le righe COMMENTATE non contano, e in PHP vince
     * l'ULTIMA assegnazione, non la prima. La stessa lettura la usa l'aggiornamento di Roundcube
     * (UpdateManager.dsnRoundcube): la migrazione e la copia del database devono vedere lo stesso
     * collegamento. null se non ce n'e' uno attivo.
     */
    public static Dsn activeDsn(String config) {
        if (config == null) return null;
        Dsn last = null;
        String[] lines = config.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String t = lines[i].trim();
            if (t.startsWith("//") || t.startsWith("#") || t.startsWith("*") || t.startsWith("/*")) continue;
            Matcher m = DSN.matcher(lines[i]);
            if (m.find())
                last = new Dsn(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), i, m.start(2), m.end(3));
        }
        return last;
    }

    /** La stessa configurazione con utente e password nuovi in quel db_dsnw, e nient'altro di diverso. */
    static String withCredentials(String config, Dsn d, String user, String password) {
        String[] lines = config.split("\n", -1);
        String l = lines[d.line()];
        lines[d.line()] = l.substring(0, d.userStart()) + user + ":" + password + l.substring(d.passwordEnd());
        return String.join("\n", lines);
    }

    /**
     * Gli altri collegamenti a MySQL della webmail che entrano come l'utente del pannello: righe
     * attive di config.inc.php oltre a db_dsnw (db_dsnr, un plugin configurato li') e le
     * configurazioni dei plugin. Dopo la migrazione smetterebbero di funzionare senza che il
     * pannello lo sappia: se ce ne sono, la migrazione non tocca niente.
     */
    static List<String> otherPanelDsn(Path roundcubeDir, String config, Dsn d, String panelUser) throws IOException {
        List<String> out = new ArrayList<>();
        String[] lines = config.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (i == d.line()) continue;
            if (usesPanelUser(lines[i], panelUser)) out.add("config.inc.php line " + (i + 1));
        }
        Path plugins = roundcubeDir.resolve("plugins");
        if (Files.isDirectory(plugins)) {
            List<Path> files;
            try (Stream<Path> s = Files.list(plugins)) {
                files = s.map(p -> p.resolve("config.inc.php")).filter(Files::isRegularFile)
                         .sorted(Comparator.comparing(Path::toString)).toList();
            }
            for (Path f : files) {
                String[] pl = Files.readString(f, StandardCharsets.UTF_8).split("\n", -1);
                for (int i = 0; i < pl.length; i++)
                    if (usesPanelUser(pl[i], panelUser))
                        out.add(roundcubeDir.relativize(f) + " line " + (i + 1));
            }
        }
        return out;
    }

    private static boolean usesPanelUser(String line, String panelUser) {
        String t = line.trim();
        if (t.startsWith("//") || t.startsWith("#") || t.startsWith("*") || t.startsWith("/*")) return false;
        Matcher m = ANY_DSN.matcher(line);
        while (m.find())
            if (m.group(1).startsWith("mysql") && m.group(2).equals(panelUser)) return true;
        return false;
    }

    // ===================== gli script d'installazione =====================

    /**
     * Le istruzioni SQL degli script d'installazione: l'utente roundcube con la password che il
     * pannello passa nell'ambiente, i privilegi sul solo database della webmail, e quelli
     * dell'utente del pannello su quel database tolti, perche' una reinstallazione li trova
     * dalla versione di prima. Vanno in un here-document NON quotato eseguito da root: la variabile
     * della password si espande una volta sola, e l'alfabeto del generatore non ha apici.
     */
    public static String shellAccountSql(String passwordVariable, String panelUser) {
        return accountSql(HOST, DATABASE, passwordVariable)
             + "REVOKE IF EXISTS ALL PRIVILEGES ON " + DATABASE + ".* FROM '" + panelUser + "'@'localhost', '"
             + panelUser + "'@'127.0.0.1' IGNORE UNKNOWN USER;\n";
    }

    /**
     * L'account roundcube con quella password e i privilegi sul solo database della webmail. Lo
     * stesso per gli script e per la migrazione. Niente accenti gravi intorno ai nomi: negli
     * script sta in un here-document non quotato, dove aprirebbero una sostituzione di comando.
     */
    static String accountSql(String host, String db, String password) {
        String account = "'" + USER + "'@'" + host + "'";
        return "CREATE USER IF NOT EXISTS " + account + " IDENTIFIED BY '" + password + "';\n"
             + "ALTER USER " + account + " IDENTIFIED BY '" + password + "';\n"
             + "GRANT ALL PRIVILEGES ON " + db + ".* TO " + account + ";\n";
    }

    // ===================== la migrazione all'avvio =====================

    enum Outcome { NOTHING, NOT_OURS, NO_ROOT, NOT_SERVED, NOT_ANSWERING, DONE, FINISHED, PARTIAL, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Un sito di nginx che serve la webmail: il nome e la porta su cui risponde. */
    record Site(String name, String port) {}

    /** La pagina d'accesso: se c'e' il modulo, e la sessione che Roundcube ha aperto (dal cookie). */
    record Page(boolean form, String sessionId) {}

    /** Dove sta la webmail: fissa sul server, una cartella temporanea nella prova. */
    record Places(Path roundcubeDir) {
        Path config() { return roundcubeDir.resolve("config/config.inc.php"); }
        static Places real() { return new Places(Path.of(ROUNDCUBE_DIR)); }
    }

    /** Quello che serve da MySQL, php-fpm, nginx e dalla webmail, separato per provarlo senza i servizi veri. */
    interface Services {
        /** La password di roundcube dal file dei segreti, generata la prima volta. */
        String secret();
        /** L'utente MySQL del pannello e la sua password. */
        String panelUser();
        String panelPassword();
        /** SQL eseguito da root di MySQL, dallo standard input: fallisce anche se root non entra. */
        Shell.Result root(String sql);
        /** Una domanda a MySQL con quell'utente e quella password, sul suo database. */
        Shell.Result as(String user, String password, String host, String db, String sql);
        Shell.Result phpFpmReload();
        /** I siti di nginx che servono la webmail; null se nginx -T non risponde. */
        List<Site> webmailSites();
        Page loginPage(Site s);
        /** Un accesso vero con l'SSO del pannello, poi l'uscita: null se riesce, se no il perche'. */
        String realLogin(Site s, String db);
        /** Una pausa fra un controllo e l'altro (nella prova non aspetta). */
        void pause();
    }

    public static void ensureAtBoot(RoundcubeSsoManager sso) {
        try {
            Report r = migrate(Places.real(), new RealServices(sso));
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[RoundcubeDbUser] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE || r.outcome() == Outcome.FINISHED) LOGGER.info(line);
            else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[RoundcubeDbUser] failed: " + t);
        }
    }

    /** Quello che la migrazione ha cambiato, per rimetterlo. */
    private static final class Undo {
        /** Le istruzioni che ricreano l'account roundcube com'era (vuote: non c'era). */
        List<String> accountBefore = List.of();
        String accountHost = HOST;
        boolean accountTouched;
        FileState config;
        boolean reloadFpm;
        /** Le GRANT dell'utente del pannello sul database della webmail, da rimettere. */
        List<String> panelGrants = List.of();
        boolean revoked;
    }

    static Report migrate(Places at, Services sv) throws IOException {
        Path cfg = at.config();
        if (!Files.isRegularFile(cfg, LinkOption.NOFOLLOW_LINKS)) return new Report(Outcome.NOTHING, "");
        String before = Files.readString(cfg, StandardCharsets.UTF_8);
        Dsn d = activeDsn(before);
        if (d == null)
            return new Report(Outcome.NOT_OURS, cfg + " has no active db_dsnw: nothing changed");
        if (!"mysql".equals(d.driver()) || !LOCAL_HOST.matcher(d.host()).matches() || !NAME.matcher(d.db()).matches())
            return new Report(Outcome.NOT_OURS, "db_dsnw points to " + d.driver() + "://" + d.host() + "/" + d.db()
                    + ", not to the panel's MySQL on this machine: nothing changed");
        String panel = sv.panelUser();
        if (panel == null || !NAME.matcher(panel).matches() || USER.equals(panel))
            return new Report(Outcome.NOT_OURS, "the panel's MySQL user is not readable: nothing changed");
        String secret = sv.secret();
        if (secret == null || !GENERATED.matcher(secret).matches())
            return new Report(Outcome.NOT_OURS, "the webmail password in the secrets file is not one the panel generates: nothing changed");
        String host = d.accountHost(), db = d.db();

        // Gia' fatto: resta solo, se un avvio di prima si e' fermato a meta', togliere i privilegi
        // al pannello. Si guarda con le sue credenziali, senza root: veloce quando non c'e' niente.
        if (USER.equals(d.user()) && secret.equals(d.password())) {
            if (!sv.as(panel, sv.panelPassword(), host, db, "SELECT 1").success())
                return new Report(Outcome.NOTHING, "");
            return finishRevoke(sv, panel, host, db);
        }
        if (!USER.equals(d.user()) && !panel.equals(d.user()))
            return new Report(Outcome.NOT_OURS, "db_dsnw uses the MySQL user " + d.user()
                    + ", neither the panel's (" + panel + ") nor " + USER + ": nothing changed");

        if (!rootAnswers(sv))
            return new Report(Outcome.NO_ROOT, "cannot enter MySQL as root: nothing changed, retrying at the next start");
        List<String> account = accountStatements(sv, host);
        if (account == null)
            return new Report(Outcome.NO_ROOT, "cannot read the MySQL account " + USER + "@" + host + ": nothing changed");
        if (!account.isEmpty() && !USER.equals(d.user()))
            return new Report(Outcome.NOT_OURS, "the MySQL account " + USER + "@" + host
                    + " already exists and the webmail does not use it: nothing changed");
        String beyond = privilegesBeyond(account, db);
        if (beyond != null)
            return new Report(Outcome.NOT_OURS, "the MySQL account " + USER + "@" + host + " has privileges beyond "
                    + db + " (" + beyond + "): nothing changed");
        List<String> others = otherPanelDsn(at.roundcubeDir(), before, d, panel);
        if (!others.isEmpty())
            return new Report(Outcome.NOT_OURS, "the webmail also enters MySQL as " + panel + " in "
                    + String.join(", ", others) + ": nothing changed");
        List<String> panelGrants = panelGrantsOn(sv, panel, db);
        if (panelGrants == null)
            return new Report(Outcome.NO_ROOT, "cannot read the privileges of " + panel + ": nothing changed");

        List<Site> sites = sv.webmailSites();
        if (sites == null)
            return new Report(Outcome.NOT_SERVED, "nginx -T failed: nothing changed, retrying at the next start");
        if (sites.isEmpty())
            return new Report(Outcome.NOT_SERVED, "no nginx server serves " + at.roundcubeDir() + ": nothing changed");

        // Prima di cambiare, la webmail deve funzionare: altrimenti dopo non si saprebbe dire chi l'ha rotta.
        String now = verify(sv, sites, db, false, false);
        if (now != null)
            return new Report(Outcome.NOT_ANSWERING, now + ": nothing changed, retrying at the next start");
        String noLogin = sv.realLogin(sites.get(0), db);
        boolean realLogin = noLogin == null;

        Undo u = new Undo();
        u.accountBefore = account;
        u.accountHost = host;
        u.panelGrants = panelGrants;
        try {
            u.accountTouched = true;
            Shell.Result r = sv.root(accountSql(host, db, secret));
            if (!r.success()) return rollBack(sv, u, "cannot create the MySQL account " + USER + "@" + host + ": " + r.outputTrim());
            Shell.Result in = sv.as(USER, secret, host, db, "SELECT COUNT(*) FROM session");
            if (!in.success())
                return rollBack(sv, u, USER + " cannot read " + db + " with the new password: " + in.outputTrim());

            FileState was = FileState.of(cfg, before);
            u.config = was;
            write(cfg, withCredentials(before, d, USER, secret), was.withoutOthers());
            u.reloadFpm = true;
            r = sv.phpFpmReload();
            if (!r.success()) return rollBack(sv, u, "php-fpm reload failed: " + r.outputTrim());
            String why = verify(sv, sites, db, true, realLogin);
            if (why != null) return rollBack(sv, u, why + " after the switch to " + USER);

            u.revoked = true;
            r = sv.root(revokeSql(panel, db, panelGrants));
            if (!r.success()) return rollBack(sv, u, "cannot take " + db + " away from " + panel + ": " + r.outputTrim());
            why = verify(sv, sites, db, false, realLogin);
            if (why != null) return rollBack(sv, u, why + " once " + panel + " lost " + db);
        } catch (IOException | RuntimeException e) {
            return rollBack(sv, u, "unexpected error: " + e);
        }
        String detail = "the webmail enters MySQL as " + USER + "@" + host + " with privileges on " + db + " only, "
                + panel + " no longer has them; verified with the login page, its session in the database"
                + (realLogin ? " and a real login through the panel's SSO" : ", but without a real login: " + noLogin);
        if (sv.as(panel, sv.panelPassword(), host, db, "SELECT 1").success())
            return new Report(Outcome.PARTIAL, detail + "; BUT " + panel + " still reads " + db
                    + " (privileges from somewhere else: " + String.join(" | ", grantsOf(sv, panel)) + ")");
        return new Report(Outcome.DONE, detail);
    }

    /**
     * Un avvio di prima ha gia' passato la webmail a roundcube, ma il pannello ha ancora i privilegi
     * sul suo database (si e' fermato prima di toglierli): si verifica e si tolgono, e se dopo la
     * webmail non va li si rimettono.
     */
    private static Report finishRevoke(Services sv, String panel, String host, String db) {
        if (!rootAnswers(sv))
            return new Report(Outcome.NO_ROOT, "the webmail already uses " + USER + " but " + panel + " still reads " + db
                    + ", and MySQL root does not answer: left as it is");
        List<String> grants = panelGrantsOn(sv, panel, db);
        if (grants == null || grants.isEmpty())
            return new Report(Outcome.PARTIAL, "the webmail already uses " + USER + " but " + panel + " still reads " + db
                    + " with privileges from somewhere else: " + String.join(" | ", grantsOf(sv, panel)));
        List<Site> sites = sv.webmailSites();
        if (sites == null || sites.isEmpty())
            return new Report(Outcome.NOT_SERVED, "the webmail already uses " + USER + "; " + panel
                    + " keeps " + db + " until nginx shows the webmail");
        String now = verify(sv, sites, db, true, false);
        if (now != null)
            return new Report(Outcome.NOT_ANSWERING, now + ": " + panel + " keeps " + db + ", retrying at the next start");
        boolean realLogin = sv.realLogin(sites.get(0), db) == null;
        Undo u = new Undo();
        u.panelGrants = grants;
        u.revoked = true;
        Shell.Result r = sv.root(revokeSql(panel, db, grants));
        if (!r.success()) return rollBack(sv, u, "cannot take " + db + " away from " + panel + ": " + r.outputTrim());
        String why = verify(sv, sites, db, false, realLogin);
        if (why != null) return rollBack(sv, u, why + " once " + panel + " lost " + db);
        return new Report(Outcome.FINISHED, panel + " no longer has privileges on " + db
                + " (the webmail already used " + USER + ")");
    }

    /**
     * Tre controlli, il quarto se si puo'. La pagina d'accesso risponde col modulo, e la sessione
     * che ha aperto e' nel database (con un DSN rotto Roundcube mostra «Oops... something went
     * wrong!» al posto del modulo). Dopo il cambio, MySQL ha visto entrare roundcube: con opcache
     * php-fpm potrebbe ancora girare con la configurazione di prima, e la pagina funzionerebbe col
     * pannello. E un accesso vero. null se va tutto.
     */
    private static String verify(Services sv, List<Site> sites, String db, boolean countConnections, boolean realLogin) {
        long before = countConnections ? connections(sv) : -1;
        for (Site s : sites) {
            String why = null;
            for (int i = 0; i < 10; i++) {
                why = pageWorks(sv, s, db);
                if (why == null) break;
                sv.pause();
            }
            if (why != null) return why;
        }
        if (before >= 0) {
            long after = connections(sv);
            if (after <= before)
                return "MySQL did not see the webmail enter as " + USER + " (" + before + " -> " + after
                        + " connections): php-fpm still runs the old configuration";
        }
        if (realLogin) {
            String why = sv.realLogin(sites.get(0), db);
            if (why != null) return "the real login failed: " + why;
        }
        return null;
    }

    private static String pageWorks(Services sv, Site s, String db) {
        Page p = sv.loginPage(s);
        String where = s.name() + ":" + s.port();
        if (p == null || !p.form()) return "the webmail does not show its login page on " + where;
        if (p.sessionId() == null || !SESSION_ID.matcher(p.sessionId()).matches())
            return "the webmail on " + where + " did not open a session";
        for (int i = 0; i < 5; i++) {
            Shell.Result r = sv.root("SELECT COUNT(*) FROM `" + db + "`.session WHERE sess_id = '" + p.sessionId() + "';");
            if (r.success() && "1".equals(r.outputTrim())) return null;
            sv.pause();
        }
        return "the session of the login page on " + where + " is not in the database " + db;
    }

    /** Le connessioni di roundcube viste da MySQL; -1 se performance_schema e' spento (allora non si misura). */
    private static long connections(Services sv) {
        Shell.Result r = sv.root("SELECT IF(@@performance_schema, (SELECT COALESCE(SUM(TOTAL_CONNECTIONS), 0) "
                + "FROM performance_schema.accounts WHERE USER = '" + USER + "'), -1);");
        try {
            return r.success() ? Long.parseLong(r.outputTrim()) : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    // ===================== MySQL da root =====================

    private static boolean rootAnswers(Services sv) {
        Shell.Result r = sv.root("SELECT 1;");
        return r.success() && "1".equals(r.outputTrim());
    }

    /**
     * Le istruzioni che ricreano l'account roundcube com'e' adesso: SHOW CREATE USER con l'hash in
     * esadecimale (si rimette identico, misurato su MySQL 8.4) e le sue GRANT. Vuote se l'account
     * non c'e', null se non si sa.
     */
    static List<String> accountStatements(Services sv, String host) {
        Shell.Result n = sv.root("SELECT COUNT(*) FROM mysql.user WHERE user = '" + USER + "' AND host = '" + host + "';");
        if (!n.success()) return null;
        if ("0".equals(n.outputTrim())) return List.of();
        Shell.Result r = sv.root("SET SESSION print_identified_with_as_hex = ON;\nSHOW CREATE USER '" + USER + "'@'" + host
                + "';\nSHOW GRANTS FOR '" + USER + "'@'" + host + "';");
        if (!r.success()) return null;
        List<String> out = new ArrayList<>();
        for (String l : r.output().split("\n")) if (!l.isBlank()) out.add(l.trim());
        return out.isEmpty() || !out.get(0).startsWith("CREATE USER") ? null : out;
    }

    /** Le GRANT dell'account che vanno oltre USAGE e il database della webmail; null se non ce ne sono. */
    static String privilegesBeyond(List<String> account, String db) {
        List<String> extra = new ArrayList<>();
        for (String l : account) {
            if (!l.startsWith("GRANT ")) continue;
            if (l.startsWith("GRANT USAGE ON *.* TO ") || l.contains(" ON `" + db + "`.* TO ")) continue;
            extra.add(l);
        }
        return extra.isEmpty() ? null : String.join(" | ", extra);
    }

    /** Le GRANT dell'utente del pannello sul database della webmail, da ogni host: per rimetterle. null se non si sa. */
    static List<String> panelGrantsOn(Services sv, String panel, String db) {
        Shell.Result hosts = sv.root("SELECT host FROM mysql.user WHERE user = '" + panel + "' ORDER BY host;");
        if (!hosts.success()) return null;
        List<String> out = new ArrayList<>();
        for (String h : hosts.output().split("\n")) {
            h = h.trim();
            if (h.isEmpty()) continue;
            if (!h.matches("[A-Za-z0-9.%:_-]{1,255}")) return null;
            Shell.Result g = sv.root("SHOW GRANTS FOR '" + panel + "'@'" + h + "';");
            if (!g.success()) return null;
            for (String l : g.output().split("\n"))
                if (l.contains(" ON `" + db + "`.* TO ")) out.add(l.trim());
        }
        return out;
    }

    private static List<String> grantsOf(Services sv, String panel) {
        Shell.Result hosts = sv.root("SELECT host FROM mysql.user WHERE user = '" + panel + "' ORDER BY host;");
        List<String> out = new ArrayList<>();
        if (!hosts.success()) return out;
        for (String h : hosts.output().split("\n")) {
            h = h.trim();
            if (h.isEmpty() || !h.matches("[A-Za-z0-9.%:_-]{1,255}")) continue;
            Shell.Result g = sv.root("SHOW GRANTS FOR '" + panel + "'@'" + h + "';");
            for (String l : g.output().split("\n")) if (!l.isBlank() && !l.startsWith("GRANT USAGE ON *.*")) out.add(l.trim());
        }
        return out;
    }

    /** Toglie al pannello il database della webmail su ogni host in cui ce l'ha. */
    private static String revokeSql(String panel, String db, List<String> grants) {
        Set<String> hosts = new LinkedHashSet<>();
        Matcher m = Pattern.compile(" TO `" + Pattern.quote(panel) + "`@`([^`]+)`").matcher(String.join("\n", grants));
        while (m.find()) hosts.add(m.group(1));
        StringBuilder b = new StringBuilder();
        for (String h : hosts)
            b.append("REVOKE IF EXISTS ALL PRIVILEGES ON `").append(db).append("`.* FROM '").append(panel)
             .append("'@'").append(h).append("' IGNORE UNKNOWN USER;\n");
        return b.length() == 0 ? "SELECT 1;" : b.toString();
    }

    private static Report rollBack(Services sv, Undo u, String why) {
        List<String> problems = new ArrayList<>();
        if (u.revoked && !u.panelGrants.isEmpty()) {
            Shell.Result r = sv.root(String.join(";\n", u.panelGrants) + ";");
            if (!r.success()) problems.add("the privileges of the panel's user: " + r.outputTrim());
        }
        if (u.config != null) {
            try {
                u.config.restore();
            } catch (IOException e) {
                problems.add(u.config.path() + ": " + e.getMessage());
            }
        }
        if (u.reloadFpm) {
            Shell.Result r = sv.phpFpmReload();
            if (!r.success()) problems.add("php-fpm reload: " + r.outputTrim());
        }
        if (u.accountTouched) {
            Shell.Result r = sv.root("DROP USER IF EXISTS '" + USER + "'@'" + u.accountHost + "';\n"
                    + (u.accountBefore.isEmpty() ? "" : String.join(";\n", u.accountBefore) + ";"));
            if (!r.success()) problems.add("the MySQL account " + USER + ": " + r.outputTrim());
        }
        return new Report(Outcome.ROLLED_BACK, why + "; everything put back"
                + (problems.isEmpty() ? "" : " EXCEPT: " + String.join("; ", problems)));
    }

    // ===================== config.inc.php =====================

    /** Un file com'era: testo, proprietario, gruppo, permessi. */
    record FileState(Path path, String content, String owner, String group, Set<PosixFilePermission> perms) {
        static FileState of(Path p, String content) throws IOException {
            PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            return new FileState(p, content, a.owner().getName(), a.group().getName(), a.permissions());
        }
        /** Gli stessi permessi senza quelli degli altri: dentro c'e' la password del database. */
        FileState withoutOthers() {
            Set<PosixFilePermission> s = java.util.EnumSet.noneOf(PosixFilePermission.class);
            s.addAll(perms);
            s.remove(PosixFilePermission.OTHERS_READ);
            s.remove(PosixFilePermission.OTHERS_WRITE);
            s.remove(PosixFilePermission.OTHERS_EXECUTE);
            return new FileState(path, content, owner, group, s);
        }
        /** Rimette il file esattamente com'era, permessi compresi. */
        void restore() throws IOException { write(path, content, this); }
    }

    /**
     * Scrive al posto del file, in modo atomico, con il proprietario, il gruppo e i permessi di
     * {@code like}. Il file temporaneo nasce 600 di root, quindi nessuno legge il segreto prima
     * che abbia i permessi giusti.
     */
    static void write(Path p, String content, FileState like) throws IOException {
        Path tmp = p.resolveSibling(p.getFileName() + ".mailpanel.tmp");
        Files.deleteIfExists(tmp);
        Files.createFile(tmp, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            Files.writeString(tmp, content, StandardCharsets.UTF_8);
            PosixFileAttributeView v = Files.getFileAttributeView(tmp, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            var names = tmp.getFileSystem().getUserPrincipalLookupService();
            UserPrincipal owner = names.lookupPrincipalByName(like.owner());
            GroupPrincipal group = names.lookupPrincipalByGroupName(like.group());
            v.setOwner(owner);
            v.setGroup(group);
            v.setPermissions(like.perms());
            try {
                Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    // ===================== nginx =====================

    /** I siti che servono la webmail (root nella cartella di Roundcube), da nginx -T. */
    static List<Site> webmailSites(String dump, Path roundcubeDir) {
        Pattern root = Pattern.compile("(?m)\\broot\\s+" + Pattern.quote(roundcubeDir.toString()) + "(/public_html)?/?\\s*;");
        Pattern name = Pattern.compile("(?m)\\bserver_name\\s+([^\\s;]+)");
        Pattern listen = Pattern.compile("(?m)\\blisten\\s+([^\\s;]+)");
        Map<String, Site> out = new LinkedHashMap<>();
        for (String file : RoundcubeUser.configFiles(dump).values()) {
            for (String b : RoundcubeUser.serverBlocks(RoundcubeUser.withoutComments(file))) {
                if (!root.matcher(b).find()) continue;
                Matcher n = name.matcher(b), l = listen.matcher(b);
                if (!n.find() || !l.find()) continue;
                String host = n.group(1), port = l.group(1).replaceFirst("^.*:", "");
                if (!host.matches("[A-Za-z0-9.-]+") || !port.matches("[0-9]{1,5}")) continue;
                out.putIfAbsent(host + ":" + port, new Site(host, port));
            }
        }
        return new ArrayList<>(out.values());
    }

    // ===================== i servizi veri =====================

    private static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(30);
        private final RoundcubeSsoManager sso;
        /** Come root entra in MySQL: con la password del file dei segreti, o senza (null: non si sa ancora). */
        private Boolean rootWithPassword;

        RealServices(RoundcubeSsoManager sso) { this.sso = sso; }

        @Override public String secret() { return PanelSecrets.ensureRoundcubeDbPassword(); }

        @Override public String panelUser() {
            String user = "mailpanel";
            if (org.mail_panel.Main.dbManager != null) {
                try (java.sql.ResultSet rs = org.mail_panel.Main.dbManager.get_data_config()) {
                    if (rs.next() && rs.getString("mysql_user") != null && !rs.getString("mysql_user").isBlank())
                        user = rs.getString("mysql_user").trim();
                } catch (Exception ignored) {}
            }
            return user;
        }

        @Override public String panelPassword() { return PanelSecrets.text(PanelSecrets.MYSQL_PASSWORD); }

        @Override public Shell.Result root(String sql) {
            String password = PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD);
            if (rootWithPassword == null) {
                rootWithPassword = !password.isEmpty() && "1".equals(mysql(rootOptions(password, true), "SELECT 1;").outputTrim());
                if (!rootWithPassword && !"1".equals(mysql(rootOptions(password, false), "SELECT 1;").outputTrim()))
                    rootWithPassword = null;   // root non entra: si riprova alla prossima domanda
            }
            if (rootWithPassword == null) return new Shell.Result(1, "MySQL root does not answer", false, List.of("mysql"));
            return mysql(rootOptions(password, rootWithPassword), sql);
        }

        /** Il file di opzioni di root: con la password del file dei segreti, o null (socket, senza password). */
        private static String rootOptions(String password, boolean withPassword) {
            return withPassword ? "[client]\nuser=root\npassword=\"" + password + "\"\n" : null;
        }

        @Override public Shell.Result as(String user, String password, String host, String db, String sql) {
            if (!NAME.matcher(user).matches() || !LOCAL_HOST.matcher(host).matches() || !NAME.matcher(db).matches())
                return new Shell.Result(1, "refused", false, List.of("mysql"));
            String options = "[client]\nuser=" + user + "\npassword=\"" + (password == null ? "" : password)
                    + "\"\nhost=" + host + "\ndatabase=" + db + "\n";
            return mysql(options, sql);
        }

        /**
         * mysql con il segreto in un file di opzioni e l'SQL nello standard input, tutti e due in una
         * cartella 700 che dura un comando: ne' la password ne' un IDENTIFIED BY passano dalla riga di
         * comando, che "ps" mostra a tutti. Senza file di opzioni: root dal socket, senza password.
         */
        private static Shell.Result mysql(String options, String sql) {
            Path dir = null;
            try {
                dir = Files.createTempDirectory(Path.of(WORK_DIR), ".roundcube-db-",
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                Path in = dir.resolve("statements.sql");
                Files.writeString(in, sql + "\n", StandardCharsets.UTF_8);
                List<String> cmd = new ArrayList<>();
                cmd.add("mysql");
                if (options != null) {
                    Path cnf = dir.resolve("client.cnf");
                    Files.writeString(cnf, options, StandardCharsets.UTF_8);
                    cmd.add("--defaults-extra-file=" + cnf);
                } else {
                    cmd.add("-u");
                    cmd.add("root");
                }
                cmd.add("-N");
                cmd.add("-B");
                ProcessBuilder pb = new ProcessBuilder(cmd);
                Shell.applyPath(pb);
                pb.redirectInput(in.toFile());
                pb.redirectErrorStream(true);
                Process p = pb.start();
                java.util.concurrent.CompletableFuture<String> out = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    try { return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8); }
                    catch (IOException e) { return ""; }
                });
                if (!p.waitFor(SHORT.toSeconds(), java.util.concurrent.TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    return new Shell.Result(-1, "mysql did not answer", true, cmd);
                }
                return new Shell.Result(p.exitValue(), out.get(5, java.util.concurrent.TimeUnit.SECONDS), false, cmd);
            } catch (Exception e) {
                return new Shell.Result(-2, e.toString(), false, List.of("mysql"));
            } finally {
                deleteTree(dir);
            }
        }

        @Override public Shell.Result phpFpmReload() { return Shell.run(SHORT, "service", "php_fpm", "onereload"); }

        @Override public List<Site> webmailSites() {
            if (Shell.resolve("nginx") == null) return null;
            Shell.Result r = Shell.run(SHORT, "nginx", "-T");
            return r.success() ? RoundcubeDbUser.webmailSites(r.output(), Path.of(ROUNDCUBE_DIR)) : null;
        }

        @Override public Page loginPage(Site s) {
            Shell.Result r = Shell.run(SHORT, "curl", "-sk", "-i", "-m", "15", "--resolve", s.name() + ":" + s.port() + ":127.0.0.1",
                    "https://" + s.name() + ":" + s.port() + "/");
            if (!r.success()) return new Page(false, null);
            Matcher m = Pattern.compile("(?im)^set-cookie:\\s*roundcube_sessid=([A-Za-z0-9]+)").matcher(r.output());
            return new Page(r.output().contains("rcmloginuser"), m.find() ? m.group(1) : null);
        }

        /**
         * Come il pulsante «Apri webmail»: un gettone SSO per una casella attiva, la webmail che apre
         * la posta, poi l'uscita. La casella e' una per cui l'accesso SSO c'e' gia' stato (Roundcube
         * ha gia' la sua riga "casella*admin"), altrimenti la prima: cosi' di solito non crea niente.
         * Gettone e cookie in una cartella 700 che dura un comando, mai sulla riga di comando.
         */
        @Override public String realLogin(Site s, String db) {
            if (sso == null) return "the panel's SSO is not available";
            if (org.mail_panel.Main.mailDatabase == null) return "the mail database is not available";
            List<org.mail_panel.database.MailDatabase.Mailbox> boxes;
            try {
                boxes = org.mail_panel.Main.mailDatabase.getAllMailboxes().stream()
                        .filter(b -> b.active && b.email != null && b.email.matches("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+"))
                        .sorted(Comparator.comparingInt(b -> b.id)).toList();
            } catch (Exception e) {
                return "cannot list the mailboxes: " + e.getMessage();
            }
            if (boxes.isEmpty()) return "there is no active mailbox to log in with";
            Set<String> known = new LinkedHashSet<>();
            Shell.Result u = root("SELECT username FROM `" + db + "`.users WHERE username LIKE '%*"
                    + RoundcubeSsoManager.MASTER_USER + "';");
            if (u.success()) for (String l : u.output().split("\n")) known.add(l.trim());
            org.mail_panel.database.MailDatabase.Mailbox box = boxes.stream()
                    .filter(b -> known.contains(b.email + "*" + RoundcubeSsoManager.MASTER_USER)).findFirst().orElse(boxes.get(0));
            String who = "mailbox #" + box.id;

            RoundcubeSsoManager.SsoToken t = sso.generateToken(box.email, "127.0.0.1");
            if (t == null || !t.success) return "no SSO token for " + who + ": " + (t == null ? "" : t.error);
            String base = "https://" + s.name() + ":" + s.port() + "/";
            Path dir = null;
            try {
                dir = Files.createTempDirectory(Path.of(WORK_DIR), ".roundcube-login-",
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                Path jar = dir.resolve("cookies"), url = dir.resolve("url");
                Files.writeString(url, "url = \"" + base + "?_sso=" + t.token + "\"\n", StandardCharsets.UTF_8);
                Shell.Result in = Shell.run(SHORT, "curl", "-sk", "-L", "-m", "20", "--resolve", s.name() + ":" + s.port() + ":127.0.0.1",
                        "-c", jar.toString(), "-b", jar.toString(), "-K", url.toString());
                String page = in.output();
                if (!in.success() || page.contains("rcmloginuser") || !page.contains("\"task\":\"mail\"") || !page.contains("_task=logout"))
                    return "the SSO login as " + who + " did not open the mailbox";
                Matcher m = Pattern.compile("\"request_token\":\"([A-Za-z0-9]+)\"").matcher(page);
                if (m.find()) {
                    Files.writeString(url, "url = \"" + base + "?_task=logout&_token=" + m.group(1) + "\"\n", StandardCharsets.UTF_8);
                    Shell.run(SHORT, "curl", "-sk", "-L", "-m", "20", "--resolve", s.name() + ":" + s.port() + ":127.0.0.1",
                            "-c", jar.toString(), "-b", jar.toString(), "-o", "/dev/null", "-K", url.toString());
                }
                return null;
            } catch (IOException e) {
                return "the SSO login as " + who + ": " + e.getMessage();
            } finally {
                deleteTree(dir);
            }
        }

        @Override public void pause() {
            try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }

        private static void deleteTree(Path dir) {
            if (dir == null) return;
            try (Stream<Path> s = Files.walk(dir)) {
                for (Path p : s.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
            } catch (IOException ignored) {}
        }
    }
}
