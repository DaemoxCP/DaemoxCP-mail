package org.daemoxcp.mail.system;

import org.daemoxcp.mail.database.CatalogGuard;
import org.daemoxcp.mail.database.SqlCatalog;
import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Postfix e Dovecot entrano in MySQL ognuno col suo utente, che puo' solo leggere le colonne che usa, e non piu'
 * con quello del pannello.
 *
 * <p>Prima le mappe di Postfix (mysql-virtual-*.cf, root:postfix 0640) e la connessione di Dovecot
 * (dovecot-sql.conf nella 2.3, conf.d/auth-sql.conf.ext nella 2.4, root:dovecot 0600) avevano la password
 * dell'utente del pannello, che nel database puo' tutto: caselle e hash delle password, amministratori, passkey,
 * sessioni, il vault. Chi prendeva un processo di Postfix leggeva la mappa e con quella scriveva ovunque.
 * Adesso:
 * <ul>
 *   <li>{@value #POSTFIX_USER}: SELECT su domains (domain, active), mailboxes (email, active, receive_enabled) e
 *       aliases (source, destination, active). Non vede nemmeno gli hash delle password.</li>
 *   <li>{@value #DOVECOT_USER}: SELECT su mailboxes (email, password, active, quota_mb): la password_query e il
 *       userdb del limite di ogni casella (DovecotQuota).</li>
 * </ul>
 * Le password le genera il pannello e stanno nel file dei segreti di root ({@link PanelSecrets#POSTFIX_DB_PASSWORD},
 * {@link PanelSecrets#DOVECOT_DB_PASSWORD}), oltre che nei file dei due servizi.
 *
 * <p>All'avvio della root (e dopo un'installazione o una rigenerazione di Dovecot):
 * <ol>
 *   <li>da root di MySQL, gli utenti coi due nomi con cui si entra (localhost e 127.0.0.1), solo quei permessi per
 *       colonna (un permesso in piu', da chiunque venga, li toglie tutti e si ridanno), e la password del file dei
 *       segreti;</li>
 *   <li>la prova da ciascun utente: le domande dei suoi file rispondono, e quello che non deve leggere MySQL lo
 *       rifiuta (Postfix la colonna password, Dovecot la tabella degli alias);</li>
 *   <li>i file riscritti con l'utente nuovo (scrittura atomica, stesso proprietario, gruppo e permessi), poi la
 *       prova dei servizi veri: postmap -q su ogni mappa, e per Dovecot reload, doveadm auth lookup e la sua
 *       connessione vista da MySQL col nome nuovo.</li>
 * </ol>
 * Se una prova non torna, i file di quel servizio tornano com'erano (dalla memoria: la password del pannello non
 * finisce in nessuna copia sul disco) e il servizio si ricarica; si riprova al prossimo avvio. Un file che punta a
 * un altro server, a un altro database o a un altro utente, o che non si sa leggere, resta com'e' e lo dice il
 * registro. Un secondo avvio senza niente da cambiare non scrive niente.
 */
public final class MailDbUsers {

    private static final Logger LOGGER = Logger.getLogger(MailDbUsers.class.getName());

    public static final String POSTFIX_USER = Product.ID + "_postfix";
    public static final String DOVECOT_USER = Product.ID + "_dovecot";
    private static final List<String> HOSTS = List.of("localhost", "127.0.0.1");

    /** Le mappe di Postfix che interrogano MySQL, come le scrivono gli script d'installazione. */
    static final List<String> POSTFIX_MAPS = List.of("mysql-virtual-domains.cf", "mysql-virtual-mailboxes.cf",
            "mysql-virtual-aliases.cf", MailboxAddressMap.FILE);
    /** Una chiave che non c'e' mai (.invalid e' riservato): la domanda gira, MySQL risponde vuoto. */
    static final String PROBE = "daemoxcp-mail-probe@invalid";

    private static final Pattern LOCAL_HOST = Pattern.compile("(inet:)?(127\\.0\\.0\\.1|localhost)(:[0-9]{1,5})?");
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9_]{1,64}");
    /** Le password che genera il pannello per questi utenti. */
    private static final Pattern GENERATED = Pattern.compile("[A-Za-z0-9]{32}");
    /** Una riga "chiave = valore" dei file di Postfix e della 2.4 di Dovecot. */
    private static final Pattern SETTING = Pattern.compile("^\\s*([a-z_]+)\\s*=\\s*(.*?)\\s*$");
    private static final Pattern DOVECOT24_BLOCK = Pattern.compile("^\\s*mysql\\s+(\\S+)\\s*\\{\\s*$");
    private static final Pattern BLOCK_END = Pattern.compile("^\\s*}\\s*$");

    private MailDbUsers() {}

    // ===================== Gli utenti e i loro permessi =====================

    /** I permessi per colonna di un utente: la tabella, le colonne, e l'istruzione che li da'. */
    record Grant(String table, Set<String> columns, String statement) {}

    /** Un utente dei servizi, con le istruzioni del catalogo che lo creano, gli cambiano la password e lo svuotano. */
    record Account(String user, String create, String setPassword, String revoke, List<Grant> grants) {}

    static final Account POSTFIX = new Account(POSTFIX_USER, SqlCatalog.MAILDB_CREATE_POSTFIX_USER,
            SqlCatalog.MAILDB_SET_POSTFIX_PASSWORD, SqlCatalog.MAILDB_REVOKE_POSTFIX, List.of(
                    new Grant("domains", Set.of("domain", "active"), SqlCatalog.MAILDB_GRANT_POSTFIX_DOMAINS),
                    new Grant("mailboxes", Set.of("email", "active", "receive_enabled"), SqlCatalog.MAILDB_GRANT_POSTFIX_MAILBOXES),
                    new Grant("aliases", Set.of("source", "destination", "active"), SqlCatalog.MAILDB_GRANT_POSTFIX_ALIASES)));

    static final Account DOVECOT = new Account(DOVECOT_USER, SqlCatalog.MAILDB_CREATE_DOVECOT_USER,
            SqlCatalog.MAILDB_SET_DOVECOT_PASSWORD, SqlCatalog.MAILDB_REVOKE_DOVECOT, List.of(
                    new Grant("mailboxes", Set.of("email", "password", "active", "quota_mb"), SqlCatalog.MAILDB_GRANT_DOVECOT_MAILBOXES)));

    /**
     * Da root di MySQL: i due utenti, solo i loro permessi, le loro password. Quello che ha fatto finisce in done;
     * se MySQL rifiuta un passo l'eccezione dice quale, e nei file dei servizi non e' cambiato niente.
     */
    static void prepareUsers(String url, String rootPassword, String postfixPassword, String dovecotPassword,
                             List<String> done) throws SQLException {
        try (Connection root = CatalogGuard.open(url, "root", rootPassword)) {
            Set<String> users = new HashSet<>();
            try (Statement st = root.createStatement(); ResultSet rs = st.executeQuery(SqlCatalog.MAILDB_USERS)) {
                while (rs.next()) users.add(rs.getString(1) + "@" + rs.getString(2));
            }
            prepare(root, url, POSTFIX, postfixPassword, users, done);
            prepare(root, url, DOVECOT, dovecotPassword, users, done);
        }
    }

    private static void prepare(Connection root, String url, Account a, String password, Set<String> users,
                                List<String> done) throws SQLException {
        boolean created = false;
        if (!users.contains(a.user() + "@localhost") || !users.contains(a.user() + "@127.0.0.1")) {
            try (PreparedStatement ps = root.prepareStatement(a.create())) {
                ps.setString(1, password);
                ps.setString(2, password);
                ps.execute();
            }
            created = true;
            done.add("MySQL user " + a.user());
        }
        // Niente altro che quelle colonne: un permesso in piu', da chiunque venga, li toglie tutti.
        String localhost = "'" + a.user() + "'@'localhost'", ip = "'" + a.user() + "'@'127.0.0.1'";
        boolean other;
        try (PreparedStatement ps = root.prepareStatement(SqlCatalog.MAILDB_OTHER_PRIVILEGES)) {
            for (int i = 0; i < 6; i += 2) {
                ps.setString(i + 1, localhost);
                ps.setString(i + 2, ip);
            }
            for (int i = 7; i <= 9; i++) ps.setString(i, a.user());
            try (ResultSet rs = ps.executeQuery()) {
                other = rs.next();
            }
        }
        Set<String> want = new HashSet<>();
        for (Grant g : a.grants())
            for (String c : g.columns())
                for (String h : HOSTS) want.add("'" + a.user() + "'@'" + h + "' " + g.table() + " " + c);
        Set<String> have = new HashSet<>();
        String database = root.getCatalog();
        try (PreparedStatement ps = root.prepareStatement(SqlCatalog.MAILDB_COLUMN_PRIVILEGES)) {
            ps.setString(1, localhost);
            ps.setString(2, ip);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String key = rs.getString(1) + " " + rs.getString(3) + " " + rs.getString(4);
                    if (database.equalsIgnoreCase(rs.getString(2)) && "SELECT".equalsIgnoreCase(rs.getString(5))
                            && want.contains(key)) have.add(key);
                    else other = true;
                }
            }
        }
        if (other) {
            try (Statement st = root.createStatement()) {
                st.execute(a.revoke());
            }
            have.clear();
            done.add("every other privilege of " + a.user() + " revoked");
        }
        List<String> granted = new ArrayList<>();
        try (Statement st = root.createStatement()) {
            for (Grant g : a.grants()) {
                boolean all = true;
                for (String c : g.columns())
                    for (String h : HOSTS) all &= have.contains("'" + a.user() + "'@'" + h + "' " + g.table() + " " + c);
                if (all) continue;
                st.execute(g.statement());
                granted.add(g.table() + " (" + String.join(", ", new java.util.TreeSet<>(g.columns())) + ")");
            }
        }
        if (!granted.isEmpty() && !created && !other) done.add("columns given again to " + a.user() + ": " + String.join(", ", granted));
        // Una colonna ridata accanto ad altre della stessa tabella MySQL la vede solo dopo aver ricaricato i permessi
        // (SqlCatalog.MAIL_FLUSH_PRIVILEGES): senza, la prova dopo la troverebbe ancora rifiutata.
        if (!granted.isEmpty() || other) {
            try (Statement st = root.createStatement()) {
                st.execute(SqlCatalog.MAIL_FLUSH_PRIVILEGES);
            }
        }
        if (!canLogIn(url, a.user(), password)) {
            try (PreparedStatement ps = root.prepareStatement(a.setPassword())) {
                ps.setString(1, password);
                ps.setString(2, password);
                ps.execute();
            }
            if (!canLogIn(url, a.user(), password)) throw new SQLException(a.user() + " does not get in with the password just set");
            done.add(a.user() + " password set");
        }
    }

    /** Entra con questa password? (Un altro errore che non sia «accesso negato» si ferma qui.) */
    private static boolean canLogIn(String url, String user, String password) throws SQLException {
        try (Connection c = CatalogGuard.open(url, user, password)) {
            return c.isValid(5);
        } catch (SQLException e) {
            if (e.getErrorCode() == 1045) return false;
            throw e;
        }
    }

    /**
     * Da ciascun utente: le domande dei suoi file rispondono, e MySQL rifiuta quello che non deve leggere (Postfix
     * la colonna password, 1143; Dovecot la tabella degli alias, 1142). Null se e' tutto cosi'.
     */
    static String verifyUsers(String url, String postfixPassword, String dovecotPassword) {
        try (Connection c = CatalogGuard.open(url, POSTFIX_USER, postfixPassword)) {
            for (String q : List.of(SqlCatalog.MAILDB_POSTFIX_DOMAIN_LOOKUP, SqlCatalog.MAILDB_POSTFIX_MAILBOX_LOOKUP,
                    SqlCatalog.MAILDB_POSTFIX_ALIAS_LOOKUP, SqlCatalog.MAILDB_POSTFIX_ADDRESS_LOOKUP)) {
                String failed = lookUp(c, q);
                if (failed != null) return POSTFIX_USER + " cannot run a Postfix lookup: " + failed;
            }
            String why = refused(c, SqlCatalog.MAILDB_POSTFIX_PASSWORD_REFUSED, 1143);
            if (why != null) return POSTFIX_USER + " " + why;
        } catch (SQLException e) {
            return POSTFIX_USER + " cannot get in: " + e.getMessage();
        }
        try (Connection c = CatalogGuard.open(url, DOVECOT_USER, dovecotPassword)) {
            String failed = lookUp(c, SqlCatalog.MAILDB_DOVECOT_PASSWORD_LOOKUP);
            if (failed != null) return DOVECOT_USER + " cannot run Dovecot's password query: " + failed;
            // Il userdb delle quote (DovecotQuota): senza, ogni consegna perderebbe il limite della casella.
            failed = lookUp(c, SqlCatalog.MAILDB_DOVECOT_QUOTA_LOOKUP);
            if (failed != null) return DOVECOT_USER + " cannot run Dovecot's quota query: " + failed;
            String why = refused(c, SqlCatalog.MAILDB_DOVECOT_ALIAS_REFUSED, 1142);
            if (why != null) return DOVECOT_USER + " " + why;
        } catch (SQLException e) {
            return DOVECOT_USER + " cannot get in: " + e.getMessage();
        }
        return null;
    }

    private static String lookUp(Connection c, String sql) {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, PROBE);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) { /* nessuna riga per PROBE: basta che la domanda giri */ }
            }
            return null;
        } catch (SQLException e) {
            return e.getErrorCode() + " " + e.getMessage();
        }
    }

    private static String refused(Connection c, String sql, int expected) {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, PROBE);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
            }
            return "reads what it must not read (" + sql + ")";
        } catch (SQLException e) {
            if (e.getErrorCode() == expected) return null;
            return "got " + e.getErrorCode() + " instead of " + expected + " on " + sql + " (" + e.getMessage() + ")";
        }
    }

    // ===================== I file dei servizi =====================

    /** Un pezzo di una riga: dove sta un valore, per sostituirlo senza toccare il resto. */
    record Span(int line, int start, int end) {}

    /** La connessione scritta in un file: chi entra, con che password, dove, e dove stanno utente e password. */
    record Login(String user, String password, String host, String db, Span userAt, Span passwordAt) {}

    /**
     * Una mappa di Postfix: le righe "user", "password", "hosts" e "dbname", una volta sola ciascuna e senza
     * continuazioni (una riga che comincia con uno spazio continua la precedente). Null se non e' cosi'.
     */
    static Login postfixLogin(String text) {
        String[] lines = text.split("\n", -1);
        Map<String, String> values = new LinkedHashMap<>();
        Map<String, Span> spans = new LinkedHashMap<>();
        String last = null;
        for (int i = 0; i < lines.length; i++) {
            String l = lines[i];
            if (l.isBlank() || l.trim().startsWith("#")) continue;
            if (Character.isWhitespace(l.charAt(0))) {
                if (last != null && spans.containsKey(last)) return null;
                continue;
            }
            Matcher m = SETTING.matcher(l);
            if (!m.matches()) { last = null; continue; }
            last = m.group(1);
            if (!List.of("user", "password", "hosts", "dbname").contains(last)) continue;
            if (spans.containsKey(last)) return null;
            values.put(last, m.group(2));
            spans.put(last, new Span(i, m.start(2), m.end(2)));
        }
        if (spans.size() != 4) return null;
        return new Login(values.get("user"), values.get("password"), values.get("hosts"), values.get("dbname"),
                spans.get("user"), spans.get("password"));
    }

    /** dovecot-sql.conf della 2.3: la riga "connect" (una sola), coi valori senza virgolette. Null se non e' cosi'. */
    static Login dovecot23Login(String text) {
        String[] lines = text.split("\n", -1);
        int found = -1;
        Matcher connect = null;
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].trim().startsWith("#")) continue;
            Matcher m = SETTING.matcher(lines[i]);
            if (!m.matches() || !"connect".equals(m.group(1))) continue;
            if (found >= 0) return null;
            found = i;
            connect = m;
        }
        if (connect == null) return null;
        String value = connect.group(2);
        if (value.contains("\"") || value.contains("'")) return null;
        Map<String, String> values = new LinkedHashMap<>();
        Map<String, Span> spans = new LinkedHashMap<>();
        Matcher t = Pattern.compile("(\\S+?)=(\\S*)").matcher(value);
        int offset = connect.start(2);
        while (t.find()) {
            String k = t.group(1);
            if (values.containsKey(k)) return null;
            values.put(k, t.group(2));
            spans.put(k, new Span(found, offset + t.start(2), offset + t.end(2)));
        }
        if (!values.containsKey("user") || !values.containsKey("password") || !values.containsKey("host")
                || !values.containsKey("dbname")) return null;
        return new Login(values.get("user"), values.get("password"), values.get("host"), values.get("dbname"),
                spans.get("user"), spans.get("password"));
    }

    /**
     * conf.d/auth-sql.conf.ext della 2.4: il blocco "mysql host { user = ... password = ... dbname = ... }", uno
     * solo. Null se non c'e' o non e' cosi'; {@link #hasDovecot24Block} dice se c'era un blocco.
     */
    static Login dovecot24Login(String text) {
        String[] lines = text.split("\n", -1);
        String host = null;
        Map<String, String> values = new LinkedHashMap<>();
        Map<String, Span> spans = new LinkedHashMap<>();
        boolean inside = false;
        for (int i = 0; i < lines.length; i++) {
            String l = lines[i];
            if (l.trim().startsWith("#")) continue;
            if (!inside) {
                Matcher b = DOVECOT24_BLOCK.matcher(l);
                if (b.matches()) {
                    if (host != null) return null;
                    host = b.group(1);
                    inside = true;
                }
                continue;
            }
            if (BLOCK_END.matcher(l).matches()) { inside = false; continue; }
            Matcher m = SETTING.matcher(l);
            if (!m.matches()) return null;
            String k = m.group(1);
            if (values.containsKey(k)) return null;
            String v = m.group(2);
            if (v.startsWith("\"") || v.startsWith("'")) return null;
            values.put(k, v);
            spans.put(k, new Span(i, m.start(2), m.end(2)));
        }
        if (host == null || inside || !values.containsKey("user") || !values.containsKey("password")
                || !values.containsKey("dbname")) return null;
        return new Login(values.get("user"), values.get("password"), host, values.get("dbname"),
                spans.get("user"), spans.get("password"));
    }

    static boolean hasDovecot24Block(String text) {
        for (String l : text.split("\n", -1))
            if (!l.trim().startsWith("#") && DOVECOT24_BLOCK.matcher(l).matches()) return true;
        return false;
    }

    /** Un valore nuovo al posto di quello in at. */
    private record Edit(Span at, String value) {}

    /** Lo stesso testo con quell'utente e quella password al posto di quelli di prima, e nient'altro di diverso. */
    static String withCredentials(String text, Login l, String user, String password) {
        String[] lines = text.split("\n", -1);
        List<Edit> edits = new ArrayList<>(List.of(new Edit(l.userAt(), user), new Edit(l.passwordAt(), password)));
        // Dalla fine: un cambio non sposta le posizioni di quello che resta da fare (nella 2.3 stanno sulla stessa riga).
        edits.sort(Comparator.comparingInt((Edit e) -> e.at().line()).thenComparingInt(e -> e.at().start()).reversed());
        for (Edit e : edits) {
            String line = lines[e.at().line()];
            lines[e.at().line()] = line.substring(0, e.at().start()) + e.value() + line.substring(e.at().end());
        }
        return String.join("\n", lines);
    }

    // ===================== Il cambio, servizio per servizio =====================

    /** Dove stanno i file: fissi sul server, una cartella temporanea nelle prove. */
    record Places(Path postfixDir, Path dovecotDir) {
        static Places real() {
            return new Places(Path.of("/usr/local/etc/postfix"), Path.of("/usr/local/etc/dovecot"));
        }
        Path dovecotSql() { return dovecotDir.resolve("dovecot-sql.conf"); }
        Path dovecotAuthSql() { return dovecotDir.resolve("conf.d/auth-sql.conf.ext"); }
    }

    /** I servizi veri, separati per provarli senza Postfix e Dovecot. */
    interface Services {
        boolean postfixRunning();
        Shell.Result postfixReload();
        /** postmap -q chiave mysql:file */
        Shell.Result postmap(String key, Path map);
        boolean dovecotRunning();
        Shell.Result doveconfCheck();
        Shell.Result dovecotReload();
        /** L'uscita di doveadm auth lookup per PROBE (-1 se non risponde). */
        int dovecotLookup();
        /** Le connessioni aperte adesso in MySQL da quell'utente; -1 se non si sa. */
        int connections(String user);
        void pause();
    }

    /** Un file da cambiare: il percorso, com'era, e la connessione letta. */
    record Target(Path file, RoundcubeDbUser.FileState was, Login login) {}

    /** Quello che e' successo ai file: cambiati, rimasti com'erano e perche', tornati indietro e perche'. */
    record Report(List<String> done, List<String> left, List<String> rolledBack) {}

    /** postmap -q PROBE: MySQL ha risposto vuoto (uscita 1, niente scritto). Un errore scrive sempre qualcosa. */
    static boolean postmapAnswered(Shell.Result r) {
        return r != null && !r.timedOut() && r.exitCode() == 1 && r.outputTrim().isEmpty();
    }

    /**
     * I file dei due servizi: quelli da cambiare si cambiano e si provano, gli altri restano com'erano. Gli utenti
     * MySQL devono gia' essere pronti e provati (prepareUsers, verifyUsers).
     */
    static Report switchFiles(Places at, Services sv, String panelUser, String panelDb, String postfixPassword,
                              String dovecotPassword) throws IOException {
        List<String> done = new ArrayList<>(), left = new ArrayList<>(), back = new ArrayList<>();

        List<Target> postfix = new ArrayList<>();
        for (String name : POSTFIX_MAPS) {
            Path f = at.postfixDir().resolve(name);
            if (!Files.exists(f, LinkOption.NOFOLLOW_LINKS)) continue;
            String text = read(f);
            Target t = target(f, text, text == null ? null : postfixLogin(text), panelUser, panelDb, POSTFIX_USER,
                    postfixPassword, left);
            if (t != null) postfix.add(t);
        }
        if (!postfix.isEmpty()) switchPostfix(sv, postfix, postfixPassword, done, left, back);

        List<Target> dovecot = new ArrayList<>();
        Path sql = at.dovecotSql();
        if (Files.exists(sql, LinkOption.NOFOLLOW_LINKS)) {
            String text = read(sql);
            Target t = target(sql, text, text == null ? null : dovecot23Login(text), panelUser, panelDb, DOVECOT_USER,
                    dovecotPassword, left);
            if (t != null) dovecot.add(t);
        }
        Path auth = at.dovecotAuthSql();
        if (Files.exists(auth, LinkOption.NOFOLLOW_LINKS)) {
            String text = read(auth);
            // Nella 2.3 questo file non ha la connessione (sta in dovecot-sql.conf): non c'e' niente da cambiare.
            if (text == null || hasDovecot24Block(text)) {
                Target t = target(auth, text, text == null ? null : dovecot24Login(text), panelUser, panelDb,
                        DOVECOT_USER, dovecotPassword, left);
                if (t != null) dovecot.add(t);
            }
        }
        if (!dovecot.isEmpty()) switchDovecot(sv, dovecot, dovecotPassword, done, left, back);
        return new Report(done, left, back);
    }

    private static String read(Path f) throws IOException {
        return Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS) ? Files.readString(f, StandardCharsets.UTF_8) : null;
    }

    /** Il file, se e' del pannello e va cambiato; null se e' gia' a posto o non e' suo (allora lo dice in left). */
    private static Target target(Path f, String text, Login l, String panelUser, String panelDb, String user,
                                 String password, List<String> left) throws IOException {
        if (text == null) {
            left.add(f + " is not a regular file: left as it is");
            return null;
        }
        if (l == null) {
            left.add(f + ": the MySQL connection is not written the way the panel writes it: left as it is");
            return null;
        }
        if (!LOCAL_HOST.matcher(l.host()).matches() || !panelDb.equals(l.db())) {
            left.add(f + " points to " + l.host() + "/" + l.db() + ", not to the panel's database on this machine: left as it is");
            return null;
        }
        if (user.equals(l.user()) && password.equals(l.password())) return null;
        if (!user.equals(l.user()) && !panelUser.equals(l.user())) {
            left.add(f + " uses the MySQL user " + l.user() + ", neither the panel's (" + panelUser + ") nor " + user
                    + ": left as it is");
            return null;
        }
        return new Target(f, RoundcubeDbUser.FileState.of(f, text).withoutOthers(), l);
    }

    private static void write(List<Target> targets, String user, String password) throws IOException {
        for (Target t : targets)
            RoundcubeDbUser.write(t.file(), withCredentials(t.was().content(), t.login(), user, password), t.was());
    }

    /**
     * Rimette i file com'erano: il testo dalla memoria, proprietario, gruppo e permessi di prima, tranne quelli degli
     * altri utenti, che un file con una password del database non deve avere (FileState.withoutOthers).
     */
    private static void restore(List<Target> targets) {
        for (Target t : targets) {
            try {
                RoundcubeDbUser.write(t.file(), t.was().content(), t.was());
            } catch (IOException e) {
                LOGGER.warning("[MailDbUsers] " + t.file() + " could not be put back: " + e.getMessage());
            }
        }
    }

    private static String names(List<Target> targets) {
        List<String> out = new ArrayList<>();
        for (Target t : targets) out.add(t.file().getFileName().toString());
        return String.join(", ", out);
    }

    private static void switchPostfix(Services sv, List<Target> maps, String password, List<String> done,
                                      List<String> left, List<String> back) throws IOException {
        // Prima di cambiare, le mappe devono rispondere: altrimenti dopo non si saprebbe dire chi le ha rotte.
        for (Target t : maps) {
            Shell.Result r = sv.postmap(PROBE, t.file());
            if (!postmapAnswered(r)) {
                left.add("Postfix: " + t.file().getFileName() + " already fails before any change (" + oneLine(r) + "): left as it is");
                return;
            }
        }
        boolean running = sv.postfixRunning();
        try {
            write(maps, POSTFIX_USER, password);
            for (Target t : maps) {
                Shell.Result r = sv.postmap(PROBE, t.file());
                if (!postmapAnswered(r)) {
                    restore(maps);
                    back.add("Postfix: postmap -q fails on " + t.file().getFileName() + " with " + POSTFIX_USER + " ("
                            + oneLine(r) + "): " + names(maps) + " put back");
                    return;
                }
            }
            if (running) {
                Shell.Result r = sv.postfixReload();
                if (!r.success() || !sv.postfixRunning()) {
                    restore(maps);
                    sv.postfixReload();
                    back.add("Postfix: the reload failed (" + oneLine(r) + "): " + names(maps) + " put back and Postfix reloaded");
                    return;
                }
            }
        } catch (IOException | RuntimeException e) {
            restore(maps);
            if (running) sv.postfixReload();
            back.add("Postfix: unexpected error (" + e + "): " + names(maps) + " put back");
            return;
        }
        done.add("Postfix enters MySQL as " + POSTFIX_USER + " (" + names(maps) + ", postmap -q answers"
                + (running ? ", Postfix reloaded)" : "; Postfix is not running)"));
    }

    private static void switchDovecot(Services sv, List<Target> files, String password, List<String> done,
                                      List<String> left, List<String> back) throws IOException {
        if (!sv.dovecotRunning()) {
            left.add("Dovecot is not running: " + names(files) + " left as they are, retrying at the next start");
            return;
        }
        int before = sv.dovecotLookup();
        if (!DovecotAuthWorker.LOOKUP_OK.contains(before)) {
            left.add("Dovecot: the authentication already fails before any change (doveadm auth lookup exit " + before
                    + "): " + names(files) + " left as they are");
            return;
        }
        try {
            write(files, DOVECOT_USER, password);
            Shell.Result check = sv.doveconfCheck();
            if (!check.success()) {
                restore(files);
                back.add("Dovecot: doveconf refuses the configuration (" + oneLine(check) + "): " + names(files) + " put back");
                return;
            }
            Shell.Result r = sv.dovecotReload();
            if (!r.success()) {
                restore(files);
                sv.dovecotReload();
                back.add("Dovecot: the reload failed (" + oneLine(r) + "): " + names(files) + " put back and Dovecot reloaded");
                return;
            }
            String problem = null;
            for (int i = 0; i < 10; i++) {
                int rc = sv.dovecotLookup();
                int seen = sv.connections(DOVECOT_USER);
                if (DovecotAuthWorker.LOOKUP_OK.contains(rc) && seen > 0) { problem = null; break; }
                problem = !DovecotAuthWorker.LOOKUP_OK.contains(rc)
                        ? "doveadm auth lookup fails after the reload (exit " + rc + ")"
                        : "MySQL does not see Dovecot enter as " + DOVECOT_USER + " (" + seen + " connections)";
                sv.pause();
            }
            if (problem != null) {
                restore(files);
                sv.dovecotReload();
                back.add("Dovecot: " + problem + ": " + names(files) + " put back and Dovecot reloaded (lookup now exit "
                        + sv.dovecotLookup() + ")");
                return;
            }
        } catch (IOException | RuntimeException e) {
            restore(files);
            sv.dovecotReload();
            back.add("Dovecot: unexpected error (" + e + "): " + names(files) + " put back and Dovecot reloaded");
            return;
        }
        done.add("Dovecot enters MySQL as " + DOVECOT_USER + " (" + names(files) + ", reloaded; doveadm auth lookup answers"
                + " and MySQL sees its connection)");
    }

    private static String oneLine(Shell.Result r) {
        if (r == null) return "no answer";
        String s = r.timedOut() ? "timed out" : "exit " + r.exitCode();
        String o = r.outputTrim();
        if (!o.isEmpty()) {
            int i = o.indexOf('\n');
            s += ": " + (i < 0 ? o : o.substring(0, i));
        }
        return s.length() > 300 ? s.substring(0, 300) : s;
    }

    // ===================== All'avvio, dopo un'installazione, dopo la rigenerazione di Dovecot =====================

    /** All'avvio della root (e del pannello non separato), col database del pannello gia' aperto. */
    public static void ensureAtBoot() {
        if (org.daemoxcp.mail.Main.mailDatabase == null || !org.daemoxcp.mail.Main.mysqlAvailable) return;
        org.daemoxcp.mail.scripts.DovecotConfig c = org.daemoxcp.mail.scripts.DovecotConfig.fromPanelConfig();
        run(org.daemoxcp.mail.Main.mailDatabase.existingDatabaseUrl(), c.getDbUser(), c.getDbName());
    }

    /** Dopo un'installazione: gli script scrivono nei file l'utente del pannello, qui si passa ai due utenti. */
    public static void ensureAfterInstall(String host, String port, String panelUser, String database) {
        if (host == null || !host.matches("[A-Za-z0-9._-]{1,128}") || port == null || !port.matches("[0-9]{1,5}")
                || panelUser == null || !NAME.matcher(panelUser).matches() || database == null
                || !NAME.matcher(database).matches()) {
            LOGGER.warning("[MailDbUsers] the panel's MySQL settings are not readable: Postfix and Dovecot keep the panel's user");
            return;
        }
        run("jdbc:mysql://" + host + ":" + port + "/" + database
                + "?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC", panelUser, database);
    }

    private static synchronized void run(String url, String panelUser, String panelDb) {
        try {
            String outcome = ensure(Places.real(), new RealServices(url), url.replace("&autoReconnect=true", ""),
                    panelUser, panelDb);
            if (outcome != null) LOGGER.warning("[MailDbUsers] " + outcome);
        } catch (Throwable t) {
            LOGGER.warning("[MailDbUsers] failed: " + t);
        }
    }

    /**
     * Tutto: utenti, prova, file. Null se non c'e' niente da dire (e quello che e' stato fatto e' nel registro);
     * altrimenti il perche' qualcosa e' rimasto com'era.
     */
    static String ensure(Places at, Services sv, String url, String panelUser, String panelDb) throws IOException {
        boolean any = Files.exists(at.dovecotSql(), LinkOption.NOFOLLOW_LINKS)
                || Files.exists(at.dovecotAuthSql(), LinkOption.NOFOLLOW_LINKS);
        for (String m : POSTFIX_MAPS) any |= Files.exists(at.postfixDir().resolve(m), LinkOption.NOFOLLOW_LINKS);
        if (!any) return null;   // niente server di posta installato
        if (panelUser == null || !NAME.matcher(panelUser).matches() || panelDb == null || !NAME.matcher(panelDb).matches())
            return "the panel's MySQL user or database is not readable: nothing changed";
        String rootPassword = PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD);
        if (rootPassword.isEmpty())
            return "the MySQL root password is not in " + PanelSecrets.location(PanelSecrets.MYSQL_ROOT_PASSWORD)
                    + ": Postfix and Dovecot keep the panel's MySQL user";
        String postfixPassword = secret(PanelSecrets.POSTFIX_DB_PASSWORD);
        String dovecotPassword = secret(PanelSecrets.DOVECOT_DB_PASSWORD);
        if (postfixPassword.isEmpty() || dovecotPassword.isEmpty())
            return "the passwords of " + POSTFIX_USER + " and " + DOVECOT_USER + " could not be kept in "
                    + PanelSecrets.location(PanelSecrets.POSTFIX_DB_PASSWORD) + ": nothing changed";
        return ensure(at, sv, url, rootPassword, panelUser, panelDb, postfixPassword, dovecotPassword);
    }

    /** Lo stesso con le password date (le prove: il MySQL di prova e le sue). */
    static String ensure(Places at, Services sv, String url, String rootPassword, String panelUser, String panelDb,
                         String postfixPassword, String dovecotPassword) throws IOException {
        List<String> done = new ArrayList<>();
        try {
            prepareUsers(url, rootPassword, postfixPassword, dovecotPassword, done);
        } catch (SQLException | RuntimeException e) {
            return "MySQL refused a step (" + e.getMessage() + "): the files of Postfix and Dovecot are unchanged"
                    + (done.isEmpty() ? "" : "; done before: " + String.join(", ", done));
        }
        String failed = verifyUsers(url, postfixPassword, dovecotPassword);
        if (failed != null) return "the check failed: " + failed + "; the files of Postfix and Dovecot are unchanged"
                + (done.isEmpty() ? "" : " (done: " + String.join(", ", done) + ")");
        Report r = switchFiles(at, sv, panelUser, panelDb, postfixPassword, dovecotPassword);
        done.addAll(r.done());
        if (!done.isEmpty()) LOGGER.info("[MailDbUsers] DONE: " + String.join("; ", done));
        List<String> problems = new ArrayList<>(r.rolledBack());
        problems.addAll(r.left());
        if (!r.rolledBack().isEmpty()) problems.set(0, "ROLLED_BACK: " + problems.get(0));
        return problems.isEmpty() ? null : String.join("; ", problems);
    }

    /** La password dal file dei segreti di root, generata la prima volta, e riletta dal disco: "" se non c'e'. */
    private static String secret(String name) {
        String v = PanelSecrets.ensureServiceDbPassword(name);
        if (!GENERATED.matcher(v).matches() || !v.equals(PanelSecrets.reread(name))) return "";
        return v;
    }

    /** Postfix, Dovecot e MySQL veri. */
    static final class RealServices implements Services {
        private static final String POSTFIX = "/usr/local/sbin/postfix";
        private static final String POSTMAP = "/usr/local/sbin/postmap";
        private final String url;

        RealServices(String url) { this.url = url.replace("&autoReconnect=true", ""); }

        @Override public boolean postfixRunning() {
            return Shell.run(Duration.ofSeconds(15), "service", "postfix", "status").success();
        }
        @Override public Shell.Result postfixReload() {
            return Shell.run(Duration.ofSeconds(60), POSTFIX, "reload");
        }
        @Override public Shell.Result postmap(String key, Path map) {
            return Shell.run(Duration.ofSeconds(30), POSTMAP, "-q", key, "mysql:" + map);
        }
        @Override public boolean dovecotRunning() { return DovecotAuthWorker.running(); }
        @Override public Shell.Result doveconfCheck() {
            return Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n");
        }
        @Override public Shell.Result dovecotReload() {
            Shell.Result r = Shell.run(Duration.ofSeconds(30), "service", "dovecot", "reload");
            pause();
            pause();
            return r;
        }
        @Override public int dovecotLookup() { return DovecotAuthWorker.lookup(); }
        @Override public int connections(String user) {
            String rootPassword = PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD);
            try (Connection root = CatalogGuard.open(url, "root", rootPassword);
                 PreparedStatement ps = root.prepareStatement(SqlCatalog.MAILDB_CONNECTIONS)) {
                ps.setString(1, user);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : -1;
                }
            } catch (SQLException e) {
                return -1;
            }
        }
        @Override public void pause() {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
