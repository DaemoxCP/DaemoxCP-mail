package org.mail_panel.database;

import org.mail_panel.security.PanelSecrets;
import org.mail_panel.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * L'utente root di MySQL: come il pannello lo usa, e la sua password sui server installati prima.
 *
 * Misurato il 07/11/2026 sul server vero (MySQL 8.4.11): root@localhost senza password, e nessuna
 * `mysql_root_password` nel file dei segreti. In mysql84-server di FreeBSD non c'e' auth_socket,
 * quindi "senza password" vuol dire che entra chiunque abbia un utente sulla macchina: da
 * `su -m nobody` si entrava come root sia dal socket sia da 127.0.0.1. Un difetto in Roundcube o
 * in rspamd valeva tutto MySQL, posta compresa. Le installazioni fatte dal pannello dal 17/10
 * impostano la password (FullMailServerScript); questa riparazione la imposta all'avvio sui server
 * installati prima.
 *
 * L'ordine e' quello che non puo' chiudere fuori nessuno: prima la password nel file dei segreti
 * (scritta e riletta dal disco), poi ALTER USER. Se il pannello si fermasse a meta', al prossimo
 * avvio root entrerebbe ancora senza password e la riparazione ripartirebbe con la stessa password
 * del file. Una password messa a mano non si tocca mai: se root non entra senza password, non c'e'
 * niente da fare.
 *
 * Tutte le domande come root passano di qui: la password in un file di opzioni 600 in una cartella
 * 700 che dura un comando, l'SQL nello standard input, mai sulla riga di comando che "ps" mostra a
 * tutti. Al client mysql vanno solo istruzioni fisse del catalogo (SqlCatalog), senza valori: lo
 * controlla CatalogGuard.allowed prima di scrivere il file. La sola istruzione con un valore, la
 * password di root, passa da JDBC come parametro ({@link #setPassword}).
 */
public final class MysqlRoot {

    private static final Logger LOGGER = Logger.getLogger(MysqlRoot.class.getName());

    /** Il socket di MySQL; vuoto = quello predefinito del client. Le prove lo cambiano. */
    static String socket = System.getProperty("mailpanel.mysql.socket", "");
    /** La porta TCP su 127.0.0.1, per controllare che root non entri senza password nemmeno da li'. */
    static String port = System.getProperty("mailpanel.mysql.port", "3306");
    /** Dove nascono le cartelle temporanee dei comandi. */
    static String workDir = System.getProperty("mailpanel.mysql.workdir", "/var/tmp");

    private static final Pattern HOST = Pattern.compile("[A-Za-z0-9._:%-]{1,255}");
    private static final long TIMEOUT_SECONDS = 30;

    private MysqlRoot() {}

    /** Il file di opzioni di root con la password, oppure senza password. */
    static String options(String password) {
        StringBuilder b = new StringBuilder("[client]\nuser=root\n");
        if (password != null) b.append("password=\"").append(password).append("\"\n");
        else b.append("password=\n");
        if (!socket.isEmpty()) b.append("socket=").append(socket).append('\n');
        return b.toString();
    }

    /** Come options, ma da 127.0.0.1 in TCP invece che dal socket. */
    static String tcpOptions(String password) {
        return "[client]\nuser=root\npassword=" + (password == null ? "" : "\"" + password + "\"")
                + "\nhost=127.0.0.1\nport=" + port + "\nprotocol=TCP\n";
    }

    /**
     * Una domanda come root, con la password del file dei segreti se c'e' e funziona, altrimenti
     * senza (un MySQL che non ce l'ha ancora). L'uscita, oppure "" se root non entra. Solo
     * un'istruzione del catalogo: un altro testo e' rifiutato prima del client.
     */
    public static String query(String sql) {
        // Prima il testo, poi i segreti: un testo rifiutato non deve nemmeno far leggere la password.
        if (!CatalogGuard.allowed(sql))
            throw new IllegalArgumentException("not a statement of the catalog: the mysql client gets only SqlCatalog's fixed statements");
        String password = PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD);
        if (!password.isEmpty()) {
            Shell.Result r = mysql(options(password), sql);
            if (r.success()) return r.outputTrim();
        }
        Shell.Result r = mysql(options(null), sql);
        return r.success() ? r.outputTrim() : "";
    }

    /**
     * mysql col file di opzioni (--defaults-file: nessun altro file, nemmeno un ~/.my.cnf) e l'SQL
     * nello standard input, in una cartella 700 che si cancella subito.
     */
    static Shell.Result mysql(String options, String sql) {
        if (!CatalogGuard.allowed(sql))
            throw new IllegalArgumentException("not a statement of the catalog: the mysql client gets only SqlCatalog's fixed statements");
        Path dir = null;
        List<String> cmd = new ArrayList<>();
        try {
            dir = Files.createTempDirectory(Path.of(workDir), ".mysql-root-",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            Path cnf = dir.resolve("client.cnf");
            Path in = dir.resolve("statements.sql");
            Files.writeString(cnf, options, StandardCharsets.UTF_8);
            Files.writeString(in, sql + ";\n", StandardCharsets.UTF_8);
            cmd.add("mysql");
            cmd.add("--defaults-file=" + cnf);
            cmd.add("-N");
            cmd.add("-B");
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Shell.applyPath(pb);
            pb.redirectInput(in.toFile());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            CompletableFuture<String> out = CompletableFuture.supplyAsync(() -> {
                try { return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8); }
                catch (IOException e) { return ""; }
            });
            if (!p.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return new Shell.Result(-1, "mysql did not answer", true, cmd);
            }
            return new Shell.Result(p.exitValue(), out.get(5, TimeUnit.SECONDS), false, cmd);
        } catch (Exception e) {
            return new Shell.Result(-2, e.toString(), false, cmd.isEmpty() ? List.of("mysql") : cmd);
        } finally {
            if (dir != null) {
                try (var s = Files.walk(dir)) {
                    s.sorted(java.util.Comparator.reverseOrder()).forEach(f -> f.toFile().delete());
                } catch (IOException ignored) {
                    // una cartella 700 di root in /var/tmp: la toglie la pulizia del sistema
                }
            }
        }
    }

    static boolean entersWith(String options) {
        Shell.Result r = mysql(options, SqlCatalog.MYSQL_ROOT_PING);
        return r.success() && "1".equals(r.outputTrim());
    }

    /** Gli account root senza password, dalla tabella degli account (solo user e host, nessun dato). */
    static List<String> emptyRootHosts() {
        Shell.Result r = mysql(options(null), SqlCatalog.MYSQL_ROOT_EMPTY_HOSTS);
        List<String> hosts = new ArrayList<>();
        if (!r.success()) return hosts;
        for (String h : r.outputTrim().split("\n")) if (!h.isBlank()) hosts.add(h.trim());
        return hosts;
    }

    /**
     * La password agli account root, da JDBC: root senza password da 127.0.0.1 (lo stesso account del socket,
     * MySQL risolve 127.0.0.1 in localhost), host e password come parametri. Gli host passano prima da un
     * elenco chiuso di caratteri. Null se e' andata; altrimenti il perche', e MySQL resta com'era per gli
     * account che mancano.
     */
    static String setPassword(List<String> hosts, String password) {
        for (String h : hosts)
            if (!HOST.matcher(h).matches()) throw new IllegalArgumentException("unexpected host for root: " + h);
        String url = "jdbc:mysql://127.0.0.1:" + port + "/?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true"
                + "&serverTimezone=UTC&connectTimeout=10000&socketTimeout=30000";
        try (Connection c = CatalogGuard.open(url, "root", "");
             PreparedStatement ps = c.prepareStatement(SqlCatalog.MYSQL_ROOT_SET_PASSWORD)) {
            for (String h : hosts) {
                ps.setString(1, h);
                ps.setString(2, password);
                ps.execute();
            }
            return null;
        } catch (SQLException e) {
            return e.getErrorCode() + " " + e.getMessage();
        }
    }

    /**
     * Un'istruzione del catalogo da JDBC, con quell'utente su quel database (null: nessuno), i valori come
     * parametri. L'uscita come la scriveva il client mysql (una riga per riga, le colonne separate da un tab, NULL
     * per un valore vuoto), oppure uscita 1 col codice e il messaggio di MySQL. Host, porta e database devono essere
     * gia' passati da una forma stretta: finiscono nell'URL.
     */
    public static Shell.Result jdbc(String host, String port, String db, String user, String password, String sql, Object... params) {
        String url = "jdbc:mysql://" + host + ":" + port + "/" + (db == null ? "" : db) + "?useSSL=true&requireSSL=false"
                + "&allowPublicKeyRetrieval=true&serverTimezone=UTC&connectTimeout=10000&socketTimeout=30000";
        List<String> what = List.of("jdbc", user + "@" + host, db == null ? "" : db);
        try (Connection c = CatalogGuard.open(url, user, password == null ? "" : password);
             PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) ps.setObject(i + 1, params[i]);
            StringBuilder out = new StringBuilder();
            if (ps.execute()) {
                try (ResultSet rs = ps.getResultSet()) {
                    int n = rs.getMetaData().getColumnCount();
                    while (rs.next()) {
                        for (int i = 1; i <= n; i++) {
                            if (i > 1) out.append('\t');
                            String v = rs.getString(i);
                            out.append(v == null ? "NULL" : v);
                        }
                        out.append('\n');
                    }
                }
            }
            return new Shell.Result(0, out.toString(), false, what);
        } catch (SQLException e) {
            return new Shell.Result(1, "ERROR " + e.getErrorCode() + " (" + e.getSQLState() + "): " + e.getMessage(), false, what);
        } catch (RuntimeException e) {
            return new Shell.Result(1, e.toString(), false, what);
        }
    }

    /**
     * Lo stesso come root da 127.0.0.1 (MySQL la risolve in localhost: lo stesso account del socket), con la password
     * del file dei segreti, o senza se MySQL non ce l'ha ancora.
     */
    public static Shell.Result rootJdbc(String db, String sql, Object... params) {
        String password = PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD);
        if (!password.isEmpty()) {
            Shell.Result r = jdbc("127.0.0.1", port, db, "root", password, sql, params);
            if (r.success() || !r.output().startsWith("ERROR 1045 ")) return r;
        }
        return jdbc("127.0.0.1", port, db, "root", "", sql, params);
    }

    /** Il risultato della riparazione, per la prova e per il log. */
    public enum Outcome { NOTHING, DONE, NOT_APPLIED, LOCKED_OUT }

    public static void ensureAtBoot() {
        try {
            if (Shell.resolve("mysql") == null) return;
            repair();
        } catch (Throwable t) {
            LOGGER.warning("[MysqlRoot] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static Outcome repair() {
        // Root entra senza password? Se no, o una password c'e' gia', o MySQL e' spento: niente da fare.
        if (!entersWith(options(null))) return Outcome.NOTHING;
        List<String> hosts = emptyRootHosts();
        if (hosts.isEmpty()) {
            LOGGER.info("[MysqlRoot] root gets in without a password but no root account has an empty one: left as it is");
            return Outcome.NOTHING;
        }
        // Prima nel file, poi in MySQL: e si rilegge dal disco, non dalla memoria. Se il file non si
        // scrive, MySQL non si tocca: una password che esiste solo in MySQL chiuderebbe fuori tutti.
        String password;
        String onDisk;
        try {
            password = PanelSecrets.ensureMysqlRootPassword();
            onDisk = PanelSecrets.reread(PanelSecrets.MYSQL_ROOT_PASSWORD);
        } catch (RuntimeException e) {
            password = "";
            onDisk = "";
        }
        if (password.isEmpty() || !password.equals(onDisk)) {
            LOGGER.warning("[MysqlRoot] NOT_APPLIED: the root password could not be saved in the panel secrets file;"
                    + " MySQL root left without a password");
            return Outcome.NOT_APPLIED;
        }
        String alter = setPassword(hosts, password);
        boolean withPassword = entersWith(options(password));
        boolean socketOpen = entersWith(options(null));
        boolean tcpOpen = entersWith(tcpOptions(null));
        if (withPassword && !socketOpen && !tcpOpen) {
            LOGGER.info("[MysqlRoot] DONE: root@" + String.join(", root@", hosts) + " has a password now, kept in the root"
                    + " secrets file; without it MySQL refuses root, from the socket and from 127.0.0.1");
            return Outcome.DONE;
        }
        if (!withPassword && !socketOpen) {
            LOGGER.severe("[MysqlRoot] LOCKED_OUT: root refuses both the password of the panel secrets file and no password"
                    + " (ALTER USER: " + (alter == null ? "done" : alter) + "): the password to try by hand is mysql_root_password in "
                    + PanelSecrets.location(PanelSecrets.MYSQL_ROOT_PASSWORD));
            return Outcome.LOCKED_OUT;
        }
        LOGGER.warning("[MysqlRoot] NOT_APPLIED: ALTER USER " + (alter == null ? "done" : firstLine(alter))
                + "; with the password " + (withPassword ? "root gets in" : "root does not get in")
                + ", without it " + (socketOpen || tcpOpen ? "root STILL gets in" : "root is refused"));
        return Outcome.NOT_APPLIED;
    }

    private static String firstLine(String s) {
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
