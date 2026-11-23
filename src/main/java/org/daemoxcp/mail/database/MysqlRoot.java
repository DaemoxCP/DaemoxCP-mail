package org.daemoxcp.mail.database;

import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.util.Shell;

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
 * MySQL's root user: how the panel uses it, and its password on the servers installed before.
 *
 * Measured on 2026-11-07 on the production server (MySQL 8.4.11): root@localhost without a password, and no
 * `mysql_root_password` in the secrets file. In FreeBSD's mysql84-server there is no auth_socket,
 * so "without a password" means that anyone with a user on the machine gets in: from
 * `su -m nobody` you got in as root both from the socket and from 127.0.0.1. A flaw in Roundcube or
 * in rspamd was worth all of MySQL, mail included. The installations done by the panel since 17 October
 * set the password (FullMailServerScript); this repair sets it at startup on the servers
 * installed before.
 *
 * The order is the one that cannot lock anyone out: first the password in the secrets file
 * (written and read back from disk), then ALTER USER. If the panel stopped halfway, at the next
 * start root would still get in without a password and the repair would start again with the same password
 * from the file. A password set by hand is never touched: if root does not get in without a password, there is
 * nothing to do.
 *
 * All the questions as root go through here: the password in a 600 options file in a 700
 * folder that lasts one command, the SQL on standard input, never on the command line that "ps" shows to
 * everyone. Only fixed statements from the catalog (SqlCatalog), without values, go to the mysql client: it
 * is checked by CatalogGuard.allowed before writing the file. The only statement with a value, the
 * root password, goes through JDBC as a parameter ({@link #setPassword}).
 */
public final class MysqlRoot {

    private static final Logger LOGGER = Logger.getLogger(MysqlRoot.class.getName());

    /** MySQL's socket; empty = the client's default one. The tests change it. */
    static String socket = System.getProperty("daemoxcp.mail.mysql.socket", "");
    /** The TCP port on 127.0.0.1, to check that root does not get in without a password from there either. */
    static String port = System.getProperty("daemoxcp.mail.mysql.port", "3306");
    /** Where the commands' temporary folders are created. */
    static String workDir = System.getProperty("daemoxcp.mail.mysql.workdir", "/var/tmp");

    private static final Pattern HOST = Pattern.compile("[A-Za-z0-9._:%-]{1,255}");
    private static final long TIMEOUT_SECONDS = 30;

    private MysqlRoot() {}

    /** Root's options file with the password, or without a password. */
    static String options(String password) {
        StringBuilder b = new StringBuilder("[client]\nuser=root\n");
        if (password != null) b.append("password=\"").append(password).append("\"\n");
        else b.append("password=\n");
        if (!socket.isEmpty()) b.append("socket=").append(socket).append('\n');
        return b.toString();
    }

    /** Like options, but from 127.0.0.1 over TCP instead of from the socket. */
    static String tcpOptions(String password) {
        return "[client]\nuser=root\npassword=" + (password == null ? "" : "\"" + password + "\"")
                + "\nhost=127.0.0.1\nport=" + port + "\nprotocol=TCP\n";
    }

    /**
     * A question as root, with the password from the secrets file if there is one and it works, otherwise
     * without (a MySQL that does not have one yet). The output, or "" if root does not get in. Only
     * a statement from the catalog: any other text is refused before the client.
     */
    public static String query(String sql) {
        // First the text, then the secrets: a refused text must not even cause the password to be read.
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
     * mysql with the options file (--defaults-file: no other file, not even a ~/.my.cnf) and the SQL
     * on standard input, in a 700 folder that is deleted at once.
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
                    // a 700 root folder in /var/tmp: the system cleanup removes it
                }
            }
        }
    }

    static boolean entersWith(String options) {
        Shell.Result r = mysql(options, SqlCatalog.MYSQL_ROOT_PING);
        return r.success() && "1".equals(r.outputTrim());
    }

    /** The root accounts without a password, from the accounts table (only user and host, no data). */
    static List<String> emptyRootHosts() {
        Shell.Result r = mysql(options(null), SqlCatalog.MYSQL_ROOT_EMPTY_HOSTS);
        List<String> hosts = new ArrayList<>();
        if (!r.success()) return hosts;
        for (String h : r.outputTrim().split("\n")) if (!h.isBlank()) hosts.add(h.trim());
        return hosts;
    }

    /**
     * The password for the root accounts, via JDBC: root without a password from 127.0.0.1 (the same account
     * as the socket, MySQL resolves 127.0.0.1 to localhost), host and password as parameters. The hosts first go
     * through a closed list of characters. Null if it worked; otherwise the reason, and MySQL stays as it was
     * for the accounts that are missing.
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
     * A catalog statement via JDBC, with that user on that database (null: none), the values as
     * parameters. The output as the mysql client wrote it (one line per row, the columns separated by a tab, NULL
     * for an empty value), or exit 1 with MySQL's code and message. Host, port and database must have
     * already gone through a strict form: they end up in the URL.
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
     * The same as root from 127.0.0.1 (MySQL resolves it to localhost: the same account as the socket), with the
     * password from the secrets file, or without if MySQL does not have one yet.
     */
    public static Shell.Result rootJdbc(String db, String sql, Object... params) {
        String password = PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD);
        if (!password.isEmpty()) {
            Shell.Result r = jdbc("127.0.0.1", port, db, "root", password, sql, params);
            if (r.success() || !r.output().startsWith("ERROR 1045 ")) return r;
        }
        return jdbc("127.0.0.1", port, db, "root", "", sql, params);
    }

    /** The result of the repair, for the test and for the log. */
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
        // Does root get in without a password? If not, either a password already exists, or MySQL is off: nothing
        // to do.
        if (!entersWith(options(null))) return Outcome.NOTHING;
        List<String> hosts = emptyRootHosts();
        if (hosts.isEmpty()) {
            LOGGER.info("[MysqlRoot] root gets in without a password but no root account has an empty one: left as it is");
            return Outcome.NOTHING;
        }
        // First in the file, then in MySQL: and it is read back from disk, not from memory. If the file cannot
        // be written, MySQL is not touched: a password that exists only in MySQL would lock everyone out.
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
