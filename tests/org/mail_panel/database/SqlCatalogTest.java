package org.mail_panel.database;

import org.mail_panel.security.AuthStore;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The panel runs only the SQL of its catalog.
 *
 *  1. the catalog: every statement is a constant made only of text and of other constants of the
 *     catalog (no value, no method call), and the pieces that are not statements are private;
 *  2. the guard (SQLite in memory): a catalog statement passes; any other text is refused before it
 *     reaches the driver, by every way a text gets there (prepareStatement, prepareCall, nativeSQL,
 *     execute, executeQuery, executeUpdate, addBatch, also the ones a PreparedStatement inherits), and
 *     the statements and the metadata do not hand out the connection without the guard;
 *  3. from the project folder, the code (src/main/java):
 *     a. no SQL text outside the catalog, except the install scripts (shell text for the mysql client);
 *     b. what goes to a JDBC call is a catalog constant or a name that holds one, never a text built
 *        there (a +, a literal, String.format, a StringBuilder);
 *     c. only CatalogGuard opens a connection (DriverManager), and nobody takes the driver's statement
 *        back from a result (getStatement);
 *  4. the lists that must match: the tables of the reset's DROP and MailDatabase.PANEL_TABLES, the
 *     busy timeout of SQLite and database.BUSY_TIMEOUT_MS;
 *  5. with the test MySQL, as its root (-Dmysql.root=yes): the user that MailDatabase creates with
 *     CREATE USER ... IDENTIFIED BY ? gets in with exactly the password given, quotes and backslash
 *     included (the driver prepares on the client side and escapes the value);
 *  6. the web part's list (WebPartStatements): every name is a statement of
 *     the catalog, none writes administrators, passkeys, codes or sessions (only the root does, A), and in
 *     the web part's mode the guard takes the list and refuses the rest of the catalog;
 *  7. the web part's procedures (0.8.2, second part): every MySQL statement of the list has one, and only
 *     those; its call has the session and then the statement's parameters, its creation as many parameters
 *     and one placeholder (the comment), the same name in the four texts; every one but the public ones is
 *     bound to the session (the helper with a real permission, or the session's own row); the idle time is
 *     WebSessions.IDLE_SECONDS; no procedure gives the DKIM private keys or the password hashes and copies; the reads give no "*" of a table; and every text parameter compared with a
 *     column is ASCII (the database's collation is not the one of its tables).
 *
 * Usage (on the VM, from the project folder for part 3):
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.SqlCatalogTest
 *   java -Dmysql.root=yes -Dmysql.port=33062 -cp ... org.mail_panel.database.SqlCatalogTest
 */
public class SqlCatalogTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    interface SqlAction { void run() throws Exception; }

    static boolean refused(SqlAction a) {
        try {
            a.run();
            return false;
        } catch (SQLException e) {
            return e.getMessage() != null && e.getMessage().contains("catalog");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * The mysql client's SQL that is not in the catalog: none any more.
     * MysqlRoot, MysqlListen and UpdateManager give the client only catalog statements (MysqlRoot.mysql refuses any
     * other text), and the questions with a value, RoundcubeDbUser's included, go through JDBC. Only the install
     * scripts remain: shell text for the mysql client and for Postfix and Dovecot (RoundcubeDbAccountScript too).
     */
    static final Set<String> MYSQL_CLIENT = Set.of();
    static final String SCRIPTS = "org/mail_panel/scripts/";

    /** The start of an SQL statement, in the panel's style (keywords in capitals). */
    static final Pattern SQL = Pattern.compile("^\\s*(SELECT\\s+\\S|INSERT\\s+(OR\\s+\\w+\\s+)?INTO\\b|UPDATE\\s+(OR\\s+\\w+\\s+)?\\w+\\s+SET\\b"
            + "|DELETE\\s+FROM\\b|REPLACE\\s+INTO\\b|CREATE\\s+(TABLE|USER|DATABASE|INDEX|PROCEDURE)\\b|ALTER\\s+(TABLE|USER)\\b"
            + "|DROP\\s+(TABLE|USER|DATABASE|INDEX|PROCEDURE)\\b|GRANT\\s|REVOKE\\s|PRAGMA\\s|SHOW\\s+(CREATE|TABLES|COLUMNS|GRANTS)\\b"
            + "|FLUSH\\s+PRIVILEGES|TRUNCATE\\s|CALL\\s+\\w+\\s*\\(|SET\\s+(SESSION|GLOBAL|@)|BEGIN\\s+IMMEDIATE|COMMIT\\b|ROLLBACK\\b)");
    static final Pattern JDBC = Pattern.compile("\\.(prepareStatement|prepareCall|nativeSQL|executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch)\\(");
    /** A catalog constant, a name, a field, an array element or an accessor without arguments. */
    static final Pattern HOLDER = Pattern.compile("SqlCatalog\\.[A-Z0-9_]+|[A-Za-z_]\\w*(\\[\\w+\\])?(\\.[A-Za-z_]\\w*(\\(\\))?)*");
    static final Set<String> TEXT_METHODS = Set.of("toString()", "trim()", "strip()", "toLowerCase()", "toUpperCase()", "intern()");

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. The catalog ==");
        int statements = 0;
        List<String> notConstant = new ArrayList<>();
        for (Field f : SqlCatalog.class.getDeclaredFields()) {
            int m = f.getModifiers();
            if (f.getType() != String.class || !Modifier.isStatic(m)) continue;
            f.setAccessible(true);
            String v = (String) f.get(null);
            // A compile-time constant is interned: a value computed while the class loads is not.
            if (v != v.intern() || !Modifier.isFinal(m)) notConstant.add(f.getName());
            if (Modifier.isPublic(m)) statements++;
        }
        check("every constant is fixed when the panel is compiled " + notConstant, notConstant.isEmpty());
        check("the guard knows every public statement, each text under one name only (" + statements + ")",
                statements == CatalogGuard.size() && statements > 300);
        Path catalog = Path.of("src/main/java/org/mail_panel/database/SqlCatalog.java");
        if (Files.isRegularFile(catalog)) {
            List<String> built = new ArrayList<>();
            Matcher c = Pattern.compile("static final String (\\w+) =\\s*(.*?);\\n", Pattern.DOTALL).matcher(Files.readString(catalog));
            while (c.find()) {
                String rest = stripStrings(c.group(2)).replaceAll("\\s+", "");
                // Left after the strings: only + and names of other constants of the catalog.
                if (!rest.matches("(\\+|[A-Z][A-Z0-9_]*)*")) built.add(c.group(1));
            }
            check("in the source, every constant is only text and other constants " + built, built.isEmpty());
        }
        check("the pieces that are not statements are private, so the guard does not take them alone",
                !CatalogGuard.allowed(field("AUTH_ADMIN_SELECT")) && !CatalogGuard.allowed(field("AUTH_PASSKEY_SELECT")));

        System.out.println("\n== 2. The guard ==");
        try (Connection c = CatalogGuard.open("jdbc:sqlite::memory:")) {
            try (Statement s = c.createStatement()) {
                s.execute(SqlCatalog.CONFIG_DB_CREATE_TABLE);
            }
            check("a catalog statement passes", columns(c) > 20);
            try (PreparedStatement p = c.prepareStatement(SqlCatalog.CONFIG_SET_MYSQL_PASSWORD)) {
                p.setString(1, "x");
                check("a prepared catalog statement with its parameter passes", p.executeUpdate() == 0);
            }
            check("Statement.execute of another text is refused", refused(() -> {
                try (Statement s = c.createStatement()) { s.execute("DROP TABLE config"); }
            }));
            check("executeQuery, executeUpdate, addBatch of another text are refused", refused(() -> {
                try (Statement s = c.createStatement()) { s.executeQuery("SELECT 2"); }
            }) && refused(() -> {
                try (Statement s = c.createStatement()) { s.executeUpdate("DELETE FROM config"); }
            }) && refused(() -> {
                try (Statement s = c.createStatement()) { s.addBatch("DELETE FROM config"); }
            }));
            check("prepareStatement, prepareCall, nativeSQL of another text are refused",
                    refused(() -> c.prepareStatement("SELECT 2")) && refused(() -> c.prepareCall("SELECT 2"))
                    && refused(() -> c.nativeSQL("SELECT 2")));
            check("a catalog statement with one character more is refused",
                    refused(() -> c.prepareStatement(SqlCatalog.CONFIG_GET_MYSQL_PASSWORD + " ")));
            check("the texts a PreparedStatement inherits are refused", refused(() -> {
                try (PreparedStatement p = c.prepareStatement(SqlCatalog.CONFIG_GET_MYSQL_PASSWORD)) { p.execute("DROP TABLE config"); }
            }));
            check("the connection from a statement is the guarded one", refused(() -> {
                try (Statement s = c.createStatement()) { s.getConnection().prepareStatement("SELECT 2"); }
            }));
            check("the connection from the metadata is the guarded one", refused(() -> {
                DatabaseMetaData md = c.getMetaData();
                md.getConnection().createStatement().execute("DROP TABLE config");
            }));
            boolean noDriver;
            try {
                c.unwrap(org.sqlite.SQLiteConnection.class);
                noDriver = false;
            } catch (SQLException e) {
                noDriver = true;
            }
            check("unwrap does not hand out the driver's connection", noDriver && c.unwrap(Connection.class) == c
                    && !c.isWrapperFor(org.sqlite.SQLiteConnection.class));
            check("after all that, the table is still there", columns(c) > 20);
        }

        Path src = Path.of("src/main/java");
        if (Files.isDirectory(src)) {
            System.out.println("\n== 3. The code ==");
            List<String> sqlOutside = new ArrayList<>(), built = new ArrayList<>(), driver = new ArrayList<>();
            int files = 0, calls = 0;
            List<Path> all;
            try (Stream<Path> s = Files.walk(src)) { all = s.filter(p -> p.toString().endsWith(".java")).sorted().toList(); }
            for (Path p : all) {
                String rel = src.relativize(p).toString().replace('\\', '/');
                if (rel.equals("org/mail_panel/database/SqlCatalog.java")) continue;
                files++;
                String text = Files.readString(p);
                String code = stripComments(text);
                boolean client = MYSQL_CLIENT.contains(rel) || rel.startsWith(SCRIPTS);
                if (!client) {
                    for (String lit : literals(code)) {
                        if (SQL.matcher(lit).find()) sqlOutside.add(rel + ": " + oneLine(lit));
                    }
                }
                Matcher m = JDBC.matcher(code);
                while (m.find()) {
                    String arg = firstArgument(code, m.end()).strip();
                    // An executor's execute(task): a lambda or a method reference, not SQL.
                    if (arg.isEmpty() || arg.contains("->") || arg.contains("::")) continue;
                    calls++;
                    String last = arg.contains(".") ? arg.substring(arg.lastIndexOf('.') + 1) : "";
                    if (!HOLDER.matcher(arg).matches() || TEXT_METHODS.contains(last))
                        built.add(rel + ": ." + m.group(1) + "(" + oneLine(arg) + ")");
                }
                if (!rel.equals("org/mail_panel/database/CatalogGuard.java") && code.contains("DriverManager"))
                    driver.add(rel + " (DriverManager)");
                if (code.contains(".getStatement()")) driver.add(rel + " (getStatement)");
            }
            check("no SQL text outside the catalog, in " + files + " files" + show(sqlOutside), sqlOutside.isEmpty());
            check("every JDBC call gets a catalog statement, not a text built there (" + calls + " calls)" + show(built),
                    built.isEmpty() && calls > 200);
            check("only CatalogGuard opens a connection" + show(driver), driver.isEmpty());
        } else {
            System.out.println("\n  (part 3 skipped: run it from the project folder, where src/ is)");
        }

        System.out.println("\n== 4. The lists that must match ==");
        Field tables = MailDatabase.class.getDeclaredField("PANEL_TABLES");
        tables.setAccessible(true);
        @SuppressWarnings("unchecked") List<String> panelTables = (List<String>) tables.get(null);
        check("the reset's DROP has the tables of MailDatabase.PANEL_TABLES, in their order",
                SqlCatalog.MAIL_DROP_PANEL_TABLES.equals("DROP TABLE IF EXISTS " + String.join(", ", panelTables)));
        Field busy = Class.forName("org.mail_panel.sqli.database").getDeclaredField("BUSY_TIMEOUT_MS");
        busy.setAccessible(true);
        check("SQLite's busy timeout is database.BUSY_TIMEOUT_MS",
                SqlCatalog.CONFIG_DB_BUSY_TIMEOUT.equals("PRAGMA busy_timeout = " + busy.getInt(null)));

        String port = System.getProperty("mysql.port");
        if (port != null && "yes".equals(System.getProperty("mysql.root"))) {
            System.out.println("\n== 5. With the test MySQL, as its root: CREATE USER with the password as a parameter ==");
            MailDatabase root = new MailDatabase();
            root.setConnection("127.0.0.1", Integer.parseInt(port), "");
            check("connected as the test MySQL's root", root.connectAsRoot(System.getProperty("mysql.root.password", "")));
            String url = "jdbc:mysql://127.0.0.1:" + port + "/?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
            try (Connection own = java.sql.DriverManager.getConnection(url, "root", System.getProperty("mysql.root.password", ""));
                 Statement s = own.createStatement()) {
                s.execute("DROP USER IF EXISTS 'mailserver'@'127.0.0.1'");
                // Quotes, a backslash, a dollar: before, only the quotes were doubled into the text.
                String password = "Pa'ss\\wo\"rd $x " + System.nanoTime();
                root.createDatabaseAndUser(password);
                boolean in;
                try (Connection c = java.sql.DriverManager.getConnection(url, "mailserver", password)) {
                    in = c.isValid(5);
                } catch (SQLException e) {
                    in = false;
                }
                check("the user created with that password gets in with exactly that password", in);
                boolean wrong;
                try (Connection c = java.sql.DriverManager.getConnection(url, "mailserver", password.replace("\\", ""))) {
                    wrong = true;
                } catch (SQLException e) {
                    wrong = false;
                }
                check("  and not with the password without the backslash", !wrong);
                s.execute("DROP USER IF EXISTS 'mailserver'@'127.0.0.1'");
                s.execute("DROP DATABASE IF EXISTS mailserver");
                s.execute("DROP DATABASE IF EXISTS mailpanel");
            }
        } else {
            System.out.println("\n  (part 5 skipped: it creates MySQL users, turned on with -Dmysql.root=yes and the test MySQL's -Dmysql.port)");
        }

        System.out.println("\n== 6. The web part's list ==");
        List<String> unknown = new ArrayList<>();
        for (String name : WebPartStatements.NAMES) {
            try {
                Field f = SqlCatalog.class.getField(name);
                if (f.getType() != String.class) unknown.add(name);
            } catch (NoSuchFieldException e) {
                unknown.add(name);
            }
        }
        check("every name of the list is a statement of the catalog " + unknown, unknown.isEmpty());
        List<String> writesAuth = new ArrayList<>();
        for (String name : WebPartStatements.NAMES) {
            String sql = field(name).trim().toUpperCase(java.util.Locale.ROOT);
            boolean write = !sql.startsWith("SELECT") && !sql.startsWith("PRAGMA");
            if (write && sql.matches("(?s).*\\b(PANEL_ADMIN|ADMIN_PASSKEYS|PANEL_SESSIONS|LOGIN_CODE_EMAIL|LOGIN_CODE_CONSOLE|STEPUP_CODE|EMAIL_CHANGE_CODE)\\b.*")
                    && !name.equals("SESSION_TOUCH") && !name.equals("MAIL_SET_ADMIN_THEME") && !name.equals("MAIL_SET_ADMIN_LANGUAGE"))
                writesAuth.add(name);
        }
        check("none of them writes administrators, passkeys, codes or sessions, save the session's last activity "
                + "and the administrator's theme and language " + writesAuth, writesAuth.isEmpty());
        CatalogGuard.webPartOnly();
        check("in the web part's mode the guard takes the list (the session check, the domains)",
                CatalogGuard.allowed(SqlCatalog.SESSION_CHECK) && CatalogGuard.allowed(SqlCatalog.MAIL_GET_DOMAINS));
        check("  and refuses the rest of the catalog: creating a session, an administrator, a migration",
                !CatalogGuard.allowed(SqlCatalog.SESSION_CREATE) && !CatalogGuard.allowed(SqlCatalog.AUTH_CREATE_ADMIN)
                && !CatalogGuard.allowed(SqlCatalog.MAIL_CREATE_PANEL_SESSIONS) && !CatalogGuard.allowed(SqlCatalog.AUTH_CODE_CONSOLE_LOGIN_INSERT));

        System.out.println("\n== 7. The web part's procedures ==");
        java.util.Set<String> mysqlStatements = new java.util.TreeSet<>(), withRoutine = new java.util.TreeSet<>();
        for (String name : WebPartStatements.NAMES) if (!name.startsWith("CONFIG_")) mysqlStatements.add(name);
        java.util.Map<String, String> nameOf = new java.util.HashMap<>();
        for (Field f : SqlCatalog.class.getFields()) if (f.getType() == String.class) nameOf.put((String) f.get(null), f.getName());
        List<String> shape = new ArrayList<>(), unbound = new ArrayList<>(), secrets = new ArrayList<>(), star = new ArrayList<>();
        java.util.Set<String> routineNames = new java.util.HashSet<>();
        Pattern helper = Pattern.compile("CALL web_session_admin\\(p_session, '([a-z.,]*)', v_admin\\)");
        java.util.Set<String> publicOnes = java.util.Set.of("check_session", "has_admin", "get_setting", "log_audit_event", "list_domain_names");
        for (WebPartStatements.Routine r : WebPartStatements.ROUTINES) {
            String statement = nameOf.get(r.statement());
            withRoutine.add(statement);
            Matcher call = Pattern.compile("CALL ([a-z_]+)\\(([?, ]*)\\)").matcher(r.call());
            String routine = call.matches() ? call.group(1) : "?";
            routineNames.add(routine);
            long params = r.statement().chars().filter(ch -> ch == '?').count();
            long callParams = r.call().chars().filter(ch -> ch == '?').count();
            int createParams = r.create().split("\\b(IN|OUT) p_").length - 1;
            boolean ok = call.matches() && callParams == params + 1 && createParams == params + 1
                    && r.create().chars().filter(ch -> ch == '?').count() == 1
                    && r.create().startsWith("CREATE DEFINER = 'mailpanel_routines'@'localhost' PROCEDURE " + routine + "(IN p_session CHAR(64) CHARACTER SET ascii")
                    && r.create().contains(" COMMENT ? SQL SECURITY DEFINER\n") && r.create().endsWith("END")
                    && r.drop().equals("DROP PROCEDURE IF EXISTS " + routine)
                    && r.grant().equals("GRANT EXECUTE ON PROCEDURE " + routine + " TO 'mailpanel_web'@'localhost', 'mailpanel_web'@'127.0.0.1'")
                    && r.read() == r.create().replaceAll("(?s).*\nBEGIN\n", "").lines()
                            .filter(l -> !l.contains("DECLARE") && !l.contains("CALL web_session_admin") && !l.trim().startsWith("IF ")
                                    && !l.contains("SIGNAL") && !l.trim().equals("END IF;")).findFirst().orElse("").trim().startsWith("SELECT");
            if (!ok) shape.add(statement + " -> " + routine);
            Matcher h = helper.matcher(r.create());
            boolean permission = h.find() && (h.group(1).isEmpty() ? r.create().contains("WHERE id = v_admin")
                    : java.util.Arrays.stream(h.group(1).split(",")).allMatch(AuthStore.ALL_PERMISSIONS::contains));
            boolean ownRow = r.create().contains("s.token_hash = p_session AND s.expires_at > UTC_TIMESTAMP()");
            if (!publicOnes.contains(routine) && !permission && !ownRow) unbound.add(routine);
            String body = r.create().replace("(d.dkim_private_key IS NOT NULL AND d.dkim_private_key <> '') AS has_dkim", "");
            if (r.read() && (body.contains("private_key") || (body.matches("(?s).*SELECT((?!\\bFROM\\b).)*\\bpassword(_encrypted)?\\b.*"))))
                secrets.add(routine);
            if (body.matches("(?s).*(\\.\\*|SELECT \\*).*")) star.add(routine);
        }
        check("every MySQL statement of the web's list has a procedure, and only those " + mysqlStatements.size(),
                mysqlStatements.equals(withRoutine) && WebPartStatements.ROUTINES.size() == mysqlStatements.size());
        check("a name each, and every name in English words with underscores (" + routineNames.size() + ")",
                routineNames.size() == WebPartStatements.ROUTINES.size() && routineNames.stream().allMatch(n -> n.matches("[a-z]+(_[a-z]+)+")));
        check("the call has the session and the statement's parameters, the creation as many and the comment, the same name"
                + " in the four texts, and a read is a read" + (shape.isEmpty() ? "" : " " + shape), shape.isEmpty());
        check("every procedure but the public ones is bound to the session" + (unbound.isEmpty() ? "" : " " + unbound), unbound.isEmpty());
        check("the idle time of the procedures is WebSessions.IDLE_SECONDS (" + org.mail_panel.webserver.WebSessions.IDLE_SECONDS + ")",
                SqlCatalog.WEB_CREATE_SESSION_ADMIN.contains("INTERVAL " + org.mail_panel.webserver.WebSessions.IDLE_SECONDS + " SECOND")
                && WebPartStatements.ROUTINES.stream().filter(r -> r.create().contains("INTERVAL") && r.create().contains("last_seen_at"))
                        .allMatch(r -> r.create().contains("INTERVAL " + org.mail_panel.webserver.WebSessions.IDLE_SECONDS + " SECOND")));
        check("no DKIM private key, no password hash or copy out of the database (Show password is the root part's)" + (secrets.isEmpty() ? "" : " " + secrets),
                secrets.isEmpty());
        check("no read gives every column of a table (*)" + (star.isEmpty() ? "" : " " + star), star.isEmpty());
        check("the helper is not the web's: nobody gets EXECUTE on it", WebPartStatements.ROUTINES.stream()
                .noneMatch(r -> r.grant().contains("web_session_admin")));
        // The database's collation (utf8mb4_unicode_ci, from the installer) is not the one of its tables (utf8mb4_0900_ai_ci): a
        // text parameter compared with a column must not take the database's, or MySQL refuses the mix.
        List<String> creates = new ArrayList<>(List.of(SqlCatalog.WEB_CREATE_SESSION_ADMIN));
        WebPartStatements.ROUTINES.forEach(r -> creates.add(r.create()));
        Pattern textParam = Pattern.compile("\\b(?:IN|OUT) (p_\\w+) (?:VAR)?CHAR\\(\\d+\\)( CHARACTER SET ascii)?");
        List<String> mixed = new ArrayList<>();
        for (String c : creates) {
            int begin = c.indexOf("\nBEGIN\n");
            StringBuilder where = new StringBuilder();
            Matcher w = Pattern.compile("WHERE[^;]*;").matcher(c.substring(begin));
            while (w.find()) where.append(w.group()).append('\n');
            Matcher m = textParam.matcher(c.substring(0, begin));
            while (m.find()) {
                if (m.group(2) == null && Pattern.compile("\\b" + m.group(1) + "\\b").matcher(where).find())
                    mixed.add(c.replaceAll("(?s).*PROCEDURE (\\w+)\\(.*", "$1") + "." + m.group(1));
            }
        }
        check("every text parameter compared with a column is ASCII, whatever the database's collation" + (mixed.isEmpty() ? "" : " " + mixed),
                mixed.isEmpty());

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static String field(String name) throws Exception {
        Field f = SqlCatalog.class.getDeclaredField(name);
        f.setAccessible(true);
        return (String) f.get(null);
    }

    static int columns(Connection c) throws SQLException {
        int n = 0;
        try (PreparedStatement p = c.prepareStatement(SqlCatalog.CONFIG_DB_COLUMNS); ResultSet r = p.executeQuery()) {
            while (r.next()) n++;
        }
        return n;
    }

    static String show(List<String> l) {
        if (l.isEmpty()) return "";
        return "\n           " + String.join("\n           ", l.subList(0, Math.min(25, l.size())))
                + (l.size() > 25 ? "\n           ... " + (l.size() - 25) + " more" : "");
    }

    static String oneLine(String s) {
        String t = s.replaceAll("\\s+", " ").strip();
        return t.length() > 90 ? t.substring(0, 90) + "..." : t;
    }

    /** The source without comments; strings and text blocks stay as they are. */
    static String stripComments(String s) {
        StringBuilder out = new StringBuilder(s.length());
        int i = 0, n = s.length();
        while (i < n) {
            if (s.startsWith("\"\"\"", i)) {
                int e = s.indexOf("\"\"\"", i + 3);
                e = e < 0 ? n : e + 3;
                out.append(s, i, e);
                i = e;
            } else if (s.charAt(i) == '"' || s.charAt(i) == '\'') {
                int e = endOfQuoted(s, i);
                out.append(s, i, e);
                i = e;
            } else if (s.startsWith("//", i)) {
                int e = s.indexOf('\n', i);
                i = e < 0 ? n : e;
            } else if (s.startsWith("/*", i)) {
                int e = s.indexOf("*/", i + 2);
                i = e < 0 ? n : e + 2;
                out.append(' ');
            } else {
                out.append(s.charAt(i++));
            }
        }
        return out.toString();
    }

    static int endOfQuoted(String s, int i) {
        char q = s.charAt(i);
        int j = i + 1;
        while (j < s.length() && s.charAt(j) != q) {
            if (s.charAt(j) == '\\') j++;
            j++;
        }
        return Math.min(j + 1, s.length());
    }

    /** The text of every string literal and text block (escapes left as they are: enough to see SQL). */
    static List<String> literals(String code) {
        List<String> out = new ArrayList<>();
        int i = 0, n = code.length();
        while (i < n) {
            if (code.startsWith("\"\"\"", i)) {
                int e = code.indexOf("\"\"\"", i + 3);
                if (e < 0) break;
                String body = code.substring(i + 3, e);
                int nl = body.indexOf('\n');
                out.add(nl < 0 ? body : body.substring(nl + 1));
                i = e + 3;
            } else if (code.charAt(i) == '"') {
                int e = endOfQuoted(code, i);
                out.add(code.substring(i + 1, Math.max(i + 1, e - 1)));
                i = e;
            } else if (code.charAt(i) == '\'') {
                i = endOfQuoted(code, i);
            } else {
                i++;
            }
        }
        return out;
    }

    /** From just after "(" to the first "," or ")" at the same depth, outside strings. */
    static String firstArgument(String code, int start) {
        int depth = 0, i = start, n = code.length();
        while (i < n) {
            char ch = code.charAt(i);
            if (code.startsWith("\"\"\"", i)) {
                int e = code.indexOf("\"\"\"", i + 3);
                i = e < 0 ? n : e + 3;
                continue;
            }
            if (ch == '"' || ch == '\'') {
                i = endOfQuoted(code, i);
                continue;
            }
            if (ch == '(' || ch == '[' || ch == '{') depth++;
            else if (ch == ')' || ch == ']' || ch == '}') {
                if (depth == 0) return code.substring(start, i);
                depth--;
            } else if (ch == ',' && depth == 0) {
                return code.substring(start, i);
            }
            i++;
        }
        return code.substring(start);
    }

    /** The code with the string literals and text blocks taken out. */
    static String stripStrings(String s) {
        StringBuilder out = new StringBuilder();
        int i = 0, n = s.length();
        while (i < n) {
            if (s.startsWith("\"\"\"", i)) {
                int e = s.indexOf("\"\"\"", i + 3);
                i = e < 0 ? n : e + 3;
            } else if (s.charAt(i) == '"') {
                i = endOfQuoted(s, i);
            } else {
                out.append(s.charAt(i++));
            }
        }
        return out.toString();
    }

}
