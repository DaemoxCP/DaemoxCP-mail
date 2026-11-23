package org.daemoxcp.mail.database;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;

/**
 * The only point from which the panel opens a JDBC connection, MySQL or SQLite:
 * the connection it returns accepts only the statements of {@link SqlCatalog}, that is, exactly one
 * of its texts, and refuses any other SQL text before it reaches the driver.
 *
 * <p>SqlCatalogTest already checks on the code that SQL is only in the catalog; this guard does it
 * while the panel runs, for every statement: a text composed by mistake, or a value that ended up in the
 * text instead of in a parameter, does not pass. The points watched are those from which an SQL text reaches the
 * driver: prepareStatement, prepareCall and nativeSQL of the connection, and execute, executeQuery,
 * executeUpdate, executeLargeUpdate and addBatch of every statement (also of a PreparedStatement, which
 * inherits them). A statement and the metadata return the guarded connection, and unwrap does not hand over
 * the real one. ResultSet.getStatement remains, which the panel does not use (SqlCatalogTest checks it).
 *
 * <p>It is not a defence against whoever runs their own code in the process: that would open a connection
 * of its own. Against that, the web part's MySQL user and the procedures are needed: {@link #openRoutines} is the
 * web part's connection with that user, which sends in place of every statement its procedure
 * (WebPartStatements.ROUTINES) with the fingerprint of the request's session ({@link #useSession}).
 */
public final class CatalogGuard {

    private static final Logger LOGGER = Logger.getLogger(CatalogGuard.class.getName());

    private CatalogGuard() {}

    /** The catalog's texts: the public constants of SqlCatalog (the private pieces are not statements). */
    private static final Set<String> STATEMENTS = load();

    private static Set<String> load() {
        Set<String> s = new HashSet<>();
        for (Field f : SqlCatalog.class.getDeclaredFields()) {
            int m = f.getModifiers();
            if (f.getType() == String.class && Modifier.isStatic(m) && Modifier.isFinal(m) && Modifier.isPublic(m)) {
                try {
                    s.add((String) f.get(null));
                } catch (IllegalAccessException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        return Set.copyOf(s);
    }

    /** The accepted statements: the whole catalog, or in the web part only its list (webPartOnly). */
    private static volatile Set<String> accepted = STATEMENTS;

    /** True if the text is one of the accepted statements, character by character. */
    public static boolean allowed(String sql) {
        return sql != null && accepted.contains(sql);
    }

    /**
     * The web part of the separated panel, at startup: from here only the statements of WebPartStatements.
     * There is no going back. A name that is not in the catalog stops the startup.
     */
    public static synchronized void webPartOnly() {
        Set<String> web = new HashSet<>();
        for (String name : WebPartStatements.NAMES) {
            try {
                Field f = SqlCatalog.class.getField(name);
                web.add((String) f.get(null));
            } catch (ReflectiveOperationException | ClassCastException e) {
                throw new IllegalStateException("WebPartStatements names a statement that is not in the catalog: " + name, e);
            }
        }
        accepted = Set.copyOf(web);
    }

    /** How many statements the catalog has. */
    public static int size() {
        return STATEMENTS.size();
    }

    public static Connection open(String url) throws SQLException {
        return guard(DriverManager.getConnection(url));
    }

    public static Connection open(String url, String user, String password) throws SQLException {
        return guard(DriverManager.getConnection(url, user, password));
    }

    public static Connection open(String url, Properties properties) throws SQLException {
        return guard(DriverManager.getConnection(url, properties));
    }

    // ===================== The web part with its own MySQL user: procedures only =====================

    /** The fingerprint of the session token of the current request (WebSessions.tokenHash), or none. */
    private static final ThreadLocal<String> SESSION = new ThreadLocal<>();
    private static final java.util.regex.Pattern SESSION_HASH = java.util.regex.Pattern.compile("[0-9a-f]{64}");

    /**
     * The web part, while it checks the cookie of a request: from here the procedures receive the fingerprint of that
     * token, and the database decides whether the session exists and what its role can do. It holds for the
     * thread, until the request ends ({@link #forgetSession}).
     */
    public static void useSession(String tokenHash) {
        if (tokenHash != null && SESSION_HASH.matcher(tokenHash).matches()) SESSION.set(tokenHash);
        else SESSION.remove();
    }

    /** The request has ended, or there is no session: the procedures receive NULL. */
    public static void forgetSession() {
        SESSION.remove();
    }

    /**
     * The web part's connection with its own MySQL user, which can only call the procedures. It accepts only the
     * statements of the web part's list that have a procedure, and sends the procedure: the session fingerprint
     * as first parameter, then the same parameters. For whoever uses it nothing changes: a read returns the
     * same columns, a write the rows touched and, if it is an insert, the new key (getGeneratedKeys).
     */
    public static Connection openRoutines(String url, String user, String password) throws SQLException {
        Connection raw = DriverManager.getConnection(url, user, password);
        if (raw == null) return null;
        return (Connection) Proxy.newProxyInstance(CatalogGuard.class.getClassLoader(),
                new Class<?>[]{Connection.class}, new RoutineConnectionHandler(raw));
    }

    /** The procedure of the text, if it is an accepted statement that has one; otherwise it refuses it. */
    private static WebPartStatements.Routine routine(Object sql) throws SQLException {
        check(sql);
        WebPartStatements.Routine r = WebPartStatements.routineOf((String) sql);
        if (r != null) return r;
        String text = (String) sql;
        LOGGER.warning("SQL without a procedure refused on the web part's MySQL connection: "
                + text.substring(0, Math.min(60, text.length())).replaceAll("\\p{Cntrl}", " "));
        throw new SQLException("SQL statement without a procedure for the web part", "42000");
    }

    private static SQLException notThroughRoutines(String what) {
        return new SQLException("Not available through the web part's procedures: " + what, "0A000");
    }

    private static final class RoutineConnectionHandler implements InvocationHandler {
        private final Connection raw;

        RoutineConnectionHandler(Connection raw) { this.raw = raw; }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            switch (method.getName()) {
                case "equals", "hashCode", "toString":
                    if (method.getDeclaringClass() == Object.class) return identity(proxy, method, args, raw);
                    break;
                case "unwrap", "isWrapperFor":
                    return wrapper(proxy, method, args);
                case "prepareStatement": {
                    // The variants with generated keys or the cursor type: the procedure is the same.
                    WebPartStatements.Routine r = routine(args[0]);
                    PreparedStatement call = raw.prepareStatement(r.call());
                    return Proxy.newProxyInstance(CatalogGuard.class.getClassLoader(), new Class<?>[]{PreparedStatement.class},
                            new RoutineStatementHandler(call, r, (Connection) proxy, raw));
                }
                case "createStatement":
                    return Proxy.newProxyInstance(CatalogGuard.class.getClassLoader(), new Class<?>[]{Statement.class},
                            new RoutineStatementHandler(raw.createStatement(), null, (Connection) proxy, raw));
                case "prepareCall", "nativeSQL":
                    check(args[0]);
                    throw notThroughRoutines(method.getName());
                case "getMetaData":
                    Object meta = call(raw, method, args);
                    return meta == null ? null : Proxy.newProxyInstance(CatalogGuard.class.getClassLoader(),
                            new Class<?>[]{DatabaseMetaData.class}, new MetaDataHandler(meta, (Connection) proxy));
                default:
                    break;
            }
            return call(raw, method, args);
        }
    }

    /**
     * A statement of the procedure connection. Prepared (routine not null): base is the prepared CALL, the
     * parameters shift by one. Plain (createStatement): every execute with the text prepares the CALL of its
     * procedure, which must have no other parameters; base serves only for the settings (timeout and the like).
     */
    private static final class RoutineStatementHandler implements InvocationHandler {
        private final Statement base;
        private final WebPartStatements.Routine routine;
        private final Connection connection;
        private final Connection raw;
        /** The CALL of the last execute with the text of a plain statement. */
        private PreparedStatement current;
        private long updateCount = -1;
        private Long generatedKey;

        RoutineStatementHandler(Statement base, WebPartStatements.Routine routine, Connection connection, Connection raw) {
            this.base = base;
            this.routine = routine;
            this.connection = connection;
            this.raw = raw;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String name = method.getName();
            boolean withText = args != null && args.length > 0 && args[0] instanceof String
                    && (name.startsWith("execute") || name.equals("addBatch"));
            switch (name) {
                case "equals", "hashCode", "toString":
                    if (method.getDeclaringClass() == Object.class) return identity(proxy, method, args, base);
                    break;
                case "unwrap", "isWrapperFor":
                    return wrapper(proxy, method, args);
                case "getConnection":
                    return connection;
                case "addBatch", "executeBatch", "executeLargeBatch", "clearBatch":
                    if (withText) check(args[0]);
                    throw notThroughRoutines(name);
                case "getGeneratedKeys":
                    return generatedKeys(generatedKey);
                case "getUpdateCount":
                    return (int) updateCount;
                case "getLargeUpdateCount":
                    return updateCount;
                case "close":
                    if (current != null) current.close();
                    base.close();
                    return null;
                default:
                    break;
            }
            if (withText) {
                // Plain Statement: execute(text), executeQuery(text), executeUpdate(text[, ...]).
                if (routine != null) {
                    check(args[0]);      // a PreparedStatement does not run a different text
                    throw notThroughRoutines(name + " with a text on a prepared statement");
                }
                WebPartStatements.Routine r = routine(args[0]);
                if (current != null) current.close();
                if (r.call().chars().filter(c -> c == '?').count() != 1)
                    throw notThroughRoutines("a statement with parameters, without preparing it");
                current = raw.prepareStatement(r.call());
                return run(current, r, name);
            }
            if (routine != null && args == null && name.startsWith("execute")) return run((PreparedStatement) base, routine, name);
            // The results of a plain statement are those of its last CALL.
            if (routine == null && current != null && (name.equals("getResultSet") || name.equals("getMoreResults")
                    || name.equals("getWarnings") || name.equals("clearWarnings"))) return call(current, method, args);
            if (routine != null && method.getDeclaringClass() == PreparedStatement.class && name.startsWith("set")
                    && args != null && args.length > 0 && args[0] instanceof Integer index) {
                // The statement's parameters are the procedure's from the second onwards.
                Object[] shifted = args.clone();
                shifted[0] = index + 1;
                return call(base, method, shifted);
            }
            return call(base, method, args);
        }

        /** Runs the CALL with the session fingerprint: the rows of a read, the rows touched by a write. */
        private Object run(PreparedStatement call, WebPartStatements.Routine r, String how) throws SQLException {
            String session = SESSION.get();
            if (session == null) call.setNull(1, Types.CHAR);
            else call.setString(1, session);
            updateCount = -1;
            generatedKey = null;
            if (r.read()) {
                return switch (how) {
                    case "executeQuery" -> call.executeQuery();
                    case "execute" -> call.execute();
                    default -> throw notThroughRoutines(how + " of a read");
                };
            }
            long affected = 0;
            if (call.execute()) {
                try (ResultSet rs = call.getResultSet()) {
                    if (rs.next()) {
                        affected = rs.getLong("affected");
                        ResultSetMetaData md = rs.getMetaData();
                        for (int i = 1; i <= md.getColumnCount(); i++) {
                            if ("id".equalsIgnoreCase(md.getColumnLabel(i))) generatedKey = rs.getLong(i);
                        }
                    }
                }
            }
            // The rest of the CALL's results (its final status), so that the connection stays clean.
            while (call.getMoreResults() || call.getUpdateCount() != -1) {
                // nothing: they are discarded
            }
            updateCount = affected;
            return switch (how) {
                case "executeUpdate" -> (int) affected;
                case "executeLargeUpdate" -> affected;
                case "execute" -> false;
                default -> throw notThroughRoutines(how + " of a write");
            };
        }
    }

    /** The keys generated by the last insert, as the driver would give them: a row with the key, or none. */
    private static ResultSet generatedKeys(Long key) {
        return (ResultSet) Proxy.newProxyInstance(CatalogGuard.class.getClassLoader(), new Class<?>[]{ResultSet.class},
                new InvocationHandler() {
                    private int row = 0;
                    private boolean closed = false;

                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        switch (method.getName()) {
                            case "next":
                                row++;
                                return key != null && row == 1;
                            case "getLong", "getInt", "getObject", "getString":
                                if (key == null || row != 1) throw new SQLException("No generated key", "24000");
                                if (args[0] instanceof Integer i && i != 1) throw new SQLException("Only one generated key", "07009");
                                return switch (method.getName()) {
                                    case "getLong" -> key;
                                    case "getInt" -> (int) (long) key;
                                    case "getString" -> String.valueOf(key);
                                    default -> key;
                                };
                            case "wasNull":
                                return false;
                            case "close":
                                closed = true;
                                return null;
                            case "isClosed":
                                return closed;
                            case "equals":
                                return proxy == args[0];
                            case "hashCode":
                                return System.identityHashCode(proxy);
                            case "toString":
                                return "CatalogGuard generated keys";
                            default:
                                throw notThroughRoutines("ResultSet." + method.getName() + " of the generated keys");
                        }
                    }
                });
    }

    private static Connection guard(Connection raw) {
        if (raw == null) return null;
        return (Connection) Proxy.newProxyInstance(CatalogGuard.class.getClassLoader(),
                new Class<?>[]{Connection.class}, new ConnectionHandler(raw));
    }

    private static void check(Object sql) throws SQLException {
        if (sql instanceof String s && allowed(s)) return;
        String text = String.valueOf(sql);
        // In the log the start of the text, without newlines and control characters: the values are in the
        // parameters, not in the text, and a refused text is a code error or an attempt.
        String head = text.substring(0, Math.min(60, text.length())).replaceAll("\\p{Cntrl}", " ");
        LOGGER.warning("SQL outside the panel's catalog refused (" + text.length() + " characters"
                + (STATEMENTS.contains(text) ? ", in the catalog but not in this part's list" : "") + "): " + head);
        throw new SQLException("SQL statement not in the panel's catalog", "42000");
    }

    private static Object call(Object target, Method method, Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    /** unwrap and isWrapperFor: only towards the guard's interfaces, never towards the driver's object. */
    private static Object wrapper(Object proxy, Method method, Object[] args) throws SQLException {
        Class<?> iface = (Class<?>) args[0];
        boolean ok = iface.isInstance(proxy);
        if (method.getName().equals("isWrapperFor")) return ok;
        if (ok) return proxy;
        throw new SQLException("Not available through the panel's catalog guard: " + iface.getName());
    }

    private static Object identity(Object proxy, Method method, Object[] args, Object raw) {
        return switch (method.getName()) {
            case "equals" -> proxy == args[0];
            case "hashCode" -> System.identityHashCode(proxy);
            default -> "CatalogGuard(" + raw + ")";
        };
    }

    private static final class ConnectionHandler implements InvocationHandler {
        private final Connection raw;

        ConnectionHandler(Connection raw) { this.raw = raw; }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            switch (method.getName()) {
                case "equals", "hashCode", "toString":
                    if (method.getDeclaringClass() == Object.class) return identity(proxy, method, args, raw);
                    break;
                case "unwrap", "isWrapperFor":
                    return wrapper(proxy, method, args);
                case "nativeSQL":
                    check(args[0]);
                    return call(raw, method, args);
                case "prepareStatement":
                    check(args[0]);
                    return statement(PreparedStatement.class, call(raw, method, args), (Connection) proxy);
                case "prepareCall":
                    check(args[0]);
                    return statement(CallableStatement.class, call(raw, method, args), (Connection) proxy);
                case "createStatement":
                    return statement(Statement.class, call(raw, method, args), (Connection) proxy);
                case "getMetaData":
                    Object meta = call(raw, method, args);
                    return meta == null ? null : Proxy.newProxyInstance(CatalogGuard.class.getClassLoader(),
                            new Class<?>[]{DatabaseMetaData.class}, new MetaDataHandler(meta, (Connection) proxy));
                default:
                    break;
            }
            return call(raw, method, args);
        }
    }

    private static Object statement(Class<?> type, Object raw, Connection connection) {
        if (raw == null) return null;
        return Proxy.newProxyInstance(CatalogGuard.class.getClassLoader(), new Class<?>[]{type},
                new StatementHandler(raw, connection));
    }

    private static final class StatementHandler implements InvocationHandler {
        private final Object raw;
        private final Connection connection;

        StatementHandler(Object raw, Connection connection) {
            this.raw = raw;
            this.connection = connection;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            switch (method.getName()) {
                case "equals", "hashCode", "toString":
                    if (method.getDeclaringClass() == Object.class) return identity(proxy, method, args, raw);
                    break;
                case "unwrap", "isWrapperFor":
                    return wrapper(proxy, method, args);
                case "getConnection":
                    return connection;
                case "execute", "executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch":
                    // With a text as first argument: that of a Statement, or the one inherited by a
                    // PreparedStatement. Without arguments it is the already prepared statement, checked back then.
                    if (args != null && args.length > 0) check(args[0]);
                    break;
                default:
                    break;
            }
            return call(raw, method, args);
        }
    }

    /** The metadata: everything as the driver, but getConnection is the guarded connection. */
    private static final class MetaDataHandler implements InvocationHandler {
        private final Object raw;
        private final Connection connection;

        MetaDataHandler(Object raw, Connection connection) {
            this.raw = raw;
            this.connection = connection;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            switch (method.getName()) {
                case "equals", "hashCode", "toString":
                    if (method.getDeclaringClass() == Object.class) return identity(proxy, method, args, raw);
                    break;
                case "unwrap", "isWrapperFor":
                    return wrapper(proxy, method, args);
                case "getConnection":
                    return connection;
                default:
                    break;
            }
            return call(raw, method, args);
        }
    }
}
