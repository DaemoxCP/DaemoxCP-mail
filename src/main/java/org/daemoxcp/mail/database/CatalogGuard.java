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
 * L'unico punto da cui il pannello apre una connessione JDBC, MySQL o SQLite:
 * la connessione che restituisce accetta solo le istruzioni di {@link SqlCatalog}, cioe' esattamente uno
 * dei suoi testi, e rifiuta qualunque altro testo SQL prima che arrivi al driver.
 *
 * <p>SqlCatalogTest controlla gia' sul codice che l'SQL stia solo nel catalogo; questa guardia lo fa
 * mentre il pannello gira, per ogni istruzione: un testo composto per errore, o un valore finito nel
 * testo invece che in un parametro, non passa. Si guardano i punti da cui un testo SQL raggiunge il
 * driver: prepareStatement, prepareCall e nativeSQL della connessione, e execute, executeQuery,
 * executeUpdate, executeLargeUpdate e addBatch di ogni statement (anche di un PreparedStatement, che li
 * eredita). Uno statement e i metadati restituiscono la connessione guardata, e unwrap non consegna
 * quella vera. Resta ResultSet.getStatement, che il pannello non usa (lo controlla SqlCatalogTest).
 *
 * <p>Non e' una difesa contro chi esegue codice suo nel processo: quello aprirebbe una connessione
 * sua. Contro quello servono l'utente MySQL della parte web e le procedure: {@link #openRoutines} e' la
 * connessione della web con quell'utente, che manda al posto di ogni istruzione la sua procedura
 * (WebPartStatements.ROUTINES) con l'impronta della sessione della richiesta ({@link #useSession}).
 */
public final class CatalogGuard {

    private static final Logger LOGGER = Logger.getLogger(CatalogGuard.class.getName());

    private CatalogGuard() {}

    /** I testi del catalogo: le costanti pubbliche di SqlCatalog (i pezzi privati non sono istruzioni). */
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

    /** Le istruzioni accettate: tutto il catalogo, o nella parte web solo il suo elenco (webPartOnly). */
    private static volatile Set<String> accepted = STATEMENTS;

    /** Vero se il testo e' una delle istruzioni accettate, carattere per carattere. */
    public static boolean allowed(String sql) {
        return sql != null && accepted.contains(sql);
    }

    /**
     * La parte web del pannello separato, all'avvio: da qui solo le istruzioni di WebPartStatements.
     * Non si torna indietro. Un nome che non e' nel catalogo ferma l'avvio.
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

    /** Quante istruzioni ha il catalogo. */
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

    // ===================== La parte web con il suo utente MySQL: solo procedure =====================

    /** L'impronta del token della sessione della richiesta in corso (WebSessions.tokenHash), o nessuna. */
    private static final ThreadLocal<String> SESSION = new ThreadLocal<>();
    private static final java.util.regex.Pattern SESSION_HASH = java.util.regex.Pattern.compile("[0-9a-f]{64}");

    /**
     * La parte web, mentre controlla il cookie di una richiesta: da qui le procedure ricevono l'impronta di quel
     * token, e il database decide se la sessione c'e' e che cosa puo' fare il suo ruolo. Vale per il thread, finche'
     * la richiesta non finisce ({@link #forgetSession}).
     */
    public static void useSession(String tokenHash) {
        if (tokenHash != null && SESSION_HASH.matcher(tokenHash).matches()) SESSION.set(tokenHash);
        else SESSION.remove();
    }

    /** La richiesta e' finita, o la sessione non c'e': le procedure ricevono NULL. */
    public static void forgetSession() {
        SESSION.remove();
    }

    /**
     * La connessione della parte web con il suo utente MySQL, che puo' solo chiamare le procedure. Accetta solo le
     * istruzioni dell'elenco della web che hanno una procedura, e manda la procedura: l'impronta della sessione
     * come primo parametro, poi gli stessi parametri. Per chi la usa non cambia niente: una lettura restituisce le
     * stesse colonne, una scrittura le righe toccate e, se e' un inserimento, la chiave nuova (getGeneratedKeys).
     */
    public static Connection openRoutines(String url, String user, String password) throws SQLException {
        Connection raw = DriverManager.getConnection(url, user, password);
        if (raw == null) return null;
        return (Connection) Proxy.newProxyInstance(CatalogGuard.class.getClassLoader(),
                new Class<?>[]{Connection.class}, new RoutineConnectionHandler(raw));
    }

    /** La procedura del testo, se e' un'istruzione accettata che ne ha una; altrimenti lo rifiuta. */
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
                    // Le varianti con le chiavi generate o il tipo di cursore: la procedura e' la stessa.
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
     * Uno statement della connessione a procedure. Preparato (routine non null): base e' la CALL preparata, i
     * parametri si spostano di uno. Semplice (createStatement): ogni execute col testo prepara la CALL della sua
     * procedura, che non deve avere altri parametri; base serve solo alle impostazioni (timeout e simili).
     */
    private static final class RoutineStatementHandler implements InvocationHandler {
        private final Statement base;
        private final WebPartStatements.Routine routine;
        private final Connection connection;
        private final Connection raw;
        /** La CALL dell'ultimo execute col testo di uno statement semplice. */
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
                // Statement semplice: execute(testo), executeQuery(testo), executeUpdate(testo[, ...]).
                if (routine != null) {
                    check(args[0]);      // un PreparedStatement non esegue un altro testo
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
            // Le risposte di uno statement semplice sono quelle della sua ultima CALL.
            if (routine == null && current != null && (name.equals("getResultSet") || name.equals("getMoreResults")
                    || name.equals("getWarnings") || name.equals("clearWarnings"))) return call(current, method, args);
            if (routine != null && method.getDeclaringClass() == PreparedStatement.class && name.startsWith("set")
                    && args != null && args.length > 0 && args[0] instanceof Integer index) {
                // I parametri dell'istruzione sono quelli della procedura dal secondo in poi.
                Object[] shifted = args.clone();
                shifted[0] = index + 1;
                return call(base, method, shifted);
            }
            return call(base, method, args);
        }

        /** Esegue la CALL con l'impronta della sessione: le righe di una lettura, le righe toccate di una scrittura. */
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
            // Il resto delle risposte della CALL (il suo stato finale), perche' la connessione resti pulita.
            while (call.getMoreResults() || call.getUpdateCount() != -1) {
                // niente: si scartano
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

    /** Le chiavi generate dall'ultimo inserimento, come le darebbe il driver: una riga con la chiave, o nessuna. */
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
        // Nel registro l'inizio del testo, senza a capo e caratteri di controllo: i valori stanno nei
        // parametri, non nel testo, e un testo rifiutato e' un errore del codice o un tentativo.
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

    /** unwrap e isWrapperFor: solo verso le interfacce della guardia, mai verso l'oggetto del driver. */
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
                    // Con un testo come primo argomento: quello di un Statement, o quello ereditato da un
                    // PreparedStatement. Senza argomenti e' l'istruzione gia' preparata, controllata allora.
                    if (args != null && args.length > 0) check(args[0]);
                    break;
                default:
                    break;
            }
            return call(raw, method, args);
        }
    }

    /** I metadati: tutto come il driver, ma getConnection e' la connessione guardata. */
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
