package org.mail_panel.database;

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
import java.sql.SQLException;
import java.sql.Statement;
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
 * sua. Contro quello servono l'utente MySQL della parte web e le procedure (0.8, passi seguenti).
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
