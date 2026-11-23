package org.daemoxcp.mail.database;

import org.daemoxcp.mail.security.AuthStore;
import org.daemoxcp.mail.security.PanelSecrets;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * The web part of the separated panel logs into MySQL with its own user, {@value #WEB_USER}, which can only call
 * the procedures of the web part. This is the migration that prepares
 * it: the root part runs it at every boot, before turning on the web part, as MySQL root (the password is in
 * root's file).
 *
 * <ol>
 *   <li>The role permissions in the database (panel_role_permissions), copied from the Java ones: the procedures
 *       read them to decide what the session calling them may do.</li>
 *   <li>{@value #ROUTINES_USER}: who owns the procedures, locked, with only the permissions they need.</li>
 *   <li>The procedures (SqlCatalog, WEB_CREATE_), each with its own text; only the changed ones are recreated,
 *       recognised by the comment, which is the fingerprint of the text they were created with.</li>
 *   <li>{@value #WEB_USER}, with the two names it logs in with (localhost and 127.0.0.1): only EXECUTE on those
 *       procedures. If it had anything else, everything is revoked and the procedures are granted again.</li>
 *   <li>The test: it logs in, a public procedure answers, one tied to the session does not answer without a
 *       session, and a direct SELECT on a table is refused by MySQL.</li>
 *   <li>Only if the test passes: its password in the web part's file, and the panel user's one in root's file
 *       (PanelSecrets.giveWebItsOwnUser). From that moment the web part can no longer log in as the panel.</li>
 * </ol>
 *
 * If something does not add up, the web part stays as it was (with the panel's user, if it had it) and the log
 * says why. A second boot with nothing to change changes nothing and writes nothing.
 */
public final class WebDbAccess {

    private static final Logger LOGGER = Logger.getLogger(WebDbAccess.class.getName());

    /** The MySQL user of the web part. */
    public static final String WEB_USER = org.daemoxcp.mail.system.Product.ID + "_web";
    /** Who owns the procedures: nobody logs in as it. */
    static final String ROUTINES_USER = org.daemoxcp.mail.system.Product.ID + "_routines";
    /** As information_schema and mysql.procs_priv write it. */
    private static final String ROUTINES_DEFINER = ROUTINES_USER + "@localhost";
    private static final List<String> WEB_HOSTS = List.of("localhost", "127.0.0.1");
    /** The comment of every procedure starts like this, followed by the fingerprint of the text. */
    static final String COMMENT_PREFIX = org.daemoxcp.mail.system.Product.ID + " ";

    /** The permissions of the procedures' owner: all idempotent, granted at every boot. */
    private static final List<String> ROUTINES_GRANTS = List.of(
            SqlCatalog.WEB_DB_GRANT_ROUTINES_EXECUTE, SqlCatalog.WEB_DB_GRANT_ROUTINES_SESSIONS,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_ADMINS, SqlCatalog.WEB_DB_GRANT_ROUTINES_ROLES,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_SETTINGS, SqlCatalog.WEB_DB_GRANT_ROUTINES_AUDIT,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_DOMAINS, SqlCatalog.WEB_DB_GRANT_ROUTINES_MAILBOXES,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_ALIASES, SqlCatalog.WEB_DB_GRANT_ROUTINES_RATE_LIMITS,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_AUTO_RESPONDERS, SqlCatalog.WEB_DB_GRANT_ROUTINES_FORWARDING,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_FILTERS, SqlCatalog.WEB_DB_GRANT_ROUTINES_STATISTICS,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_TRAINING, SqlCatalog.WEB_DB_GRANT_ROUTINES_WEBMAIL_TOKENS);

    /** The procedures the web part no longer has: they are dropped where they exist, and with them its grant. */
    private static final List<String> RETIRED = List.of(SqlCatalog.WEB_DROP_RETIRED_GET_MAILBOX_VAULT_COPY,
            SqlCatalog.WEB_DROP_RETIRED_GET_MAILBOX_PASSWORD_HASH);

    private WebDbAccess() {}

    /** A procedure to create: the name, the text that creates it and the one that drops it. */
    record Definition(String name, String create, String drop) {}

    /** All of them, first the one the others call. */
    static List<Definition> definitions() {
        List<Definition> all = new ArrayList<>();
        all.add(new Definition(nameOf(SqlCatalog.WEB_DROP_SESSION_ADMIN), SqlCatalog.WEB_CREATE_SESSION_ADMIN,
                SqlCatalog.WEB_DROP_SESSION_ADMIN));
        for (WebPartStatements.Routine r : WebPartStatements.ROUTINES) all.add(new Definition(nameOf(r.drop()), r.create(), r.drop()));
        return all;
    }

    /** The name of a procedure from the text that drops it: the last word. */
    static String nameOf(String drop) {
        return drop.substring(drop.lastIndexOf(' ') + 1);
    }

    /** The comment of a procedure: the fingerprint (SHA-256, the first 16 characters) of the text that creates it. */
    static String commentOf(String create) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(create.getBytes(StandardCharsets.UTF_8));
            return COMMENT_PREFIX + HexFormat.of().formatHex(h).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * At the boot of the root part, before turning on the web part. Null if the web part can log in with its own
     * user (and its secrets file has the password); otherwise the reason, and the web part stays as it was.
     */
    public static synchronized String ensure(MailDatabase db) {
        String rootPassword = PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD);
        if (rootPassword.isEmpty())
            return "the MySQL root password is not in " + PanelSecrets.location(PanelSecrets.MYSQL_ROOT_PASSWORD);
        return ensure(db, rootPassword);
    }

    /** With the given MySQL root password (the tests: the test MySQL has none). */
    static synchronized String ensure(MailDatabase db, String rootPassword) {
        // The columns of later versions before the per-column permissions (theme, language...).
        db.ensureColumnUpgrades();
        // Without automatic reconnection: with it, the driver, on a wrong password, retries and then
        // answers "Could not create connection" instead of "Access denied" (1045), and the login test would not
        // recognise it. The connections here last for one boot.
        String url = db.existingDatabaseUrl().replace("&autoReconnect=true", "");
        List<String> done = new ArrayList<>();
        String webPassword = PanelSecrets.text(PanelSecrets.MYSQL_WEB_PASSWORD);
        boolean fresh = webPassword.isEmpty();
        if (fresh) webPassword = PanelSecrets.newAlphanumericPassword(32);
        try (Connection root = CatalogGuard.open(url, "root", rootPassword)) {
            roles(root, done);
            routinesUser(root, done);
            routines(root, done);
            webUser(root, url, webPassword, done);
        } catch (SQLException | RuntimeException e) {
            return "MySQL refused a step (" + e.getMessage() + "): " + (done.isEmpty() ? "nothing changed" : "done before: " + String.join(", ", done));
        }
        String failed = verify(url, webPassword);
        if (failed != null) return failed + (done.isEmpty() ? "" : " (done: " + String.join(", ", done) + ")");
        try {
            if (PanelSecrets.giveWebItsOwnUser(webPassword))
                done.add("the web part's MySQL password in its secrets file, the panel user's in root's");
        } catch (RuntimeException e) {
            return "the secrets files were not written: " + e.getMessage();
        }
        if (!done.isEmpty()) LOGGER.info("[WebDbAccess] DONE: " + String.join("; ", done));
        return null;
    }

    // ===================== The steps =====================

    /** The permissions of each role, as in the Java code. They are rewritten only if they have changed. */
    private static void roles(Connection root, List<String> done) throws SQLException {
        try (Statement st = root.createStatement()) {
            st.execute(SqlCatalog.ROLES_CREATE_TABLE);
        }
        Set<String> have = new HashSet<>();
        try (Statement st = root.createStatement(); ResultSet rs = st.executeQuery(SqlCatalog.ROLES_LIST)) {
            while (rs.next()) have.add(rs.getString(1) + " " + rs.getString(2));
        }
        Set<String> want = new HashSet<>();
        for (String role : AuthStore.ROLES) for (String p : AuthStore.permissionsOf(role)) want.add(role + " " + p);
        if (have.equals(want)) return;
        boolean auto = root.getAutoCommit();
        root.setAutoCommit(false);
        try {
            try (Statement st = root.createStatement()) {
                st.executeUpdate(SqlCatalog.ROLES_CLEAR);
            }
            try (PreparedStatement ps = root.prepareStatement(SqlCatalog.ROLES_ADD)) {
                for (String role : AuthStore.ROLES) {
                    for (String p : AuthStore.permissionsOf(role)) {
                        ps.setString(1, role);
                        ps.setString(2, p);
                        ps.executeUpdate();
                    }
                }
            }
            root.commit();
        } catch (SQLException e) {
            root.rollback();
            throw e;
        } finally {
            root.setAutoCommit(auto);
        }
        done.add("role permissions (" + want.size() + ")");
    }

    /** The users that exist, user@host, and whether they are locked. */
    private static Map<String, Boolean> users(Connection root) throws SQLException {
        Map<String, Boolean> users = new HashMap<>();
        try (Statement st = root.createStatement(); ResultSet rs = st.executeQuery(SqlCatalog.WEB_DB_USERS)) {
            while (rs.next()) users.put(rs.getString(1) + "@" + rs.getString(2), "Y".equalsIgnoreCase(rs.getString(3)));
        }
        return users;
    }

    private static void routinesUser(Connection root, List<String> done) throws SQLException {
        Boolean locked = users(root).get(ROUTINES_DEFINER);
        if (locked == null) {
            try (PreparedStatement ps = root.prepareStatement(SqlCatalog.WEB_DB_CREATE_ROUTINES_USER)) {
                ps.setString(1, PanelSecrets.newAlphanumericPassword(32));
                ps.execute();
            }
            done.add("user " + ROUTINES_USER + " (locked)");
        } else if (!locked) {
            try (Statement st = root.createStatement()) {
                st.execute(SqlCatalog.WEB_DB_LOCK_ROUTINES_USER);
            }
            done.add(ROUTINES_USER + " locked again");
        }
        try (Statement st = root.createStatement()) {
            for (String grant : ROUTINES_GRANTS) st.execute(grant);
        }
    }

    /** The procedures that are missing or have a different text (the comment) are recreated; the others stay. */
    private static void routines(Connection root, List<String> done) throws SQLException {
        Map<String, String[]> have = new HashMap<>();
        try (Statement st = root.createStatement(); ResultSet rs = st.executeQuery(SqlCatalog.WEB_DB_ROUTINES)) {
            while (rs.next()) have.put(rs.getString(1), new String[]{rs.getString(2), rs.getString(3), rs.getString(4)});
        }
        List<String> changed = new ArrayList<>();
        for (Definition d : definitions()) {
            String comment = commentOf(d.create());
            String[] h = have.get(d.name());
            if (h != null && comment.equals(h[0]) && ROUTINES_DEFINER.equals(h[1]) && "DEFINER".equalsIgnoreCase(h[2])) continue;
            try (Statement st = root.createStatement()) {
                st.execute(d.drop());
            }
            try (PreparedStatement ps = root.prepareStatement(d.create())) {
                ps.setString(1, comment);
                ps.execute();
            }
            changed.add(d.name());
        }
        if (!changed.isEmpty())
            done.add(changed.size() == definitions().size() ? "all " + changed.size() + " procedures" : "procedures " + String.join(", ", changed));
        List<String> removed = new ArrayList<>();
        for (String drop : RETIRED) {
            if (!have.containsKey(nameOf(drop))) continue;
            try (Statement st = root.createStatement()) {
                st.execute(drop);
            }
            removed.add(nameOf(drop));
        }
        if (!removed.isEmpty()) done.add("procedures the web part no longer has, removed: " + String.join(", ", removed));
    }

    private static void webUser(Connection root, String url, String password, List<String> done) throws SQLException {
        Map<String, Boolean> users = users(root);
        boolean created = false;
        if (!users.containsKey(WEB_USER + "@localhost") || !users.containsKey(WEB_USER + "@127.0.0.1")) {
            try (PreparedStatement ps = root.prepareStatement(SqlCatalog.WEB_DB_CREATE_WEB_USER)) {
                ps.setString(1, password);
                ps.setString(2, password);
                ps.execute();
            }
            created = true;
            done.add("user " + WEB_USER);
        }
        // Nothing but the procedures: one extra permission, wherever it comes from, gets all of them revoked.
        boolean other;
        try (PreparedStatement ps = root.prepareStatement(SqlCatalog.WEB_DB_WEB_OTHER_PRIVILEGES)) {
            for (int i = 0; i < 8; i += 2) {
                ps.setString(i + 1, "'" + WEB_USER + "'@'localhost'");
                ps.setString(i + 2, "'" + WEB_USER + "'@'127.0.0.1'");
            }
            try (ResultSet rs = ps.executeQuery()) {
                other = rs.next();
            }
        }
        Set<String> want = new HashSet<>();
        for (WebPartStatements.Routine r : WebPartStatements.ROUTINES) {
            for (String host : WEB_HOSTS) want.add(host + " " + nameOf(r.drop()));
        }
        Set<String> granted = new HashSet<>();
        String database = root.getCatalog();
        try (Statement st = root.createStatement(); ResultSet rs = st.executeQuery(SqlCatalog.WEB_DB_WEB_ROUTINE_PRIVILEGES)) {
            while (rs.next()) {
                String key = rs.getString(1) + " " + rs.getString(3);
                boolean expected = database.equalsIgnoreCase(rs.getString(2)) && "PROCEDURE".equalsIgnoreCase(rs.getString(4))
                        && "Execute".equalsIgnoreCase(rs.getString(5)) && want.contains(key);
                if (expected) granted.add(key);
                else other = true;
            }
        }
        if (other) {
            try (Statement st = root.createStatement()) {
                st.execute(SqlCatalog.WEB_DB_REVOKE_WEB);
            }
            granted.clear();
            done.add("every other privilege of " + WEB_USER + " revoked");
        }
        List<String> grants = new ArrayList<>();
        try (Statement st = root.createStatement()) {
            for (WebPartStatements.Routine r : WebPartStatements.ROUTINES) {
                String name = nameOf(r.drop());
                boolean all = true;
                for (String host : WEB_HOSTS) all &= granted.contains(host + " " + name);
                if (all) continue;
                st.execute(r.grant());
                grants.add(name);
            }
        }
        if (!grants.isEmpty() && !created && !other)
            done.add("EXECUTE to " + WEB_USER + " on " + String.join(", ", grants));
        if (!canLogIn(url, password)) {
            try (PreparedStatement ps = root.prepareStatement(SqlCatalog.WEB_DB_SET_WEB_PASSWORD)) {
                ps.setString(1, password);
                ps.setString(2, password);
                ps.execute();
            }
            if (!canLogIn(url, password)) throw new SQLException(WEB_USER + " does not get in with the password just set");
            done.add(WEB_USER + " password set");
        }
    }

    /** Does the web user log in with this password? (Any error other than "access denied" stops here.) */
    private static boolean canLogIn(String url, String password) throws SQLException {
        try (Connection c = CatalogGuard.open(url, WEB_USER, password)) {
            return c.isValid(5);
        } catch (SQLException e) {
            if (e.getErrorCode() == 1045) return false;
            throw e;
        }
    }

    /**
     * As the web user: a public procedure answers; one tied to the session, without a session, does not (SIGNAL
     * 45000); a direct SELECT on a table is refused by MySQL (1142). Null if it is all like this.
     */
    static String verify(String url, String password) {
        CatalogGuard.forgetSession();
        try (Connection web = CatalogGuard.openRoutines(url, WEB_USER, password)) {
            try (Statement st = web.createStatement(); ResultSet rs = st.executeQuery(SqlCatalog.MAIL_HAS_ADMIN_USER)) {
                rs.next();
            }
            try (Statement st = web.createStatement(); ResultSet rs = st.executeQuery(SqlCatalog.MAIL_GET_DOMAINS)) {
                return "the check failed: a procedure bound to a session answered without one";
            } catch (SQLException e) {
                if (!"45000".equals(e.getSQLState()))
                    return "the check failed: a procedure without a session answered " + e.getSQLState() + " " + e.getMessage();
            }
        } catch (SQLException e) {
            return "the check failed: " + WEB_USER + " could not call a public procedure (" + e.getMessage() + ")";
        }
        try (Connection plain = CatalogGuard.open(url, WEB_USER, password); Statement st = plain.createStatement();
             ResultSet rs = st.executeQuery(SqlCatalog.MAIL_HAS_ADMIN_USER)) {
            return "the check failed: " + WEB_USER + " can read a table directly";
        } catch (SQLException e) {
            if (e.getErrorCode() != 1142)
                return "the check failed: a direct SELECT got " + e.getErrorCode() + " instead of 1142 (" + e.getMessage().toLowerCase(Locale.ROOT) + ")";
        }
        return null;
    }
}
