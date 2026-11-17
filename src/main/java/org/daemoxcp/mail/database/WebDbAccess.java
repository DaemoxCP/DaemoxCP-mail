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
 * La parte web del pannello separato entra in MySQL con un utente suo, {@value #WEB_USER}, che puo' solo chiamare
 * le procedure della web. Questa e' la migrazione che lo prepara: la
 * fa la root a ogni avvio, prima di accendere la web, come root di MySQL (la password sta nel file di root).
 *
 * <ol>
 *   <li>I permessi dei ruoli nel database (panel_role_permissions), copiati da quelli del Java: le procedure li
 *       leggono per decidere che cosa puo' fare la sessione che le chiama.</li>
 *   <li>{@value #ROUTINES_USER}: chi possiede le procedure, bloccato, con i soli permessi che servono loro.</li>
 *   <li>Le procedure (SqlCatalog, WEB_CREATE_), ognuna col suo testo; si ricreano solo quelle cambiate, riconosciute
 *       dal commento, che e' l'impronta del testo con cui sono state create.</li>
 *   <li>{@value #WEB_USER}, coi due nomi con cui entra (localhost e 127.0.0.1): solo EXECUTE su quelle procedure.
 *       Se avesse altro, gli si toglie tutto e gli si ridanno le procedure.</li>
 *   <li>La prova: entra, una procedura pubblica risponde, una legata alla sessione senza sessione no, e una SELECT
 *       diretta su una tabella e' rifiutata da MySQL.</li>
 *   <li>Solo se la prova torna: la sua password nel file della web, e quella dell'utente del pannello nel file di
 *       root (PanelSecrets.giveWebItsOwnUser). Da quel momento la web non puo' piu' entrare come il pannello.</li>
 * </ol>
 *
 * Se qualcosa non torna, la web resta com'era (con l'utente del pannello, se lo aveva) e il registro dice perche'.
 * Un secondo avvio senza niente da cambiare non cambia niente e non scrive niente.
 */
public final class WebDbAccess {

    private static final Logger LOGGER = Logger.getLogger(WebDbAccess.class.getName());

    /** L'utente MySQL della parte web. */
    public static final String WEB_USER = "mailpanel_web";
    /** Chi possiede le procedure: nessuno entra con lui. */
    static final String ROUTINES_USER = "mailpanel_routines";
    /** Come lo scrivono information_schema e mysql.procs_priv. */
    private static final String ROUTINES_DEFINER = ROUTINES_USER + "@localhost";
    private static final List<String> WEB_HOSTS = List.of("localhost", "127.0.0.1");
    /** Il commento di ogni procedura comincia cosi', seguito dall'impronta del testo. */
    static final String COMMENT_PREFIX = "mailpanel ";

    /** I permessi di chi possiede le procedure: tutti idempotenti, si danno a ogni avvio. */
    private static final List<String> ROUTINES_GRANTS = List.of(
            SqlCatalog.WEB_DB_GRANT_ROUTINES_EXECUTE, SqlCatalog.WEB_DB_GRANT_ROUTINES_SESSIONS,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_ADMINS, SqlCatalog.WEB_DB_GRANT_ROUTINES_ROLES,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_SETTINGS, SqlCatalog.WEB_DB_GRANT_ROUTINES_AUDIT,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_DOMAINS, SqlCatalog.WEB_DB_GRANT_ROUTINES_MAILBOXES,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_ALIASES, SqlCatalog.WEB_DB_GRANT_ROUTINES_RATE_LIMITS,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_AUTO_RESPONDERS, SqlCatalog.WEB_DB_GRANT_ROUTINES_FORWARDING,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_FILTERS, SqlCatalog.WEB_DB_GRANT_ROUTINES_STATISTICS,
            SqlCatalog.WEB_DB_GRANT_ROUTINES_TRAINING, SqlCatalog.WEB_DB_GRANT_ROUTINES_WEBMAIL_TOKENS);

    /** Le procedure che la web non ha piu': si tolgono dove ci sono, e con loro il suo permesso. */
    private static final List<String> RETIRED = List.of(SqlCatalog.WEB_DROP_RETIRED_GET_MAILBOX_VAULT_COPY,
            SqlCatalog.WEB_DROP_RETIRED_GET_MAILBOX_PASSWORD_HASH);

    private WebDbAccess() {}

    /** Una procedura da creare: il nome, il testo che la crea e quello che la toglie. */
    record Definition(String name, String create, String drop) {}

    /** Tutte, prima quella che le altre chiamano. */
    static List<Definition> definitions() {
        List<Definition> all = new ArrayList<>();
        all.add(new Definition(nameOf(SqlCatalog.WEB_DROP_SESSION_ADMIN), SqlCatalog.WEB_CREATE_SESSION_ADMIN,
                SqlCatalog.WEB_DROP_SESSION_ADMIN));
        for (WebPartStatements.Routine r : WebPartStatements.ROUTINES) all.add(new Definition(nameOf(r.drop()), r.create(), r.drop()));
        return all;
    }

    /** Il nome di una procedura dal testo che la toglie: l'ultima parola. */
    static String nameOf(String drop) {
        return drop.substring(drop.lastIndexOf(' ') + 1);
    }

    /** Il commento di una procedura: l'impronta (SHA-256, i primi 16 caratteri) del testo che la crea. */
    static String commentOf(String create) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(create.getBytes(StandardCharsets.UTF_8));
            return COMMENT_PREFIX + HexFormat.of().formatHex(h).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * All'avvio della parte root, prima di accendere la web. Null se la web puo' entrare col suo utente (e il suo
     * file dei segreti ne ha la password); altrimenti il perche', e la web resta com'era.
     */
    public static synchronized String ensure(MailDatabase db) {
        String rootPassword = PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD);
        if (rootPassword.isEmpty())
            return "the MySQL root password is not in " + PanelSecrets.location(PanelSecrets.MYSQL_ROOT_PASSWORD);
        return ensure(db, rootPassword);
    }

    /** Con la password di root di MySQL data (le prove: il MySQL di prova non ne ha). */
    static synchronized String ensure(MailDatabase db, String rootPassword) {
        // Le colonne delle versioni successive prima dei permessi per colonna (theme, language...).
        db.ensureColumnUpgrades();
        // Senza il ricollegamento automatico: con quello il driver, a una password sbagliata, riprova e poi
        // risponde «Could not create connection» invece di «Access denied» (1045), e la prova d'accesso non lo
        // riconoscerebbe. Le connessioni di qui durano un avvio.
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

    // ===================== I passi =====================

    /** I permessi di ogni ruolo, come nel Java. Si riscrivono solo se sono cambiati. */
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

    /** Gli utenti che ci sono, user@host, e se sono bloccati. */
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

    /** Le procedure che mancano o hanno un testo diverso (il commento) si ricreano; le altre restano. */
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
        // Niente altro che le procedure: un permesso in piu', da chiunque venga, li toglie tutti.
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

    /** L'utente della web entra con questa password? (Un altro errore che non sia «accesso negato» si ferma qui.) */
    private static boolean canLogIn(String url, String password) throws SQLException {
        try (Connection c = CatalogGuard.open(url, WEB_USER, password)) {
            return c.isValid(5);
        } catch (SQLException e) {
            if (e.getErrorCode() == 1045) return false;
            throw e;
        }
    }

    /**
     * Da utente della web: una procedura pubblica risponde; una legata alla sessione, senza sessione, no (SIGNAL
     * 45000); una SELECT diretta su una tabella MySQL la rifiuta (1142). Null se e' tutto cosi'.
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
