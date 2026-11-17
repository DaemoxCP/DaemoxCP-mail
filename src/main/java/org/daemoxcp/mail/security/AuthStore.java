package org.daemoxcp.mail.security;

import org.daemoxcp.mail.database.SqlCatalog;

import com.yubico.webauthn.data.ByteArray;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Il database dell'accesso senza password: amministratori, passkey e codici monouso (MySQL).
 *
 *  - nessuna password e nessun hash di password: le colonne non esistono piu';
 *  - l'email dell'amministratore e' cifrata (DataCrypto) e si cerca solo col suo indice cieco;
 *  - ogni flusso di codici ha la sua tabella, e nel database c'e' solo l'impronta HMAC del codice;
 *  - le date sono in UTC, colonne DATETIME, scritte da qui (mai NOW() col fuso del server);
 *  - solo PreparedStatement: le istruzioni sono costanti, i valori sono parametri;
 *  - l'unicita' (email, user handle, credenziale) la garantiscono i vincoli UNIQUE.
 */
public final class AuthStore {

    private static final Logger LOGGER = Logger.getLogger(AuthStore.class.getName());
    private static final SecureRandom RANDOM = new SecureRandom();

    /** La connessione MySQL del pannello; i test ne passano una loro. */
    public static Supplier<Connection> connection = () -> org.daemoxcp.mail.Main.mailDatabase.getConnection();

    /** L'orologio: i test lo spostano per provare le scadenze. */
    static Supplier<Instant> clock = Instant::now;

    private AuthStore() {}

    static Instant now() { return clock.get(); }

    /** Un istante come lo scrive una colonna DATETIME in UTC. */
    public static LocalDateTime utc(Instant i) { return LocalDateTime.ofInstant(i, ZoneOffset.UTC); }

    private static Connection db() { return connection.get(); }

    // ===================== Permessi =====================

    /**
     * Cosa puo' fare ciascun ruolo. Le rotte chiedono un permesso per nome (Access, controllato
     * prima del gestore), mai un livello di ruolo: un ruolo nuovo si scrive solo qui.
     *
     *  - "x.view": vedere le pagine e gli stati di quell'area, senza cambiare niente;
     *  - "x.manage": cambiare. Rivelare la password di una casella, aprire la sua webmail e
     *    leggere un messaggio in coda sono "manage": vuol dire leggere la posta di qualcuno;
     *  - sicurezza, sistema, impostazioni, amministratori, vault e chiavi SSH di root sono solo del superadmin: chi
     *    li ha (firewall, aggiornamenti come root) puo' darsi qualunque altro permesso.
     */
    private static final Map<String, Set<String>> PERMISSIONS;
    static {
        Set<String> viewer = Set.of("home.view", "mail.view", "queue.view", "dns.view", "security.view", "system.view", "account.self");
        Set<String> operator = union(viewer, Set.of("mailboxes.manage", "queue.manage"));
        Set<String> admin = union(operator, Set.of("domains.manage", "dns.manage"));
        Set<String> superadmin = union(admin, Set.of("security.manage", "system.manage", "settings.manage", "admins.manage", "vault.manage",
                "ssh.manage"));
        Map<String, Set<String>> m = new java.util.LinkedHashMap<>();
        m.put("superadmin", superadmin);
        m.put("admin", admin);
        m.put("operator", operator);
        m.put("viewer", viewer);
        PERMISSIONS = java.util.Collections.unmodifiableMap(m);
    }

    private static Set<String> union(Set<String> a, Set<String> b) {
        Set<String> u = new java.util.HashSet<>(a);
        u.addAll(b);
        return Set.copyOf(u);
    }

    /** Vero se l'amministratore ha il permesso. Un ruolo sconosciuto non ne ha nessuno. */
    public static boolean may(Admin admin, String permission) {
        return admin != null && permission != null && permissionsOf(admin.role()).contains(permission);
    }

    public static Set<String> permissionsOf(String role) {
        return role == null ? Set.of() : PERMISSIONS.getOrDefault(role, Set.of());
    }

    /** I ruoli, dal piu' ampio al piu' ristretto (l'ordine delle pagine). */
    public static final List<String> ROLES = List.copyOf(PERMISSIONS.keySet());

    /** Ogni permesso che qualche ruolo da': le rotte possono chiedere solo uno di questi. */
    public static final Set<String> ALL_PERMISSIONS = PERMISSIONS.get("superadmin");

    // ===================== Migrazione =====================

    /**
     * All'avvio, prima che il server risponda. Si puo' ripetere. Le colonne le sistema
     * MailDatabase.ensurePasswordlessSchema; qui i dati: lo user handle di chi non l'ha, le
     * passkey di prima legate al loro, almeno un superadmin.
     */
    public static void migrate() throws SQLException {
        PanelSecrets.ensureKeys();
        org.daemoxcp.mail.Main.mailDatabase.ensurePasswordlessSchema();
        assignUserHandles();
        linkOldPasskeys();
        ensureSuperadmin();
        purgeExpired();
    }

    /**
     * Ogni amministratore ha un identificativo per le passkey (user handle). A quelli che c'erano
     * gia' si da' quello della vecchia registrazione, l'id in quattro byte: le passkey gia' create
     * continuano a funzionare.
     */
    private static void assignUserHandles() throws SQLException {
        List<Long> ids = new ArrayList<>();
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_ASSIGN_USER_HANDLES);
             ResultSet r = p.executeQuery()) {
            while (r.next()) ids.add(r.getLong(1));
        }
        for (long id : ids) {
            try (PreparedStatement u = db().prepareStatement(SqlCatalog.AUTH_ASSIGN_USER_HANDLES_2)) {
                u.setString(1, b64url(new byte[]{(byte) (id >> 24), (byte) (id >> 16), (byte) (id >> 8), (byte) id}));
                u.setLong(2, id);
                u.executeUpdate();
            }
        }
    }

    private static void linkOldPasskeys() throws SQLException {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_LINK_OLD_PASSKEYS)) {
            int n = p.executeUpdate();
            if (n > 0) LOGGER.info("Linked " + n + " existing passkeys to their user handle");
        }
    }

    /**
     * Gli amministratori li gestisce solo un superadmin. L'installazione di prima creava il primo
     * amministratore con il ruolo "admin", e nessuno poteva gestire gli altri: se non c'e' un
     * superadmin attivo, lo diventa il piu' vecchio.
     */
    private static void ensureSuperadmin() throws SQLException {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_ENSURE_SUPERADMIN);
             ResultSet r = p.executeQuery()) {
            if (r.next()) return;
        }
        try (PreparedStatement u = db().prepareStatement(SqlCatalog.AUTH_ENSURE_SUPERADMIN_2)) {
            if (u.executeUpdate() == 1) LOGGER.info("No active superadmin: the oldest administrator is now superadmin");
        }
    }

    // ===================== Amministratori =====================

    public record Admin(long id, String username, String role, boolean active, String emailEnc, String userHandle,
                        LocalDateTime createdAt, LocalDateTime lastLogin) {
        /** L'email in chiaro, o "" se non e' impostata o non si decifra. */
        public String email() { return DataCrypto.decryptOrEmpty(emailEnc); }
        public boolean hasEmail() { return emailEnc != null && !emailEnc.isEmpty(); }
        public ByteArray userHandleBytes() {
            try { return ByteArray.fromBase64Url(userHandle); } catch (Exception e) { throw new IllegalStateException(e); }
        }
    }

    // Le colonne lette da admin(): SqlCatalog.AUTH_ADMIN_SELECT, in quest'ordine.
    private static Admin admin(ResultSet r) throws SQLException {
        return new Admin(r.getLong(1), r.getString(2), r.getString(3), r.getBoolean(4), r.getString(5), r.getString(6),
                r.getObject(7, LocalDateTime.class), r.getObject(8, LocalDateTime.class));
    }

    private static Optional<Admin> oneAdmin(PreparedStatement p) throws SQLException {
        try (ResultSet r = p.executeQuery()) {
            return r.next() ? Optional.of(admin(r)) : Optional.empty();
        }
    }

    public static List<Admin> admins() {
        List<Admin> out = new ArrayList<>();
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_LIST_ADMINS);
             ResultSet r = p.executeQuery()) {
            while (r.next()) out.add(admin(r));
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Admins unreadable", e);
        }
        return out;
    }

    /** Un amministratore attivo, per id. */
    public static Optional<Admin> adminById(long id) {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_ADMIN_BY_ID)) {
            p.setLong(1, id);
            return oneAdmin(p);
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Admin unreadable", e);
            return Optional.empty();
        }
    }

    public static Optional<Admin> adminByUsername(String username) {
        if (username == null) return Optional.empty();
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_ADMIN_BY_USERNAME)) {
            p.setString(1, username);
            return oneAdmin(p);
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Admin unreadable", e);
            return Optional.empty();
        }
    }

    public static Optional<Admin> adminByEmail(String email) {
        if (email == null || email.isBlank()) return Optional.empty();
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_ADMIN_BY_EMAIL_INDEX)) {
            p.setString(1, DataCrypto.emailIndex(email));
            return oneAdmin(p);
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Admin unreadable", e);
            return Optional.empty();
        }
    }

    public static Optional<Admin> adminByUserHandle(ByteArray handle) {
        if (handle == null) return Optional.empty();
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_ADMIN_BY_USER_HANDLE)) {
            p.setString(1, handle.getBase64Url());
            return oneAdmin(p);
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Admin unreadable", e);
            return Optional.empty();
        }
    }

    public enum CreateResult { CREATED, NAME_TAKEN, EMAIL_TAKEN, FAILED }

    public record Created(CreateResult result, long id) {}

    /**
     * Un amministratore nuovo, senza password: entra con un codice mandato alla sua email e
     * registra una passkey. Nome ed email unici per vincolo UNIQUE, non per un controllo prima.
     */
    public static Created createAdmin(String username, String email, String role) {
        byte[] handle = new byte[16];
        RANDOM.nextBytes(handle);
        boolean withEmail = email != null && !email.isBlank();
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_CREATE_ADMIN,
                Statement.RETURN_GENERATED_KEYS)) {
            p.setString(1, username);
            p.setString(2, role);
            p.setString(3, withEmail ? DataCrypto.encrypt(email.trim()) : null);
            p.setString(4, withEmail ? DataCrypto.emailIndex(email) : null);
            p.setString(5, b64url(handle));
            p.setObject(6, utc(now()));
            p.executeUpdate();
            try (ResultSet k = p.getGeneratedKeys()) {
                return k.next() ? new Created(CreateResult.CREATED, k.getLong(1)) : new Created(CreateResult.FAILED, -1);
            }
        } catch (SQLException e) {
            return new Created(duplicateOf(e), -1);
        }
    }

    /** Quale vincolo UNIQUE ha fermato un INSERT o un UPDATE (codice MySQL 1062). */
    private static CreateResult duplicateOf(SQLException e) {
        if (e.getErrorCode() == 1062 && e.getMessage() != null) {
            if (e.getMessage().contains("email_index")) return CreateResult.EMAIL_TAKEN;
            if (e.getMessage().contains("username")) return CreateResult.NAME_TAKEN;
        }
        LOGGER.log(Level.WARNING, "Admin not saved: " + e.getMessage());
        return CreateResult.FAILED;
    }

    /** Cambia il nome. NAME_TAKEN se e' gia' di un altro (vincolo UNIQUE). */
    public static CreateResult renameAdmin(long adminId, String username) {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_RENAME_ADMIN)) {
            p.setString(1, username);
            p.setLong(2, adminId);
            return p.executeUpdate() == 1 ? CreateResult.CREATED : CreateResult.FAILED;
        } catch (SQLException e) {
            return duplicateOf(e);
        }
    }

    /** Imposta l'email (cifrata, con l'indice cieco). EMAIL_TAKEN se e' gia' di un altro amministratore. */
    public static CreateResult setEmail(long adminId, String email) {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_SET_EMAIL)) {
            p.setString(1, DataCrypto.encrypt(email.trim()));
            p.setString(2, DataCrypto.emailIndex(email));
            p.setLong(3, adminId);
            return p.executeUpdate() == 1 ? CreateResult.CREATED : CreateResult.FAILED;
        } catch (SQLException e) {
            return duplicateOf(e);
        }
    }

    public static boolean setRole(long adminId, String role) {
        if (!ROLES.contains(role)) return false;
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_SET_ROLE)) {
            p.setString(1, role);
            p.setLong(2, adminId);
            return p.executeUpdate() == 1;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Role not saved", e);
            return false;
        }
    }

    /** Toglie un amministratore: con lui (ON DELETE CASCADE) le sue passkey, sessioni e codici. */
    public static boolean deleteAdmin(long adminId) {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_DELETE_ADMIN)) {
            p.setLong(1, adminId);
            return p.executeUpdate() == 1;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Admin not deleted", e);
            return false;
        }
    }

    /** Quanti superadmin attivi ci sono: l'ultimo non si toglie e non si declassa. */
    public static int activeSuperadmins() {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_ACTIVE_SUPERADMINS);
             ResultSet r = p.executeQuery()) {
            return r.next() ? r.getInt(1) : 0;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Superadmins unreadable", e);
            return 0;
        }
    }

    public static void loggedIn(long adminId) {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_LOGGED_IN)) {
            p.setObject(1, utc(now()));
            p.setLong(2, adminId);
            p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Last login not recorded", e);
        }
    }

    // ===================== Passkey =====================

    public record Passkey(long id, long adminId, ByteArray credentialId, ByteArray publicKeyCose, long signCount,
                          String name, LocalDateTime createdAt, LocalDateTime lastUsed, String userHandle) {}

    // Le colonne lette da passkeys(): SqlCatalog.AUTH_PASSKEY_SELECT, in quest'ordine.
    private static List<Passkey> passkeys(PreparedStatement p) throws SQLException {
        List<Passkey> out = new ArrayList<>();
        try (ResultSet r = p.executeQuery()) {
            while (r.next()) out.add(new Passkey(r.getLong(1), r.getLong(2), new ByteArray(r.getBytes(3)), new ByteArray(r.getBytes(4)),
                    r.getLong(5), r.getString(6), r.getObject(7, LocalDateTime.class), r.getObject(8, LocalDateTime.class), r.getString(9)));
        }
        return out;
    }

    public static List<Passkey> passkeysOf(long adminId) {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_PASSKEYS_OF_ADMIN)) {
            p.setLong(1, adminId);
            return passkeys(p);
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Passkeys unreadable", e);
            return List.of();
        }
    }

    public static List<Passkey> passkeysByCredentialId(ByteArray credentialId) {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_PASSKEYS_BY_CREDENTIAL_ID)) {
            p.setBytes(1, credentialId.getBytes());
            return passkeys(p);
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Passkey unreadable", e);
            return List.of();
        }
    }

    /** Salva una passkey. Falso anche se la credenziale c'e' gia' (vincolo UNIQUE). */
    public static boolean addPasskey(long adminId, ByteArray credentialId, ByteArray publicKeyCose, long signCount,
                                     String name, String rpId, String userHandle) {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_ADD_PASSKEY)) {
            p.setLong(1, adminId);
            p.setBytes(2, credentialId.getBytes());
            p.setBytes(3, publicKeyCose.getBytes());
            p.setLong(4, signCount);
            p.setString(5, name);
            p.setObject(6, utc(now()));
            p.setString(7, rpId);
            p.setString(8, userHandle);
            return p.executeUpdate() == 1;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Passkey not saved: " + e.getMessage());
            return false;
        }
    }

    public static void passkeyUsed(ByteArray credentialId, long signCount) {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_PASSKEY_USED)) {
            p.setLong(1, signCount);
            p.setObject(2, utc(now()));
            p.setBytes(3, credentialId.getBytes());
            p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Passkey use not recorded", e);
        }
    }

    public static boolean renamePasskey(long id, long adminId, String name) {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_RENAME_PASSKEY)) {
            p.setString(1, name);
            p.setLong(2, id);
            p.setLong(3, adminId);
            return p.executeUpdate() == 1;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Passkey not renamed", e);
            return false;
        }
    }

    public static boolean deletePasskey(long id, long adminId) {
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_DELETE_PASSKEY)) {
            p.setLong(1, id);
            p.setLong(2, adminId);
            return p.executeUpdate() == 1;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Passkey not deleted", e);
            return false;
        }
    }

    // ===================== Codici monouso, una tabella per flusso =====================

    /**
     * I flussi, ognuno con la sua tabella e le sue istruzioni, fisse nel catalogo: una tabella non e'
     * un parametro, e il nome non si compone piu' qui.
     */
    public enum CodeFlow {
        EMAIL_LOGIN(SqlCatalog.AUTH_CODE_EMAIL_LOGIN_INVALIDATE, SqlCatalog.AUTH_CODE_EMAIL_LOGIN_INSERT, SqlCatalog.AUTH_CODE_EMAIL_LOGIN_ACTIVE_OF, SqlCatalog.AUTH_CODE_EMAIL_LOGIN_ACTIVE_ALL,
                SqlCatalog.AUTH_CODE_EMAIL_LOGIN_ATTEMPT, SqlCatalog.AUTH_CODE_EMAIL_LOGIN_CONSUME, SqlCatalog.AUTH_CODE_EMAIL_LOGIN_PURGE),
        CONSOLE_LOGIN(SqlCatalog.AUTH_CODE_CONSOLE_LOGIN_INVALIDATE, SqlCatalog.AUTH_CODE_CONSOLE_LOGIN_INSERT, SqlCatalog.AUTH_CODE_CONSOLE_LOGIN_ACTIVE_OF, SqlCatalog.AUTH_CODE_CONSOLE_LOGIN_ACTIVE_ALL,
                SqlCatalog.AUTH_CODE_CONSOLE_LOGIN_ATTEMPT, SqlCatalog.AUTH_CODE_CONSOLE_LOGIN_CONSUME, SqlCatalog.AUTH_CODE_CONSOLE_LOGIN_PURGE),
        STEP_UP(SqlCatalog.AUTH_CODE_STEP_UP_INVALIDATE, SqlCatalog.AUTH_CODE_STEP_UP_INSERT, SqlCatalog.AUTH_CODE_STEP_UP_ACTIVE_OF, SqlCatalog.AUTH_CODE_STEP_UP_ACTIVE_ALL,
                SqlCatalog.AUTH_CODE_STEP_UP_ATTEMPT, SqlCatalog.AUTH_CODE_STEP_UP_CONSUME, SqlCatalog.AUTH_CODE_STEP_UP_PURGE),
        EMAIL_CHANGE(SqlCatalog.AUTH_CODE_EMAIL_CHANGE_INVALIDATE, SqlCatalog.AUTH_CODE_EMAIL_CHANGE_INSERT, SqlCatalog.AUTH_CODE_EMAIL_CHANGE_ACTIVE_OF, SqlCatalog.AUTH_CODE_EMAIL_CHANGE_ACTIVE_ALL,
                SqlCatalog.AUTH_CODE_EMAIL_CHANGE_ATTEMPT, SqlCatalog.AUTH_CODE_EMAIL_CHANGE_CONSUME, SqlCatalog.AUTH_CODE_EMAIL_CHANGE_PURGE);

        final String invalidate, insert, activeOf, activeAll, attempt, consume, purge;

        CodeFlow(String invalidate, String insert, String activeOf, String activeAll, String attempt, String consume, String purge) {
            this.invalidate = invalidate;
            this.insert = insert;
            this.activeOf = activeOf;
            this.activeAll = activeAll;
            this.attempt = attempt;
            this.consume = consume;
            this.purge = purge;
        }
    }

    public record CodeRow(long id, long adminId, String codeHash, int attempts, String targetEnc, String targetIndex) {}

    /** Salva un codice nuovo e annulla quelli ancora validi dello stesso amministratore. */
    public static boolean saveCode(CodeFlow flow, long adminId, String codeHash, Instant expires, String targetEnc, String targetIndex) {
        LocalDateTime now = utc(now());
        try (PreparedStatement inv = db().prepareStatement(flow.invalidate);
             PreparedStatement ins = db().prepareStatement(flow.insert)) {
            inv.setObject(1, now);
            inv.setLong(2, adminId);
            inv.executeUpdate();
            ins.setLong(1, adminId);
            ins.setString(2, codeHash);
            ins.setObject(3, now);
            ins.setObject(4, utc(expires));
            if (flow == CodeFlow.EMAIL_CHANGE) {
                ins.setString(5, targetEnc);
                ins.setString(6, targetIndex);
            }
            return ins.executeUpdate() == 1;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Code not saved (" + flow + ")", e);
            return false;
        }
    }

    /** I codici ancora validi di un amministratore (adminId >= 0) o di tutti (adminId < 0). */
    public static List<CodeRow> activeCodes(CodeFlow flow, long adminId) {
        LocalDateTime now = utc(now());
        String active = adminId >= 0 ? flow.activeOf : flow.activeAll;
        try (PreparedStatement p = db().prepareStatement(active)) {
            if (adminId >= 0) { p.setLong(1, adminId); p.setObject(2, now); }
            else p.setObject(1, now);
            List<CodeRow> out = new ArrayList<>();
            try (ResultSet r = p.executeQuery()) {
                while (r.next()) out.add(new CodeRow(r.getLong(1), r.getLong(2), r.getString(3), r.getInt(4), r.getString(5), r.getString(6)));
            }
            return out;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Codes unreadable (" + flow + ")", e);
            return List.of();
        }
    }

    public static void codeAttempt(CodeFlow flow, long id) {
        try (PreparedStatement p = db().prepareStatement(flow.attempt)) {
            p.setLong(1, id);
            p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Code attempt not recorded (" + flow + ")", e);
        }
    }

    /**
     * Usa il codice: vero solo per la prima richiesta che ci riesce (una riga aggiornata), e solo
     * se i tentativi non hanno superato il massimo nel frattempo.
     */
    public static boolean consumeCode(CodeFlow flow, long id, int maxAttempts) {
        try (PreparedStatement p = db().prepareStatement(flow.consume)) {
            p.setObject(1, utc(now()));
            p.setLong(2, id);
            p.setInt(3, maxAttempts);
            return p.executeUpdate() == 1;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Code not consumed (" + flow + ")", e);
            return false;
        }
    }

    /** Toglie i codici scaduti da piu' di un giorno e le sessioni scadute. */
    public static void purgeExpired() {
        LocalDateTime limit = utc(now().minusSeconds(86400));
        for (CodeFlow f : CodeFlow.values()) {
            try (PreparedStatement p = db().prepareStatement(f.purge)) {
                p.setObject(1, limit);
                p.executeUpdate();
            } catch (SQLException e) {
                LOGGER.log(Level.WARNING, "Old codes not purged (" + f + ")", e);
            }
        }
        try (PreparedStatement p = db().prepareStatement(SqlCatalog.AUTH_PURGE_EXPIRED)) {
            p.setObject(1, utc(now()));
            p.setObject(2, utc(now().minusSeconds(org.daemoxcp.mail.webserver.WebSessions.IDLE_SECONDS)));
            p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Expired sessions not purged", e);
        }
    }

    // ===================== Utilita' =====================

    public static String b64url(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
}
