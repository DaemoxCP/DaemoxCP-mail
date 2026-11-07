package org.mail_panel.database;

import org.mindrot.jbcrypt.BCrypt;

import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Unified MySQL database for Mail Panel
 * Handles both panel state (admin, settings, components) and mail data (domains, mailboxes, aliases)
 *
 * Database: mailpanel
 *
 * Tables:
 * - panel_admin: Admin user authentication
 * - panel_settings: Key-value settings
 * - installed_components: Installed mail stack components
 * - domains: Mail domains
 * - mailboxes: Virtual mailboxes
 * - aliases: Email aliases
 * - roundcube_tokens: Auto-login tokens for webmail
 */
public class MailDatabase {
    private static final Logger LOGGER = Logger.getLogger(MailDatabase.class.getName());


    private Connection connection;
    private String host = "127.0.0.1";
    private int port = 3306;
    private String database = "mailpanel";
    private String username = "mailpanel";
    private String password;

    // Flag to track if database is available
    private boolean connected = false;

    public MailDatabase() {
        // Default constructor - password will be set later or read from config
    }

    public MailDatabase(String password) {
        this.password = password;
    }

    public void setCredentials(String username, String password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Da dove rileggere la password a ogni collegamento: quella del pannello, nel file dei segreti.
     *
     * <p>Senza, il pannello si ricollegava con la password che aveva in memoria dall'avvio. Una
     * reinstallazione completa dal menu cambia la password dell'utente MySQL del pannello (e la
     * scrive nel file dei segreti quando MySQL la conosce, PendingDbPassword) e riavvia MySQL: il
     * servizio --web acceso intanto perdeva la connessione e riprovava per sempre con quella
     * vecchia, «Access denied», finche' qualcuno non lo riavviava (reperto 156).
     */
    public void setPasswordSource(java.util.function.Supplier<String> source) {
        this.passwordSource = source;
    }

    private java.util.function.Supplier<String> passwordSource;

    /** La password per il prossimo collegamento: quella della fonte se ne da' una, altrimenti l'ultima. */
    private String currentPassword() {
        if (passwordSource != null) {
            try {
                String p = passwordSource.get();
                if (p != null && !p.isEmpty()) {
                    if (password != null && !password.isEmpty() && !p.equals(password))
                        LOGGER.info("The panel's MySQL password changed in the secrets file: connecting with the new one.");
                    password = p;
                }
            } catch (RuntimeException e) {
                LOGGER.warning("Cannot read the panel's MySQL password again, using the previous one: " + e.getMessage());
            }
        }
        return password;
    }

    public void setConnection(String host, int port, String database) {
        this.host = host;
        this.port = port;
        this.database = database;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setDatabase(String database) {
        this.database = database;
    }

    public boolean isConnected() {
        return connected;
    }

    /**
     * Try to connect to MySQL. Returns false if MySQL is not available.
     */
    public boolean connect() {
        boolean again = connection != null;
        try {
            connection = CatalogGuard.open(databaseUrl(), username, currentPassword());
            connected = true;
            if (again) System.out.println("Connected to MySQL again.");
            return true;
        } catch (SQLException e) {
            System.err.println("MySQL not available: " + e.getMessage());
            connected = false;
            return false;
        }
    }

    private String databaseUrl() {
        return String.format(
            "jdbc:mysql://%s:%d/%s?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&createDatabaseIfNotExist=true&autoReconnect=true",
            host, port, database
        );
    }

    /**
     * Una connessione tutta per chi la chiede, che la chiude. Serve alle transazioni: la
     * connessione condivisa la usano anche i lavori in background (rapporto, DKIM, MTA-STS), e con
     * l'autocommit spento i loro comandi finirebbero dentro la transazione di un altro.
     */
    private Connection ownConnection() throws SQLException {
        return CatalogGuard.open(databaseUrl(), username, currentPassword());
    }

    /**
     * Try to connect with root credentials to create database and user
     */
    public boolean connectAsRoot(String rootPassword) {
        try {
            String url = String.format(
                "jdbc:mysql://%s:%d/?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC",
                host, port
            );
            connection = CatalogGuard.open(url, "root", rootPassword);
            connected = true;
            return true;
        } catch (SQLException e) {
            System.err.println("Cannot connect as root: " + e.getMessage());
            connected = false;
            return false;
        }
    }

    /**
     * Try to connect as root via socket authentication (no password required when running as root on FreeBSD)
     * This is the default MySQL configuration on FreeBSD - root can connect without password via unix socket
     */
    public boolean connectAsRootSocket() {
        // Try multiple connection methods for FreeBSD MySQL
        String[] socketPaths = {
            "/var/run/mysql/mysql.sock",
            "/tmp/mysql.sock",
            "/var/db/mysql/mysql.sock"
        };

        // First try TCP with empty password (some FreeBSD MySQL configs allow this)
        try {
            String url = String.format(
                "jdbc:mysql://%s:%d/?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC",
                host, port
            );
            connection = CatalogGuard.open(url, "root", "");
            connected = true;
            System.out.println("Connected to MySQL as root via TCP (no password)");
            return true;
        } catch (SQLException e) {
            // Try socket paths
        }

        // Try unix socket connections
        for (String socketPath : socketPaths) {
            try {
                String url = String.format(
                    "jdbc:mysql://localhost/?socket=%s&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC",
                    socketPath
                );
                connection = CatalogGuard.open(url, "root", "");
                connected = true;
                System.out.println("Connected to MySQL as root via socket: " + socketPath);
                return true;
            } catch (SQLException e) {
                // Try next socket
            }
        }

        System.err.println("Cannot connect as root via socket authentication. MySQL may require a password.");
        connected = false;
        return false;
    }

    /**
     * Create the mailpanel database and user (run as root)
     */
    public void createDatabaseAndUser(String panelPassword) throws SQLException {
        try (Statement stmt = getConnection().createStatement()) {
            // Create database
            stmt.execute(SqlCatalog.MAIL_CREATE_PANEL_DATABASE);

            // Create user: la password e' un parametro, non un pezzo del testo
            createUser(SqlCatalog.MAIL_CREATE_PANEL_USER, panelPassword);
            stmt.execute(SqlCatalog.MAIL_GRANT_PANEL_USER);

            // Create mailserver database for Dovecot
            stmt.execute(SqlCatalog.MAIL_CREATE_MAILSERVER_DATABASE);
            createUser(SqlCatalog.MAIL_CREATE_MAILSERVER_USER, panelPassword);
            stmt.execute(SqlCatalog.MAIL_GRANT_MAILSERVER_USER);

            stmt.execute(SqlCatalog.MAIL_FLUSH_PRIVILEGES);
        }

        // Store the password for later use
        this.password = panelPassword;
    }

    /**
     * CREATE USER con la password come parametro. MySQL non accetta un segnaposto in IDENTIFIED BY
     * quando prepara lui l'istruzione; Connector/J pero', se non gli si chiede altro, prepara dalla
     * parte del client e mette il valore fra apici con il suo escape, apici e barre rovesciate
     * compresi. Prima la password entrava nel testo con il solo raddoppio degli apici.
     */
    private void createUser(String statement, String password) throws SQLException {
        try (PreparedStatement ps = getConnection().prepareStatement(statement)) {
            ps.setString(1, password);
            ps.execute();
        }
    }

    /**
     * Tutte le tabelle che il pannello crea (createSchema e le migrazioni), piu' quelle di versioni
     * vecchie (virtual_*): le cancella il reset, e nessun'altra del database. Prima le tabelle che
     * puntano ad altre con una chiave esterna, poi quelle a cui si punta.
     */
    static final List<String> PANEL_TABLES = List.of(
        "admin_passkeys", "rspamd_training", "panel_sessions",                // -> panel_admin
        "login_code_email", "login_code_console", "stepup_code", "email_change_code",
        "roundcube_tokens", "auto_responders", "sieve_filters", "forwarding_rules",
        "email_statistics",                                                   // -> mailboxes, domains
        "aliases", "mailboxes",                                               // -> domains
        "dkim_rotation_history", "domains", "cloudflare_accounts",
        "audit_log", "rate_limits", "panel_settings", "installed_components", "panel_admin",
        "virtual_aliases", "virtual_users", "virtual_domains"
    );

    /**
     * Svuota il database del pannello per il reset: cancella tutte le sue tabelle e torna solo se
     * non ne resta nessuna. Restituisce quelle che c'erano.
     *
     * Un solo DROP con tutte le tabelle: MySQL toglie insieme quelle legate da chiavi esterne senza
     * spegnere i controlli, e su InnoDB il comando e' atomico, o le cancella tutte o nessuna. Il
     * vecchio reset le cancellava una alla volta: quelle a cui un'altra puntava (mailboxes, domains,
     * panel_admin) restavano, con i loro dati, e mancavano admin_passkeys, cloudflare_accounts e
     * dkim_rotation_history. Su una connessione tutta sua, perche' un DROP chiude la transazione
     * della connessione su cui gira.
     */
    public List<String> dropAllTables() throws SQLException {
        if (!connected) throw new SQLException("Not connected to MySQL: the reset did not start.");
        try (Connection c = ownConnection()) {
            List<String> before = panelTables(c);
            try (Statement st = c.createStatement()) {
                // Un DROP non prende parametri: l'elenco e' fisso nel catalogo, uguale a PANEL_TABLES.
                st.executeUpdate(SqlCatalog.MAIL_DROP_PANEL_TABLES);
            } catch (SQLException e) {
                String present;
                try {
                    List<String> t = panelTables(c);
                    present = t.isEmpty() ? "none" : String.join(", ", t);
                } catch (SQLException lost) {
                    present = "unknown, MySQL does not answer";
                }
                throw new SQLException("Reset failed: " + e.getMessage()
                        + " Panel tables still present: " + present + ".", e);
            }
            List<String> remain = panelTables(c);
            if (!remain.isEmpty()) {
                throw new SQLException("Reset not complete: these tables remain: " + String.join(", ", remain) + ".");
            }
            return before;
        }
    }

    /** Le tabelle del pannello che ci sono adesso nel database della connessione. */
    private static List<String> panelTables(Connection c) throws SQLException {
        List<String> found = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(SqlCatalog.MAIL_PANEL_TABLES);
             ResultSet r = ps.executeQuery()) {
            while (r.next()) {
                String name = r.getString(1);
                if (PANEL_TABLES.contains(name)) found.add(name);
            }
        }
        return found;
    }

    /**
     * Create all tables for the mail panel
     */
    public void createSchema() throws SQLException {
        // ========== PANEL TABLES ==========

        // Admin users table
        // theme: 'auto' = follow browser, 'light' = always light, 'dark' = always dark

        // Settings table

        // Installed components

        // ========== MAIL TABLES ==========

        // Domains table

        // Cloudflare accounts table (un account = un token + label informativa)

        // DKIM rotation history (audit log: ogni evento del workflow viene registrato)

        // Mailboxes table (virtual users)
        // quota_mb: 0 = unlimited, >0 = limit in MB
        // receive_enabled: false = no-reply account (can only send, not receive)

        // Aliases table

        // Auto-login tokens for Roundcube SSO

        // Auto-responder (vacation messages)

        // Sieve filters

        // Forwarding rules

        // Rate limits

        // Email statistics

        // Rspamd training log


        // Passkeys (WebAuthn) for passwordless login

        try (Statement stmt = getConnection().createStatement()) {
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_2);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_3);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_4);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_5);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_6);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_7);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_8);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_9);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_10);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_11);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_12);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_13);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_14);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_15);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_16);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_17);
            createAuthTables(stmt);
        }
    }

    /**
     * Le tabelle dell'accesso senza password: le sessioni e i codici monouso, una tabella per
     * flusso (accesso via email, accesso dalla console, cambio dell'email, conferma di
     * un'operazione delicata). Nei codici c'e' solo l'impronta HMAC, mai il codice; della sessione
     * c'e' solo l'impronta SHA-256 del token. Date in UTC, colonne DATETIME.
     */
    private static void createAuthTables(Statement st) throws SQLException {
        st.execute(SqlCatalog.MAIL_CREATE_PANEL_SESSIONS);
        st.execute(SqlCatalog.MAIL_CREATE_LOGIN_CODE_EMAIL);
        st.execute(SqlCatalog.MAIL_CREATE_LOGIN_CODE_CONSOLE);
        st.execute(SqlCatalog.MAIL_CREATE_STEPUP_CODE);
        st.execute(SqlCatalog.MAIL_CREATE_EMAIL_CHANGE_CODE);
    }

    /**
     * Da un'installazione con le password a quella senza. Si puo' ripetere: ogni passo guarda prima
     * se serve. Su una connessione sua con il fuso UTC, perche' passare da TIMESTAMP a DATETIME
     * converte con il fuso della sessione, e le date devono restare in UTC.
     *
     *  - via password_hash, totp_secret, totp_enabled, backup_codes: nessun hash nel database;
     *  - email cifrata, indice cieco, user handle delle passkey;
     *  - le passkey sanno a quale user handle e a quale nome (rpId) appartengono;
     *  - le date dell'accesso in DATETIME.
     */
    public void ensurePasswordlessSchema() throws SQLException {
        try (Connection c = ownConnection(); Statement st = c.createStatement()) {
            st.execute(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA);
            createAuthTables(st);
            // Un ALTER non prende parametri: una istruzione fissa per colonna.
            String[][] old = {
                {"password_hash", SqlCatalog.MAIL_DROP_ADMIN_PASSWORD_HASH},
                {"totp_secret", SqlCatalog.MAIL_DROP_ADMIN_TOTP_SECRET},
                {"totp_enabled", SqlCatalog.MAIL_DROP_ADMIN_TOTP_ENABLED},
                {"backup_codes", SqlCatalog.MAIL_DROP_ADMIN_BACKUP_CODES}};
            for (String[] col : old) {
                if (columnType(c, "panel_admin", col[0]) != null) {
                    st.executeUpdate(col[1]);
                    LOGGER.info("Removed panel_admin." + col[0]);
                }
            }
            if (columnType(c, "panel_admin", "email_enc") == null)
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_2);
            if (columnType(c, "panel_admin", "email_index") == null)
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_3);
            if (columnType(c, "panel_admin", "user_handle") == null)
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_4);
            if ("timestamp".equals(columnType(c, "panel_admin", "created_at")))
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_5);
            if ("timestamp".equals(columnType(c, "panel_admin", "last_login")))
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_6);
            if (columnType(c, "admin_passkeys", "user_handle") == null)
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_7);
            if (columnType(c, "admin_passkeys", "rp_id") == null)
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_8);
            if ("timestamp".equals(columnType(c, "admin_passkeys", "created_at")))
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_9);
            if ("timestamp".equals(columnType(c, "admin_passkeys", "last_used")))
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_10);
        }
    }

    /** Il tipo di una colonna (minuscolo, "datetime", "varchar"...) o null se la colonna non c'e'. */
    private static String columnType(Connection c, String table, String column) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(SqlCatalog.MAIL_COLUMN_TYPE)) {
            ps.setString(1, table);
            ps.setString(2, column);
            try (ResultSet r = ps.executeQuery()) {
                return r.next() ? r.getString(1).toLowerCase(java.util.Locale.ROOT) : null;
            }
        }
    }

    // ========== ADMIN ==========

    /**
     * Check if any admin exists
     */
    public boolean hasAdminUser() {
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_HAS_ADMIN_USER)) {
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    // ========== THEME MANAGEMENT ==========

    /**
     * Get admin theme preference
     * @return 'auto', 'light', or 'dark'
     */
    public String getAdminTheme(String username) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ADMIN_THEME)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String theme = rs.getString("theme");
                return (theme != null && !theme.isEmpty()) ? theme : "auto";
            }
        } catch (SQLException e) {
            System.err.println("Error getting theme: " + e.getMessage());
        }
        return "auto";
    }

    /**
     * Set admin theme preference
     */
    public boolean setAdminTheme(String username, String theme) {
        // Validate theme value
        if (!theme.equals("auto") && !theme.equals("light") && !theme.equals("dark")) {
            theme = "auto";
        }
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_ADMIN_THEME)) {
            stmt.setString(1, theme);
            stmt.setString(2, username);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error setting theme: " + e.getMessage());
            return false;
        }
    }

    /**
     * La lingua scelta dall'amministratore ("it" o "en"), o null se non l'ha mai scelta: allora
     * vale quella del browser. Lo segue su ogni browser, come il tema.
     */
    public String getAdminLanguage(String username) {
        if (username == null) return null;
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ADMIN_LANGUAGE)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    String lang = rs.getString("language");
                    return "it".equals(lang) || "en".equals(lang) ? lang : null;
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Cannot read the admin language", e);
        }
        return null;
    }

    /** Salva la lingua dell'amministratore: solo "it" o "en". */
    public boolean setAdminLanguage(String username, String lang) {
        if (username == null || !("it".equals(lang) || "en".equals(lang))) return false;
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_ADMIN_LANGUAGE)) {
            stmt.setString(1, lang);
            stmt.setString(2, username);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Cannot save the admin language", e);
            return false;
        }
    }

    /** La colonna della lingua in panel_admin, per le installazioni di prima (NULL: mai scelta). */
    public void ensureLanguageColumn() {
        try (Statement stmt = getConnection().createStatement(); ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_LANGUAGE_COLUMN)) {
            if (rs.next() && rs.getInt(1) == 0) {
                try (Statement alter = getConnection().createStatement()) {
                    alter.executeUpdate(SqlCatalog.MAIL_ENSURE_LANGUAGE_COLUMN_2);
                }
                LOGGER.info("Added language column to panel_admin");
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Cannot add the language column", e);
        }
    }

    /**
     * Ensure DKIM rotation columns exist in domains table (for database migration).
     * Aggiunge in modo idempotente i campi dkim_pending_*, dkim_previous_*,
     * dkim_rotation_state, dkim_rotation_started_at, dkim_rotation_activated_at.
     */
    public void ensureDkimRotationColumns() {
        // Nome della colonna e la sua istruzione fissa: un ALTER non prende parametri.
        String[][] cols = {
            {"dkim_pending_selector", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PENDING_SELECTOR},
            {"dkim_pending_private_key", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PENDING_PRIVATE_KEY},
            {"dkim_pending_public_key", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PENDING_PUBLIC_KEY},
            {"dkim_rotation_state", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_ROTATION_STATE},
            {"dkim_rotation_started_at", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_ROTATION_STARTED_AT},
            {"dkim_rotation_activated_at", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_ROTATION_ACTIVATED_AT},
            {"dkim_previous_selector", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PREVIOUS_SELECTOR},
            {"dkim_previous_private_key", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PREVIOUS_PRIVATE_KEY},
            {"dkim_previous_public_key", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PREVIOUS_PUBLIC_KEY},
            // Cloudflare automation: zone + ID dei record TXT, per cancellarli
            {"dkim_dns_zone_id", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_DNS_ZONE_ID},
            {"dkim_pending_dns_record_id", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PENDING_DNS_RECORD_ID},
            {"dkim_previous_dns_record_id", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PREVIOUS_DNS_RECORD_ID},
            // Rotazione programmata
            {"dkim_rotation_interval_days", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_ROTATION_INTERVAL_DAYS},
            {"dkim_last_rotation_at", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_LAST_ROTATION_AT},
            // Modalità rotazione (ereditata da tutti gli eventi della catena)
            {"dkim_rotation_mode", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_ROTATION_MODE}
        };
        try (Statement stmt = getConnection().createStatement()) {
            for (String[] col : cols) {
                if (columnType(getConnection(), "domains", col[0]) == null) {
                    stmt.executeUpdate(col[1]);
                    System.out.println("Added " + col[0] + " column to domains table");
                }
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring DKIM rotation columns: " + e.getMessage());
        }
    }

    /**
     * Ensure cloudflare_accounts table + domains.cloudflare_account_id column exist.
     * Migra anche il token legacy (panel_settings.cloudflare_api_token) creando un
     * account "Account principale" e legandolo a tutti i domini esistenti.
     */
    public void ensureCloudflareAccountsSchema() {
        try (Statement stmt = getConnection().createStatement()) {
            // 1) tabella cloudflare_accounts
            stmt.execute(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA);

            // 2) colonna domains.cloudflare_account_id
            ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_2);
            if (rs.next() && rs.getInt(1) == 0) {
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_3);
                System.out.println("Added cloudflare_account_id column to domains table");
            }

            // 3) migrazione token legacy
            String legacyToken = getSetting("cloudflare_api_token", "");
            String legacyEnabled = getSetting("cloudflare_enabled", "0");
            if (!legacyToken.isEmpty() && "1".equals(legacyEnabled)) {
                // Verifica che non ci siano già account: se la tabella è vuota, importa
                ResultSet cnt = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_4);
                if (cnt.next() && cnt.getInt(1) == 0) {
                    try (PreparedStatement ins = getConnection().prepareStatement(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_5,
                        Statement.RETURN_GENERATED_KEYS)) {
                        ins.setString(1, "Account principale");
                        ins.setString(2, legacyToken);
                        ins.executeUpdate();
                        ResultSet gk = ins.getGeneratedKeys();
                        if (gk.next()) {
                            int newId = gk.getInt(1);
                            // Lega tutti i domini esistenti a questo account (preserva il comportamento)
                            try (PreparedStatement upd = getConnection().prepareStatement(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_6)) {
                                upd.setInt(1, newId);
                                int affected = upd.executeUpdate();
                                System.out.println("Migrated legacy Cloudflare token to account '" + newId
                                    + "', assigned to " + affected + " domain(s)");
                            }
                        }
                    }
                    // Cancella il settings legacy così non viene più riusato
                    deleteSetting("cloudflare_api_token");
                    deleteSetting("cloudflare_enabled");
                }
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring cloudflare accounts schema: " + e.getMessage());
        }
    }

    /**
     * Ensure dkim_rotation_history table exists (idempotente).
     */
    public void ensureDkimRotationHistoryTable() {
        try (Statement stmt = getConnection().createStatement()) {
            stmt.execute(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE);
            // Migrazione: aggiungi triggered_by se la tabella esiste già senza quel campo
            ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_2);
            if (rs.next() && rs.getInt(1) == 0) {
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_3);
                System.out.println("Added triggered_by column to dkim_rotation_history table");
            }
            // Migrazione: aggiungi previous_selector se la tabella esiste già senza quel campo
            ResultSet rs2 = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_4);
            if (rs2.next() && rs2.getInt(1) == 0) {
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_5);
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_6);
                System.out.println("Added previous_selector column + index to dkim_rotation_history table");
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring dkim_rotation_history table: " + e.getMessage());
        }
    }

    /**
     * Registra un evento del workflow di rotazione DKIM.
     * @param triggeredBy "user" se avviato cliccando un bottone, "scheduler" se dal timer automatico,
     *                    null per eventi non avviati esplicitamente (verifiche, propagazione, ecc.)
     */
    public void logDkimRotationEvent(int domainId, String domain, String eventType,
                                      String selector, String mode, String triggeredBy,
                                      Integer cloudflareAccountId, String cloudflareAccountLabel,
                                      boolean success, String message) {
        logDkimRotationEvent(domainId, domain, eventType, selector, null, mode, triggeredBy,
                             cloudflareAccountId, cloudflareAccountLabel, success, message);
    }

    public void logDkimRotationEvent(int domainId, String domain, String eventType,
                                      String selector, String previousSelector,
                                      String mode, String triggeredBy,
                                      Integer cloudflareAccountId, String cloudflareAccountLabel,
                                      boolean success, String message) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_LOG_DKIM_ROTATION_EVENT)) {
            stmt.setInt(1, domainId);
            stmt.setString(2, domain == null ? "" : domain);
            stmt.setString(3, eventType);
            if (selector == null) stmt.setNull(4, Types.VARCHAR); else stmt.setString(4, selector);
            if (previousSelector == null) stmt.setNull(5, Types.VARCHAR); else stmt.setString(5, previousSelector);
            if (mode == null) stmt.setNull(6, Types.VARCHAR); else stmt.setString(6, mode);
            if (triggeredBy == null) stmt.setNull(7, Types.VARCHAR); else stmt.setString(7, triggeredBy);
            if (cloudflareAccountId == null) stmt.setNull(8, Types.INTEGER); else stmt.setInt(8, cloudflareAccountId);
            if (cloudflareAccountLabel == null) stmt.setNull(9, Types.VARCHAR); else stmt.setString(9, cloudflareAccountLabel);
            stmt.setBoolean(10, success);
            if (message == null) stmt.setNull(11, Types.LONGVARCHAR); else stmt.setString(11, message);
            stmt.setTimestamp(12, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to log DKIM rotation event: " + e.getMessage());
        }
    }

    /**
     * Trova il timestamp più recente di disattivazione di un selector per un dominio.
     * Un selector è considerato "disattivato" al momento di un evento key_activated dove
     * compare come previous_selector (cioè quando una nuova chiave l'ha sostituito).
     *
     * Ritorna null se il selector non è mai stato registrato come disattivato (probabilmente
     * non era mai stato il selector attivo nel pannello).
     */
    public Timestamp findSelectorDeactivationTime(int domainId, String selector) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_FIND_SELECTOR_DEACTIVATION_TIME)) {
            stmt.setInt(1, domainId);
            stmt.setString(2, selector);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return rs.getTimestamp("occurred_at");
            }
        }
        return null;
    }

    /**
     * Storico eventi di rotazione DKIM per un dominio, dal più recente.
     */
    public List<DkimRotationEvent> getDkimRotationHistory(int domainId, int limit) throws SQLException {
        List<DkimRotationEvent> result = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_DKIM_ROTATION_HISTORY)) {
            stmt.setInt(1, domainId);
            stmt.setInt(2, Math.max(1, Math.min(500, limit)));
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    DkimRotationEvent e = new DkimRotationEvent();
                    e.id = rs.getInt("id");
                    e.domainId = rs.getInt("domain_id");
                    e.domain = rs.getString("domain");
                    e.eventType = rs.getString("event_type");
                    e.selector = rs.getString("selector");
                    try { e.previousSelector = rs.getString("previous_selector"); } catch (SQLException ignore) {}
                    e.mode = rs.getString("mode");
                    try { e.triggeredBy = rs.getString("triggered_by"); } catch (SQLException ignore) {}
                    int cfId = rs.getInt("cloudflare_account_id");
                    e.cloudflareAccountId = rs.wasNull() ? 0 : cfId;
                    e.cloudflareAccountLabel = rs.getString("cloudflare_account_label");
                    e.success = rs.getBoolean("success");
                    e.message = rs.getString("message");
                    e.occurredAt = rs.getTimestamp("occurred_at");
                    result.add(e);
                }
            }
        }
        return result;
    }

    public static class DkimRotationEvent {
        public int id;
        public int domainId;
        public String domain;
        public String eventType;
        public String selector;
        public String previousSelector;  // valorizzato per key_activated (vecchio selector che è stato rimpiazzato)
        public String mode;
        public String triggeredBy;   // "user" / "scheduler" / null
        public int cloudflareAccountId;
        public String cloudflareAccountLabel;
        public boolean success;
        public String message;
        public Timestamp occurredAt;
    }

    /**
     * Ensure theme column exists (for database migration)
     */
    public void ensureThemeColumn() {
        try (Statement stmt = getConnection().createStatement()) {
            ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_THEME_COLUMN);
            if (rs.next() && rs.getInt(1) == 0) {
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_THEME_COLUMN_2);
                System.out.println("Added theme column to panel_admin table");
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring theme column: " + e.getMessage());
        }
    }

    // ========== SETTINGS MANAGEMENT ==========

    public String getSetting(String key, String defaultValue) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_SETTING)) {
            stmt.setString(1, key);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("setting_value");
            }
        } catch (SQLException e) {
            // ignore
        }
        return defaultValue;
    }

    public void setSetting(String key, String value) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_SETTING)) {
            stmt.setString(1, key);
            stmt.setString(2, value);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to set setting: " + e.getMessage());
        }
    }

    public void deleteSetting(String key) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_SETTING)) {
            stmt.setString(1, key);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to delete setting: " + e.getMessage());
        }
    }

    // ========== CLOUDFLARE ACCOUNTS MANAGEMENT ==========

    public int addCloudflareAccount(String label, String email, String apiToken) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_ADD_CLOUDFLARE_ACCOUNT, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, label);
            if (email == null || email.isEmpty()) stmt.setNull(2, Types.VARCHAR); else stmt.setString(2, email);
            stmt.setString(3, apiToken);
            stmt.executeUpdate();
            try (ResultSet rs = stmt.getGeneratedKeys()) {
                if (rs.next()) return rs.getInt(1);
            }
        }
        return -1;
    }

    public boolean updateCloudflareAccount(int id, String label, String email) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_CLOUDFLARE_ACCOUNT)) {
            stmt.setString(1, label);
            if (email == null || email.isEmpty()) stmt.setNull(2, Types.VARCHAR); else stmt.setString(2, email);
            stmt.setInt(3, id);
            return stmt.executeUpdate() > 0;
        }
    }

    public boolean updateCloudflareAccountToken(int id, String newToken) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_CLOUDFLARE_ACCOUNT_TOKEN)) {
            stmt.setString(1, newToken);
            stmt.setInt(2, id);
            return stmt.executeUpdate() > 0;
        }
    }

    public boolean deleteCloudflareAccount(int id) throws SQLException {
        // Prima disassocia i domini, poi cancella l'account
        try (PreparedStatement upd = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_CLOUDFLARE_ACCOUNT)) {
            upd.setInt(1, id);
            upd.executeUpdate();
        }
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_CLOUDFLARE_ACCOUNT_2)) {
            stmt.setInt(1, id);
            return stmt.executeUpdate() > 0;
        }
    }

    public CloudflareAccount getCloudflareAccount(int id) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_CLOUDFLARE_ACCOUNT)) {
            stmt.setInt(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return mapCloudflareAccount(rs);
            }
        }
        return null;
    }

    public List<CloudflareAccount> listCloudflareAccounts() throws SQLException {
        List<CloudflareAccount> result = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_LIST_CLOUDFLARE_ACCOUNTS);
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) result.add(mapCloudflareAccount(rs));
        }
        return result;
    }

    /** Ritorna l'account CF assegnato a un dominio, o null. */
    public CloudflareAccount getCloudflareAccountForDomain(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_CLOUDFLARE_ACCOUNT_FOR_DOMAIN)) {
            stmt.setInt(1, domainId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return mapCloudflareAccount(rs);
            }
        }
        return null;
    }

    /** Assegna (o disassegna passando 0/-1) un account a un dominio. */
    public boolean assignCloudflareAccountToDomain(int domainId, int accountId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_ASSIGN_CLOUDFLARE_ACCOUNT_TO_DOMAIN)) {
            if (accountId <= 0) stmt.setNull(1, Types.INTEGER);
            else                stmt.setInt(1, accountId);
            stmt.setInt(2, domainId);
            return stmt.executeUpdate() > 0;
        }
    }

    private CloudflareAccount mapCloudflareAccount(ResultSet rs) throws SQLException {
        CloudflareAccount a = new CloudflareAccount();
        a.id = rs.getInt("id");
        a.label = rs.getString("label");
        a.email = rs.getString("email");
        a.apiToken = rs.getString("api_token");
        a.verifiedAt = rs.getTimestamp("verified_at");
        a.createdAt = rs.getTimestamp("created_at");
        return a;
    }

    public static class CloudflareAccount {
        public int id;
        public String label;
        public String email;
        public String apiToken;
        public Timestamp verifiedAt;
        public Timestamp createdAt;
    }

    // ========== COMPONENT MANAGEMENT ==========

    public boolean isComponentInstalled(String componentName) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_IS_COMPONENT_INSTALLED)) {
            stmt.setString(1, componentName);
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    public void markComponentInstalled(String componentName, String version) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MARK_COMPONENT_INSTALLED)) {
            stmt.setString(1, componentName);
            stmt.setString(2, version);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to mark component installed: " + e.getMessage());
        }
    }

    public void markComponentUninstalled(String componentName) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MARK_COMPONENT_UNINSTALLED)) {
            stmt.setString(1, componentName);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to mark component uninstalled: " + e.getMessage());
        }
    }

    public String getInstalledComponentsJson() {
        StringBuilder json = new StringBuilder("[");
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_INSTALLED_COMPONENTS_JSON)) {
            boolean first = true;
            while (rs.next()) {
                if (!first) json.append(",");
                json.append("{")
                    .append("\"name\":\"").append(escapeJson(rs.getString("component_name"))).append("\",")
                    .append("\"version\":\"").append(escapeJson(rs.getString("version"))).append("\",")
                    .append("\"installed_at\":\"").append(rs.getString("installed_at")).append("\"")
                    .append("}");
                first = false;
            }
        } catch (SQLException e) {
            // ignore
        }
        json.append("]");
        return json.toString();
    }

    // ========== DOMAIN MANAGEMENT ==========

    public int addDomain(String domain, String description) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_ADD_DOMAIN, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, domain.toLowerCase());
            stmt.setString(2, description);
            stmt.executeUpdate();
            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                int newId = rs.getInt(1);
                // Postfix uses MySQL directly - no file sync needed
                return newId;
            }
        }
        return -1;
    }

    public boolean deleteDomain(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_DOMAIN)) {
            stmt.setInt(1, domainId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateDomainStatus(int domainId, boolean active) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_DOMAIN_STATUS)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, domainId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateDomainDescription(int domainId, String description) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_DOMAIN_DESCRIPTION)) {
            stmt.setString(1, description);
            stmt.setInt(2, domainId);
            return stmt.executeUpdate() > 0;
        }
    }

    public Domain getDomain(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_DOMAIN)) {
            stmt.setInt(1, domainId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapDomain(rs);
            }
        }
        return null;
    }

    public Domain getDomainByName(String domainName) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_DOMAIN_BY_NAME)) {
            stmt.setString(1, domainName.toLowerCase());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapDomain(rs);
            }
        }
        return null;
    }

    public List<Domain> getDomains() throws SQLException {
        List<Domain> domains = new ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_DOMAINS)) {
            while (rs.next()) {
                Domain d = mapDomain(rs);
                d.mailboxCount = rs.getInt("mailbox_count");
                d.aliasCount = rs.getInt("alias_count");
                domains.add(d);
            }
        }
        return domains;
    }

    private Domain mapDomain(ResultSet rs) throws SQLException {
        Domain d = new Domain();
        d.id = rs.getInt("id");
        d.domain = rs.getString("domain");
        d.description = rs.getString("description");
        d.active = rs.getBoolean("active");
        d.createdAt = rs.getTimestamp("created_at");
        d.dkimSelector = rs.getString("dkim_selector");
        d.dkimPrivateKey = rs.getString("dkim_private_key");
        d.dkimPublicKey = rs.getString("dkim_public_key");
        d.hasDkim = d.dkimPrivateKey != null && !d.dkimPrivateKey.isEmpty();
        // Pending rotation
        d.dkimPendingSelector = rs.getString("dkim_pending_selector");
        d.dkimPendingPrivateKey = rs.getString("dkim_pending_private_key");
        d.dkimPendingPublicKey = rs.getString("dkim_pending_public_key");
        d.dkimRotationState = rs.getString("dkim_rotation_state");
        d.dkimRotationStartedAt = rs.getTimestamp("dkim_rotation_started_at");
        d.dkimRotationActivatedAt = rs.getTimestamp("dkim_rotation_activated_at");
        // Previous key (grace period)
        d.dkimPreviousSelector = rs.getString("dkim_previous_selector");
        d.dkimPreviousPrivateKey = rs.getString("dkim_previous_private_key");
        d.dkimPreviousPublicKey = rs.getString("dkim_previous_public_key");
        // Cloudflare automation (può non esistere su DB legacy se ensureDkimRotationColumns non è ancora girato)
        try { d.dkimDnsZoneId            = rs.getString("dkim_dns_zone_id"); } catch (SQLException ignore) {}
        try { d.dkimPendingDnsRecordId   = rs.getString("dkim_pending_dns_record_id"); } catch (SQLException ignore) {}
        try { d.dkimPreviousDnsRecordId  = rs.getString("dkim_previous_dns_record_id"); } catch (SQLException ignore) {}
        try {
            int cfId = rs.getInt("cloudflare_account_id");
            d.cloudflareAccountId = rs.wasNull() ? 0 : cfId;
        } catch (SQLException ignore) {}
        try { d.dkimRotationIntervalDays = rs.getInt("dkim_rotation_interval_days"); } catch (SQLException ignore) {}
        try { d.dkimLastRotationAt       = rs.getTimestamp("dkim_last_rotation_at"); } catch (SQLException ignore) {}
        try { d.dkimRotationMode         = rs.getString("dkim_rotation_mode"); } catch (SQLException ignore) {}
        return d;
    }

    public void setDkim(int domainId, String selector, String privateKey, String publicKey) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_DKIM)) {
            stmt.setString(1, selector);
            stmt.setString(2, privateKey);
            stmt.setString(3, publicKey);
            stmt.setInt(4, domainId);
            stmt.executeUpdate();
        }
    }

    // ========== DKIM ROTATION ==========

    /**
     * Salva una chiave DKIM "pending" (nuovo selector + chiavi) e imposta lo stato di rotazione.
     * Lo stato iniziale è solitamente "pending_dns" (utente deve aggiungere il TXT in DNS).
     */
    public void setDkimPending(int domainId, String pendingSelector, String pendingPrivateKey,
                                String pendingPublicKey, String state) throws SQLException {
        setDkimPending(domainId, pendingSelector, pendingPrivateKey, pendingPublicKey, state, null);
    }

    public void setDkimPending(int domainId, String pendingSelector, String pendingPrivateKey,
                                String pendingPublicKey, String state, String rotationMode) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_DKIM_PENDING)) {
            stmt.setString(1, pendingSelector);
            stmt.setString(2, pendingPrivateKey);
            stmt.setString(3, pendingPublicKey);
            stmt.setString(4, state);
            if (rotationMode == null) stmt.setNull(5, Types.VARCHAR); else stmt.setString(5, rotationMode);
            stmt.setTimestamp(6, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(7, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Aggiorna solo lo stato della rotazione (es. da "pending_dns" a "propagated").
     */
    public void setDkimRotationState(int domainId, String state) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_DKIM_ROTATION_STATE)) {
            stmt.setString(1, state);
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Promuove la chiave "pending" a "attiva":
     *  - attuale (dkim_*) → previous (dkim_previous_*)
     *  - pending (dkim_pending_*) → attuale (dkim_*)
     *  - pending campi puliti
     *  - stato → "active_grace"
     *  - dkim_rotation_activated_at = NOW
     */
    public void promotePendingToActive(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_PROMOTE_PENDING_TO_ACTIVE)) {
            stmt.setTimestamp(1, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Salva i metadati Cloudflare del record TXT pending (zone + record id),
     * così possiamo cancellarlo via API se la rotazione viene annullata o completata.
     */
    public void setDkimPendingCloudflareIds(int domainId, String zoneId, String recordId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_DKIM_PENDING_CLOUDFLARE_IDS)) {
            stmt.setString(1, zoneId);
            stmt.setString(2, recordId);
            stmt.setInt(3, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Annulla una rotazione in corso (cancella la pending key senza promuoverla).
     */
    public void clearDkimPending(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CLEAR_DKIM_PENDING)) {
            stmt.setInt(1, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Completa la rotazione: rimuove la previous key e azzera lo stato di rotazione.
     * Dopo questa chiamata l'utente può rimuovere il vecchio record _domainkey TXT dal DNS.
     */
    public void clearDkimPrevious(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CLEAR_DKIM_PREVIOUS)) {
            stmt.setInt(1, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Imposta l'intervallo di rotazione programmata (in giorni). 0 = disattivato.
     */
    public void setDkimRotationInterval(int domainId, int days) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_DKIM_ROTATION_INTERVAL)) {
            stmt.setInt(1, Math.max(0, days));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Aggiorna il timestamp dell'ultima rotazione (chiamato all'attivazione della chiave).
     * Usa Java Instant.now() (UTC, JVM clock) anziché MySQL CURRENT_TIMESTAMP per evitare
     * ambiguità di timezone tra MySQL session, JDBC e JVM.
     */
    public void markDkimRotationActivated(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MARK_DKIM_ROTATION_ACTIVATED)) {
            stmt.setTimestamp(1, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Forza il timestamp dell'ultima rotazione a una data specifica (epoch ms).
     * Utile per correggere valori "fossili" memorizzati prima del fix timezone.
     */
    public void setDkimLastRotationAtMs(int domainId, long epochMs) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MARK_DKIM_ROTATION_ACTIVATED)) {
            stmt.setTimestamp(1, java.sql.Timestamp.from(java.time.Instant.ofEpochMilli(epochMs)));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Cancella il timestamp dell'ultima rotazione (NULL).
     * L'UI lo mostrerà come "Mai effettuata".
     */
    public void clearDkimLastRotation(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CLEAR_DKIM_LAST_ROTATION)) {
            stmt.setInt(1, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Domini con rotazione programmata attiva (intervallo > 0).
     */
    public List<Domain> getDomainsWithRotationSchedule() throws SQLException {
        List<Domain> result = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_DOMAINS_WITH_ROTATION_SCHEDULE);
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) result.add(mapDomain(rs));
        }
        return result;
    }

    /**
     * Ritorna tutti i domini con una rotazione DKIM in corso
     * (stato non null), per i task di background.
     */
    public List<Domain> getDomainsInRotation() throws SQLException {
        List<Domain> result = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_DOMAINS_IN_ROTATION);
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) {
                result.add(mapDomain(rs));
            }
        }
        return result;
    }

    // ========== MAILBOX MANAGEMENT ==========

    public int addMailbox(int domainId, String email, String password, String name, int quotaMb) throws SQLException {
        return addMailbox(domainId, email, password, name, quotaMb, true);
    }

    public int addMailbox(int domainId, String email, String password, String name, int quotaMb, boolean receiveEnabled) throws SQLException {
        return insertMailbox(getConnection(), domainId, email, password, name, quotaMb, receiveEnabled);
    }

    /** L'INSERT di una casella sulla connessione data: da sola, o dentro una transazione. */
    private int insertMailbox(Connection c, int domainId, String email, String password, String name, int quotaMb, boolean receiveEnabled) throws SQLException {
        // Hash password with bcrypt (compatible with Dovecot)
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));
        // La copia cifrata che il pannello mostra quando serve: senza, la casella non si crea
        String encryptedPassword = vaultCopy(password);

        try (PreparedStatement stmt = c.prepareStatement(SqlCatalog.MAIL_INSERT_MAILBOX, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setInt(1, domainId);
            stmt.setString(2, email.toLowerCase());
            stmt.setString(3, hashedPassword);
            stmt.setString(4, encryptedPassword);
            stmt.setTimestamp(5, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setString(6, name);
            stmt.setInt(7, quotaMb);
            stmt.setBoolean(8, receiveEnabled);
            stmt.executeUpdate();
            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                int newId = rs.getInt(1);
                return newId;
            }
        }
        return -1;
    }

    public boolean deleteMailbox(int mailboxId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_MAILBOX)) {
            stmt.setInt(1, mailboxId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateMailboxPassword(int mailboxId, String newPassword) throws SQLException {
        // Bcrypt hash (compatible with Dovecot)
        String hashedPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt(12));
        // Hash e copia cambiano insieme: una copia vecchia accanto a un hash nuovo mostrerebbe la password sbagliata
        String encryptedPassword = vaultCopy(newPassword);

        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_MAILBOX_PASSWORD)) {
            stmt.setString(1, hashedPassword);
            stmt.setString(2, encryptedPassword);
            stmt.setTimestamp(3, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(4, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * La copia cifrata (vault) di una password di casella. Le password delle caselle si devono
     * poter sempre rivedere dal pannello: se il vault non cifra, la password non si salva affatto,
     * invece di salvare l'hash da solo e scoprire dopo che la copia manca.
     */
    private static String vaultCopy(String password) throws SQLException {
        try {
            return org.mail_panel.security.PasswordVault.getInstance().encrypt(password);
        } catch (RuntimeException e) {
            throw new SQLException("Mailbox password not saved: the password vault could not encrypt it", e);
        }
    }

    /** Un hash bcrypt come lo scrivono il pannello ($2a$) e doveadm pw ($2y$, $2b$, anche con {BLF-CRYPT} davanti). */
    static String bcryptPart(String stored) {
        if (stored == null) return null;
        String s = stored;
        if (s.startsWith("{BLF-CRYPT}")) s = s.substring("{BLF-CRYPT}".length());
        else if (s.startsWith("{BLF}")) s = s.substring("{BLF}".length());
        if (s.length() == 60 && (s.startsWith("$2a$") || s.startsWith("$2b$") || s.startsWith("$2y$"))) {
            return "$2a$" + s.substring(4);     // jBCrypt 0.4 conosce solo $2a$: per password fino a 72 byte sono lo stesso algoritmo
        }
        return null;
    }

    /**
     * Il valore della colonna password e' testo in chiaro: niente hash bcrypt e niente schema
     * {NOME} di Dovecot davanti. Succedeva quando la webmail scriveva da se' nella tabella con
     * l'algoritmo predefinito del plugin password di Roundcube ('clear').
     */
    static boolean isPlaintextPassword(String stored) {
        return stored != null && !stored.isEmpty() && bcryptPart(stored) == null && !stored.startsWith("{");
    }

    /**
     * La password data e' quella della casella adesso? Confronta con l'hash bcrypt della colonna
     * password (o, per una riga rimasta in chiaro, confronta a tempo costante). Lo schema
     * sconosciuto risponde false: meglio dire "non so" che mostrare una password sbagliata.
     */
    public boolean mailboxPasswordMatches(int mailboxId, String plain) throws SQLException {
        if (plain == null) return false;
        String stored = null;
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MAILBOX_PASSWORD_MATCHES)) {
            stmt.setInt(1, mailboxId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) stored = rs.getString(1);
            }
        }
        return passwordMatchesStored(stored, plain);
    }

    static boolean passwordMatchesStored(String stored, String plain) {
        if (stored == null || plain == null) return false;
        String bcrypt = bcryptPart(stored);
        if (bcrypt != null) {
            try {
                return BCrypt.checkpw(plain, bcrypt);
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        if (isPlaintextPassword(stored)) {
            return java.security.MessageDigest.isEqual(stored.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    plain.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        return false;
    }

    /**
     * Il vault ha la copia di una password giusta ma la casella non l'ha (caselle di prima del
     * vault): la aggiunge, solo se la password corrisponde all'hash di adesso. Serve a chi entra
     * dalla webmail, che e' l'unico momento in cui la password vera passa dal server.
     * Ritorna true se ha scritto la copia.
     */
    public boolean fillMissingVaultCopy(int mailboxId, String plain) throws SQLException {
        if (!mailboxPasswordMatches(mailboxId, plain)) return false;
        String current = getMailboxPasswordEncrypted(mailboxId);
        if (current != null && !current.isEmpty()) {
            try {
                if (plain.equals(org.mail_panel.security.PasswordVault.getInstance().decrypt(current))) return false;
            } catch (RuntimeException e) {
                // copia illeggibile (chiave cambiata o blob rovinato): la si riscrive
            }
        }
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_FILL_MISSING_VAULT_COPY)) {
            stmt.setString(1, vaultCopy(plain));
            stmt.setTimestamp(2, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(3, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Le righe con la password in chiaro (vedi isPlaintextPassword): l'hash bcrypt al posto del
     * testo, e la copia nel vault. Dovecot legge BLF-CRYPT: con il testo in chiaro quelle caselle
     * non entravano piu'. Ritorna quante righe ha sistemato; mai le password nel log.
     */
    public int repairPlaintextMailboxPasswords() throws SQLException {
        java.util.List<Object[]> rows = new java.util.ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_REPAIR_PLAINTEXT_MAILBOX_PASSWORDS)) {
            while (rs.next()) {
                String stored = rs.getString(2);
                if (isPlaintextPassword(stored)) rows.add(new Object[]{rs.getInt(1), stored});
            }
        }
        int repaired = 0;
        for (Object[] row : rows) {
            String plain = (String) row[1];
            try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_REPAIR_PLAINTEXT_MAILBOX_PASSWORDS_2)) {
                stmt.setString(1, BCrypt.hashpw(plain, BCrypt.gensalt(12)));
                stmt.setString(2, vaultCopy(plain));
                stmt.setTimestamp(3, java.sql.Timestamp.from(java.time.Instant.now()));
                stmt.setInt(4, (Integer) row[0]);
                stmt.setString(5, plain);
                repaired += stmt.executeUpdate();
            }
        }
        return repaired;
    }

    /**
     * Recupera la password cifrata di una casella (per la feature "rivela password").
     * Ritorna null se non c'è una password cifrata (caselle vecchie pre-vault, o vault non
     * funzionante al momento del set).
     */
    public String getMailboxPasswordEncrypted(int mailboxId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_MAILBOX_PASSWORD_ENCRYPTED)) {
            stmt.setInt(1, mailboxId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return rs.getString("password_encrypted");
            }
        }
        return null;
    }

    /**
     * Ritorna true se la casella ha una password cifrata archiviata.
     * Usato dalla UI per decidere se mostrare l'icona "rivela".
     */
    public boolean mailboxHasEncryptedPassword(int mailboxId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MAILBOX_HAS_ENCRYPTED_PASSWORD)) {
            stmt.setInt(1, mailboxId);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Lista tutte le caselle che hanno una password cifrata archiviata, restituendo
     * solo id + blob cifrato. Usato per la rotazione della master key.
     */
    public java.util.List<int[]> listMailboxesWithEncryptedPassword() throws SQLException {
        // Wrapper semplice: ritorniamo coppie (id, ?) ma serviranno anche i blob.
        // Usa la variante più completa qui sotto.
        java.util.List<int[]> ids = new java.util.ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_LIST_MAILBOXES_WITH_ENCRYPTED_PASSWORD)) {
            while (rs.next()) ids.add(new int[]{rs.getInt(1)});
        }
        return ids;
    }

    /**
     * Variante con blob cifrato: ritorna (id, encrypted_blob) per ogni casella con vault.
     */
    public java.util.List<Object[]> listMailboxesWithEncryptedPasswordAndBlob() throws SQLException {
        java.util.List<Object[]> rows = new java.util.ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_LIST_MAILBOXES_WITH_ENCRYPTED_PASSWORD_AND_BLOB)) {
            while (rs.next()) {
                rows.add(new Object[]{rs.getInt(1), rs.getString(2)});
            }
        }
        return rows;
    }

    /**
     * Aggiorna SOLO il blob cifrato di una casella (usato durante la rotazione master key,
     * dove non rigeneriamo bcrypt — la password resta logicamente la stessa).
     */
    public void setMailboxEncryptedPasswordOnly(int mailboxId, String newEncryptedBlob) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_FILL_MISSING_VAULT_COPY)) {
            stmt.setString(1, newEncryptedBlob);
            stmt.setTimestamp(2, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(3, mailboxId);
            stmt.executeUpdate();
        }
    }

    public boolean updateMailboxStatus(int mailboxId, boolean active) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_MAILBOX_STATUS)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, mailboxId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateMailboxQuota(int mailboxId, int quotaMb) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_MAILBOX_QUOTA)) {
            stmt.setInt(1, quotaMb);
            stmt.setInt(2, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Update mailbox receive_enabled status (no-reply toggle)
     */
    public boolean updateMailboxReceiveEnabled(int mailboxId, boolean receiveEnabled) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_MAILBOX_RECEIVE_ENABLED)) {
            stmt.setBoolean(1, receiveEnabled);
            stmt.setInt(2, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Full mailbox update - updates all editable fields
     * @param mailboxId The mailbox ID
     * @param name Display name
     * @param quotaMb Quota in MB (0 = unlimited)
     * @param active Account active status
     * @param receiveEnabled Can receive emails (false = no-reply)
     */
    public boolean updateMailbox(int mailboxId, String name, int quotaMb, boolean active, boolean receiveEnabled) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_MAILBOX)) {
            stmt.setString(1, name);
            stmt.setInt(2, quotaMb);
            stmt.setBoolean(3, active);
            stmt.setBoolean(4, receiveEnabled);
            stmt.setInt(5, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Ensure mailbox password vault columns exist (idempotente).
     * Aggiunge password_encrypted (TEXT) + password_encrypted_at (TIMESTAMP).
     * Le nuove password create/aggiornate dalla UI verranno cifrate e archiviate qui.
     */
    public void ensureMailboxPasswordVaultColumns() {
        String[][] cols = {
            {"password_encrypted",     SqlCatalog.MAIL_ADD_MAILBOXES_PASSWORD_ENCRYPTED},
            {"password_encrypted_at",  SqlCatalog.MAIL_ADD_MAILBOXES_PASSWORD_ENCRYPTED_AT}
        };
        try (Statement stmt = getConnection().createStatement()) {
            for (String[] col : cols) {
                if (columnType(getConnection(), "mailboxes", col[0]) == null) {
                    stmt.executeUpdate(col[1]);
                    System.out.println("Added " + col[0] + " column to mailboxes table");
                }
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring mailbox password vault columns: " + e.getMessage());
        }
    }

    /**
     * Ensure receive_enabled column exists (for database migration)
     */
    public void ensureMailboxReceiveEnabledColumn() {
        try (Statement stmt = getConnection().createStatement()) {
            // Check if column exists
            ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_MAILBOX_RECEIVE_ENABLED_COLUMN);
            if (rs.next() && rs.getInt(1) == 0) {
                // Column doesn't exist, add it
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_MAILBOX_RECEIVE_ENABLED_COLUMN_2);
                System.out.println("Added receive_enabled column to mailboxes table");
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring receive_enabled column: " + e.getMessage());
        }
    }

    /**
     * Reload Postfix configuration
     * Postfix uses MySQL directly for virtual users, so no file sync is needed.
     * This just tells Postfix to reload if any configuration changes were made.
     *
     * Postfix queries MySQL directly via:
     * - mysql-virtual-domains.cf → SELECT domain FROM domains WHERE domain='%s' AND active=1
     * - mysql-virtual-mailboxes.cf → SELECT ... FROM mailboxes WHERE email='%s' AND active=1 AND receive_enabled=1
     * - mysql-virtual-aliases.cf → SELECT destination FROM aliases WHERE source='%s' AND active=1
     *
     * Note: receive_enabled=1 ensures no-reply accounts (receive_enabled=0) reject incoming mail
     */
    public boolean reloadPostfix() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", "service postfix reload 2>/dev/null || true");
            org.mail_panel.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor();
            System.out.println("Postfix configuration reloaded");
            return true;
        } catch (Exception e) {
            System.err.println("Failed to reload Postfix: " + e.getMessage());
            return false;
        }
    }

    /**
     * Sync mail server configuration after changes
     * With Postfix + MySQL, database changes are picked up automatically.
     * This method is kept for API compatibility.
     */
    public void syncAllSmtpFiles() {
        // Postfix uses MySQL directly - no file sync needed
        // Database changes are picked up automatically on next query
        System.out.println("Postfix uses MySQL directly - no sync needed");
    }

    public Mailbox getMailbox(int mailboxId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_MAILBOX)) {
            stmt.setInt(1, mailboxId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapMailbox(rs);
            }
        }
        return null;
    }

    public Mailbox getMailboxByEmail(String email) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_MAILBOX_BY_EMAIL)) {
            stmt.setString(1, email.toLowerCase());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapMailbox(rs);
            }
        }
        return null;
    }

    public Mailbox getMailboxById(int id) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_MAILBOX)) {
            stmt.setInt(1, id);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapMailbox(rs);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public List<Mailbox> getMailboxes(int domainId) throws SQLException {
        List<Mailbox> mailboxes = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_MAILBOXES)) {
            stmt.setInt(1, domainId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                mailboxes.add(mapMailbox(rs));
            }
        }
        return mailboxes;
    }

    public List<Mailbox> getAllMailboxes() throws SQLException {
        List<Mailbox> mailboxes = new ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_ALL_MAILBOXES)) {
            while (rs.next()) {
                mailboxes.add(mapMailbox(rs));
            }
        }
        return mailboxes;
    }

    private Mailbox mapMailbox(ResultSet rs) throws SQLException {
        Mailbox m = new Mailbox();
        m.id = rs.getInt("id");
        m.domainId = rs.getInt("domain_id");
        m.domainName = rs.getString("domain_name");
        m.email = rs.getString("email");
        m.name = rs.getString("name");
        m.quotaMb = rs.getInt("quota_mb");
        m.active = rs.getBoolean("active");
        m.createdAt = rs.getTimestamp("created_at");
        m.lastLogin = rs.getTimestamp("last_login");
        // receive_enabled field (default true if column doesn't exist yet)
        try {
            m.receiveEnabled = rs.getBoolean("receive_enabled");
        } catch (SQLException ignored) {
            m.receiveEnabled = true; // Default for old databases
        }
        // Additional UI counts (may not be present in all queries)
        try {
            m.forwardingCount = rs.getInt("forwarding_count");
            m.filtersCount = rs.getInt("filters_count");
            m.autoresponderEnabled = rs.getBoolean("autoresponder_enabled");
        } catch (SQLException ignored) {
            // Fields not present in simpler queries
        }
        return m;
    }

    // ========== ALIAS <-> CASELLA ==========

    /**
     * Un indirizzo che oggi e' solo alias diventa una casella, in una transazione: per Postfix,
     * che legge le tabelle a ogni messaggio, si passa da "alias" a "casella" senza un istante in
     * mezzo in cui l'indirizzo non esiste o vale in tutti e due i modi.
     *
     * @param keepForwards false: le righe con questa sorgente se ne vanno e la posta resta nella
     *                     casella; true: restano, e un alias "indirizzo -> se stesso" attivo fa
     *                     arrivare una copia anche nella casella
     * @return l'id della casella nuova
     */
    public int transformAliasToMailbox(int domainId, String email, String password, String name, int quotaMb,
                                       boolean keepForwards) throws SQLException {
        try (Connection c = ownConnection()) {
            c.setAutoCommit(false);
            try {
                int id = insertMailbox(c, domainId, email, password, name, quotaMb, true);
                if (id <= 0) throw new SQLException("the mailbox was not created");
                if (keepForwards) {
                    try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_ALIAS_TO_MAILBOX)) {
                        p.setInt(1, domainId);
                        p.setString(2, email.toLowerCase());
                        p.setString(3, email.toLowerCase());
                        p.executeUpdate();
                    }
                } else {
                    try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_ALIAS_TO_MAILBOX_2)) {
                        p.setString(1, email.toLowerCase());
                        p.executeUpdate();
                    }
                }
                c.commit();
                return id;
            } catch (SQLException e) {
                c.rollback();
                throw e;
            }
        }
    }

    /**
     * Una casella diventa un alias verso le destinazioni date, in una transazione. Se ne vanno la
     * casella (e con lei, per le chiavi esterne, risposta automatica, filtri, inoltri, token della
     * webmail), il suo limite di invio e l'alias "se stessa -> se stessa": senza casella porterebbe
     * a un indirizzo che non esiste. Gli altri alias con questa sorgente restano. La posta gia'
     * arrivata non e' nel database: resta sul disco.
     */
    public void transformMailboxToAlias(int mailboxId, int domainId, String email, List<String> destinations) throws SQLException {
        String address = email.toLowerCase();
        try (Connection c = ownConnection()) {
            c.setAutoCommit(false);
            try {
                try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_ALIAS_TO_MAILBOX)) {
                    for (String d : destinations) {
                        p.setInt(1, domainId);
                        p.setString(2, address);
                        p.setString(3, d.toLowerCase());
                        p.executeUpdate();
                    }
                }
                try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_MAILBOX_TO_ALIAS)) {
                    p.setString(1, address);
                    p.setString(2, address);
                    p.executeUpdate();
                }
                try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_MAILBOX_TO_ALIAS_2)) {
                    p.setInt(1, mailboxId);
                    p.executeUpdate();
                }
                try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_MAILBOX_TO_ALIAS_3)) {
                    p.setInt(1, mailboxId);
                    p.setString(2, address);
                    if (p.executeUpdate() != 1) throw new SQLException("the mailbox no longer exists");
                }
                c.commit();
            } catch (SQLException e) {
                c.rollback();
                throw e;
            }
        }
    }

    /** Gli alias con questa sorgente, attivi o no. */
    public List<Alias> getAliasesBySource(String source) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ALIASES_BY_SOURCE)) {
            stmt.setString(1, source.toLowerCase());
            return aliasWithDomain(stmt);
        }
    }

    /** Gli alias che portano a questo indirizzo, da qualunque dominio. */
    public List<Alias> getAliasesByDestination(String destination) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ALIASES_BY_DESTINATION)) {
            stmt.setString(1, destination.toLowerCase());
            return aliasWithDomain(stmt);
        }
    }

    private List<Alias> aliasWithDomain(PreparedStatement stmt) throws SQLException {
        List<Alias> aliases = new ArrayList<>();
        try (ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) {
                Alias a = mapAlias(rs);
                a.domainName = rs.getString("domain_name");
                aliases.add(a);
            }
        }
        return aliases;
    }

    // ========== ALIAS MANAGEMENT ==========

    public int addAlias(int domainId, String source, String destination) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_ADD_ALIAS, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setInt(1, domainId);
            stmt.setString(2, source.toLowerCase());
            stmt.setString(3, destination.toLowerCase());
            stmt.executeUpdate();
            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                int newId = rs.getInt(1);
                // Postfix uses MySQL directly - no file sync needed
                return newId;
            }
        }
        return -1;
    }

    public boolean deleteAlias(int aliasId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_ALIAS)) {
            stmt.setInt(1, aliasId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    /**
     * Cambia la destinazione di un alias con un solo UPDATE: nessun momento in cui la sorgente
     * resta senza alias, come succederebbe eliminando e ricreando. Una coppia sorgente ->
     * destinazione gia' esistente fa scattare il vincolo UNIQUE (SQLIntegrityConstraintViolationException).
     */
    public boolean updateAliasDestination(int aliasId, String destination) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_ALIAS_DESTINATION)) {
            stmt.setString(1, destination.toLowerCase());
            stmt.setInt(2, aliasId);
            return stmt.executeUpdate() > 0;
        }
    }

    /** Un alias per id, o null se non c'e'. */
    public Alias getAliasById(int aliasId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ALIAS_BY_ID)) {
            stmt.setInt(1, aliasId);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next() ? mapAlias(rs) : null;
            }
        }
    }

    public boolean updateAliasStatus(int aliasId, boolean active) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_ALIAS_STATUS)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, aliasId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public List<Alias> getAliases(int domainId) throws SQLException {
        List<Alias> aliases = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ALIASES)) {
            stmt.setInt(1, domainId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                aliases.add(mapAlias(rs));
            }
        }
        return aliases;
    }

    public List<Alias> getAllAliases() throws SQLException {
        List<Alias> aliases = new ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_ALL_ALIASES)) {
            while (rs.next()) {
                Alias a = mapAlias(rs);
                a.domainName = rs.getString("domain_name");
                aliases.add(a);
            }
        }
        return aliases;
    }

    private Alias mapAlias(ResultSet rs) throws SQLException {
        Alias a = new Alias();
        a.id = rs.getInt("id");
        a.domainId = rs.getInt("domain_id");
        a.source = rs.getString("source");
        a.destination = rs.getString("destination");
        a.active = rs.getBoolean("active");
        a.createdAt = rs.getTimestamp("created_at");
        return a;
    }

    // ========== ROUNDCUBE AUTO-LOGIN ==========

    public String createAutoLoginToken(int mailboxId) throws SQLException {
        String token = UUID.randomUUID().toString().replace("-", "");
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CREATE_AUTO_LOGIN_TOKEN)) {
            stmt.setString(1, token);
            stmt.setInt(2, mailboxId);
            stmt.executeUpdate();
            return token;
        }
    }

    public Mailbox validateAutoLoginToken(String token) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_VALIDATE_AUTO_LOGIN_TOKEN)) {
            stmt.setString(1, token);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                // Mark token as used
                try (PreparedStatement update = getConnection().prepareStatement(SqlCatalog.MAIL_VALIDATE_AUTO_LOGIN_TOKEN_2)) {
                    update.setString(1, token);
                    update.executeUpdate();
                }
                return mapMailbox(rs);
            }
        }
        return null;
    }

    public void cleanupExpiredTokens() throws SQLException {
        try (Statement stmt = getConnection().createStatement()) {
            stmt.executeUpdate(SqlCatalog.MAIL_CLEANUP_EXPIRED_TOKENS);
        }
    }

    // ========== STATISTICS ==========

    public int getDomainCount() {
        return getCount(SqlCatalog.MAIL_COUNT_ACTIVE_DOMAINS);
    }

    public int getMailboxCount() {
        return getCount(SqlCatalog.MAIL_COUNT_ACTIVE_MAILBOXES);
    }

    public int getAliasCount() {
        return getCount(SqlCatalog.MAIL_COUNT_ACTIVE_ALIASES);
    }

    private int getCount(String sql) {
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            // ignore
        }
        return 0;
    }

    /** La versione del server MySQL a cui il pannello e' collegato adesso (SELECT VERSION()), o null. */
    public String serverVersion() {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SERVER_VERSION);
             ResultSet rs = stmt.executeQuery()) {
            return rs.next() ? rs.getString(1) : null;
        } catch (Exception e) {
            return null;
        }
    }

    // ========== UTILITY ==========

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            // ignore
        }
        connected = false;
    }

    public Connection getConnection() {
        // Check if connection is still valid, reconnect if needed
        try {
            if (connection == null || connection.isClosed() || !connection.isValid(5)) {
                System.out.println("Connection lost, attempting to reconnect...");
                connect();
            }
        } catch (SQLException e) {
            System.err.println("Error checking connection validity: " + e.getMessage());
            connect();
        }
        return connection;
    }

    /**
     * Ensure connection is valid before use
     */
    public void ensureConnection() {
        try {
            if (connection == null || connection.isClosed() || !connection.isValid(5)) {
                System.out.println("Reconnecting to MySQL...");
                connect();
            }
        } catch (SQLException e) {
            System.err.println("Error checking connection: " + e.getMessage());
            connect();
        }
    }

    // ========== MODEL CLASSES ==========

    public static class Domain {
        public int id;
        public String domain;
        public String description;
        public boolean active;
        public Timestamp createdAt;
        public int mailboxCount;
        public int aliasCount;
        public String dkimSelector;
        public String dkimPrivateKey;
        public String dkimPublicKey;
        public boolean hasDkim;
        // DKIM rotation - pending key (in attesa di propagazione DNS)
        public String dkimPendingSelector;
        public String dkimPendingPrivateKey;
        public String dkimPendingPublicKey;
        // Stato rotazione: null (nessuna), "pending_dns", "propagated", "active_grace"
        public String dkimRotationState;
        public Timestamp dkimRotationStartedAt;
        public Timestamp dkimRotationActivatedAt;
        // Vecchia chiave conservata durante il grace period
        public String dkimPreviousSelector;
        public String dkimPreviousPrivateKey;
        public String dkimPreviousPublicKey;
        // Cloudflare automation
        public String dkimDnsZoneId;
        public String dkimPendingDnsRecordId;
        public String dkimPreviousDnsRecordId;
        // Account Cloudflare assegnato (0 = nessuno / manuale)
        public int cloudflareAccountId;
        // Rotazione programmata (0 = disattivata)
        public int dkimRotationIntervalDays;
        public Timestamp dkimLastRotationAt;
        // Modalità rotazione corrente (ereditata da eventi della catena)
        public String dkimRotationMode;
    }

    public static class Mailbox {
        public int id;
        public int domainId;
        public String domainName;
        public String email;
        public String name;
        public int quotaMb;  // 0 = unlimited
        public boolean active;
        public boolean receiveEnabled;  // false = no-reply (send only)
        public Timestamp createdAt;
        public Timestamp lastLogin;
        // Additional counts for UI display
        public boolean autoresponderEnabled;
        public int forwardingCount;
        public int filtersCount;
    }

    public static class Alias {
        public int id;
        public int domainId;
        public String domainName;
        public String source;
        public String destination;
        public boolean active;
        public Timestamp createdAt;
    }

    // ========== AUTO-RESPONDER ==========

    public static class AutoResponder {
        public int id;
        public int mailboxId;
        public String email;
        public boolean enabled;
        public String subject;
        public String body;
        public java.sql.Date startDate;
        public java.sql.Date endDate;
        public int intervalHours;
    }

    public AutoResponder getAutoResponder(int mailboxId) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_AUTO_RESPONDER)) {
            stmt.setInt(1, mailboxId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                AutoResponder ar = new AutoResponder();
                ar.id = rs.getInt("id");
                ar.mailboxId = rs.getInt("mailbox_id");
                ar.email = rs.getString("email");
                ar.enabled = rs.getBoolean("enabled");
                ar.subject = rs.getString("subject");
                ar.body = rs.getString("body");
                ar.startDate = rs.getDate("start_date");
                ar.endDate = rs.getDate("end_date");
                ar.intervalHours = rs.getInt("interval_hours");
                return ar;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean saveAutoResponder(int mailboxId, boolean enabled, String subject, String body,
                                     java.sql.Date startDate, java.sql.Date endDate, int intervalHours) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SAVE_AUTO_RESPONDER)) {
            stmt.setInt(1, mailboxId);
            stmt.setBoolean(2, enabled);
            stmt.setString(3, subject);
            stmt.setString(4, body);
            stmt.setDate(5, startDate);
            stmt.setDate(6, endDate);
            stmt.setInt(7, intervalHours);
            // For UPDATE
            stmt.setBoolean(8, enabled);
            stmt.setString(9, subject);
            stmt.setString(10, body);
            stmt.setDate(11, startDate);
            stmt.setDate(12, endDate);
            stmt.setInt(13, intervalHours);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public List<AutoResponder> getActiveAutoResponders() {
        List<AutoResponder> list = new ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_ACTIVE_AUTO_RESPONDERS)) {
            while (rs.next()) {
                AutoResponder ar = new AutoResponder();
                ar.id = rs.getInt("id");
                ar.mailboxId = rs.getInt("mailbox_id");
                ar.email = rs.getString("email");
                ar.enabled = rs.getBoolean("enabled");
                ar.subject = rs.getString("subject");
                ar.body = rs.getString("body");
                ar.startDate = rs.getDate("start_date");
                ar.endDate = rs.getDate("end_date");
                ar.intervalHours = rs.getInt("interval_hours");
                list.add(ar);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    // ========== SIEVE FILTERS ==========

    public static class SieveFilter {
        public int id;
        public int mailboxId;
        public String email;
        public String name;
        public int priority;
        public boolean enabled;
        public String conditions; // JSON
        public String actions; // JSON
    }

    public List<SieveFilter> getSieveFilters(int mailboxId) {
        List<SieveFilter> filters = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_SIEVE_FILTERS)) {
            stmt.setInt(1, mailboxId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                SieveFilter f = new SieveFilter();
                f.id = rs.getInt("id");
                f.mailboxId = rs.getInt("mailbox_id");
                f.email = rs.getString("email");
                f.name = rs.getString("name");
                f.priority = rs.getInt("priority");
                f.enabled = rs.getBoolean("enabled");
                f.conditions = rs.getString("conditions");
                f.actions = rs.getString("actions");
                filters.add(f);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return filters;
    }

    public boolean createSieveFilter(int mailboxId, String name, int priority, String conditions, String actions) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CREATE_SIEVE_FILTER)) {
            stmt.setInt(1, mailboxId);
            stmt.setString(2, name);
            stmt.setInt(3, priority);
            stmt.setString(4, conditions);
            stmt.setString(5, actions);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean updateSieveFilter(int filterId, String name, int priority, boolean enabled, String conditions, String actions) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_SIEVE_FILTER)) {
            stmt.setString(1, name);
            stmt.setInt(2, priority);
            stmt.setBoolean(3, enabled);
            stmt.setString(4, conditions);
            stmt.setString(5, actions);
            stmt.setInt(6, filterId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean deleteSieveFilter(int filterId) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_SIEVE_FILTER)) {
            stmt.setInt(1, filterId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // ========== FORWARDING RULES ==========

    public static class ForwardingRule {
        public int id;
        public int mailboxId;
        public String email;
        public String destination;
        public boolean keepCopy;
        public boolean enabled;
    }

    public List<ForwardingRule> getForwardingRules(int mailboxId) {
        List<ForwardingRule> rules = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_FORWARDING_RULES)) {
            stmt.setInt(1, mailboxId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                ForwardingRule r = new ForwardingRule();
                r.id = rs.getInt("id");
                r.mailboxId = rs.getInt("mailbox_id");
                r.email = rs.getString("email");
                r.destination = rs.getString("destination");
                r.keepCopy = rs.getBoolean("keep_copy");
                r.enabled = rs.getBoolean("enabled");
                rules.add(r);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return rules;
    }

    public boolean createForwardingRule(int mailboxId, String destination, boolean keepCopy) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CREATE_FORWARDING_RULE)) {
            stmt.setInt(1, mailboxId);
            stmt.setString(2, destination);
            stmt.setBoolean(3, keepCopy);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean updateForwardingRule(int ruleId, String destination, boolean keepCopy, boolean enabled) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_FORWARDING_RULE)) {
            stmt.setString(1, destination);
            stmt.setBoolean(2, keepCopy);
            stmt.setBoolean(3, enabled);
            stmt.setInt(4, ruleId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean deleteForwardingRule(int ruleId) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_FORWARDING_RULE)) {
            stmt.setInt(1, ruleId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // ========== RATE LIMITS ==========

    public static class RateLimit {
        public int id;
        public String targetType;
        public Integer targetId;
        public String targetName;
        public int maxPerHour;
        public int maxPerDay;
        public int maxRecipients;
        public boolean enabled;
    }

    public List<RateLimit> getRateLimits() {
        List<RateLimit> limits = new ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_RATE_LIMITS)) {
            while (rs.next()) {
                RateLimit rl = new RateLimit();
                rl.id = rs.getInt("id");
                rl.targetType = rs.getString("target_type");
                rl.targetId = rs.getObject("target_id") != null ? rs.getInt("target_id") : null;
                rl.targetName = rs.getString("target_name");
                rl.maxPerHour = rs.getInt("max_per_hour");
                rl.maxPerDay = rs.getInt("max_per_day");
                rl.maxRecipients = rs.getInt("max_recipients");
                rl.enabled = rs.getBoolean("enabled");
                limits.add(rl);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return limits;
    }

    /**
     * Salva un limite di invio, aggiornando la riga che c'e' gia' per lo stesso obiettivo.
     *
     * Il limite globale ha target_id 0 e non NULL: nell'indice UNIQUE (target_type, target_id) di
     * MySQL due NULL non sono uguali, e ogni salvataggio dei limiti globali aggiungeva una riga
     * invece di aggiornare quella che c'era. Le righe globali con NULL rimaste da prima si tolgono
     * nella stessa transazione.
     */
    public boolean saveRateLimit(String targetType, Integer targetId, int maxPerHour, int maxPerDay, int maxRecipients, boolean enabled) {
        boolean global = "global".equals(targetType);
        if (!global && targetId == null) return false;
        try (Connection c = ownConnection()) {
            c.setAutoCommit(false);
            try {
                try (PreparedStatement stmt = c.prepareStatement(SqlCatalog.MAIL_SAVE_RATE_LIMIT)) {
                    stmt.setString(1, targetType);
                    stmt.setInt(2, global ? 0 : targetId);
                    stmt.setInt(3, maxPerHour);
                    stmt.setInt(4, maxPerDay);
                    stmt.setInt(5, maxRecipients);
                    stmt.setBoolean(6, enabled);
                    stmt.executeUpdate();
                }
                if (global) {
                    try (PreparedStatement stmt = c.prepareStatement(SqlCatalog.MAIL_SAVE_RATE_LIMIT_2)) {
                        stmt.executeUpdate();
                    }
                }
                c.commit();
                return true;
            } catch (SQLException e) {
                c.rollback();
                throw e;
            }
        } catch (SQLException e) {
            LOGGER.log(java.util.logging.Level.WARNING, "Saving a rate limit failed", e);
            return false;
        }
    }

    public boolean deleteRateLimit(int limitId) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_RATE_LIMIT)) {
            stmt.setInt(1, limitId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // ========== EMAIL STATISTICS ==========

    public static class EmailStat {
        public java.sql.Date statDate;
        public Integer mailboxId;
        public Integer domainId;
        public String name;
        public int sentCount;
        public int receivedCount;
        public int spamCount;
        public int virusCount;
        public int bouncedCount;
        public long bytesSent;
        public long bytesReceived;
    }

    public List<EmailStat> getEmailStatistics(int days) {
        List<EmailStat> stats = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_EMAIL_STATISTICS)) {
            stmt.setInt(1, days);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                EmailStat stat = new EmailStat();
                stat.statDate = rs.getDate("stat_date");
                stat.mailboxId = rs.getObject("mailbox_id") != null ? rs.getInt("mailbox_id") : null;
                stat.domainId = rs.getObject("domain_id") != null ? rs.getInt("domain_id") : null;
                stat.name = rs.getString("name");
                stat.sentCount = rs.getInt("sent_count");
                stat.receivedCount = rs.getInt("received_count");
                stat.spamCount = rs.getInt("spam_count");
                stat.virusCount = rs.getInt("virus_count");
                stat.bouncedCount = rs.getInt("bounced_count");
                stat.bytesSent = rs.getLong("bytes_sent");
                stat.bytesReceived = rs.getLong("bytes_received");
                stats.add(stat);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return stats;
    }

    public EmailStat getTodayStats() {
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_TODAY_STATS)) {
            if (rs.next()) {
                EmailStat stat = new EmailStat();
                stat.statDate = rs.getDate("stat_date");
                stat.name = "Today";
                stat.sentCount = rs.getInt("sent_count");
                stat.receivedCount = rs.getInt("received_count");
                stat.spamCount = rs.getInt("spam_count");
                stat.virusCount = rs.getInt("virus_count");
                stat.bouncedCount = rs.getInt("bounced_count");
                stat.bytesSent = rs.getLong("bytes_sent");
                stat.bytesReceived = rs.getLong("bytes_received");
                return stat;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void incrementEmailStat(Integer mailboxId, Integer domainId, String statType, int count, long bytes) {
        // Un'istruzione fissa per tipo: le colonne non sono parametri.
        String sql = switch (statType) {
            case "sent" -> SqlCatalog.MAIL_ADD_STAT_SENT;
            case "received" -> SqlCatalog.MAIL_ADD_STAT_RECEIVED;
            case "spam" -> SqlCatalog.MAIL_ADD_STAT_SPAM;
            case "virus" -> SqlCatalog.MAIL_ADD_STAT_VIRUS;
            case "bounced" -> SqlCatalog.MAIL_ADD_STAT_BOUNCED;
            default -> null;
        };
        if (sql == null) return;

        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            if (mailboxId != null) {
                stmt.setInt(1, mailboxId);
            } else {
                stmt.setNull(1, java.sql.Types.INTEGER);
            }
            if (domainId != null) {
                stmt.setInt(2, domainId);
            } else {
                stmt.setNull(2, java.sql.Types.INTEGER);
            }
            stmt.setInt(3, count);
            stmt.setLong(4, bytes);
            stmt.setInt(5, count);
            stmt.setLong(6, bytes);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ========== RSPAMD TRAINING ==========

    public boolean logRspamdTraining(String messageId, String trainedAs, int trainedBy) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_LOG_RSPAMD_TRAINING)) {
            stmt.setString(1, messageId);
            stmt.setString(2, trainedAs);
            stmt.setInt(3, trainedBy);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public int getTrainingCount(String trainedAs, int days) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_TRAINING_COUNT)) {
            stmt.setString(1, trainedAs);
            stmt.setInt(2, days);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
    }

    // ========== AUDIT LOGGING ==========

    /**
     * Log an audit event for security tracking
     * @param action The action type (LOGIN_SUCCESS, LOGIN_FAILURE, DOMAIN_CREATED, etc.)
     * @param ipAddress Client IP address
     * @param details Additional details about the action
     * @param username The username performing the action (null for anonymous)
     */
    public void logAuditEvent(String action, String ipAddress, String details, String username) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_LOG_AUDIT_EVENT)) {
            stmt.setString(1, action);
            stmt.setString(2, username);
            stmt.setString(3, ipAddress);
            stmt.setString(4, details);
            stmt.executeUpdate();
        } catch (SQLException e) {
            // Don't propagate - audit logging should not break the application
            System.err.println("Failed to log audit event: " + e.getMessage());
        }
    }

    /**
     * Log an audit event with user agent
     */
    public void logAuditEventFull(String action, String ipAddress, String details, String username, String userAgent) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_LOG_AUDIT_EVENT_FULL)) {
            stmt.setString(1, action);
            stmt.setString(2, username);
            stmt.setString(3, ipAddress);
            stmt.setString(4, details);
            stmt.setString(5, userAgent);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to log audit event: " + e.getMessage());
        }
    }

    /**
     * Data class for audit log entries
     */
    public static class AuditLogEntry {
        public int id;
        public String action;
        public String username;
        public String ipAddress;
        public String details;
        public String userAgent;
        public java.sql.Timestamp createdAt;
    }

    /**
     * Get audit log entries with optional filters
     * @param action Filter by action type (null for all)
     * @param username Filter by username (null for all)
     * @param ipAddress Filter by IP address (null for all)
     * @param limit Maximum number of entries to return
     * @return List of audit log entries
     */
    public java.util.List<AuditLogEntry> getAuditLog(String action, String username, String ipAddress, int limit) {
        // Un filtro vuoto e' NULL, e (? IS NULL OR colonna = ?) lo lascia passare: un'istruzione sola,
        // invece di comporre il WHERE con i filtri presenti.
        String[] filters = {
            action == null || action.isEmpty() ? null : action,
            username == null || username.isEmpty() ? null : username,
            ipAddress == null || ipAddress.isEmpty() ? null : ipAddress};

        java.util.List<AuditLogEntry> entries = new java.util.ArrayList<>();

        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_AUDIT_LOG)) {
            for (int f = 0; f < filters.length; f++) {
                stmt.setString(2 * f + 1, filters[f]);
                stmt.setString(2 * f + 2, filters[f]);
            }
            stmt.setInt(7, limit);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                AuditLogEntry entry = new AuditLogEntry();
                entry.id = rs.getInt("id");
                entry.action = rs.getString("action");
                entry.username = rs.getString("username");
                entry.ipAddress = rs.getString("ip_address");
                entry.details = rs.getString("details");
                entry.userAgent = rs.getString("user_agent");
                entry.createdAt = rs.getTimestamp("created_at");
                entries.add(entry);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return entries;
    }

    /**
     * Get count of audit events by action type in the last N days
     */
    public java.util.Map<String, Integer> getAuditStats(int days) {
        java.util.Map<String, Integer> stats = new java.util.LinkedHashMap<>();

        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_AUDIT_STATS)) {
            stmt.setInt(1, days);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                stats.put(rs.getString("action"), rs.getInt("count"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return stats;
    }

    /**
     * Clean up old audit log entries (older than N days)
     * @param days Number of days to keep
     * @return Number of deleted entries
     */
    public int cleanupAuditLog(int days) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CLEANUP_AUDIT_LOG)) {
            stmt.setInt(1, days);
            return stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
            return 0;
        }
    }

    /**
     * Get recent login attempts for an IP address
     * @param ipAddress The IP address to check
     * @param minutes Time window in minutes
     * @return Number of failed login attempts
     */
    public int getRecentLoginFailures(String ipAddress, int minutes) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_RECENT_LOGIN_FAILURES)) {
            stmt.setString(1, ipAddress);
            stmt.setInt(2, minutes);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
    }
}
