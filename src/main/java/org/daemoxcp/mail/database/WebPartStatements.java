package org.daemoxcp.mail.database;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The catalog statements that the web part of the separated panel may run:
 * in the web part CatalogGuard accepts only these. They are those of the routes the web part serves by itself and
 * of its filters, measured on the bytecode (the call graph) and tested on the VM. The login writes are not here:
 * administrators, passkeys, codes and sessions are written only by the root part (A), and it runs the migrations.
 * Nor the webmail routes (password change, copy in the vault): the root part serves them.
 *
 * <p>The MySQL statements each have their own procedure ({@link #ROUTINES}): when the web part logs into MySQL
 * with its own user, which can only call them, the connection sends the procedure instead of the statement. The
 * SQLite ones (CONFIG_) stay statements.
 */
public final class WebPartStatements {

    private WebPartStatements() {}

    /** The names of the SqlCatalog constants: SqlCatalogTest checks that they are all there. */
    public static final Set<String> NAMES = Set.of(
            // The request's session: who it is, when it last did something.
            "SESSION_CHECK", "SESSION_TOUCH", "AUTH_ADMIN_BY_ID",
            // The preferences of the logged-in administrator, and whether there is already an administrator.
            "MAIL_GET_ADMIN_LANGUAGE", "MAIL_SET_ADMIN_LANGUAGE", "MAIL_GET_ADMIN_THEME", "MAIL_SET_ADMIN_THEME",
            "MAIL_HAS_ADMIN_USER",
            // Settings and audit log.
            "MAIL_GET_SETTING", "MAIL_LOG_AUDIT_EVENT",
            // Domains: the names for autoconfig and MTA-STS, the list, one, add, describe, remove.
            "MAIL_GET_DOMAIN_NAMES", "MAIL_GET_DOMAINS", "MAIL_GET_DOMAIN_BY_NAME", "MAIL_ADD_DOMAIN",
            "MAIL_UPDATE_DOMAIN_DESCRIPTION", "MAIL_DELETE_DOMAIN",
            // Mailboxes and their linked data. The copies of the passwords ("Show password") are read only by the root
            // part.
            "MAIL_GET_MAILBOXES", "MAIL_GET_ALL_MAILBOXES", "MAIL_GET_MAILBOX", "MAIL_GET_MAILBOX_BY_EMAIL",
            "MAIL_INSERT_MAILBOX", "MAIL_UPDATE_MAILBOX", "MAIL_UPDATE_MAILBOX_PASSWORD", "MAIL_DELETE_MAILBOX",
            "MAIL_MAILBOX_HAS_ENCRYPTED_PASSWORD",
            "MAIL_GET_ALIASES_BY_SOURCE", "MAIL_GET_ALIASES_BY_DESTINATION", "MAIL_GET_AUTO_RESPONDER",
            "MAIL_GET_FORWARDING_RULES", "MAIL_GET_SIEVE_FILTERS",
            "MAIL_TRANSFORM_MAILBOX_TO_ALIAS", "MAIL_TRANSFORM_MAILBOX_TO_ALIAS_2", "MAIL_TRANSFORM_MAILBOX_TO_ALIAS_3",
            "MAIL_TRANSFORM_ALIAS_TO_MAILBOX",
            // Webmail and statistics.
            "MAIL_CREATE_AUTO_LOGIN_TOKEN", "MAIL_GET_EMAIL_STATISTICS", "MAIL_GET_TRAINING_COUNT",
            // Read-only SQLite: the configuration and the previous secrets left in the columns.
            "CONFIG_DB_BUSY_TIMEOUT", "CONFIG_GET_DATA_CONFIG", "CONFIG_GET_PANEL_TLS_KEY", "CONFIG_GET_MYSQL_PASSWORD",
            "CONFIG_GET_MAIL_HOSTNAME", "CONFIG_GET_ROUNDCUBE_DOMAIN");

    /**
     * The procedure of a MySQL statement of the web part: the statement, its call (the session's fingerprint and then
     * the same parameters, in the same order), and the texts with which the root part creates it, drops it and
     * grants it to the web part.
     */
    public record Routine(String statement, String call, String create, String drop, String grant) {

        /** A read (SELECT) returns the rows; a write returns one row with affected, and id if it is an insert. */
        public boolean read() {
            return statement.stripLeading().startsWith("SELECT");
        }
    }

    /** The procedures, one for each MySQL statement in the list: SqlCatalogTest checks that they are all there. */
    public static final List<Routine> ROUTINES = List.of(
            new Routine(SqlCatalog.SESSION_CHECK, SqlCatalog.WEB_CALL_CHECK_SESSION, SqlCatalog.WEB_CREATE_CHECK_SESSION,
                    SqlCatalog.WEB_DROP_CHECK_SESSION, SqlCatalog.WEB_GRANT_CHECK_SESSION),
            new Routine(SqlCatalog.SESSION_TOUCH, SqlCatalog.WEB_CALL_TOUCH_SESSION, SqlCatalog.WEB_CREATE_TOUCH_SESSION,
                    SqlCatalog.WEB_DROP_TOUCH_SESSION, SqlCatalog.WEB_GRANT_TOUCH_SESSION),
            new Routine(SqlCatalog.AUTH_ADMIN_BY_ID, SqlCatalog.WEB_CALL_GET_SESSION_ADMIN, SqlCatalog.WEB_CREATE_GET_SESSION_ADMIN,
                    SqlCatalog.WEB_DROP_GET_SESSION_ADMIN, SqlCatalog.WEB_GRANT_GET_SESSION_ADMIN),
            new Routine(SqlCatalog.MAIL_GET_ADMIN_LANGUAGE, SqlCatalog.WEB_CALL_GET_ADMIN_LANGUAGE, SqlCatalog.WEB_CREATE_GET_ADMIN_LANGUAGE,
                    SqlCatalog.WEB_DROP_GET_ADMIN_LANGUAGE, SqlCatalog.WEB_GRANT_GET_ADMIN_LANGUAGE),
            new Routine(SqlCatalog.MAIL_SET_ADMIN_LANGUAGE, SqlCatalog.WEB_CALL_SET_ADMIN_LANGUAGE, SqlCatalog.WEB_CREATE_SET_ADMIN_LANGUAGE,
                    SqlCatalog.WEB_DROP_SET_ADMIN_LANGUAGE, SqlCatalog.WEB_GRANT_SET_ADMIN_LANGUAGE),
            new Routine(SqlCatalog.MAIL_GET_ADMIN_THEME, SqlCatalog.WEB_CALL_GET_ADMIN_THEME, SqlCatalog.WEB_CREATE_GET_ADMIN_THEME,
                    SqlCatalog.WEB_DROP_GET_ADMIN_THEME, SqlCatalog.WEB_GRANT_GET_ADMIN_THEME),
            new Routine(SqlCatalog.MAIL_SET_ADMIN_THEME, SqlCatalog.WEB_CALL_SET_ADMIN_THEME, SqlCatalog.WEB_CREATE_SET_ADMIN_THEME,
                    SqlCatalog.WEB_DROP_SET_ADMIN_THEME, SqlCatalog.WEB_GRANT_SET_ADMIN_THEME),
            new Routine(SqlCatalog.MAIL_HAS_ADMIN_USER, SqlCatalog.WEB_CALL_HAS_ADMIN, SqlCatalog.WEB_CREATE_HAS_ADMIN,
                    SqlCatalog.WEB_DROP_HAS_ADMIN, SqlCatalog.WEB_GRANT_HAS_ADMIN),
            new Routine(SqlCatalog.MAIL_GET_SETTING, SqlCatalog.WEB_CALL_GET_SETTING, SqlCatalog.WEB_CREATE_GET_SETTING,
                    SqlCatalog.WEB_DROP_GET_SETTING, SqlCatalog.WEB_GRANT_GET_SETTING),
            new Routine(SqlCatalog.MAIL_LOG_AUDIT_EVENT, SqlCatalog.WEB_CALL_LOG_AUDIT_EVENT, SqlCatalog.WEB_CREATE_LOG_AUDIT_EVENT,
                    SqlCatalog.WEB_DROP_LOG_AUDIT_EVENT, SqlCatalog.WEB_GRANT_LOG_AUDIT_EVENT),
            new Routine(SqlCatalog.MAIL_GET_DOMAIN_NAMES, SqlCatalog.WEB_CALL_LIST_DOMAIN_NAMES, SqlCatalog.WEB_CREATE_LIST_DOMAIN_NAMES,
                    SqlCatalog.WEB_DROP_LIST_DOMAIN_NAMES, SqlCatalog.WEB_GRANT_LIST_DOMAIN_NAMES),
            new Routine(SqlCatalog.MAIL_GET_DOMAINS, SqlCatalog.WEB_CALL_LIST_DOMAINS, SqlCatalog.WEB_CREATE_LIST_DOMAINS,
                    SqlCatalog.WEB_DROP_LIST_DOMAINS, SqlCatalog.WEB_GRANT_LIST_DOMAINS),
            new Routine(SqlCatalog.MAIL_GET_DOMAIN_BY_NAME, SqlCatalog.WEB_CALL_GET_DOMAIN_BY_NAME, SqlCatalog.WEB_CREATE_GET_DOMAIN_BY_NAME,
                    SqlCatalog.WEB_DROP_GET_DOMAIN_BY_NAME, SqlCatalog.WEB_GRANT_GET_DOMAIN_BY_NAME),
            new Routine(SqlCatalog.MAIL_ADD_DOMAIN, SqlCatalog.WEB_CALL_ADD_DOMAIN, SqlCatalog.WEB_CREATE_ADD_DOMAIN,
                    SqlCatalog.WEB_DROP_ADD_DOMAIN, SqlCatalog.WEB_GRANT_ADD_DOMAIN),
            new Routine(SqlCatalog.MAIL_UPDATE_DOMAIN_DESCRIPTION, SqlCatalog.WEB_CALL_SET_DOMAIN_DESCRIPTION, SqlCatalog.WEB_CREATE_SET_DOMAIN_DESCRIPTION,
                    SqlCatalog.WEB_DROP_SET_DOMAIN_DESCRIPTION, SqlCatalog.WEB_GRANT_SET_DOMAIN_DESCRIPTION),
            new Routine(SqlCatalog.MAIL_DELETE_DOMAIN, SqlCatalog.WEB_CALL_DELETE_DOMAIN, SqlCatalog.WEB_CREATE_DELETE_DOMAIN,
                    SqlCatalog.WEB_DROP_DELETE_DOMAIN, SqlCatalog.WEB_GRANT_DELETE_DOMAIN),
            new Routine(SqlCatalog.MAIL_GET_MAILBOXES, SqlCatalog.WEB_CALL_LIST_DOMAIN_MAILBOXES, SqlCatalog.WEB_CREATE_LIST_DOMAIN_MAILBOXES,
                    SqlCatalog.WEB_DROP_LIST_DOMAIN_MAILBOXES, SqlCatalog.WEB_GRANT_LIST_DOMAIN_MAILBOXES),
            new Routine(SqlCatalog.MAIL_GET_ALL_MAILBOXES, SqlCatalog.WEB_CALL_LIST_MAILBOXES, SqlCatalog.WEB_CREATE_LIST_MAILBOXES,
                    SqlCatalog.WEB_DROP_LIST_MAILBOXES, SqlCatalog.WEB_GRANT_LIST_MAILBOXES),
            new Routine(SqlCatalog.MAIL_GET_MAILBOX, SqlCatalog.WEB_CALL_GET_MAILBOX, SqlCatalog.WEB_CREATE_GET_MAILBOX,
                    SqlCatalog.WEB_DROP_GET_MAILBOX, SqlCatalog.WEB_GRANT_GET_MAILBOX),
            new Routine(SqlCatalog.MAIL_GET_MAILBOX_BY_EMAIL, SqlCatalog.WEB_CALL_GET_MAILBOX_BY_EMAIL, SqlCatalog.WEB_CREATE_GET_MAILBOX_BY_EMAIL,
                    SqlCatalog.WEB_DROP_GET_MAILBOX_BY_EMAIL, SqlCatalog.WEB_GRANT_GET_MAILBOX_BY_EMAIL),
            new Routine(SqlCatalog.MAIL_INSERT_MAILBOX, SqlCatalog.WEB_CALL_ADD_MAILBOX, SqlCatalog.WEB_CREATE_ADD_MAILBOX,
                    SqlCatalog.WEB_DROP_ADD_MAILBOX, SqlCatalog.WEB_GRANT_ADD_MAILBOX),
            new Routine(SqlCatalog.MAIL_UPDATE_MAILBOX, SqlCatalog.WEB_CALL_UPDATE_MAILBOX, SqlCatalog.WEB_CREATE_UPDATE_MAILBOX,
                    SqlCatalog.WEB_DROP_UPDATE_MAILBOX, SqlCatalog.WEB_GRANT_UPDATE_MAILBOX),
            new Routine(SqlCatalog.MAIL_UPDATE_MAILBOX_PASSWORD, SqlCatalog.WEB_CALL_SET_MAILBOX_PASSWORD, SqlCatalog.WEB_CREATE_SET_MAILBOX_PASSWORD,
                    SqlCatalog.WEB_DROP_SET_MAILBOX_PASSWORD, SqlCatalog.WEB_GRANT_SET_MAILBOX_PASSWORD),
            new Routine(SqlCatalog.MAIL_DELETE_MAILBOX, SqlCatalog.WEB_CALL_DELETE_MAILBOX, SqlCatalog.WEB_CREATE_DELETE_MAILBOX,
                    SqlCatalog.WEB_DROP_DELETE_MAILBOX, SqlCatalog.WEB_GRANT_DELETE_MAILBOX),
            new Routine(SqlCatalog.MAIL_MAILBOX_HAS_ENCRYPTED_PASSWORD, SqlCatalog.WEB_CALL_MAILBOX_HAS_VAULT_COPY, SqlCatalog.WEB_CREATE_MAILBOX_HAS_VAULT_COPY,
                    SqlCatalog.WEB_DROP_MAILBOX_HAS_VAULT_COPY, SqlCatalog.WEB_GRANT_MAILBOX_HAS_VAULT_COPY),
            new Routine(SqlCatalog.MAIL_GET_ALIASES_BY_SOURCE, SqlCatalog.WEB_CALL_LIST_ALIASES_BY_SOURCE, SqlCatalog.WEB_CREATE_LIST_ALIASES_BY_SOURCE,
                    SqlCatalog.WEB_DROP_LIST_ALIASES_BY_SOURCE, SqlCatalog.WEB_GRANT_LIST_ALIASES_BY_SOURCE),
            new Routine(SqlCatalog.MAIL_GET_ALIASES_BY_DESTINATION, SqlCatalog.WEB_CALL_LIST_ALIASES_BY_DESTINATION, SqlCatalog.WEB_CREATE_LIST_ALIASES_BY_DESTINATION,
                    SqlCatalog.WEB_DROP_LIST_ALIASES_BY_DESTINATION, SqlCatalog.WEB_GRANT_LIST_ALIASES_BY_DESTINATION),
            new Routine(SqlCatalog.MAIL_GET_AUTO_RESPONDER, SqlCatalog.WEB_CALL_GET_AUTO_RESPONDER, SqlCatalog.WEB_CREATE_GET_AUTO_RESPONDER,
                    SqlCatalog.WEB_DROP_GET_AUTO_RESPONDER, SqlCatalog.WEB_GRANT_GET_AUTO_RESPONDER),
            new Routine(SqlCatalog.MAIL_GET_FORWARDING_RULES, SqlCatalog.WEB_CALL_LIST_FORWARDING_RULES, SqlCatalog.WEB_CREATE_LIST_FORWARDING_RULES,
                    SqlCatalog.WEB_DROP_LIST_FORWARDING_RULES, SqlCatalog.WEB_GRANT_LIST_FORWARDING_RULES),
            new Routine(SqlCatalog.MAIL_GET_SIEVE_FILTERS, SqlCatalog.WEB_CALL_LIST_SIEVE_FILTERS, SqlCatalog.WEB_CREATE_LIST_SIEVE_FILTERS,
                    SqlCatalog.WEB_DROP_LIST_SIEVE_FILTERS, SqlCatalog.WEB_GRANT_LIST_SIEVE_FILTERS),
            new Routine(SqlCatalog.MAIL_TRANSFORM_MAILBOX_TO_ALIAS, SqlCatalog.WEB_CALL_DELETE_ALIAS, SqlCatalog.WEB_CREATE_DELETE_ALIAS,
                    SqlCatalog.WEB_DROP_DELETE_ALIAS, SqlCatalog.WEB_GRANT_DELETE_ALIAS),
            new Routine(SqlCatalog.MAIL_TRANSFORM_MAILBOX_TO_ALIAS_2, SqlCatalog.WEB_CALL_DELETE_MAILBOX_RATE_LIMIT, SqlCatalog.WEB_CREATE_DELETE_MAILBOX_RATE_LIMIT,
                    SqlCatalog.WEB_DROP_DELETE_MAILBOX_RATE_LIMIT, SqlCatalog.WEB_GRANT_DELETE_MAILBOX_RATE_LIMIT),
            new Routine(SqlCatalog.MAIL_TRANSFORM_MAILBOX_TO_ALIAS_3, SqlCatalog.WEB_CALL_DELETE_MAILBOX_BY_ADDRESS, SqlCatalog.WEB_CREATE_DELETE_MAILBOX_BY_ADDRESS,
                    SqlCatalog.WEB_DROP_DELETE_MAILBOX_BY_ADDRESS, SqlCatalog.WEB_GRANT_DELETE_MAILBOX_BY_ADDRESS),
            new Routine(SqlCatalog.MAIL_TRANSFORM_ALIAS_TO_MAILBOX, SqlCatalog.WEB_CALL_ADD_ALIAS, SqlCatalog.WEB_CREATE_ADD_ALIAS,
                    SqlCatalog.WEB_DROP_ADD_ALIAS, SqlCatalog.WEB_GRANT_ADD_ALIAS),
            new Routine(SqlCatalog.MAIL_CREATE_AUTO_LOGIN_TOKEN, SqlCatalog.WEB_CALL_CREATE_WEBMAIL_TOKEN, SqlCatalog.WEB_CREATE_CREATE_WEBMAIL_TOKEN,
                    SqlCatalog.WEB_DROP_CREATE_WEBMAIL_TOKEN, SqlCatalog.WEB_GRANT_CREATE_WEBMAIL_TOKEN),
            new Routine(SqlCatalog.MAIL_GET_EMAIL_STATISTICS, SqlCatalog.WEB_CALL_LIST_EMAIL_STATISTICS, SqlCatalog.WEB_CREATE_LIST_EMAIL_STATISTICS,
                    SqlCatalog.WEB_DROP_LIST_EMAIL_STATISTICS, SqlCatalog.WEB_GRANT_LIST_EMAIL_STATISTICS),
            new Routine(SqlCatalog.MAIL_GET_TRAINING_COUNT, SqlCatalog.WEB_CALL_COUNT_TRAINING, SqlCatalog.WEB_CREATE_COUNT_TRAINING,
                    SqlCatalog.WEB_DROP_COUNT_TRAINING, SqlCatalog.WEB_GRANT_COUNT_TRAINING));

    private static final Map<String, Routine> BY_STATEMENT = byStatement();

    private static Map<String, Routine> byStatement() {
        Map<String, Routine> m = new HashMap<>();
        for (Routine r : ROUTINES) {
            if (m.put(r.statement(), r) != null) throw new IllegalStateException("Two routines for one statement: " + r.call());
        }
        return Map.copyOf(m);
    }

    /** The procedure of a statement, or null if it has none (SQLite, or a statement the web part does not run). */
    public static Routine routineOf(String statement) {
        return statement == null ? null : BY_STATEMENT.get(statement);
    }
}
