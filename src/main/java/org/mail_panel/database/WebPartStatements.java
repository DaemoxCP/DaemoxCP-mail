package org.mail_panel.database;

import java.util.Set;

/**
 * Le istruzioni del catalogo che la parte web del pannello separato puo' fare:
 * nella web CatalogGuard accetta solo queste. Sono quelle delle rotte che la web serve da se' e dei suoi
 * filtri, misurate sul bytecode (il grafo delle chiamate) e provate sulla VM. Non ci sono le scritture
 * dell'accesso: amministratori, passkey, codici e sessioni li scrive solo la root (A), e le migrazioni le fa
 * lei. Sara' anche l'elenco delle procedure della seconda parte.
 */
public final class WebPartStatements {

    private WebPartStatements() {}

    /** I nomi delle costanti di SqlCatalog: SqlCatalogTest controlla che ci siano tutte. */
    public static final Set<String> NAMES = Set.of(
            // La sessione della richiesta: chi e', quando ha fatto l'ultima cosa.
            "SESSION_CHECK", "SESSION_TOUCH", "AUTH_ADMIN_BY_ID",
            // Le preferenze dell'amministratore collegato, e se c'e' gia' un amministratore.
            "MAIL_GET_ADMIN_LANGUAGE", "MAIL_SET_ADMIN_LANGUAGE", "MAIL_GET_ADMIN_THEME", "MAIL_SET_ADMIN_THEME",
            "MAIL_HAS_ADMIN_USER",
            // Impostazioni e registro di controllo.
            "MAIL_GET_SETTING", "MAIL_LOG_AUDIT_EVENT",
            // Domini.
            "MAIL_GET_DOMAINS", "MAIL_GET_DOMAIN_BY_NAME", "MAIL_ADD_DOMAIN", "MAIL_UPDATE_DOMAIN_DESCRIPTION",
            "MAIL_DELETE_DOMAIN",
            // Caselle, la loro copia nel vault, i loro dati collegati.
            "MAIL_GET_MAILBOXES", "MAIL_GET_ALL_MAILBOXES", "MAIL_GET_MAILBOX", "MAIL_GET_MAILBOX_BY_EMAIL",
            "MAIL_INSERT_MAILBOX", "MAIL_UPDATE_MAILBOX", "MAIL_UPDATE_MAILBOX_PASSWORD", "MAIL_DELETE_MAILBOX",
            "MAIL_GET_MAILBOX_PASSWORD_ENCRYPTED", "MAIL_MAILBOX_HAS_ENCRYPTED_PASSWORD", "MAIL_MAILBOX_PASSWORD_MATCHES",
            "MAIL_FILL_MISSING_VAULT_COPY",
            "MAIL_GET_ALIASES_BY_SOURCE", "MAIL_GET_ALIASES_BY_DESTINATION", "MAIL_GET_AUTO_RESPONDER",
            "MAIL_GET_FORWARDING_RULES", "MAIL_GET_SIEVE_FILTERS",
            "MAIL_TRANSFORM_MAILBOX_TO_ALIAS", "MAIL_TRANSFORM_MAILBOX_TO_ALIAS_2", "MAIL_TRANSFORM_MAILBOX_TO_ALIAS_3",
            "MAIL_TRANSFORM_ALIAS_TO_MAILBOX",
            // Webmail e statistiche.
            "MAIL_CREATE_AUTO_LOGIN_TOKEN", "MAIL_GET_EMAIL_STATISTICS", "MAIL_GET_TRAINING_COUNT",
            // SQLite in sola lettura: la configurazione e i segreti di prima rimasti nelle colonne.
            "CONFIG_DB_BUSY_TIMEOUT", "CONFIG_GET_DATA_CONFIG", "CONFIG_GET_PANEL_TLS_KEY", "CONFIG_GET_MYSQL_PASSWORD",
            "CONFIG_GET_MAIL_HOSTNAME", "CONFIG_GET_ROUNDCUBE_DOMAIN");
}
