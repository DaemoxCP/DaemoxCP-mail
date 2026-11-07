package org.mail_panel.sqli;

import org.mail_panel.database.CatalogGuard;
import org.mail_panel.database.SqlCatalog;

import java.sql.*;

public class database {
    Connection connection;

    /**
     * Quanto aspetta una scrittura se il database e' occupato da un altro processo, prima di
     * arrendersi con SQLITE_BUSY. Il database lo usano insieme il servizio --web e il menu (o un
     * comando da console) avviati dalla stessa cartella. sqlite-jdbc aspetta gia' 3 secondi di suo:
     * misurato sulla VM il 06/11/2026 (reperto 160), il jar di prima falliva dopo 3 secondi a
     * scrittura. Il difetto del reperto 156 non era l'attesa ma il lock tenuto per sempre dalle
     * letture lasciate aperte (sotto). Quindici secondi sono il margine per una scrittura lunga
     * dell'altro processo: una tenuta di 6 secondi passa con 15, con 3 no (misurato).
     * L'istruzione e' SqlCatalog.CONFIG_DB_BUSY_TIMEOUT, con lo stesso numero (lo controlla SqlCatalogTest).
     */
    static final int BUSY_TIMEOUT_MS = 15_000;

    public database() {
        this(false);
    }

    /**
     * @param readOnly la parte web del pannello separato (utente mailpanel): legge la configurazione e non
     *                 la scrive mai. La cartella e il file sono di root (0750/0640 root:mailpanel): con
     *                 SQLITE_OPEN_READONLY SQLite non prova nemmeno a creare un journal.
     */
    public database(boolean readOnly) {
        Connection conn = null;
        try {
            String url = "jdbc:sqlite:database/mail_panel.db";
            if (readOnly) {
                org.sqlite.SQLiteConfig config = new org.sqlite.SQLiteConfig();
                config.setReadOnly(true);
                conn = CatalogGuard.open(url, config.toProperties());
            } else {
                conn = CatalogGuard.open(url);
            }
            if (conn != null) {
                try (Statement s = conn.createStatement()) {
                    s.execute(SqlCatalog.CONFIG_DB_BUSY_TIMEOUT);
                }
            }
            this.connection = conn;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public Integer check_tables() {
        Integer count = 0;
        try (ResultSet resultSet = this.connection.getMetaData().getTables(null, null, "config", new String[]{"TABLE"})) {
            if (resultSet.next()) {
                count++;
            }
            return count;
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return count;
    }

    /*
     * Ogni statement si chiude, sempre, anche quelli di sola lettura. In SQLite uno statement
     * lasciato a meta' (un executeQuery senza chiusura, un ResultSet letto fino alla prima riga e
     * abbandonato) tiene aperta la lettura, e con lei il lock SHARED sul file: nessun altro
     * processo puo' piu' scrivere finche' la JVM non lo raccoglie. Il servizio --web chiama questi
     * metodi a ogni avvio e a ogni richiesta, e il menu avviato dalla stessa cartella finiva in
     * SQLITE_BUSY su nome del server, flag dei servizi e configurazione MySQL (reperto 156).
     */

    /**
     * Vero se la colonna esiste: dall'elenco delle colonne di config (un'istruzione fissa, invece di
     * leggere la colonna per nome), e lo statement si chiude prima di tornare.
     */
    boolean columnExists(String column) {
        try (PreparedStatement check = connection.prepareStatement(SqlCatalog.CONFIG_DB_COLUMNS);
             ResultSet rs = check.executeQuery()) {
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) return true;
            }
            return false;
        } catch (SQLException e) {
            return false;
        }
    }

    /** Un comando del catalogo che non legge niente, chiuso subito. */
    void execute(String sql) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.executeUpdate();
        }
    }

    public boolean create_tables() {
        try {
            execute(SqlCatalog.CONFIG_DB_CREATE_TABLE);
            return true;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    public void ensureMailHostnameColumn() {
        if (columnExists("mail_hostname")) return;
        try {
            execute(SqlCatalog.CONFIG_DB_ADD_MAIL_HOSTNAME);
        } catch (SQLException e2) {
            // Silent fail
        }
    }

    public void ensureSslChainColumn() {
        if (columnExists("mail_panel_ssl_chain")) return;
        try {
            execute(SqlCatalog.CONFIG_DB_ADD_MAIL_PANEL_SSL_CHAIN);
        } catch (SQLException e2) {
            // Silent fail
        }
    }

    public void ensureRoundcubeColumns() {
        // Nome della colonna e la sua istruzione fissa: un ALTER non prende parametri.
        String[][] columns = {
            {"roundcube_domain", SqlCatalog.CONFIG_DB_ADD_ROUNDCUBE_DOMAIN},
            {"roundcube_port", SqlCatalog.CONFIG_DB_ADD_ROUNDCUBE_PORT},
            {"roundcube_ssl_cert", SqlCatalog.CONFIG_DB_ADD_ROUNDCUBE_SSL_CERT},
            {"roundcube_ssl_key", SqlCatalog.CONFIG_DB_ADD_ROUNDCUBE_SSL_KEY},
            {"roundcube_ssl_chain", SqlCatalog.CONFIG_DB_ADD_ROUNDCUBE_SSL_CHAIN}
        };

        for (String[] col : columns) {
            if (columnExists(col[0])) continue;
            try {
                execute(col[1]);
            } catch (SQLException e2) {
                // Silent fail
            }
        }
    }

    public void ensurePostfixColumn() {
        // Ensure postfix_installed column exists
        // Migrate from old opensmtpd_installed if it exists
        if (columnExists("postfix_installed")) return;     // Column exists, nothing to do
        try {
            if (columnExists("opensmtpd_installed")) {
                // Old column exists - add new column and copy data
                execute(SqlCatalog.CONFIG_DB_ADD_POSTFIX_INSTALLED);
                execute(SqlCatalog.CONFIG_DB_COPY_OPENSMTPD_INSTALLED);
            } else {
                // Neither column exists, add postfix_installed
                execute(SqlCatalog.CONFIG_DB_ADD_POSTFIX_INSTALLED);
            }
        } catch (SQLException e3) {
            // Silent fail
        }
    }

    public void closeConnections() {
        try {
            if (this.connection != null) {
                this.connection.close();
            }
        } catch (SQLException e) {
            // Silent fail
        }
    }
}
