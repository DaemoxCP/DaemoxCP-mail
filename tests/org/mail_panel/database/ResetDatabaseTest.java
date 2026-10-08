package org.mail_panel.database;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * Il reset del database del pannello (MailDatabase.dropAllTables, che Main usa nel reset).
 *
 * Il vecchio reset cancellava le tabelle una alla volta e di un errore scriveva solo un avviso:
 * MySQL non cancella una tabella a cui un'altra punta con una chiave esterna, e cosi' restavano
 * mailboxes, domains e panel_admin con i loro dati (piu' le tabelle che l'elenco non aveva),
 * mentre Main scriveva "Database reset completed!". Qui, su un MySQL vero: il vecchio reset
 * rifatto, per vedere che cosa lasciava; il nuovo, con una riga in ogni tabella del pannello, che
 * non lascia niente e non tocca le tabelle d'altri; ogni tabella che lo schema crea e' nel suo
 * elenco; un reset sul database gia' vuoto; uno che MySQL deve rifiutare (una tabella d'altri
 * punta a domains), che non cancella niente e lo dice. Senza MySQL si prova solo che senza
 * collegamento il reset non parte. Il MySQL si indica cosi':
 *   -Dmysql.porta=33062 -Dmysql.utente=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova
 */
public class ResetDatabaseTest {

    static int falliti = 0;

    static void vero(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("\n== Senza collegamento a MySQL il reset non parte ==");
        try {
            new MailDatabase().dropAllTables();
            vero("un'eccezione", false);
        } catch (SQLException e) {
            vero("un'eccezione: " + e.getMessage(), e.getMessage().contains("Non collegato"));
        }

        String porta = System.getProperty("mysql.porta");
        if (porta == null) {
            System.out.println("\n== MySQL non indicato (-Dmysql.porta=...): salto la parte sul database ==");
        } else {
            database(porta);
        }
        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }

    static void database(String porta) throws Exception {
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.utente", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(porta), System.getProperty("mysql.database", "mailpanel_prova"));
        if (!db.connect()) { vero("connessione a MySQL", false); return; }
        Connection c = db.getConnection();
        try (Statement st = c.createStatement(); ResultSet r = st.executeQuery("SELECT VERSION()")) {
            r.next();
            System.out.println("\n  MySQL " + r.getString(1));
        }

        System.out.println("\n== Ogni tabella che il pannello crea e' nell'elenco del reset ==");
        svuota(c);
        schema(db);
        List<String> create = tabelle(c);
        int n = create.size();
        List<String> fuori = create.stream().filter(t -> !MailDatabase.TABELLE_DEL_PANNELLO.contains(t)).toList();
        vero("createSchema e le migrazioni creano " + n + " tabelle, tutte nell'elenco"
                + (fuori.isEmpty() ? "" : " (mancano: " + fuori + ")"), fuori.isEmpty() && n >= 17);

        System.out.println("\n== Il vecchio reset, rifatto: che cosa lasciava ==");
        popola(c);
        List<String> avvisi = vecchioReset(c);
        vero("MySQL rifiutava tre DROP, e restavano solo avvisi: " + avvisi,
                avvisi.equals(List.of("mailboxes", "domains", "panel_admin")));
        List<String> rimaste = tabelle(c);
        vero("restavano " + rimaste, new HashSet<>(rimaste).equals(new HashSet<>(List.of("admin_passkeys",
                "cloudflare_accounts", "dkim_rotation_history", "domains", "mailboxes", "panel_admin"))));
        db.createSchema();
        vero("e dopo \"Database reset completed!\" c'erano ancora il dominio, la casella e l'amministratore di prima",
                righe(c, "domains") == 1 && righe(c, "mailboxes") == 1 && righe(c, "panel_admin") == 1
                        && righe(c, "admin_passkeys") == 1);
        List<String> via = db.dropAllTables();
        vero("il reset nuovo, sui resti del vecchio: non resta niente (" + via.size() + " tabelle cancellate)",
                tabelle(c).isEmpty() && via.size() == n);

        System.out.println("\n== Il reset nuovo: una riga in ogni tabella, una tabella d'altri accanto ==");
        schema(db);
        popola(c);
        try (Statement st = c.createStatement()) {
            // Le tabelle di versioni vecchie del pannello, legate fra loro come allora.
            st.execute("CREATE TABLE virtual_domains (id INT PRIMARY KEY) ENGINE=InnoDB");
            st.execute("CREATE TABLE virtual_users (id INT PRIMARY KEY, domain_id INT NOT NULL, "
                    + "FOREIGN KEY (domain_id) REFERENCES virtual_domains(id)) ENGINE=InnoDB");
            st.execute("CREATE TABLE virtual_aliases (id INT PRIMARY KEY, domain_id INT NOT NULL, "
                    + "FOREIGN KEY (domain_id) REFERENCES virtual_domains(id)) ENGINE=InnoDB");
            st.execute("INSERT INTO virtual_domains VALUES (1)");
            st.execute("INSERT INTO virtual_users VALUES (1, 1)");
            st.execute("INSERT INTO virtual_aliases VALUES (1, 1)");
            // Una tabella che non e' del pannello: il reset non la deve toccare.
            st.execute("CREATE TABLE estranea_prova (id INT PRIMARY KEY, nota VARCHAR(40) NOT NULL) ENGINE=InnoDB");
        }
        inserisci(c, "INSERT INTO estranea_prova (id, nota) VALUES (?, ?)", 1, "non e' del pannello");
        List<String> prima = tabelle(c);
        prima.remove("estranea_prova");
        List<String> vuote = prima.stream().filter(t -> righe(c, t) == 0).toList();
        vero("una riga in ognuna delle " + prima.size() + " tabelle del pannello" + (vuote.isEmpty() ? "" : " (vuote: " + vuote + ")"),
                vuote.isEmpty() && prima.size() == n + 3);
        List<String> cancellate = db.dropAllTables();
        vero("restituisce le tabelle che ha cancellato: " + cancellate.size(), new HashSet<>(cancellate).equals(new HashSet<>(prima)));
        vero("non resta nessuna tabella del pannello, nemmeno le virtual_*: " + tabelle(c), tabelle(c).equals(List.of("estranea_prova")));
        vero("la tabella d'altri resta, con la sua riga", righe(c, "estranea_prova") == 1);
        db.createSchema();
        List<String> piene = tabelle(c).stream().filter(t -> !t.equals("estranea_prova") && righe(c, t) > 0).toList();
        vero("ricreate da createSchema, le tabelle sono vuote: nessun dato di prima" + (piene.isEmpty() ? "" : " (piene: " + piene + ")"),
                piene.isEmpty() && tabelle(c).size() == n + 1);

        System.out.println("\n== Il reset sul database gia' vuoto ==");
        vero("con le tabelle vuote: le cancella tutte", db.dropAllTables().size() == n && tabelle(c).equals(List.of("estranea_prova")));
        List<String> niente = db.dropAllTables();
        vero("senza tabelle: nessun errore, nessuna tabella cancellata", niente.isEmpty() && tabelle(c).equals(List.of("estranea_prova")));

        System.out.println("\n== Una tabella d'altri punta a domains: MySQL rifiuta, e non si cancella niente ==");
        schema(db);
        int dominio = popola(c);
        try (Statement st = c.createStatement()) {
            st.execute("CREATE TABLE estranea_figlia (id INT PRIMARY KEY, dominio INT NOT NULL, "
                    + "FOREIGN KEY (dominio) REFERENCES domains(id)) ENGINE=InnoDB");
        }
        inserisci(c, "INSERT INTO estranea_figlia (id, dominio) VALUES (?, ?)", 1, dominio);
        try {
            db.dropAllTables();
            vero("un'eccezione", false);
        } catch (SQLException e) {
            String m = e.getMessage();
            System.out.println("  " + m);
            vero("un'eccezione che dice perche' e che cosa resta", m.startsWith("Reset non riuscito")
                    && m.contains("estranea_figlia") && m.contains("ancora presenti: admin_passkeys, aliases"));
        }
        vero("tutto com'era: le " + n + " tabelle, con i loro dati", tabelle(c).size() == n + 2
                && righe(c, "domains") == 1 && righe(c, "mailboxes") == 1 && righe(c, "admin_passkeys") == 1);
        try (Statement st = c.createStatement()) {
            st.execute("DROP TABLE estranea_figlia");
        }
        db.dropAllTables();
        vero("tolta la tabella che puntava a domains, il reset passa", tabelle(c).equals(List.of("estranea_prova")));

        try (Statement st = c.createStatement()) {
            st.execute("DROP TABLE estranea_prova");
        }
        db.close();
    }

    /** Lo schema come lo prepara il pannello: createSchema e le migrazioni che SSLMailServer fa all'avvio. */
    static void schema(MailDatabase db) throws SQLException {
        db.createSchema();
        db.ensurePasskeysTable();
        db.ensureMailboxReceiveEnabledColumn();
        db.ensureMailboxPasswordVaultColumns();
        db.ensureThemeColumn();
        db.ensureDkimRotationColumns();
        db.ensureCloudflareAccountsSchema();
        db.ensureDkimRotationHistoryTable();
    }

    /** Una riga in ogni tabella del pannello, legate come nell'uso vero. Restituisce l'id del dominio. */
    static int popola(Connection c) throws SQLException {
        int dominio = inserisci(c, "INSERT INTO domains (domain) VALUES (?)", "esempio.test");
        int casella = inserisci(c, "INSERT INTO mailboxes (domain_id, email, password) VALUES (?, ?, ?)",
                dominio, "posta@esempio.test", "x");
        int admin = inserisci(c, "INSERT INTO panel_admin (username, password_hash) VALUES (?, ?)", "amministratore", "x");
        inserisci(c, "INSERT INTO admin_passkeys (admin_id, credential_id, public_key_cose) VALUES (?, ?, ?)",
                admin, new byte[] {1, 2, 3}, new byte[] {4, 5, 6});
        inserisci(c, "INSERT INTO rspamd_training (message_id, trained_as, trained_by) VALUES (?, ?, ?)",
                "<1@esempio.test>", "spam", admin);
        inserisci(c, "INSERT INTO roundcube_tokens (token, mailbox_id, expires_at) VALUES (?, ?, ?)",
                "t".repeat(64), casella, "2030-01-01 00:00:00");
        inserisci(c, "INSERT INTO auto_responders (mailbox_id, body) VALUES (?, ?)", casella, "Sono in ferie.");
        inserisci(c, "INSERT INTO sieve_filters (mailbox_id, name, conditions, actions) VALUES (?, ?, ?, ?)",
                casella, "filtro", "[]", "[]");
        inserisci(c, "INSERT INTO forwarding_rules (mailbox_id, destination) VALUES (?, ?)", casella, "altro@esempio.test");
        inserisci(c, "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id) VALUES (?, ?, ?)",
                "2026-10-03", casella, dominio);
        inserisci(c, "INSERT INTO aliases (domain_id, source, destination) VALUES (?, ?, ?)",
                dominio, "info@esempio.test", "posta@esempio.test");
        inserisci(c, "INSERT INTO dkim_rotation_history (domain_id, domain, event_type) VALUES (?, ?, ?)",
                dominio, "esempio.test", "key_generated");
        inserisci(c, "INSERT INTO cloudflare_accounts (label, api_token) VALUES (?, ?)", "prova", "x");
        inserisci(c, "INSERT INTO audit_log (action, ip_address) VALUES (?, ?)", "PROVA", "192.0.2.1");
        inserisci(c, "INSERT INTO rate_limits (target_type, target_id) VALUES (?, ?)", "domain", dominio);
        inserisci(c, "INSERT INTO panel_settings (setting_key, setting_value) VALUES (?, ?)", "prova", "1");
        inserisci(c, "INSERT INTO installed_components (component_name) VALUES (?)", "postfix");
        return dominio;
    }

    /** Il reset di prima, com'era: una tabella alla volta, e di un errore solo un avviso. */
    static List<String> vecchioReset(Connection c) throws SQLException {
        String[] tables = {
            "audit_log", "rspamd_training", "email_statistics", "roundcube_tokens", "aliases", "mailboxes",
            "domains", "virtual_aliases", "virtual_users", "virtual_domains", "rate_limits", "forwarding_rules",
            "sieve_filters", "auto_responders", "panel_settings", "panel_admin", "installed_components"
        };
        List<String> avvisi = new ArrayList<>();
        try (Statement st = c.createStatement()) {
            for (String t : tables) {
                try {
                    st.executeUpdate("DROP TABLE IF EXISTS " + t);
                } catch (SQLException e) {
                    avvisi.add(t);
                }
            }
        }
        return avvisi;
    }

    /** Il database di prova vuoto, senza passare dal codice che si prova. */
    static void svuota(Connection c) throws SQLException {
        try (Statement st = c.createStatement()) {
            st.execute("SET FOREIGN_KEY_CHECKS=0");
            try {
                for (String t : tabelle(c)) st.execute("DROP TABLE `" + t.replace("`", "") + "`");
            } finally {
                st.execute("SET FOREIGN_KEY_CHECKS=1");
            }
        }
    }

    static List<String> tabelle(Connection c) throws SQLException {
        List<String> t = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name");
             ResultSet r = ps.executeQuery()) {
            while (r.next()) t.add(r.getString(1));
        }
        return t;
    }

    static int righe(Connection c, String tabella) {
        try (Statement st = c.createStatement();
             ResultSet r = st.executeQuery("SELECT COUNT(*) FROM `" + tabella.replace("`", "") + "`")) {
            r.next();
            return r.getInt(1);
        } catch (SQLException e) {
            return -1;
        }
    }

    static int inserisci(Connection c, String sql, Object... parametri) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            for (int k = 0; k < parametri.length; k++) ps.setObject(k + 1, parametri[k]);
            ps.executeUpdate();
            try (ResultSet r = ps.getGeneratedKeys()) {
                return r.next() ? r.getInt(1) : -1;
            }
        }
    }
}
