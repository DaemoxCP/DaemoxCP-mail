package org.daemoxcp.mail.system;

import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.database.MysqlRoot;
import org.daemoxcp.mail.database.SqlCatalog;
import org.daemoxcp.mail.sqli.dataBaseManager;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * All'avvio del servizio, prima che qualcuno entri in MySQL: il database e gli utenti MySQL del pannello prendono il
 * nome nuovo (DaemoxCP Mail, 17/11/2026).
 *
 * <p>Fino a questa versione il database si chiamava come l'aveva chiamato l'installatore (mailserver) e gli utenti
 * mailpanel (il pannello), mailpanel_web (la parte web), mailpanel_routines (il proprietario delle procedure, bloccato),
 * mailpanel_postfix e mailpanel_dovecot (le letture di Postfix e Dovecot). Diventano daemoxcp_mail e daemoxcp_mail_*.
 *
 * <p>MySQL non sa rinominare un database. Si crea quello nuovo e ci si spostano le tabelle con RENAME TABLE, che non
 * copia niente: una tabella alla volta, le sole che il pannello conosce (MailDatabase.PANEL_TABLES). Una tabella che il
 * pannello non conosce resta dov'era, e con lei il database di prima. Gli utenti si rinominano con RENAME USER, che
 * porta con se' password e permessi; MySQL pero' rifiuta di rinominare chi ha definito una procedura, quindi le
 * procedure della parte web si tolgono prima (WebDbAccess le ricrea all'avvio, nel database nuovo, col proprietario
 * nuovo). I permessi sulle singole tabelle non seguono la tabella spostata: si tolgono e si ridanno (quelli di Postfix e
 * Dovecot qui, quelli delle procedure WebDbAccess), e l'utente del pannello prende tutto sul database nuovo come glielo
 * da' l'installatore.
 *
 * <p>Poi i file che nominano utente e database: le tre mappe di Postfix e la connessione di Dovecot. Si controllano
 * (postfix check, doveconf -n), si ricaricano Postfix e Dovecot, e si prova che una ricerca vera arrivi a MySQL
 * (postmap -q e doveadm auth lookup, come MailDbUsers). Infine la configurazione del pannello (SQLite) dice il nome
 * nuovo, e il database di prima, se e' quello dell'installatore ed e' rimasto vuoto, se ne va.
 *
 * <p>Tutto o niente: al primo passo che non torna si rimette tutto com'era (file, utenti, tabelle) e si ricaricano
 * Postfix e Dovecot. Senza la password di root di MySQL non si fa niente: al prossimo avvio si riprova. Fino ad allora il
 * pannello lavora coi nomi di prima, che restano validi (WebDbAccess e MailDbUsers creano i loro utenti col nome nuovo
 * accanto a quelli vecchi).
 */
public final class MysqlRename {

    private static final Logger LOGGER = Logger.getLogger(MysqlRename.class.getName());

    /** Il database di adesso, come in SqlCatalog.RENAME_CREATE_DATABASE. */
    static final String NEW_DB = Product.ID;
    /** Il nome che l'installatore dava al database (SqlCatalog.RENAME_DROP_OLD_DEFAULT_DATABASE). */
    static final String OLD_DEFAULT_DB = "mailserver";

    enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** MySQL, i file e i servizi, separati per provarli. */
    interface Services {
        /** Un'istruzione del catalogo come root, con la connessione su {@code db} (null: nessuno). */
        Shell.Result sql(String db, String statement, Object... params);
        /** I file dei servizi che nominano utente e database. */
        List<Path> files();
        /** Il controllo della configurazione: null se va. */
        String check();
        /** Ricarica Postfix e Dovecot: null se e' andato. */
        String reload();
        /** Una ricerca vera da Postfix e da Dovecot: null se arriva a MySQL. */
        String probe();
    }

    private MysqlRename() {}

    /** All'avvio, col database del pannello gia' aperto (SQLite). */
    public static void ensureAtBoot(dataBaseManager config) {
        try {
            if (!"root".equals(System.getProperty("user.name"))) return;
            String[] t = PendingDbPassword.mysqlTarget(config);
            String oldDb = OLD_DEFAULT_DB, panelUser = t[2];
            try (java.sql.ResultSet r = config.get_data_config()) {
                if (r.next() && r.getString("mysql_database") != null && !r.getString("mysql_database").isBlank())
                    oldDb = r.getString("mysql_database");
            }
            Report rep = rename(oldDb, panelUser, new RealServices());
            if (rep.outcome() == Outcome.DONE && !config.renameMysql(Product.ID, NEW_DB))
                rep = new Report(Outcome.DONE, rep.detail() + "; WARNING: the panel's configuration still names the old database");
            if (rep.outcome() == Outcome.NOTHING) return;
            String line = "[MysqlRename] " + rep.outcome() + ": " + rep.detail();
            if (rep.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable e) {
            LOGGER.warning("[MysqlRename] failed: " + e);
        }
    }

    // ===================== funzioni pure =====================

    /** Le righe di un'uscita (una riga per riga, colonne separate da tab). */
    static List<String[]> rows(Shell.Result r) {
        List<String[]> out = new ArrayList<>();
        if (r == null || !r.success()) return out;
        for (String l : r.output().split("\n")) if (!l.isBlank()) out.add(l.split("\t", -1));
        return out;
    }

    /**
     * Il testo di un file di Postfix o Dovecot coi nomi di adesso: gli utenti di prima e il database di prima, solo
     * come parole intere (mailpanel non tocca mailpanel_postfix, mailserver non tocca mailserver2).
     */
    static String renamedNames(String text, String oldDb, Map<String, String> users) {
        String out = text;
        for (Map.Entry<String, String> u : users.entrySet())
            out = word(u.getKey()).matcher(out).replaceAll(Matcher.quoteReplacement(u.getValue()));
        if (!oldDb.equals(NEW_DB)) out = word(oldDb).matcher(out).replaceAll(Matcher.quoteReplacement(NEW_DB));
        return out;
    }

    private static Pattern word(String w) {
        return Pattern.compile("(?<![A-Za-z0-9_])" + Pattern.quote(w) + "(?![A-Za-z0-9_])");
    }

    /** Le istruzioni del catalogo che iniziano con un prefisso, per nome: RENAME_TABLE_DOMAINS -> l'istruzione. */
    static Map<String, String> catalog(String prefix) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Field f : SqlCatalog.class.getFields()) {
            if (!f.getName().startsWith(prefix) || f.getType() != String.class) continue;
            try { out.put(f.getName().substring(prefix.length()), (String) f.get(null)); } catch (IllegalAccessException ignored) {}
        }
        return out;
    }

    // ===================== il passaggio =====================

    static Report rename(String oldDb, String panelUser, Services sv) {
        if (oldDb.equals(NEW_DB)) return new Report(Outcome.NOTHING, "");
        Shell.Result schemas = sv.sql(null, SqlCatalog.RENAME_SCHEMAS, oldDb, NEW_DB);
        if (!schemas.success())
            return new Report(Outcome.LEFT, "MySQL does not answer as root (" + first(schemas.outputTrim()) + "): retrying at the next start");
        Set<String> present = new LinkedHashSet<>();
        for (String[] r : rows(schemas)) present.add(r[0]);
        if (!present.contains(oldDb)) return new Report(Outcome.NOTHING, "");

        // Gli utenti: col nome di prima e di adesso. Un nome nuovo gia' preso ferma tutto.
        Map<String, String> userStatements = catalog("RENAME_USER_");
        Set<String> users = new LinkedHashSet<>();
        for (String[] r : rows(sv.sql(null, SqlCatalog.RENAME_USERS))) users.add(r[0] + "@" + r[1]);
        List<String[]> toRename = new ArrayList<>();      // {nome della costante, vecchio@host, nuovo@host}
        for (Map.Entry<String, String> e : userStatements.entrySet()) {
            Matcher m = Pattern.compile("RENAME USER '([^']+)'@'([^']+)' TO '([^']+)'@'([^']+)'").matcher(e.getValue());
            if (!m.matches()) continue;
            String from = m.group(1) + "@" + m.group(2), to = m.group(3) + "@" + m.group(4);
            if (!users.contains(from)) continue;
            if (users.contains(to)) return new Report(Outcome.LEFT, "both the MySQL users " + from + " and " + to + " exist: nothing changed");
            toRename.add(new String[] {e.getKey(), from, to});
        }

        // Le tabelle: solo quelle che il pannello conosce; trigger, eventi e viste non si sanno spostare.
        Map<String, String> tableType = new LinkedHashMap<>();
        for (String[] r : rows(sv.sql(null, SqlCatalog.RENAME_TABLES_OF, oldDb))) tableType.put(r[0], r.length > 1 ? r[1] : "");
        if (tableType.values().stream().anyMatch(v -> v.toUpperCase(Locale.ROOT).contains("VIEW")))
            return new Report(Outcome.LEFT, "the database " + oldDb + " has views: nothing moved");
        List<String[]> other = rows(sv.sql(null, SqlCatalog.RENAME_OTHER_OBJECTS_OF, oldDb, oldDb));
        if (other.isEmpty() || !"0".equals(other.get(0)[0]))
            return new Report(Outcome.LEFT, "the database " + oldDb + " has triggers or events: nothing moved");
        Map<String, String> moveStatements = catalog("RENAME_TABLE_"), backStatements = catalog("RENAME_BACK_TABLE_");
        List<String> toMove = new ArrayList<>(), unknown = new ArrayList<>();
        for (String t : tableType.keySet()) {
            String k = t.toUpperCase(Locale.ROOT);
            if (MailDatabase.PANEL_TABLES.contains(t) && moveStatements.containsKey(k)) toMove.add(k); else unknown.add(t);
        }
        if (present.contains(NEW_DB) && !rows(sv.sql(null, SqlCatalog.RENAME_TABLES_OF, NEW_DB)).isEmpty())
            return new Report(Outcome.LEFT, "the database " + NEW_DB + " already exists and is not empty: nothing moved");

        // Le procedure di prima: solo quelle della parte web, che il pannello sa togliere e ricreare.
        Set<String> known = new LinkedHashSet<>();
        Map<String, String> drops = new LinkedHashMap<>();
        // Tutte le DROP PROCEDURE del catalogo: quelle di adesso e quelle delle procedure ritirate.
        for (String drop : catalog("WEB_DROP_").values()) {
            if (!drop.startsWith("DROP PROCEDURE IF EXISTS ")) continue;
            String name = drop.substring(drop.lastIndexOf(' ') + 1);
            known.add(name);
            drops.put(name, drop);
        }
        List<String> routines = new ArrayList<>();
        for (String[] r : rows(sv.sql(null, SqlCatalog.RENAME_ROUTINES_OF, oldDb))) routines.add(r[0]);
        for (String r : routines)
            if (!known.contains(r)) return new Report(Outcome.LEFT, "the database " + oldDb + " has the routine " + r
                    + ", not the panel's: nothing moved");

        // --- da qui si cambia ---
        List<String> movedTables = new ArrayList<>();
        List<String> renamedUsers = new ArrayList<>();
        List<Path> written = new ArrayList<>();
        Map<Path, String> before = new LinkedHashMap<>();
        boolean created = false;
        String step = "";
        try {
            step = "dropping the web part's procedures";
            for (String r : routines) need(sv.sql(oldDb, drops.get(r)), step);
            if (!present.contains(NEW_DB)) {
                step = "creating " + NEW_DB;
                need(sv.sql(null, SqlCatalog.RENAME_CREATE_DATABASE), step);
                created = true;
            }
            for (String k : toMove) {
                step = "moving " + k.toLowerCase(Locale.ROOT);
                need(sv.sql(oldDb, moveStatements.get(k)), step);
                movedTables.add(k);
            }
            for (String[] u : toRename) {
                step = "renaming " + u[1];
                need(sv.sql(null, userStatements.get(u[0])), step);
                renamedUsers.add(u[0]);
            }
            // I permessi. L'utente del pannello: tutto sul database nuovo, niente su quello di prima.
            Set<String> after = new LinkedHashSet<>();
            for (String[] r : rows(sv.sql(null, SqlCatalog.RENAME_USERS))) after.add(r[0] + "@" + r[1]);
            step = "granting the panel's user";
            if (after.contains(Product.ID + "@localhost")) need(sv.sql(null, SqlCatalog.RENAME_GRANT_PANEL_LOCALHOST), step);
            if (after.contains(Product.ID + "@127.0.0.1")) need(sv.sql(null, SqlCatalog.RENAME_GRANT_PANEL_LOOPBACK), step);
            if (oldDb.equals(OLD_DEFAULT_DB)) {
                if (after.contains(Product.ID + "@localhost")) sv.sql(null, SqlCatalog.RENAME_REVOKE_OLD_DEFAULT_LOCALHOST);
                if (after.contains(Product.ID + "@127.0.0.1")) sv.sql(null, SqlCatalog.RENAME_REVOKE_OLD_DEFAULT_LOOPBACK);
            }
            // Postfix e Dovecot: via i permessi sulle tabelle di prima, e quelli sulle tabelle nuove.
            step = "granting Postfix and Dovecot";
            if (after.contains(MailDbUsers.POSTFIX_USER + "@localhost")) {
                need(sv.sql(null, SqlCatalog.MAILDB_REVOKE_POSTFIX), step);
                for (String g : List.of(SqlCatalog.MAILDB_GRANT_POSTFIX_DOMAINS, SqlCatalog.MAILDB_GRANT_POSTFIX_MAILBOXES,
                        SqlCatalog.MAILDB_GRANT_POSTFIX_ALIASES)) need(sv.sql(NEW_DB, g), step);
            }
            if (after.contains(MailDbUsers.DOVECOT_USER + "@localhost")) {
                need(sv.sql(null, SqlCatalog.MAILDB_REVOKE_DOVECOT), step);
                need(sv.sql(NEW_DB, SqlCatalog.MAILDB_GRANT_DOVECOT_MAILBOXES), step);
            }
            // Il proprietario delle procedure: i permessi li ridà WebDbAccess, sulle tabelle nuove.
            if (after.contains(Product.ID + "_routines@localhost")) sv.sql(null, SqlCatalog.RENAME_REVOKE_ROUTINES);

            // I file di Postfix e Dovecot.
            step = "rewriting the Postfix and Dovecot files";
            Map<String, String> names = new LinkedHashMap<>();
            for (String[] u : toRename) names.put(u[1].substring(0, u[1].indexOf('@')), u[2].substring(0, u[2].indexOf('@')));
            // L'utente del pannello, se un file lo usa ancora (prima di MailDbUsers): mailpanel -> daemoxcp_mail.
            if (!panelUser.equals(Product.ID) && toRename.stream().anyMatch(u -> u[1].startsWith(panelUser + "@")))
                names.put(panelUser, Product.ID);
            for (Path f : sv.files()) {
                if (!Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)) continue;
                String text = Files.readString(f, StandardCharsets.UTF_8);
                String n = renamedNames(text, oldDb, names);
                if (n.equals(text)) continue;
                before.put(f, text);
                PanelMarker.replaceKeeping(f, n);
                written.add(f);
            }
            if (!written.isEmpty()) {
                step = "checking Postfix and Dovecot";
                String p = sv.check();
                if (p != null) throw new IllegalStateException(p);
                step = "reloading Postfix and Dovecot";
                p = sv.reload();
                if (p != null) throw new IllegalStateException(p);
                step = "a lookup from Postfix and Dovecot";
                p = sv.probe();
                if (p != null) throw new IllegalStateException(p);
            }
        } catch (IOException | RuntimeException e) {
            List<String> problems = new ArrayList<>();
            for (Path f : written) {
                try { PanelMarker.replaceKeeping(f, before.get(f)); } catch (IOException x) { problems.add(f + ": " + x.getMessage()); }
            }
            Map<String, String> userBack = catalog("RENAME_BACK_USER_");
            for (int i = renamedUsers.size() - 1; i >= 0; i--)
                if (!sv.sql(null, userBack.get(renamedUsers.get(i))).success()) problems.add("user " + renamedUsers.get(i));
            for (int i = movedTables.size() - 1; i >= 0; i--)
                if (!sv.sql(oldDb, backStatements.get(movedTables.get(i))).success()) problems.add("table " + movedTables.get(i));
            if (created && rows(sv.sql(null, SqlCatalog.RENAME_TABLES_OF, NEW_DB)).isEmpty()) sv.sql(null, SqlCatalog.RENAME_DROP_NEW_DATABASE);
            if (!written.isEmpty()) sv.reload();
            // Le procedure le ricrea WebDbAccess all'avvio, nel database di prima: non c'e' da rimetterle qui.
            return new Report(Outcome.ROLLED_BACK, step + ": " + first(e.getMessage())
                    + (problems.isEmpty() ? "; everything put back as it was" : "; NOT put back: " + String.join(", ", problems)));
        }

        // Il database di prima: se e' quello dell'installatore ed e' rimasto vuoto, se ne va.
        String dropped = "";
        if (oldDb.equals(OLD_DEFAULT_DB) && unknown.isEmpty() && rows(sv.sql(null, SqlCatalog.RENAME_TABLES_OF, oldDb)).isEmpty()
                && rows(sv.sql(null, SqlCatalog.RENAME_ROUTINES_OF, oldDb)).isEmpty()
                && sv.sql(null, SqlCatalog.RENAME_DROP_OLD_DEFAULT_DATABASE).success())
            dropped = ", the empty database " + oldDb + " removed";
        List<String> renamedNames = new ArrayList<>();
        for (String[] u : toRename) if (renamedUsers.contains(u[0])) renamedNames.add(u[1] + " -> " + u[2]);
        return new Report(Outcome.DONE, "database " + oldDb + " -> " + NEW_DB + " (" + movedTables.size() + " tables"
                + (unknown.isEmpty() ? "" : "; not the panel's, left in " + oldDb + ": " + unknown) + "), users " + renamedNames
                + (written.isEmpty() ? "" : "; " + written + " rewritten, Postfix and Dovecot reloaded and checked") + dropped
                + "; the web part's procedures are recreated by WebDbAccess");
    }

    private static void need(Shell.Result r, String step) {
        if (r == null || !r.success()) throw new IllegalStateException(r == null ? "no answer" : first(r.outputTrim()));
    }

    private static String first(String s) {
        if (s == null) return "";
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }

    // ===================== il sistema vero =====================

    static final class RealServices implements Services {
        private final MailDbUsers.Places places = MailDbUsers.Places.real();

        @Override public Shell.Result sql(String db, String statement, Object... params) {
            return MysqlRoot.rootJdbc(db, statement, params);
        }

        @Override public List<Path> files() {
            List<Path> out = new ArrayList<>();
            for (String m : MailDbUsers.POSTFIX_MAPS) out.add(places.postfixDir().resolve(m));
            out.add(places.dovecotSql());
            out.add(places.dovecotAuthSql());
            // Roundcube, dove sui server piu' vecchi entra ancora con l'utente del pannello (RoundcubeDbUser.otherPanelDsn).
            out.add(Path.of(RoundcubeDbUser.ROUNDCUBE_DIR, "config", "config.inc.php"));
            return out;
        }

        @Override public String check() {
            Shell.Result p = Shell.run(java.time.Duration.ofSeconds(60), "/usr/local/sbin/postfix", "check");
            if (!p.success()) return "postfix check: " + first(p.outputTrim());
            Shell.Result d = Shell.run(java.time.Duration.ofSeconds(30), DovecotAuthWorker.DOVECONF, "-n");
            return d.success() ? null : "doveconf -n: " + first(d.outputTrim());
        }

        @Override public String reload() {
            if (Shell.run(java.time.Duration.ofSeconds(15), "service", "postfix", "status").success()) {
                Shell.Result p = Shell.run(java.time.Duration.ofSeconds(60), "/usr/local/sbin/postfix", "reload");
                if (!p.success()) return "postfix reload: " + first(p.outputTrim());
            }
            if (DovecotAuthWorker.running()) {
                Shell.Result d = Shell.run(java.time.Duration.ofSeconds(30), "service", "dovecot", "reload");
                if (!d.success()) return "dovecot reload: " + first(d.outputTrim());
                try { Thread.sleep(1500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
            return null;
        }

        @Override public String probe() {
            for (String m : MailDbUsers.POSTFIX_MAPS) {
                Path map = places.postfixDir().resolve(m);
                if (!Files.isRegularFile(map)) continue;
                Shell.Result r = Shell.run(java.time.Duration.ofSeconds(30), "/usr/local/sbin/postmap", "-q", MailDbUsers.PROBE, "mysql:" + map);
                if (!MailDbUsers.postmapAnswered(r)) return "postmap -q on " + map + ": " + first(r.outputTrim());
            }
            if (DovecotAuthWorker.running()) {
                int rc = DovecotAuthWorker.lookup();
                if (!DovecotAuthWorker.LOOKUP_OK.contains(rc)) return "doveadm auth lookup: exit " + rc;
            }
            return null;
        }
    }
}
