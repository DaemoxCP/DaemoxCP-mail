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
 * At service startup, before anyone logs into MySQL: the panel's database and MySQL users take the new name
 * (DaemoxCP Mail, 2026-11-17).
 *
 * <p>Until this version the database was named as the installer had named it (mailserver) and the users were
 * mailpanel (the panel), mailpanel_web (the web part), mailpanel_routines (the owner of the procedures, locked),
 * mailpanel_postfix and mailpanel_dovecot (the Postfix and Dovecot reads). They become daemoxcp_mail and
 * daemoxcp_mail_*.
 *
 * <p>MySQL cannot rename a database. The new one is created and the tables are moved into it with RENAME TABLE,
 * which copies nothing: one table at a time, only those the panel knows (MailDatabase.PANEL_TABLES). A table the
 * panel does not know stays where it was, and with it the previous database. Users are renamed with RENAME USER,
 * which carries password and privileges along; MySQL however refuses to rename a user who has defined a procedure,
 * so the web part's procedures are removed first (WebDbAccess recreates them at startup, in the new database, with
 * the new owner). Privileges on single tables do not follow the moved table: they are revoked and granted again
 * (Postfix's and Dovecot's here, the procedures' in WebDbAccess), and the panel user gets everything on the new
 * database, as the installer grants it.
 *
 * <p>Then the files that name user and database: the three Postfix maps and the Dovecot connection. They are
 * checked (postfix check, doveconf -n), Postfix and Dovecot are reloaded, and it is tested that a real lookup
 * reaches MySQL (postmap -q and doveadm auth lookup, like MailDbUsers). Finally the panel configuration (SQLite)
 * states the new name, and the previous database, if it is the installer's and has been left empty, is removed.
 *
 * <p>All or nothing: at the first step that does not match, everything is put back as it was (files, users,
 * tables) and Postfix and Dovecot are reloaded. Without the MySQL root password nothing is done: it is tried again
 * at the next startup. Until then the panel works with the previous names, which stay valid (WebDbAccess and
 * MailDbUsers create their users with the new name next to the old ones).
 */
public final class MysqlRename {

    private static final Logger LOGGER = Logger.getLogger(MysqlRename.class.getName());

    /** The current database, as in SqlCatalog.RENAME_CREATE_DATABASE. */
    static final String NEW_DB = Product.ID;
    /** The name the installer gave the database (SqlCatalog.RENAME_DROP_OLD_DEFAULT_DATABASE). */
    static final String OLD_DEFAULT_DB = "mailserver";

    enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** MySQL, the files and the services, kept separate to test them. */
    interface Services {
        /** A catalog statement as root, with the connection on {@code db} (null: none). */
        Shell.Result sql(String db, String statement, Object... params);
        /** The service files that name user and database. */
        List<Path> files();
        /** The configuration check: null if it passes. */
        String check();
        /** Reloads Postfix and Dovecot: null if it worked. */
        String reload();
        /** A real lookup from Postfix and from Dovecot: null if it reaches MySQL. */
        String probe();
    }

    private MysqlRename() {}

    /** At startup, with the panel database already open (SQLite). */
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

    // ===================== pure functions =====================

    /** The rows of an output (one row per line, columns separated by tabs). */
    static List<String[]> rows(Shell.Result r) {
        List<String[]> out = new ArrayList<>();
        if (r == null || !r.success()) return out;
        for (String l : r.output().split("\n")) if (!l.isBlank()) out.add(l.split("\t", -1));
        return out;
    }

    /**
     * The text of a Postfix or Dovecot file with the current names: the previous users and the previous database,
     * only as whole words (mailpanel does not touch mailpanel_postfix, mailserver does not touch mailserver2).
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

    /** The catalogue statements that start with a prefix, by name: RENAME_TABLE_DOMAINS -> the statement. */
    static Map<String, String> catalog(String prefix) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Field f : SqlCatalog.class.getFields()) {
            if (!f.getName().startsWith(prefix) || f.getType() != String.class) continue;
            try { out.put(f.getName().substring(prefix.length()), (String) f.get(null)); } catch (IllegalAccessException ignored) {}
        }
        return out;
    }

    // ===================== the switchover =====================

    static Report rename(String oldDb, String panelUser, Services sv) {
        if (oldDb.equals(NEW_DB)) return new Report(Outcome.NOTHING, "");
        Shell.Result schemas = sv.sql(null, SqlCatalog.RENAME_SCHEMAS, oldDb, NEW_DB);
        if (!schemas.success())
            return new Report(Outcome.LEFT, "MySQL does not answer as root (" + first(schemas.outputTrim()) + "): retrying at the next start");
        Set<String> present = new LinkedHashSet<>();
        for (String[] r : rows(schemas)) present.add(r[0]);
        if (!present.contains(oldDb)) return new Report(Outcome.NOTHING, "");

        // The users: with the previous and the current name. A new name already taken stops everything.
        Map<String, String> userStatements = catalog("RENAME_USER_");
        Set<String> users = new LinkedHashSet<>();
        for (String[] r : rows(sv.sql(null, SqlCatalog.RENAME_USERS))) users.add(r[0] + "@" + r[1]);
        List<String[]> toRename = new ArrayList<>();      // {constant name, old@host, new@host}
        for (Map.Entry<String, String> e : userStatements.entrySet()) {
            Matcher m = Pattern.compile("RENAME USER '([^']+)'@'([^']+)' TO '([^']+)'@'([^']+)'").matcher(e.getValue());
            if (!m.matches()) continue;
            String from = m.group(1) + "@" + m.group(2), to = m.group(3) + "@" + m.group(4);
            if (!users.contains(from)) continue;
            if (users.contains(to)) return new Report(Outcome.LEFT, "both the MySQL users " + from + " and " + to + " exist: nothing changed");
            toRename.add(new String[] {e.getKey(), from, to});
        }

        // The tables: only those the panel knows; triggers, events and views cannot be moved.
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

        // The previous procedures: only those of the web part, which the panel knows how to remove and recreate.
        Set<String> known = new LinkedHashSet<>();
        Map<String, String> drops = new LinkedHashMap<>();
        // All the DROP PROCEDURE statements of the catalogue: the current ones and those of retired procedures. They
        // are recognised by their words, not by SQL text written here (SqlCatalogTest: no SQL outside the catalogue).
        for (String drop : catalog("WEB_DROP_").values()) {
            String[] w = drop.trim().split("\\s+");
            if (w.length != 5 || !w[0].equals("DROP") || !w[1].equals("PROCEDURE") || !w[2].equals("IF") || !w[3].equals("EXISTS")) continue;
            String name = w[4];
            known.add(name);
            drops.put(name, drop);
        }
        List<String> routines = new ArrayList<>();
        for (String[] r : rows(sv.sql(null, SqlCatalog.RENAME_ROUTINES_OF, oldDb))) routines.add(r[0]);
        for (String r : routines)
            if (!known.contains(r)) return new Report(Outcome.LEFT, "the database " + oldDb + " has the routine " + r
                    + ", not the panel's: nothing moved");

        // --- from here on, things change ---
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
            // The privileges. The panel user: everything on the new database, nothing on the previous one.
            Set<String> after = new LinkedHashSet<>();
            for (String[] r : rows(sv.sql(null, SqlCatalog.RENAME_USERS))) after.add(r[0] + "@" + r[1]);
            step = "granting the panel's user";
            if (after.contains(Product.ID + "@localhost")) need(sv.sql(null, SqlCatalog.RENAME_GRANT_PANEL_LOCALHOST), step);
            if (after.contains(Product.ID + "@127.0.0.1")) need(sv.sql(null, SqlCatalog.MAIL_GRANT_PANEL_USER), step);
            if (oldDb.equals(OLD_DEFAULT_DB)) {
                if (after.contains(Product.ID + "@localhost")) sv.sql(null, SqlCatalog.RENAME_REVOKE_OLD_DEFAULT_LOCALHOST);
                if (after.contains(Product.ID + "@127.0.0.1")) sv.sql(null, SqlCatalog.RENAME_REVOKE_OLD_DEFAULT_LOOPBACK);
            }
            // Postfix and Dovecot: the privileges on the previous tables go away, those on the new tables come.
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
            // The owner of the procedures: WebDbAccess grants its privileges again, on the new tables.
            if (after.contains(Product.ID + "_routines@localhost")) sv.sql(null, SqlCatalog.RENAME_REVOKE_ROUTINES);

            // The Postfix and Dovecot files.
            step = "rewriting the Postfix and Dovecot files";
            Map<String, String> names = new LinkedHashMap<>();
            for (String[] u : toRename) names.put(u[1].substring(0, u[1].indexOf('@')), u[2].substring(0, u[2].indexOf('@')));
            // The panel user, if a file still uses it (before MailDbUsers): mailpanel -> daemoxcp_mail.
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
            // WebDbAccess recreates the procedures at startup, in the previous database: no need to put them back
            // here.
            return new Report(Outcome.ROLLED_BACK, step + ": " + first(e.getMessage())
                    + (problems.isEmpty() ? "; everything put back as it was" : "; NOT put back: " + String.join(", ", problems)));
        }

        // The previous database: if it is the installer's and has been left empty, it is removed.
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

    // ===================== the real system =====================

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
            // Roundcube, which on older servers still logs in with the panel user (RoundcubeDbUser.otherPanelDsn).
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
