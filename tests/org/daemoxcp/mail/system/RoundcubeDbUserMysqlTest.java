package org.daemoxcp.mail.system;

import org.daemoxcp.mail.database.MysqlRoot;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * The webmail moved to its own MySQL user (RoundcubeDbUser.migrate) against a REAL MySQL, the test one, as its root:
 * the catalog statements the migration sends are run by MySQL, not by a fake. The
 * accounts and the privileges are read back with SHOW GRANTS; the webmail is a small fake that enters MySQL with the
 * db_dsnw php-fpm loaded and writes its session into the real session table.
 *
 *  1. it succeeds: roundcube@127.0.0.1 with everything on the webmail's database and nothing else, the panel's user
 *     without that database from both hosts, roundcube really reads its sessions; the second time nothing;
 *  2. php-fpm keeps the configuration of before: back, roundcube dropped, the panel's privileges as they were;
 *  3. something still enters as the panel after the revoke: back, the panel gets the database again from both
 *     hosts (GRANT ... ON * on the webmail's database), roundcube dropped;
 *  4. the scripts of before (roundcube with the panel's password): with a fault the old password comes back and the
 *     webmail gets in with it; without, the password of the secrets file;
 *  5. refusals that change nothing: a roundcube account with more than its database, a panel with only part of it.
 *
 * Usage (on the VM, with the test MySQL of tests/README.md, as root):
 *   java -Dmysql.port=33062 -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.RoundcubeDbUserMysqlTest
 */
public class RoundcubeDbUserMysqlTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String port;
    static final String DB = "rcmailtest", PANEL = "rcpaneltest", PANEL_PW = "PanelTestPassword0123456", SECRET = "RoundcubeTestSecret0123456";
    static final String RC = RoundcubeDbUser.USER;

    static Connection root(String db) throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://127.0.0.1:" + port + "/" + (db == null ? "" : db)
                + "?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC", "root", "");
    }

    static void exec(String db, String... sql) throws SQLException {
        try (Connection c = root(db)) {
            for (String s : sql) try (PreparedStatement ps = c.prepareStatement(s)) { ps.execute(); }
        }
    }

    static List<String> grants(String user, String host) throws SQLException {
        List<String> out = new ArrayList<>();
        try (Connection c = root(null); PreparedStatement ps = c.prepareStatement("SHOW GRANTS FOR ?@?")) {
            ps.setString(1, user);
            ps.setString(2, host);
            try (ResultSet rs = ps.executeQuery()) { while (rs.next()) out.add(rs.getString(1)); }
        } catch (SQLException e) {
            if (e.getErrorCode() == 1141) return List.of();   // no such grant: the account is not there
            throw e;
        }
        return out;
    }

    static boolean exists(String user, String host) throws SQLException {
        try (Connection c = root(null); PreparedStatement ps = c.prepareStatement("SELECT COUNT(*) FROM mysql.user WHERE user = ? AND host = ?")) {
            ps.setString(1, user);
            ps.setString(2, host);
            try (ResultSet rs = ps.executeQuery()) { rs.next(); return rs.getInt(1) == 1; }
        }
    }

    static boolean entersAndReads(String user, String password) {
        try (Connection c = DriverManager.getConnection("jdbc:mysql://127.0.0.1:" + port + "/" + DB
                + "?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC", user, password);
             PreparedStatement ps = c.prepareStatement("SELECT COUNT(*) FROM session")) {
            ps.executeQuery().close();
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

    /** The state that matters: config.inc.php, the two accounts' privileges, whether roundcube exists. */
    static String state(Path config) throws Exception {
        return Files.readString(config) + "|" + grants(PANEL, "localhost") + grants(PANEL, "127.0.0.1")
                + "|rc=" + exists(RC, "127.0.0.1") + grants(RC, "127.0.0.1");
    }

    static String config(String user, String password) {
        return "<?php\n$config['db_dsnw'] = 'mysql://" + user + ":" + password + "@127.0.0.1/" + DB + "';\n"
             + "$config['plugins'] = array('daemoxcp_mail_sso');\n";
    }

    /** MySQL as the panel's root part has it (MysqlRoot's JDBC); php-fpm, nginx and the webmail faked, on the real database. */
    static final class Bench implements RoundcubeDbUser.Services {
        final Path config;
        String loaded;
        boolean reloadIgnored, reloadFailsOnce, panelStillUsedAfterRevoke;
        Bench(Path config) throws Exception { this.config = config; loaded = Files.readString(config); }

        @Override public String secret() { return SECRET; }
        @Override public String panelUser() { return PANEL; }
        @Override public String panelPassword() { return PANEL_PW; }
        @Override public Shell.Result root(String db, String sql, Object... params) { return MysqlRoot.rootJdbc(db, sql, params); }
        @Override public Shell.Result as(String user, String password, String host, String db, String sql, Object... params) {
            return MysqlRoot.jdbc("127.0.0.1", port, db, user, password, sql, params);
        }
        @Override public Shell.Result phpFpmReload() {
            if (reloadFailsOnce) { reloadFailsOnce = false; return new Shell.Result(1, "ERROR: FPM initialization failed", false, List.of()); }
            try { if (!reloadIgnored) loaded = Files.readString(config); } catch (Exception e) { return new Shell.Result(1, e.toString(), false, List.of()); }
            return new Shell.Result(0, "", false, List.of());
        }
        @Override public List<RoundcubeDbUser.Site> webmailSites() { return List.of(new RoundcubeDbUser.Site("webmail.example.test", "8443")); }
        /** The login page: Roundcube writes its session with the db_dsnw php-fpm loaded. */
        @Override public RoundcubeDbUser.Page loginPage(RoundcubeDbUser.Site s) {
            RoundcubeDbUser.Dsn d = RoundcubeDbUser.activeDsn(loaded);
            String id = UUID.randomUUID().toString().replace("-", "");
            try (Connection c = DriverManager.getConnection("jdbc:mysql://127.0.0.1:" + port + "/" + d.db()
                    + "?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC", d.user(), d.password());
                 PreparedStatement ps = c.prepareStatement("INSERT INTO session (sess_id, changed) VALUES (?, UTC_TIMESTAMP())")) {
                ps.setString(1, id);
                ps.execute();
                if (panelStillUsedAfterRevoke && !entersAndReads(PANEL, PANEL_PW)) return new RoundcubeDbUser.Page(false, null);
                return new RoundcubeDbUser.Page(true, id);
            } catch (SQLException e) {
                return new RoundcubeDbUser.Page(false, null);
            }
        }
        @Override public String realLogin(RoundcubeDbUser.Site s, String db) { return "no SSO in this test"; }
        @Override public void pause() { }
    }

    static Path folder;

    static Bench bench(String name, String configText) throws Exception {
        Path rc = folder.resolve(name);
        Files.createDirectories(rc.resolve("config"));
        Files.createDirectories(rc.resolve("plugins"));
        Path cfg = rc.resolve("config/config.inc.php");
        Files.writeString(cfg, configText);
        return new Bench(cfg);
    }

    static RoundcubeDbUser.Report run(Bench b) throws Exception {
        return RoundcubeDbUser.migrate(new RoundcubeDbUser.Places(b.config.getParent().getParent()), b);
    }

    /** The webmail's database and the panel's user as the installer leaves them, roundcube not there. */
    static void fresh() throws SQLException {
        exec(null, "DROP DATABASE IF EXISTS " + DB, "CREATE DATABASE " + DB,
                "DROP USER IF EXISTS '" + RC + "'@'127.0.0.1', '" + RC + "'@'localhost'",
                "DROP USER IF EXISTS '" + PANEL + "'@'localhost', '" + PANEL + "'@'127.0.0.1'",
                "CREATE USER '" + PANEL + "'@'localhost' IDENTIFIED BY '" + PANEL_PW + "', '" + PANEL + "'@'127.0.0.1' IDENTIFIED BY '" + PANEL_PW + "'",
                "GRANT ALL PRIVILEGES ON " + DB + ".* TO '" + PANEL + "'@'localhost', '" + PANEL + "'@'127.0.0.1'");
        exec(DB, "CREATE TABLE session (sess_id VARCHAR(128) PRIMARY KEY, changed DATETIME)",
                "CREATE TABLE users (user_id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(128))");
    }

    static boolean allOn(List<String> grants, String user, String host) {
        return grants.contains("GRANT ALL PRIVILEGES ON `" + DB + "`.* TO `" + user + "`@`" + host + "`");
    }

    public static void main(String[] args) throws Exception {
        port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): this test needs the test MySQL, and its root.");
            System.exit(1);
        }
        // Prima di tutto: i segreti della prova (root senza password) e la porta del MySQL di prova per MysqlRoot.
        folder = Files.createTempDirectory("roundcube-db-user-mysql");
        System.setProperty("daemoxcp.mail.secrets.dir", Files.createDirectories(folder.resolve("secrets")).toString());
        System.setProperty("daemoxcp.mail.mysql.port", port);

        System.out.println("== 1. It succeeds, on the real MySQL");
        fresh();
        Bench b = bench("ok", config(PANEL, PANEL_PW));
        RoundcubeDbUser.Report r = run(b);
        check("DONE (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.DONE);
        List<String> rc = grants(RC, "127.0.0.1");
        check("roundcube@127.0.0.1: everything on its database and nothing else " + rc,
                rc.size() == 2 && rc.get(0).equals("GRANT USAGE ON *.* TO `" + RC + "`@`127.0.0.1`") && allOn(rc, RC, "127.0.0.1"));
        check("roundcube gets in with the password of the secrets file and reads its sessions", entersAndReads(RC, SECRET));
        check("the panel's user no longer has the webmail's database, from both hosts",
                !allOn(grants(PANEL, "localhost"), PANEL, "localhost") && !allOn(grants(PANEL, "127.0.0.1"), PANEL, "127.0.0.1")
                        && !entersAndReads(PANEL, PANEL_PW));
        check("db_dsnw now enters as roundcube", Files.readString(b.config).contains("mysql://" + RC + ":" + SECRET + "@127.0.0.1/"));
        String st = state(b.config);
        r = run(b);
        check("the second time: NOTHING, and nothing changed", r.outcome() == RoundcubeDbUser.Outcome.NOTHING && state(b.config).equals(st));

        System.out.println("== 2. php-fpm keeps the configuration of before: back");
        fresh();
        b = bench("stale", config(PANEL, PANEL_PW));
        st = state(b.config);
        b.reloadIgnored = true;
        r = run(b);
        check("ROLLED_BACK (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.ROLLED_BACK && r.detail().endsWith("everything put back"));
        check("  config, accounts and privileges as before (roundcube dropped)", state(b.config).equals(st) && !exists(RC, "127.0.0.1"));

        System.out.println("== 3. Something still enters as the panel after the revoke: back, the panel gets the database again");
        fresh();
        b = bench("plugin", config(PANEL, PANEL_PW));
        st = state(b.config);
        b.panelStillUsedAfterRevoke = true;
        r = run(b);
        check("ROLLED_BACK after the revoke (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.ROLLED_BACK
                && r.detail().contains("once " + PANEL + " lost " + DB) && r.detail().endsWith("everything put back"));
        check("  the panel has everything on the webmail's database again, from both hosts (GRANT ... ON * on that database)",
                allOn(grants(PANEL, "localhost"), PANEL, "localhost") && allOn(grants(PANEL, "127.0.0.1"), PANEL, "127.0.0.1")
                        && entersAndReads(PANEL, PANEL_PW));
        check("  config, accounts and privileges as before", state(b.config).equals(st));

        System.out.println("== 4. The scripts of before: roundcube with the panel's password");
        fresh();
        exec(null, "REVOKE ALL PRIVILEGES ON " + DB + ".* FROM '" + PANEL + "'@'localhost', '" + PANEL + "'@'127.0.0.1'",
                "CREATE USER '" + RC + "'@'127.0.0.1' IDENTIFIED BY '" + PANEL_PW + "'",
                "GRANT ALL PRIVILEGES ON " + DB + ".* TO '" + RC + "'@'127.0.0.1'");
        b = bench("shared", config(RC, PANEL_PW));
        st = state(b.config);
        b.reloadFailsOnce = true;
        r = run(b);
        check("with a fault: ROLLED_BACK (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.ROLLED_BACK);
        check("  roundcube gets in again with the password of before, the one in config.inc.php", entersAndReads(RC, PANEL_PW)
                && !entersAndReads(RC, SECRET));
        check("  config and privileges as before", state(b.config).equals(st));
        r = run(b);
        check("without a fault: DONE (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.DONE
                && entersAndReads(RC, SECRET) && !entersAndReads(RC, PANEL_PW));

        System.out.println("== 5. Refusals that change nothing");
        fresh();
        exec(null, "CREATE USER '" + RC + "'@'127.0.0.1' IDENTIFIED BY 'OldPassword0123456789'",
                "GRANT ALL PRIVILEGES ON " + DB + ".* TO '" + RC + "'@'127.0.0.1'",
                "GRANT SELECT ON mysql.* TO '" + RC + "'@'127.0.0.1'");
        b = bench("beyond", config(RC, "OldPassword0123456789"));
        st = state(b.config);
        r = run(b);
        check("a roundcube account with more than its database: NOT_OURS (" + r.detail() + ")",
                r.outcome() == RoundcubeDbUser.Outcome.NOT_OURS && r.detail().contains("privileges beyond") && state(b.config).equals(st));
        fresh();
        exec(null, "REVOKE ALL PRIVILEGES ON " + DB + ".* FROM '" + PANEL + "'@'127.0.0.1'",
                "GRANT SELECT ON " + DB + ".* TO '" + PANEL + "'@'127.0.0.1'");
        b = bench("partial", config(PANEL, PANEL_PW));
        st = state(b.config);
        r = run(b);
        check("a panel with only part of the webmail's database: NOT_OURS (" + r.detail() + ")",
                r.outcome() == RoundcubeDbUser.Outcome.NOT_OURS && r.detail().contains("other than the installer's") && state(b.config).equals(st));

        exec(null, "DROP DATABASE IF EXISTS " + DB, "DROP USER IF EXISTS '" + RC + "'@'127.0.0.1', '" + RC + "'@'localhost'",
                "DROP USER IF EXISTS '" + PANEL + "'@'localhost', '" + PANEL + "'@'127.0.0.1'");
        Shell.run("rm", "-rf", folder.toString());
        System.out.println(failed == 0 ? "ALL OK" : failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
