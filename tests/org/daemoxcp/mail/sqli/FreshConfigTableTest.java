package org.daemoxcp.mail.sqli;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * The panel's configuration table on a server where it does not exist yet: the first start of the menu, step 6 of the
 * README. Found in the clean-install rehearsal of 18/11/2026 with the 0.9.0 jar: Main added the newer columns (ALTER
 * TABLE) BEFORE creating the table, the ALTERs failed in silence on the missing table, the table was then created
 * without roundcube_ssl_chain, and option 3 of the menu said "no such column: roundcube_ssl_chain" until a second
 * start added it. Now Main calls dataBaseManager.prepareAtStartup(): the table first, then the columns.
 *
 *  A. prepareAtStartup() on a new server: the table is created, saving the webmail settings works, the CA chain is
 *     read back, and the table has every column the start adds.
 *  B. A second start: nothing is created again, nothing saved is lost.
 *  C. A server installed with an older version (old column names, no roundcube_ssl_chain): nothing is created, the
 *     old names become the new ones with their values, the missing column is added, saving works.
 *
 * That the test sees the defect was measured once, with a jar whose prepareAtStartup() kept the order of 0.9.0 and a
 * CREATE TABLE without roundcube_ssl_chain: A and B failed (5 checks), C passed, as on the servers already installed,
 * which never had the defect. There is no case for the old order here: with the complete CREATE TABLE of now it no
 * longer breaks anything, and a check of it would prove nothing.
 *
 * Each case runs in its own process and temporary folder: dataBaseManager works on database/daemoxcp-mail.db of the
 * current folder, the secrets with -Ddaemoxcp.mail.secrets.dir.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.sqli.FreshConfigTableTest
 */
public class FreshConfigTableTest {

    static int failed = 0;

    /** The columns the start adds after the first version: the fresh table must have them all. */
    static final Set<String> ADDED_COLUMNS = Set.of("panel_host", "panel_port", "panel_ssl_cert", "panel_ssl_cert_key",
            "panel_ssl_chain", "panel_sessions_prefix", "mail_hostname", "postfix_installed", "roundcube_domain",
            "roundcube_port", "roundcube_ssl_cert", "roundcube_ssl_key", "roundcube_ssl_chain");

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0) { child(args[0]); return; }

        System.out.println("== A. prepareAtStartup() on a new server ==");
        Path b = Files.createTempDirectory("fresh-config-b");
        try {
            String out = run(b, "new-order");
            check("the table is created", out.contains("CREATED=true"));
            check("saving the webmail settings works (" + line(out, "SAVED=") + ")", out.contains("SAVED=true"));
            check("the CA chain is read back", out.contains("CHAIN=/usr/local/etc/ssl/webmail/chain.pem"));
            Set<String> cols = columns(out);
            Set<String> missing = new TreeSet<>(ADDED_COLUMNS);
            missing.removeAll(cols);
            check("the table has every column the start adds (missing: " + missing + ")", missing.isEmpty());
            check("no line about a missing table or column", !out.contains("no such"));

            System.out.println("\n== B. A second start ==");
            String again = run(b, "second-start");
            check("nothing is created again", again.contains("CREATED=false"));
            check("the webmail settings are still there", again.contains("DOMAIN=webmail.example.test")
                    && again.contains("CHAIN=/usr/local/etc/ssl/webmail/chain.pem"));
        } finally { removeTree(b); }

        System.out.println("\n== C. A server installed with an older version ==");
        Path d = Files.createTempDirectory("fresh-config-d");
        try {
            String out = run(d, "older-server");
            check("nothing is created", out.contains("CREATED=false"));
            check("the old panel host keeps its value under the new name (" + line(out, "HOST=") + ")",
                    out.contains("HOST=old-panel.example.test"));
            check("the old webmail domain is kept", out.contains("DOMAIN=old-webmail.example.test"));
            Set<String> cols = columns(out);
            check("roundcube_ssl_chain is added", cols.contains("roundcube_ssl_chain"));
            check("no column keeps the old name", cols.stream().noneMatch(c -> c.startsWith("mail_panel_")));
            check("saving the webmail settings works", out.contains("SAVED=true"));
        } finally { removeTree(d); }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ---------------------------------------------------------------- the processes

    static void child(String step) throws Exception {
        dataBaseManager db = new dataBaseManager();
        boolean created;
        switch (step) {
            case "new-order", "second-start" -> created = db.prepareAtStartup();
            case "older-server" -> {
                // A connection of the test's own: the panel's refuses SQL outside its catalog (CatalogGuard).
                try (java.sql.Connection own = org.daemoxcp.mail.TestSql.sqlite(); Statement s = own.createStatement()) {
                    s.execute("CREATE TABLE config (id INTEGER PRIMARY KEY AUTOINCREMENT, mail_panel_port TEXT DEFAULT '2096', "
                            + "mail_panel_host TEXT DEFAULT '127.0.0.1', mail_panel_ssl_cert TEXT DEFAULT '', "
                            + "mail_panel_ssl_cert_key TEXT DEFAULT '', mail_panel_sessions_prefix TEXT DEFAULT 'mailpanel-', "
                            + "mysql_host TEXT DEFAULT '127.0.0.1', mysql_port TEXT DEFAULT '3306', mysql_user TEXT DEFAULT 'mailpanel', "
                            + "mysql_password TEXT DEFAULT '', mysql_database TEXT DEFAULT 'mailserver', "
                            + "opensmtpd_installed INTEGER DEFAULT 1, dovecot_installed INTEGER DEFAULT 1, "
                            + "rspamd_installed INTEGER DEFAULT 1, clamav_installed INTEGER DEFAULT 1, "
                            + "roundcube_installed INTEGER DEFAULT 1, roundcube_domain TEXT DEFAULT '', "
                            + "roundcube_port TEXT DEFAULT '8443', roundcube_ssl_cert TEXT DEFAULT '', roundcube_ssl_key TEXT DEFAULT '')");
                    s.execute("INSERT INTO config (mail_panel_host, roundcube_domain) VALUES ('old-panel.example.test', 'old-webmail.example.test')");
                }
                created = db.prepareAtStartup();
                try (ResultSet r = db.get_data_config()) {
                    if (r.next()) System.out.println("HOST=" + r.getString("panel_host"));
                }
                System.out.println("DOMAIN=" + db.getRoundcubeDomain());
            }
            default -> throw new IllegalArgumentException(step);
        }
        System.out.println("CREATED=" + created);
        if (!step.equals("second-start")) {
            String domain = step.equals("older-server") ? "old-webmail.example.test" : "webmail.example.test";
            System.out.println("SAVED=" + db.updateRoundcubeConfig(domain, "8443", "/usr/local/etc/ssl/webmail/cert.pem",
                    "/usr/local/etc/ssl/webmail/key.pem", "/usr/local/etc/ssl/webmail/chain.pem"));
        } else {
            System.out.println("DOMAIN=" + db.getRoundcubeDomain());
        }
        System.out.println("CHAIN=" + db.getRoundcubeSslChain());
        List<String> cols = new ArrayList<>();
        try (Statement s = db.get_connection().createStatement(); ResultSet r = s.executeQuery("PRAGMA table_info(config)")) {
            while (r.next()) cols.add(r.getString("name"));
        }
        System.out.println("COLUMNS=" + String.join(",", cols));
        System.exit(0);
    }

    // ---------------------------------------------------------------- helpers

    static String run(Path d, String step) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = List.of(java, "-Ddaemoxcp.mail.secrets.dir=" + d.resolve("secrets"),
                "-cp", SqliteSharedTest.absolute(System.getProperty("java.class.path")), FreshConfigTableTest.class.getName(), step);
        Process p = new ProcessBuilder(cmd).directory(d.toFile()).redirectErrorStream(true).start();
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor();
        for (String l : out.split("\n")) if (!l.isBlank()) System.out.println("      | " + (l.length() > 150 ? l.substring(0, 150) + "..." : l));
        if (code != 0) System.out.println("      (exit " + code + ")");
        return out;
    }

    static String line(String out, String prefix) {
        for (String l : out.split("\n")) if (l.startsWith(prefix)) return l.trim();
        return "";
    }

    static Set<String> columns(String out) {
        String l = line(out, "COLUMNS=");
        return l.isEmpty() ? Set.of() : new TreeSet<>(List.of(l.substring("COLUMNS=".length()).split(",")));
    }

    static void removeTree(Path p) throws Exception {
        SqliteSharedTest.removeTree(p);
    }
}
