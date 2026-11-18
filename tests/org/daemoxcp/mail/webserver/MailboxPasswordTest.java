package org.daemoxcp.mail.webserver;

import org.daemoxcp.mail.TestSql;

import com.sun.net.httpserver.HttpsServer;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.integration.WebmailPasswordConfig;
import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.security.PasswordVault;
import org.mindrot.jbcrypt.BCrypt;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.concurrent.Executors;

/**
 * Mailbox passwords can always be shown in the panel: what must hold.
 *
 *  - Every password the panel sets is stored twice, the bcrypt hash for Dovecot and the encrypted
 *    copy (vault); if the vault cannot encrypt, nothing is saved (no hash without its copy).
 *  - "Reveal" shows the copy only if it is still the mailbox password (checked against the hash);
 *    a missing, stale or unreadable copy gets its own message, never a wrong password.
 *  - A password left in clear text in the table (the old webmail password plugin wrote it so) is
 *    matched, and repaired at startup into hash + copy.
 *  - Webmail password changes go through /api/internal/mailbox-password: only from loopback,
 *    without proxy headers, with the webmail key; the current password is checked; hash and copy
 *    change together; wrong attempts are limited; no password in the audit log.
 *  - After a webmail login, /api/internal/mailbox-vault stores a missing or stale copy, only if
 *    the password matches the hash.
 *  - The Roundcube configuration: the old sql driver lines (with the panel's MySQL password)
 *    go away, the panel block is written once, and the file is not readable by other users.
 *
 * Usage (with the test MySQL of README.md):
 *   java -Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test \
 *        -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.MailboxPasswordTest
 */
public class MailboxPasswordTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String UA = "MailboxPasswordTest/1.0";
    static String base;
    static SSLContext trustAll;

    static HttpResponse<String> send(String method, String path, String body, String type, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA);
        for (int i = 0; i + 1 < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        if (body != null) b.header("Content-Type", type);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        try (HttpClient own = HttpClient.newBuilder().sslContext(trustAll).build()) {
            return own.send(b.build(), HttpResponse.BodyHandlers.ofString());
        }
    }

    static String form(String... kv) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            if (sb.length() > 0) sb.append('&');
            sb.append(URLEncoder.encode(kv[i], StandardCharsets.UTF_8)).append('=').append(URLEncoder.encode(kv[i + 1], StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    static String column(String col, int id) throws Exception {
        try (PreparedStatement p = TestSql.mysql().prepareStatement("SELECT " + col + " FROM mailboxes WHERE id = ?")) {
            p.setInt(1, id);
            try (ResultSet r = p.executeQuery()) {
                return r.next() ? r.getString(1) : null;
            }
        }
    }

    static void setColumn(String col, int id, String value) throws Exception {
        try (PreparedStatement p = TestSql.mysql().prepareStatement("UPDATE mailboxes SET " + col + " = ? WHERE id = ?")) {
            p.setString(1, value);
            p.setInt(2, id);
            p.executeUpdate();
        }
    }

    static String copyOf(int id) throws Exception {
        String enc = column("password_encrypted", id);
        return enc == null ? null : PasswordVault.getInstance().decrypt(enc);
    }

    public static void main(String[] args) throws Exception {
        String mysqlPort = System.getProperty("mysql.port");
        if (mysqlPort == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): this test needs the test MySQL, skipped.");
            return;
        }
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        Path dir = Files.createTempDirectory("mailbox-password");
        if (System.getProperty("daemoxcp.mail.vault.key") == null) System.setProperty("daemoxcp.mail.vault.key", dir.resolve("master.key").toString());
        Path audit = dir.resolve("audit.log");

        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "daemoxcp_mail"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(mysqlPort), System.getProperty("mysql.database", "daemoxcp_mail_test"));
        check("connected to MySQL", db.connect());
        // The schema BEFORE the entry, and the entry read back: see TestSessions.auditLogTo.
        // Written before the tables existed, it was not saved and the panel wrote to the real
        // log.
        TestSessions.auditLogTo(db, audit);
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        String[] login = TestSessions.open(db, "vault-test", UA);
        // Show password asks a recent confirmation every time: given here (the checks of the request itself are in
        // RolesTest and SeparatedPanelTest).
        TestSessions.confirm(login[0], UA);
        db.ensureMailboxPasswordVaultColumns();
        String session = "__Host-DaemoxCPMail=" + login[0] + "; __Host-lang=en";
        String csrf = login[1];

        String suffix = Long.toString(System.nanoTime() % 1_000_000);
        String domain = "vault" + suffix + ".example";
        int domainId = db.addDomain(domain, "test");

        System.out.println("\n== Hash and copy together ==");
        String first = "First-Password-2026";
        String email = "anna@" + domain;
        int id = db.addMailbox(domainId, email, first, "Anna", 512);
        check("the new mailbox has a bcrypt hash", id > 0 && column("password", id).startsWith("$2a$"));
        check("and the encrypted copy of the same password", first.equals(copyOf(id)));
        check("the hash matches the right password only", db.mailboxPasswordMatches(id, first) && !db.mailboxPasswordMatches(id, "Other-Password-2026"));
        String second = "Second-Password-2026";
        db.updateMailboxPassword(id, second);
        check("a change rewrites both", db.mailboxPasswordMatches(id, second) && second.equals(copyOf(id)));

        // The vault cannot encrypt (its public key is not one): nothing is saved
        String goodKey = org.daemoxcp.mail.security.PanelSecrets.text(org.daemoxcp.mail.security.PanelSecrets.VAULT_PUBLIC_KEY);
        org.daemoxcp.mail.security.PanelSecrets.setText(org.daemoxcp.mail.security.PanelSecrets.VAULT_PUBLIC_KEY, "AAAA");
        boolean refused = false;
        try {
            db.addMailbox(domainId, "nocopy@" + domain, "Without-Copy-2026", "", 512);
        } catch (java.sql.SQLException e) {
            refused = true;
        }
        check("vault broken: the new mailbox is refused", refused && db.getMailboxByEmail("nocopy@" + domain) == null);
        refused = false;
        try {
            db.updateMailboxPassword(id, "Third-Password-2026");
        } catch (java.sql.SQLException e) {
            refused = true;
        }
        org.daemoxcp.mail.security.PanelSecrets.setText(org.daemoxcp.mail.security.PanelSecrets.VAULT_PUBLIC_KEY, goodKey);
        check("vault broken: the change is refused and the old password stays", refused && db.mailboxPasswordMatches(id, second) && second.equals(copyOf(id)));

        System.out.println("\n== Passwords the panel did not write ==");
        String clear = "Written-By-Webmail-1";
        setColumn("password", id, clear);
        check("clear text in the column (old webmail plugin): it still matches", db.mailboxPasswordMatches(id, clear) && !db.mailboxPasswordMatches(id, "x" + clear));
        String y = "$2y$" + BCrypt.hashpw(second, BCrypt.gensalt(10)).substring(4);
        setColumn("password", id, "{BLF-CRYPT}" + y);
        check("{BLF-CRYPT}$2y$ from doveadm pw: it matches", db.mailboxPasswordMatches(id, second) && !db.mailboxPasswordMatches(id, clear));
        setColumn("password", id, "{SHA512-CRYPT}$6$abc$def");
        check("an unknown scheme: never a match", !db.mailboxPasswordMatches(id, second));

        System.out.println("\n== Repair of clear-text rows ==");
        String bobPass = "Password-Of-Bob-2026";
        int bob = db.addMailbox(domainId, "bob@" + domain, bobPass, "Bob", 512);
        setColumn("password", bob, "Plain-Text-Bob-2026");
        setColumn("password_encrypted", bob, null);
        setColumn("password", id, BCrypt.hashpw(second, BCrypt.gensalt(10)));
        int repaired = db.repairPlaintextMailboxPasswords();
        check("one row repaired (" + repaired + ")", repaired == 1);
        check("now a bcrypt hash of the same password, with its copy", column("password", bob).startsWith("$2a$")
                && db.mailboxPasswordMatches(bob, "Plain-Text-Bob-2026") && "Plain-Text-Bob-2026".equals(copyOf(bob)));
        check("the other rows untouched", db.mailboxPasswordMatches(id, second) && second.equals(copyOf(id)));
        check("a second run finds nothing", db.repairPlaintextMailboxPasswords() == 0);

        System.out.println("\n== Filling a missing copy ==");
        setColumn("password_encrypted", bob, null);
        check("wrong password: no copy", !db.fillMissingVaultCopy(bob, "Wrong-Password-2026-xx") && column("password_encrypted", bob) == null);
        check("right password: the copy is written", db.fillMissingVaultCopy(bob, "Plain-Text-Bob-2026") && "Plain-Text-Bob-2026".equals(copyOf(bob)));
        check("already the same copy: nothing written", !db.fillMissingVaultCopy(bob, "Plain-Text-Bob-2026"));

        // The real server
        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        check("test certificate", cert.waitFor() == 0);
        setColumn("password", bob, "Plain-Text-Again-26");
        SSLMailServer srv = new SSLMailServer(0, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
        // What start() runs after the managers (initializeManagers needs the real services)
        java.lang.reflect.Method repair = SSLMailServer.class.getDeclaredMethod("repairPlaintextMailboxPasswords");
        repair.setAccessible(true);
        repair.invoke(srv);
        check("the startup repair fixes a clear-text row", column("password", bob).startsWith("$2a$")
                && "Plain-Text-Again-26".equals(copyOf(bob)));
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();
        base = "https://127.0.0.1:" + https.getAddress().getPort();
        trustAll = SSLContext.getInstance("TLS");
        trustAll.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) { }
            public void checkServerTrusted(X509Certificate[] c, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());

        try {
            System.out.println("\n== Reveal ==");
            String json = "application/json";
            java.util.function.IntFunction<JSONObject> reveal = mid -> {
                try {
                    return new JSONObject(send("POST", "/api/mailbox-password", "{\"id\":" + mid + "}", json,
                            "Cookie", session, "X-CSRF-Token", csrf).body());
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            };
            JSONObject r = reveal.apply(id);
            check("the copy that matches the hash is shown", r.optBoolean("success") && second.equals(r.optString("password")));
            check("without the session token: refused", send("POST", "/api/mailbox-password", "{\"id\":" + id + "}", json,
                    "Cookie", session).statusCode() == 403);
            setColumn("password", id, BCrypt.hashpw("Changed-Elsewhere-2026", BCrypt.gensalt(10)));
            r = reveal.apply(id);
            check("hash changed elsewhere: no password, the stale-copy message", !r.optBoolean("success") && !r.has("password")
                    && r.optString("error").contains("no longer the mailbox password"));
            setColumn("password_encrypted", id, null);
            r = reveal.apply(id);
            check("no copy: the message says how it fills in", !r.optBoolean("success") && r.optString("error").contains("next time someone signs in to webmail"));
            setColumn("password_encrypted", id, "bm90LWEtdmFsaWQtYmxvYi1hdC1hbGwtMTIzNDU2Nzg5MA==");
            r = reveal.apply(id);
            check("unreadable copy: the master-key message", !r.optBoolean("success") && r.optString("error").contains("master key"));
            check("an unknown mailbox", reveal.apply(999999).optString("error").equals("Mailbox not found."));
            db.updateMailboxPassword(id, second);

            System.out.println("\n== /api/internal/mailbox-password ==");
            String type = "application/x-www-form-urlencoded";
            String key = PanelSecrets.webmailKey();
            String path = WebmailPasswordConfig.PATH;
            String change = form("user", email, "curpass", second, "newpass", "From-Webmail-2026");
            check("without the key: 404", send("POST", path, change, type).statusCode() == 404);
            check("a wrong key: 404", send("POST", path, change, type, "X-DaemoxCP-Key", key.substring(1) + "A").statusCode() == 404);
            check("through a proxy (X-Forwarded-For): 404", send("POST", path, change, type, "X-DaemoxCP-Key", key,
                    "X-Forwarded-For", "203.0.113.9").statusCode() == 404);
            check("GET with the key: 405", send("GET", path, null, type, "X-DaemoxCP-Key", key).statusCode() == 405);
            check("nothing changed so far", db.mailboxPasswordMatches(id, second));
            HttpResponse<String> wrong = send("POST", path, form("user", email, "curpass", "Not-This-One-2026", "newpass", "From-Webmail-2026"), type, "X-DaemoxCP-Key", key);
            check("wrong current password: 403, unchanged", wrong.statusCode() == 403 && db.mailboxPasswordMatches(id, second));
            HttpResponse<String> weak = send("POST", path, form("user", email, "curpass", second, "newpass", "corta"), type, "X-DaemoxCP-Key", key);
            check("new password outside the rule: 400, unchanged", weak.statusCode() == 400 && db.mailboxPasswordMatches(id, second));
            check("accented letters: 400", send("POST", path, form("user", email, "curpass", second, "newpass", "Password-café-2026"), type,
                    "X-DaemoxCP-Key", key).statusCode() == 400);
            check("a repeated field: 400", send("POST", path, change + "&newpass=Yet-Another-2026", type, "X-DaemoxCP-Key", key).statusCode() == 400);
            HttpResponse<String> ok = send("POST", path, change, type, "X-DaemoxCP-Key", key);
            check("the right one: 200 ok (what Roundcube expects)", ok.statusCode() == 200 && ok.body().equals("ok"));
            check("hash and copy are the new password", db.mailboxPasswordMatches(id, "From-Webmail-2026") && "From-Webmail-2026".equals(copyOf(id)));
            r = reveal.apply(id);
            check("and the panel shows it", r.optBoolean("success") && "From-Webmail-2026".equals(r.optString("password")));
            String log = Files.exists(audit) ? Files.readString(audit) : "";
            check("audit: the change is there, no password", log.contains("WEBMAIL_PASSWORD_CHANGED") && log.contains("WEBMAIL_PASSWORD_CHANGE_REFUSED")
                    && !log.contains("From-Webmail-2026") && !log.contains(second) && !log.contains("Not-This-One-2026"));
            for (int i = 0; i < 6; i++) send("POST", path, form("user", "bob@" + domain, "curpass", "Attempt-" + i + "-2026", "newpass", "Bobs-New-One-2026"), type, "X-DaemoxCP-Key", key);
            HttpResponse<String> limited = send("POST", path, form("user", "bob@" + domain, "curpass", "Plain-Text-Again-26", "newpass", "Bobs-New-One-2026"), type, "X-DaemoxCP-Key", key);
            check("after 5 wrong current passwords: 429 even for the right one", limited.statusCode() == 429 && db.mailboxPasswordMatches(bob, "Plain-Text-Again-26"));
            srv.webmail.resetLimits();

            System.out.println("\n== /api/internal/mailbox-vault (after a webmail login) ==");
            setColumn("password_encrypted", bob, null);
            check("without the key: 404", send("POST", "/api/internal/mailbox-vault", form("user", "bob@" + domain, "pass", "Plain-Text-Again-26"), type).statusCode() == 404);
            check("a wrong password: 200 but no copy", send("POST", "/api/internal/mailbox-vault", form("user", "bob@" + domain, "pass", "Wrong-One-2026-xyz"), type,
                    "X-DaemoxCP-Key", key).statusCode() == 200 && column("password_encrypted", bob) == null);
            check("the right password: the copy is stored", send("POST", "/api/internal/mailbox-vault", form("user", "bob@" + domain, "pass", "Plain-Text-Again-26"), type,
                    "X-DaemoxCP-Key", key).statusCode() == 200 && "Plain-Text-Again-26".equals(copyOf(bob)));
            check("an unknown mailbox: 200, nothing to do", send("POST", "/api/internal/mailbox-vault", form("user", "nobody@" + domain, "pass", "Something-2026-xx"), type,
                    "X-DaemoxCP-Key", key).statusCode() == 200);
            check("audit: copy stored, no password", Files.readString(audit).contains("MAILBOX_PASSWORD_COPY_STORED")
                    && !Files.readString(audit).contains("Plain-Text-Again-26"));

            String rc = System.getProperty("roundcube.dir");
            if (rc == null) {
                System.out.println("\n(Roundcube's real code skipped: -Droundcube.dir=<roundcubemail-1.6.x-complete> and php run it)");
            } else {
                System.out.println("\n== Roundcube's real code (httpapi driver, daemoxcp_mail_sso hook) ==");
                int port = https.getAddress().getPort();
                Path config = dir.resolve("rc-config.inc.php");
                Files.writeString(config, WebmailPasswordConfig.apply("<?php\n$config['password_driver'] = 'sql';\n", port, key));
                Path plugin = dir.resolve("daemoxcp_mail_sso.php");
                Files.writeString(plugin, org.daemoxcp.mail.integration.RoundcubeSsoManager.generatePluginPhp());
                setColumn("password_encrypted", id, null);
                Process php = new ProcessBuilder("php", "tests/webmail-roundcube-test.php", rc, config.toString(), plugin.toString(),
                        email, "From-Webmail-2026", "Real-Roundcube-2026", base + "/api/internal/mailbox-vault", key)
                        .redirectErrorStream(true).start();
                String out = new String(php.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                int exit = php.waitFor();
                System.out.println(out.indent(4).stripTrailing());
                check("php ran the driver and the hook", exit == 0 && out.contains("hook_unreachable:done"));
                check("the panel's block selects httpapi (the old sql line is gone)", out.contains("driver:httpapi"));
                check("a wrong current password: PASSWORD_ERROR (2), unchanged", out.contains("wrong_current:2") && !db.mailboxPasswordMatches(id, "Another-New-2026"));
                check("the change: PASSWORD_SUCCESS (0), hash is the new password", out.contains("change:0") && db.mailboxPasswordMatches(id, "Real-Roundcube-2026"));
                check("the copy too (written by the change, then confirmed by the login hook)", "Real-Roundcube-2026".equals(copyOf(id)));
                check("panel unreachable: the login goes on, one line in the log without the password",
                        out.contains("log:daemoxcp_mail_sso: DaemoxCP Mail did not answer") && !out.contains("Real-Roundcube-2026"));
                setColumn("password_encrypted", id, null);
                Process again = new ProcessBuilder("php", "tests/webmail-roundcube-test.php", rc, config.toString(), plugin.toString(),
                        email, "Real-Roundcube-2026", "Real-Roundcube-2026", base + "/api/internal/mailbox-vault", key)
                        .redirectErrorStream(true).start();
                again.getInputStream().readAllBytes();
                again.waitFor();
                check("a missing copy is filled by the login hook alone", "Real-Roundcube-2026".equals(copyOf(id)));
            }
        } finally {
            https.stop(0);
            db.deleteMailbox(id);
            db.deleteMailbox(bob);
        }

        System.out.println("\n== The Roundcube configuration ==");
        String key = PanelSecrets.webmailKey();
        String old = "<?php\n$config['db_dsnw'] = 'mysql://roundcube:pw@127.0.0.1/roundcubemail';\n"
                + "$config['plugins'] = ['archive', 'password'];\n"
                + "// Password plugin (change password from webmail)\n"
                + "$config['password_driver'] = 'sql';\n"
                + "$config['password_db_dsn'] = 'mysql://mailpanel:Segreta123@127.0.0.1/mailpanel';\n"
                + "$config['password_query'] = 'UPDATE mailboxes SET password=%P WHERE email=%u';\n"
                + "$config['password_crypt_hash'] = 'blowfish';\n"
                + "$config['password_minimum_length'] = 12;\n"
                + "$config['managesieve_port'] = 4190;\n";
        String fixed = WebmailPasswordConfig.apply(old, 2096, key);
        check("the sql driver and the panel's MySQL password are gone", !fixed.contains("Segreta123") && !fixed.contains("'sql'")
                && !fixed.contains("password_query") && !fixed.contains("password_crypt_hash"));
        check("the rest stays", fixed.contains("db_dsnw") && fixed.contains("'archive', 'password'") && fixed.contains("managesieve_port"));
        check("the httpapi block points to the panel on loopback with the key", fixed.contains("'httpapi'")
                && fixed.contains("'https://127.0.0.1:2096/api/internal/mailbox-password'") && fixed.contains("'X-DaemoxCP-Key' => '" + key + "'")
                && fixed.contains("$config['password_httpapi_expect'] = '/^ok$/';"));
        check("applying again changes nothing (one block)", WebmailPasswordConfig.apply(fixed, 2096, key).equals(fixed)
                && fixed.split("password_driver", -1).length == 2);
        check("a new port replaces the block", WebmailPasswordConfig.apply(fixed, 2097, key).contains("127.0.0.1:2097")
                && !WebmailPasswordConfig.apply(fixed, 2097, key).contains("127.0.0.1:2096"));
        check("a closing ?> does not leave the block outside PHP", !WebmailPasswordConfig.apply(old + "?>\n", 2096, key).contains("?>"));
        boolean badKey = false;
        try { WebmailPasswordConfig.apply(old, 2096, "x'; system('id'); //"); } catch (IllegalArgumentException e) { badKey = true; }
        check("a key that is not base64url is refused", badKey);
        Path rc = dir.resolve("config.inc.php");
        Files.writeString(rc, old);
        Files.setPosixFilePermissions(rc, PosixFilePermissions.fromString("rw-r--r--"));
        check("ensure() rewrites the file once", WebmailPasswordConfig.ensure(rc, 2096, key) && !WebmailPasswordConfig.ensure(rc, 2096, key));
        java.util.Set<PosixFilePermission> perms = Files.getPosixFilePermissions(rc);
        check("the file is no longer readable by other users (" + PosixFilePermissions.toString(perms) + ")",
                !perms.contains(PosixFilePermission.OTHERS_READ) && perms.contains(PosixFilePermission.OWNER_READ));

        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
