package org.daemoxcp.mail.webserver;

import org.daemoxcp.mail.TestSql;

import com.sun.net.httpserver.HttpsServer;
import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.concurrent.Executors;

/**
 * /api/ratelimits on the REAL server (SSLMailServer), over HTTPS, with a session like the login
 * one and the test MySQL.
 *
 * Checked: without a session 401; every POST without the CSRF token 403; zero and a daily limit
 * below the hourly one refused with the reason; saving the global limits again UPDATES the one
 * global row (with target_id NULL, MySQL's UNIQUE index let every save add a row) and removes the
 * NULL rows left from before; a mailbox limit created, updated in place and deleted with the
 * action names and fields the page sends (it used to send create/update/id, which the server
 * did not know: no mailbox limit could be created or deleted); everything in the audit log.
 *
 * Usage (with the test MySQL of README.md):
 *   java -Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_test \
 *        -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.webserver.RateLimitsApiTest
 */
public class RateLimitsApiTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static HttpClient http;
    static String base;
    static final String UA = "RateLimitsApiTest/1.0";

    static HttpResponse<String> send(String method, String path, String body, String cookies) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA);
        if (cookies != null) b.header("Cookie", cookies);
        if (body != null) b.header("Content-Type", "application/json");
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        try (HttpClient own = HttpClient.newBuilder().sslContext(http.sslContext()).build()) {
            return own.send(b.build(), HttpResponse.BodyHandlers.ofString());
        }
    }

    static JSONObject post(String body, String cookies) throws Exception {
        return new JSONObject(send("POST", "/api/ratelimits", body, cookies).body());
    }

    static int count(Connection c, String sql) throws Exception {
        try (Statement st = c.createStatement(); ResultSet r = st.executeQuery(sql)) {
            r.next();
            return r.getInt(1);
        }
    }

    static boolean waitForLine(Path log, String text) throws Exception {
        for (int i = 0; i < 40; i++) {
            if (Files.exists(log) && Files.readString(log).contains(text)) return true;
            Thread.sleep(50);
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): this test needs the test MySQL, skipped.");
            return;
        }
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        Path dir = Files.createTempDirectory("ratelimits-api");
        Path audit = dir.resolve("audit.log");

        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "mailpanel_test"));
        check("connected to MySQL", db.connect());
        // The schema BEFORE the entry, and the entry read back: see TestSessions.auditLogTo.
        // Written before the tables existed, it was not saved and the panel wrote to the real
        // log.
        TestSessions.auditLogTo(db, audit);
        Connection c = TestSql.mysql();
        try (Statement st = c.createStatement()) {
            st.executeUpdate("DELETE FROM rate_limits");
        }
        MailDatabase.Domain dom = db.getDomainByName("ratelimits.example");
        int domainId = dom != null ? dom.id : db.addDomain("ratelimits.example", "test");
        MailDatabase.Mailbox box = db.getMailboxByEmail("box@ratelimits.example");
        int mailboxId = box != null ? box.id : db.addMailbox(domainId, "box@ratelimits.example", "A-long-test-password-42", "Box", 100);
        // A global row as the old code left it: target_id NULL
        try (Statement st = c.createStatement()) {
            st.executeUpdate("INSERT INTO rate_limits (target_type, target_id, max_per_hour, max_per_day) VALUES ('global', NULL, 10, 100)");
            st.executeUpdate("INSERT INTO rate_limits (target_type, target_id, max_per_hour, max_per_day) VALUES ('global', NULL, 11, 110)");
        }

        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        String[] login = TestSessions.open(db, "ratelimits-test", UA);
        String session = login[0];
        String csrf = login[1];
        String en = "__Host-DaemoxCPMail=" + session + "; __Host-lang=en";
        String tok = ",\"csrf_token\":\"" + csrf + "\"}";

        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        check("test certificate", cert.waitFor() == 0);
        SSLMailServer srv = new SSLMailServer(0, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();
        base = "https://127.0.0.1:" + https.getAddress().getPort();

        SSLContext trustAll = SSLContext.getInstance("TLS");
        trustAll.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] x, String a) { }
            public void checkServerTrusted(X509Certificate[] x, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        http = HttpClient.newBuilder().sslContext(trustAll).build();

        try {
            System.out.println("\n== Session and CSRF ==");
            check("without a session: 401", send("GET", "/api/ratelimits", null, null).statusCode() == 401);
            for (String body : new String[]{"{\"action\":\"save_global\",\"hourly\":5,\"daily\":50}",
                    "{\"action\":\"save_mailbox\",\"mailbox_id\":" + mailboxId + ",\"hourly\":5,\"daily\":50}",
                    "{\"action\":\"delete\",\"id\":1,\"csrf_token\":\"wrong\"}"}) {
                check("403 for " + body, send("POST", "/api/ratelimits", body, en).statusCode() == 403);
            }
            check("nothing saved", count(c, "SELECT COUNT(*) FROM rate_limits WHERE target_type='global' AND target_id IS NOT NULL") == 0);

            System.out.println("\n== Global limits ==");
            JSONObject zero = post("{\"action\":\"save_global\",\"hourly\":0,\"daily\":50" + tok, en);
            check("zero refused: " + zero.optString("error"), !zero.optBoolean("success") && zero.optString("error").startsWith("The hourly and daily limits must be at least 1"));
            JSONObject low = post("{\"action\":\"save_global\",\"hourly\":100,\"daily\":50" + tok, en);
            check("daily below hourly refused: " + low.optString("error"), !low.optBoolean("success") && low.optString("error").contains("(50)"));
            JSONObject g1 = post("{\"action\":\"save_global\",\"hourly\":20,\"daily\":200" + tok, en);
            check("saved: " + g1.optString("message"), g1.optBoolean("success") && g1.optString("message").equals("Global limits saved: 20 per hour, 200 per day."));
            JSONObject g2 = post("{\"action\":\"save_global\",\"hourly\":30,\"daily\":300" + tok, en);
            check("saved again", g2.optBoolean("success"));
            check("ONE global row, target_id 0, with the new values; the NULL rows gone",
                    count(c, "SELECT COUNT(*) FROM rate_limits WHERE target_type='global'") == 1
                    && count(c, "SELECT COUNT(*) FROM rate_limits WHERE target_type='global' AND target_id=0 AND max_per_hour=30 AND max_per_day=300") == 1);
            JSONObject read = new JSONObject(send("GET", "/api/ratelimits", null, en).body());
            check("read back: 30 and 300", read.getJSONObject("global").getInt("hourly") == 30 && read.getJSONObject("global").getInt("daily") == 300);
            check("in the audit log: RATELIMIT_GLOBAL", waitForLine(audit, "RATELIMIT_GLOBAL"));

            System.out.println("\n== A mailbox limit ==");
            JSONObject none = post("{\"action\":\"save_mailbox\",\"mailbox_id\":0,\"hourly\":5,\"daily\":50" + tok, en);
            check("no mailbox: " + none.optString("error"), !none.optBoolean("success") && none.optString("error").equals("Choose a mailbox."));
            JSONObject m1 = post("{\"action\":\"save_mailbox\",\"mailbox_id\":" + mailboxId + ",\"hourly\":5,\"daily\":50,\"enabled\":true" + tok, en);
            check("created: " + m1.optString("message"), m1.optBoolean("success"));
            JSONObject m2 = post("{\"action\":\"save_mailbox\",\"mailbox_id\":" + mailboxId + ",\"hourly\":7,\"daily\":70,\"enabled\":false" + tok, en);
            check("saved again: updated in place, one row", m2.optBoolean("success")
                    && count(c, "SELECT COUNT(*) FROM rate_limits WHERE target_type='mailbox' AND target_id=" + mailboxId) == 1
                    && count(c, "SELECT COUNT(*) FROM rate_limits WHERE target_type='mailbox' AND max_per_hour=7 AND max_per_day=70 AND enabled=0") == 1);
            JSONArray limits = new JSONObject(send("GET", "/api/ratelimits", null, en).body()).getJSONArray("limits");
            JSONObject row = limits.getJSONObject(0);
            check("the list shows it with the mailbox address", limits.length() == 1 && row.getString("email").equals("box@ratelimits.example")
                    && row.getInt("hourly_limit") == 7 && !row.getBoolean("enabled") && row.getInt("target_id") == mailboxId);
            check("in the audit log: RATELIMIT_MAILBOX", waitForLine(audit, "RATELIMIT_MAILBOX"));
            JSONObject del = post("{\"action\":\"delete\",\"id\":" + row.getInt("id") + tok, en);
            check("deleted", del.optBoolean("success") && count(c, "SELECT COUNT(*) FROM rate_limits WHERE target_type='mailbox'") == 0);
            JSONObject again = post("{\"action\":\"delete\",\"id\":" + row.getInt("id") + tok, en);
            check("deleted again: an error that says why", !again.optBoolean("success") && again.optString("error").startsWith("Could not delete the limit"));
            check("in the audit log: RATELIMIT_DELETE", waitForLine(audit, "RATELIMIT_DELETE"));
            JSONObject unknown = post("{\"action\":\"create\",\"mailbox_id\":" + mailboxId + tok, en);
            check("an old action name: refused", !unknown.optBoolean("success") && unknown.optString("error").equals("Unknown action."));
        } finally {
            https.stop(0);
            try (PreparedStatement p = c.prepareStatement("DELETE FROM rate_limits")) {
                p.executeUpdate();
            }
            db.close();
            Files.deleteIfExists(audit);
            Files.deleteIfExists(dir.resolve("k.pem"));
            Files.deleteIfExists(dir.resolve("c.pem"));
            Files.deleteIfExists(dir);
        }

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
