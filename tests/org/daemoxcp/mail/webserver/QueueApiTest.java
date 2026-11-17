package org.daemoxcp.mail.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.monitoring.MailQueueManager;
import org.daemoxcp.mail.util.Shell;

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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executors;

/**
 * /api/queue on the REAL server (SSLMailServer), over HTTPS, with a session like the login one
 * and the test MySQL. The queue manager runs with a fake command runner: Postfix is not here, and
 * the point is to see exactly which commands the requests would start.
 *
 * Checked: without a session 401; the list with the deferral reason, the state and the arrival in
 * UTC; a queue ID with shell characters refused before any command (it used to go into sh -c);
 * every POST without the CSRF token or with a wrong one 403 and nothing run; with the token the
 * delete runs postsuper with the ID as one argument and lands in the audit log; deleting the
 * permanent failures needs the IDs seen and their number, and touches only those; the messages
 * in the request language.
 *
 * Usage (with the test MySQL of README.md):
 *   java -Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test \
 *        -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.QueueApiTest
 */
public class QueueApiTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static HttpClient http;
    static String base, session;
    static final String UA = "QueueApiTest/1.0";

    static HttpResponse<String> send(String method, String path, String body, String cookies) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA);
        if (cookies != null) b.header("Cookie", cookies);
        if (body != null) b.header("Content-Type", "application/json");
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        // a connection of its own each time: the server may answer before reading the body
        try (HttpClient own = HttpClient.newBuilder().sslContext(http.sslContext()).build()) {
            return own.send(b.build(), HttpResponse.BodyHandlers.ofString());
        }
    }

    static boolean waitForLine(Path log, String text) throws Exception {
        for (int i = 0; i < 40; i++) {
            if (Files.exists(log) && Files.readString(log).contains(text)) return true;
            Thread.sleep(50);
        }
        return false;
    }

    /** Records every command; answers postqueue -j with the queue below and postsuper -d as removed. */
    static final List<List<String>> commands = Collections.synchronizedList(new ArrayList<>());

    static final String QUEUE =
        "{\"queue_name\": \"deferred\", \"queue_id\": \"3A1F2B4C5D\", \"arrival_time\": 1760090400, \"message_size\": 2048, "
      + "\"sender\": \"news@example.org\", \"recipients\": [{\"address\": \"gone@example.com\", "
      + "\"delay_reason\": \"host mx.example.com said: 550 5.1.1 <gone@example.com>: unknown user\"}]}\n"
      + "{\"queue_name\": \"deferred\", \"queue_id\": \"4Nq8Zk1yQPz9Lm2\", \"arrival_time\": 1760094000, \"message_size\": 512, "
      + "\"sender\": \"<img src=x onerror=alert(1)>@example.org\", \"recipients\": [{\"address\": \"b@example.net\", "
      + "\"delay_reason\": \"connect to mx.example.net[198.51.100.7]:25: Connection timed out\"}]}\n";

    static Shell.Result fake(String... cmd) {
        commands.add(List.of(cmd));
        String program = cmd[0].substring(cmd[0].lastIndexOf('/') + 1);
        if (program.equals("postqueue") && cmd[1].equals("-j")) return new Shell.Result(0, QUEUE, false, List.of(cmd));
        if (program.equals("postsuper") && cmd[1].equals("-d")) {
            return new Shell.Result(0, "postsuper: " + cmd[2] + ": removed\npostsuper: Deleted: 1 message\n", false, List.of(cmd));
        }
        return new Shell.Result(0, "", false, List.of(cmd));
    }

    static boolean postsuperRan() {
        synchronized (commands) {
            return commands.stream().anyMatch(c -> c.get(0).endsWith("/postsuper"));
        }
    }

    public static void main(String[] args) throws Exception {
        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): this test needs the test MySQL, skipped.");
            return;
        }
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        Path dir = Files.createTempDirectory("queue-api");
        Path audit = dir.resolve("audit.log");

        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "daemoxcp_mail"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "daemoxcp_mail_test"));
        check("connected to MySQL", db.connect());
        // The schema BEFORE the entry, and the entry read back: see TestSessions.auditLogTo.
        // Written before the tables existed, it was not saved and the panel wrote to the real
        // log.
        TestSessions.auditLogTo(db, audit);
        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        String[] login = TestSessions.open(db, "queue-test", UA);
        session = login[0];
        String csrf = login[1];
        String it = "__Host-DaemoxCPMail=" + session + "; __Host-lang=it";
        String en = "__Host-DaemoxCPMail=" + session + "; __Host-lang=en";

        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        check("test certificate", cert.waitFor() == 0);
        SSLMailServer srv = new SSLMailServer(0, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
        Field qm = SSLMailServer.class.getDeclaredField("queueManager");
        qm.setAccessible(true);
        qm.set(srv, new MailQueueManager(QueueApiTest::fake));
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();
        base = "https://127.0.0.1:" + https.getAddress().getPort();

        SSLContext trustAll = SSLContext.getInstance("TLS");
        trustAll.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) { }
            public void checkServerTrusted(X509Certificate[] c, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        http = HttpClient.newBuilder().sslContext(trustAll).build();

        try {
            System.out.println("\n== Reading ==");
            check("without a session: 401", send("GET", "/api/queue", null, null).statusCode() == 401);
            JSONObject list = new JSONObject(send("GET", "/api/queue", null, it).body());
            JSONArray msgs = list.optJSONArray("messages");
            check("the list: two messages", list.optBoolean("success") && msgs != null && msgs.length() == 2);
            JSONObject first = msgs.getJSONObject(0);
            check("ID, state, arrival in UTC with the Z", first.getString("id").equals("3A1F2B4C5D")
                    && first.getString("state").equals("DEFERRED") && first.getString("arrival").equals("2025-10-10T10:00:00Z"));
            check("the deferral reason and the permanent flag", first.getString("error").contains("550 5.1.1")
                    && first.getBoolean("permanent") && !msgs.getJSONObject(1).getBoolean("permanent"));
            check("the sender comes as plain text (the page escapes it)",
                    msgs.getJSONObject(1).getString("sender").equals("<img src=x onerror=alert(1)>@example.org"));
            JSONObject stats = new JSONObject(send("GET", "/api/queue?action=stats", null, it).body());
            check("statistics: total, deferred, permanent", stats.getInt("total") == 2 && stats.getInt("deferred") == 2
                    && stats.getInt("permanent") == 1 && stats.getInt("hold") == 0);

            System.out.println("\n== A queue ID with shell characters ==");
            commands.clear();
            JSONObject bad = new JSONObject(send("GET", "/api/queue?action=message&id=3A1F%3Btouch%20%2Ftmp%2Fowned", null, en).body());
            check("refused: " + bad.optString("error"), !bad.optBoolean("success") && bad.optString("error").equals("Invalid queue ID."));
            check("and no command started", commands.isEmpty());

            System.out.println("\n== The CSRF token ==");
            for (String body : new String[]{
                    "{\"action\":\"remove\",\"id\":\"3A1F2B4C5D\"}",
                    "{\"action\":\"remove\",\"id\":\"3A1F2B4C5D\",\"csrf_token\":\"wrong\"}",
                    "{\"action\":\"flush\"}", "{\"action\":\"hold\"}", "{\"action\":\"release\"}",
                    "{\"action\":\"purge_permfails\",\"ids\":[\"3A1F2B4C5D\"],\"confirm\":\"1\"}"}) {
                HttpResponse<String> r = send("POST", "/api/queue", body, it);
                check("403 for " + body, r.statusCode() == 403);
            }
            check("nothing run", commands.isEmpty());
            check("the refusal is in the audit log (CSRF_FAILURE)", waitForLine(audit, "CSRF_FAILURE"));

            System.out.println("\n== With the token ==");
            JSONObject removed = new JSONObject(send("POST", "/api/queue",
                    "{\"action\":\"remove\",\"id\":\"3A1F2B4C5D\",\"csrf_token\":\"" + csrf + "\"}", en).body());
            check("deleted: " + removed.optString("message"), removed.optBoolean("success")
                    && removed.optString("message").equals("Message 3A1F2B4C5D deleted from the queue."));
            check("postsuper -d with the ID as one argument", commands.contains(List.of("/usr/local/sbin/postsuper", "-d", "3A1F2B4C5D")));
            check("in the audit log: QUEUE_REMOVE", waitForLine(audit, "QUEUE_REMOVE"));
            commands.clear();
            JSONObject inj = new JSONObject(send("POST", "/api/queue",
                    "{\"action\":\"remove\",\"id\":\"3A1F2B4C5D; rm -rf /\",\"csrf_token\":\"" + csrf + "\"}", it).body());
            check("a bad ID with the token: refused in Italian (" + inj.optString("message") + ")", !inj.optBoolean("success")
                    && inj.optString("message").equals(org.daemoxcp.mail.i18n.I18n.t("it", "server.queue.badId")) && !postsuperRan());
            JSONObject unknown = new JSONObject(send("POST", "/api/queue",
                    "{\"action\":\"purge_deferred\",\"csrf_token\":\"" + csrf + "\"}", en).body());
            check("an action that no longer exists: refused", !unknown.optBoolean("success")
                    && unknown.optString("error").equals("Unknown action.") && !postsuperRan());

            System.out.println("\n== Deleting the permanent failures ==");
            JSONObject preview = new JSONObject(send("POST", "/api/queue",
                    "{\"action\":\"purge_permfails\",\"csrf_token\":\"" + csrf + "\"}", en).body());
            check("the preview: one message, nothing deleted (" + preview.optString("message") + ")", preview.optBoolean("preview")
                    && preview.getInt("count") == 1 && preview.getJSONArray("messages").getJSONObject(0).getString("id").equals("3A1F2B4C5D")
                    && !postsuperRan());
            JSONObject wrong = new JSONObject(send("POST", "/api/queue",
                    "{\"action\":\"purge_permfails\",\"ids\":[\"3A1F2B4C5D\",\"4Nq8Zk1yQPz9Lm2\"],\"confirm\":\"1\",\"csrf_token\":\"" + csrf + "\"}", en).body());
            check("the number typed does not match the IDs: nothing deleted", !wrong.optBoolean("success")
                    && wrong.optString("error").startsWith("Invalid confirmation") && !postsuperRan());
            JSONObject purged = new JSONObject(send("POST", "/api/queue",
                    "{\"action\":\"purge_permfails\",\"ids\":[\"3A1F2B4C5D\",\"4Nq8Zk1yQPz9Lm2\"],\"confirm\":\"2\",\"csrf_token\":\"" + csrf + "\"}", en).body());
            List<List<String>> deletions;
            synchronized (commands) {
                deletions = commands.stream().filter(c -> c.get(0).endsWith("/postsuper")).toList();
            }
            check("only the permanent one is deleted, the temporary one stays: " + deletions,
                    purged.optBoolean("success") && deletions.equals(List.of(List.of("/usr/local/sbin/postsuper", "-d", "3A1F2B4C5D"))));
            check("in the audit log: QUEUE_PURGE_PERMFAILS", waitForLine(audit, "QUEUE_PURGE_PERMFAILS"));
        } finally {
            https.stop(0);
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
