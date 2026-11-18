package org.daemoxcp.mail.webserver;

import com.sun.net.httpserver.HttpsServer;
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
import java.util.concurrent.Executors;

/**
 * /api/versions and /api/service on the REAL server (SSLMailServer), over HTTPS, with a session like
 * the login's and the test MySQL. Nothing else of the panel starts: only the HTTP server with its
 * routes is switched on, without the handlers (ACME, DKIM, report) that would touch the system.
 *
 * It checks: without a session 401; with the session the versions, with MySQL read from the real
 * server; the read kept thirty seconds and "fresh" that does not read again before three; wrong
 * parameters and methods refused; /api/service without a CSRF token or with a wrong token 403,
 * written to the audit log; with the right token the request passes (and an unknown service is
 * 400); an action on a service ends up in the log and makes the versions be read again.
 *
 * The service used for the action is redis, and the outcome of the restart is NOT required: redis
 * is installed by this same panel's installer, so on a machine with the mail server installed that
 * restart succeeds, while on a bare machine it fails. What is required instead is the thing that
 * must always hold: that the response and the audit log say the same outcome.
 *
 * Usage (with the test MySQL of README.md; it prepares the schema by itself):
 *   java -Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test \
 *        -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.VersionsApiTest
 */
public class VersionsApiTest {

    static int failed = 0;

    static void real(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static HttpClient http;
    static String base, code;
    static final String UA = "VersionsApiTest/1.0";

    static HttpResponse<String> ask(String method, String path, String body, boolean withSession) throws Exception {
        return ask(http, method, path, body, withSession);
    }

    static HttpResponse<String> ask(HttpClient client, String method, String path, String body, boolean withSession) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA);
        if (withSession) b.header("Cookie", "__Host-DaemoxCPMail=" + code);
        if (body != null) b.header("Content-Type", "application/json");
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * A POST the server answers before reading its body (405, 401: as in the whole panel) on a
     * connection of its own. On the shared connection the next request sometimes found the socket
     * closed by the server and the client, on a POST, does not retry: "HTTP/1.1 header parser
     * received no bytes", once in twenty. It is not what is being tested.
     */
    static HttpResponse<String> askSeparately(String method, String path, String body, boolean withSession) throws Exception {
        try (HttpClient onlyOne = HttpClient.newBuilder().sslContext(http.sslContext()).build()) {
            return ask(onlyOne, method, path, body, withSession);
        }
    }

    /**
     * The outcome the log gives to that action: the panel writes {@code service=<name>} and adds
     * {@code (failed)} only if it did not succeed (SSLMailServer, "service=" + service + (success ?
     * "" : " (failed)")). So the absence of that word IS the "succeeded", and it must be read on the
     * line, not on the whole file: a {@code contains("service=redis")} would also be true for
     * "service=redis (failed)".
     */
    static boolean outcomeInRegistry(Path log, String action) throws Exception {
        for (String line : Files.readString(log).split("\n"))
            if (line.contains(action)) return !line.contains("(failed)");
        throw new IllegalStateException("the log has no line " + action);
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
            System.out.println("MySQL not given (-Dmysql.port=...): this test needs the test MySQL, skipped.");
            return;
        }
        // Before creating the client: the test certificate is for localhost, it is called as 127.0.0.1.
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        Path folder = Files.createTempDirectory("versions-api");
        Path log = folder.resolve("audit.log");

        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "daemoxcp_mail"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "daemoxcp_mail_test"));
        real("connection to MySQL", db.connect());
        // The schema BEFORE the entry, and the entry read back: see TestSessions.auditLogTo.
        // Written before the tables existed, it was not saved and the panel wrote to the real
        // log.
        TestSessions.auditLogTo(db, log);
        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        String[] login = TestSessions.open(db, "versions-test", UA);
        // Restarting a service is a dangerous operation: it asks a recent confirmation, given here.
        TestSessions.confirm(login[0], UA);
        code = login[0];
        String csrf = login[1];

        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", folder.resolve("k.pem").toString(), "-out", folder.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        real("test certificate", cert.waitFor() == 0);
        SSLMailServer srv = new SSLMailServer(0, Files.readString(folder.resolve("c.pem")), Files.readString(folder.resolve("k.pem")));
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();
        base = "https://127.0.0.1:" + https.getAddress().getPort();

        SSLContext trusted = SSLContext.getInstance("TLS");
        trusted.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) { }
            public void checkServerTrusted(X509Certificate[] c, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        http = HttpClient.newBuilder().sslContext(trusted).build();

        try {
            System.out.println("\n== /api/versions ==");
            real("without a session: 401", ask("GET", "/api/versions", null, false).statusCode() == 401);
            HttpResponse<String> r = ask("GET", "/api/versions", null, true);
            JSONObject j = new JSONObject(r.body());
            String mysql = db.serverVersion();
            JSONObject line = j.getJSONObject("services").getJSONObject("mysql");
            real("with the session: 200 and the seven service rows", r.statusCode() == 200 && j.getBoolean("success")
                    && j.getJSONObject("services").length() == 7);
            real("MySQL read from the real server, running: " + line.optString("version"),
                    mysql != null && mysql.equals(line.optString("version")) && line.optBoolean("running"));
            String read = j.getString("readAt");
            real("second request: the same read (" + read + ")",
                    new JSONObject(ask("GET", "/api/versions", null, true).body()).getString("readAt").equals(read));
            real("\"fresh\" within three seconds: the same read",
                    new JSONObject(ask("GET", "/api/versions?fresh=1", null, true).body()).getString("readAt").equals(read));
            real("fresh=2: 400", ask("GET", "/api/versions?fresh=2", null, true).statusCode() == 400);
            // The CSRF token is looked at first of all (every route's filter): without it, 403; with it, the handler's 405
            real("POST without the CSRF token: 403", askSeparately("POST", "/api/versions", "{}", true).statusCode() == 403);
            real("POST with the token: 405", askSeparately("POST", "/api/versions", "{\"csrf_token\":\"" + csrf + "\"}", true).statusCode() == 405);

            System.out.println("\n== /api/service: the CSRF token ==");
            HttpResponse<String> without = ask("POST", "/api/service", "{\"service\":\"redis\",\"action\":\"stop\"}", true);
            real("without a token: 403", without.statusCode() == 403);
            real("with a wrong token: 403", ask("POST", "/api/service",
                    "{\"service\":\"redis\",\"action\":\"stop\",\"csrf_token\":\"wrong\"}", true).statusCode() == 403);
            // sendCsrfError answers and THEN writes the log: it waits for the line, two seconds at most.
            real("and the audit log says so (CSRF_FAILURE)", waitForLine(log, "CSRF_FAILURE"));
            HttpResponse<String> unknown = ask("POST", "/api/service",
                    "{\"service\":\"sshd\",\"action\":\"stop\",\"csrf_token\":\"" + csrf + "\"}", true);
            real("with the right token it passes: a service not governed from here is 400", unknown.statusCode() == 400
                    && unknown.body().contains("Invalid service"));
            real("without a session, even with the token: 401", askSeparately("POST", "/api/service",
                    "{\"service\":\"redis\",\"action\":\"restart\",\"csrf_token\":\"" + csrf + "\"}", false).statusCode() == 401);

            System.out.println("\n== An action: the log and the versions read again ==");
            Thread.sleep(1100);   // readAt has the seconds: a new read must be told apart
            HttpResponse<String> action = ask("POST", "/api/service",
                    "{\"service\":\"redis\",\"action\":\"restart\",\"csrf_token\":\"" + csrf + "\"}", true);
            // It is not required that redis FAILS. It used to be, with the comment "redis is not
            // here": but redis is installed by this same panel's installer, and on a machine with
            // the mail server installed "service redis restart" succeeds. Two checks out of two
            // fell, on a defect that was not there.
            //
            // The real invariant is another, and it holds on any machine: the response and the log
            // must say THE SAME THING. If they diverged, whoever reads the audit log would believe
            // successful what failed, or the other way round.
            boolean succeeded = new JSONObject(action.body()).getBoolean("success");
            real("redis restart: response 200, outcome " + (succeeded ? "succeeded" : "not succeeded")
                    + " (it depends on this machine, and that is fine)", action.statusCode() == 200);
            real("the log has redis's SERVICE_RESTART", waitForLine(log, "SERVICE_RESTART")
                    && waitForLine(log, "service=redis"));
            real("and the log says the SAME outcome as the response",
                    outcomeInRegistry(log, "SERVICE_RESTART") == succeeded);
            String after = new JSONObject(ask("GET", "/api/versions", null, true).body()).getString("readAt");
            real("after the action the versions are read again, even without fresh: " + after, !after.equals(read));
        } finally {
            https.stop(0);
            db.close();
            Files.deleteIfExists(log);
            Files.deleteIfExists(folder.resolve("k.pem"));
            Files.deleteIfExists(folder.resolve("c.pem"));
            Files.deleteIfExists(folder);
        }

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
