package org.mail_panel.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.mail_panel.Main;
import org.mail_panel.database.MailDatabase;

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
 * The CSRF token checked once for every route (the filter in SSLMailServer.context), on the REAL
 * server, over HTTPS, with a session like the login one and the test MySQL.
 *
 * Twenty-five authenticated routes accepted POST without asking for the token. The probe is
 * /api/timezone-diag, one of them, with a request the handler refuses without touching anything
 * ("set" with an empty value): without the token 403, with the X-CSRF-Token header or the
 * csrf_token field it reaches the handler, and the body read to look for the token is still
 * there for the handler. A wrong header 403 even with a right body token. Without a session the
 * handler answers (401). GET untouched. The routes used before logging in are not blocked.
 * Every refusal in the audit log.
 *
 * Usage (with the test MySQL of README.md):
 *   java -Dmysql.porta=33062 -Dmysql.utente=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova \
 *        -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.CsrfFilterTest
 */
public class CsrfFilterTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static HttpClient http;
    static String base;
    static final String UA = "CsrfFilterTest/1.0";

    static HttpResponse<String> send(String method, String path, String body, String cookies, String token) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA);
        if (cookies != null) b.header("Cookie", cookies);
        if (token != null) b.header("X-CSRF-Token", token);
        if (body != null) b.header("Content-Type", "application/json");
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        try (HttpClient own = HttpClient.newBuilder().sslContext(http.sslContext()).build()) {
            return own.send(b.build(), HttpResponse.BodyHandlers.ofString());
        }
    }

    static boolean waitForCount(Path log, String text, int n) throws Exception {
        for (int i = 0; i < 40; i++) {
            if (Files.exists(log) && Files.readString(log).split(text, -1).length - 1 >= n) return true;
            Thread.sleep(50);
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        String port = System.getProperty("mysql.porta");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.porta=...): this test needs the test MySQL, skipped.");
            return;
        }
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        Path dir = Files.createTempDirectory("csrf-filter");
        Path audit = dir.resolve("audit.log");

        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.utente", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "mailpanel_prova"));
        check("connected to MySQL", db.connect());
        // Lo schema PRIMA della voce, e la voce riletta: vedi TestSessions.auditLogTo.
        // Scritta prima che le tabelle esistessero, non si salvava e il pannello
        // scriveva nel registro vero.
        TestSessions.auditLogTo(db, audit);
        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        String[] login = TestSessions.open(db, "csrf-test", UA);
        String session = login[0];
        String csrf = login[1];
        AuthHandlers.codeRequestMinMs = 50;
        String cookie = "__Host-MailPanel=" + session + "; __Host-lang=en";

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

        String probe = "{\"action\":\"set\",\"value\":\"\"}";
        String probeWithToken = "{\"action\":\"set\",\"value\":\"\",\"csrf_token\":\"" + csrf + "\"}";
        try {
            System.out.println("\n== A route that never asked for the token ==");
            HttpResponse<String> none = send("POST", "/api/timezone-diag", probe, cookie, null);
            check("without the token: 403, with the message in the request language", none.statusCode() == 403
                    && none.body().contains("The page has expired"));
            check("a wrong header: 403", send("POST", "/api/timezone-diag", probe, cookie, "wrong").statusCode() == 403);
            check("a wrong header wins over a right body token: 403",
                    send("POST", "/api/timezone-diag", probeWithToken, cookie, "wrong").statusCode() == 403);
            check("a wrong body token: 403", send("POST", "/api/timezone-diag",
                    "{\"action\":\"set\",\"value\":\"\",\"csrf_token\":\"wrong\"}", cookie, null).statusCode() == 403);
            check("a body that is not JSON: 403", send("POST", "/api/timezone-diag", "not json", cookie, null).statusCode() == 403);
            check("every refusal in the audit log (5 x CSRF_FAILURE)", waitForCount(audit, "CSRF_FAILURE", 5));

            HttpResponse<String> header = send("POST", "/api/timezone-diag", probe, cookie, csrf);
            check("with the X-CSRF-Token header: the handler answers (" + header.statusCode() + ")", header.statusCode() == 200
                    && header.body().contains("\"success\":false"));
            HttpResponse<String> body = send("POST", "/api/timezone-diag", probeWithToken, cookie, null);
            check("with csrf_token in the body: the handler answers, and it read the same body",
                    body.statusCode() == 200 && body.body().equals(header.body()));

            System.out.println("\n== What the filter leaves alone ==");
            check("without a session: the handler's 401", send("POST", "/api/timezone-diag", probe, null, null).statusCode() == 401);
            check("GET: untouched", send("GET", "/api/timezone-diag", null, cookie, null).statusCode() == 200);
            int before = Files.exists(audit) ? Files.readString(audit).split("CSRF_FAILURE", -1).length - 1 : 0;
            // The login route checks the token of the login page itself, tied to the pre-login cookie.
            String pre = "p".repeat(43);
            HttpResponse<String> codeRequest = send("POST", "/api/login", "{\"action\":\"code_request\",\"email\":\"nobody@example.test\",\"csrf_token\":\""
                    + WebSessions.preLoginCsrf(pre) + "\"}", "__Host-MailPanelPre=" + pre + "; __Host-lang=en", null);
            check("a route used before logging in is not blocked by the filter (" + codeRequest.statusCode() + ")", codeRequest.statusCode() == 200);
            Thread.sleep(300);
            int after = Files.exists(audit) ? Files.readString(audit).split("CSRF_FAILURE", -1).length - 1 : 0;
            check("and no CSRF_FAILURE for it", after == before);

            System.out.println("\n== The routes that checked it themselves still do ==");
            check("/api/service without the token: 403", send("POST", "/api/service",
                    "{\"service\":\"redis\",\"action\":\"stop\"}", cookie, null).statusCode() == 403);
            HttpResponse<String> queue = send("POST", "/api/queue", "{\"action\":\"nothing\"}", cookie, csrf);
            check("/api/queue, which checks it itself, takes the header too: its own answer (unknown action)",
                    queue.statusCode() == 200 && queue.body().contains("Unknown action."));
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
