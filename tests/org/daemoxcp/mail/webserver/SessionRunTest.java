package org.daemoxcp.mail.webserver;

import org.daemoxcp.mail.TestSql;

import com.sun.net.httpserver.HttpsServer;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.security.DataCrypto;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Panel sessions last for one start of the jar only, with Strict cookies (reperto 184).
 *
 *  1. The cookies: session, pre-login and language are SameSite=Strict, __Host-, HttpOnly, Secure;
 *     the session one has no Max-Age nor Expires: a browser-session cookie.
 *  2. In the database the token's fingerprint is not its SHA-256: whoever reads the database cannot
 *     even try a token. It is tokenHash's, keyed with this start's key.
 *  3. The restart: a second process on this database (the jar started again) does not recognise the
 *     token, and computes another CSRF token and another pre-login token; then beginRun (what
 *     SSLMailServer.start does) removes the rows, and not even this process finds its session.
 *  4. On the real server, over HTTPS: a cookie that is no longer valid on a page gives a 302 to
 *     /index?session=ended and the cookie removed (Strict); on an API, 401 with X-Panel-Session:
 *     ended; without a cookie, /index and nothing else; a wrong confirmation code (also a 401)
 *     without X-Panel-Session; logout removes the cookie and sends Clear-Site-Data; with the
 *     database not answering the cookie stays and there is no X-Panel-Session (reperto 185), and the
 *     answer is 503 with X-Panel-Database: a page that says it and reloads by itself, an API the
 *     pages ask again, never the sign-in page nor a 401 (reperto 209).
 *
 * Usage (with the test MySQL of README.md, on the test VM):
 *   java -Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test \
 *        -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.SessionRunTest
 */
public class SessionRunTest {

    static int failed = 0;
    static final String UA = "SessionRunTest/1.0";

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static MailDatabase connect() {
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "daemoxcp_mail"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(System.getProperty("mysql.port")), System.getProperty("mysql.database", "daemoxcp_mail_test"));
        if (!db.connect()) throw new IllegalStateException("MySQL not reachable");
        return db;
    }

    public static void main(String[] args) throws Exception {
        if (System.getProperty("mysql.port") == null) {
            System.out.println("SKIPPED: it needs the test MySQL (-Dmysql.port=...).");
            System.exit(0);
        }
        if (args.length > 0 && args[0].equals("restarted")) { restarted(args[1], args[2], args[3]); return; }
        Path dir = Files.createTempDirectory("session-run");
        Path secrets = Files.createDirectories(dir.resolve("secrets"));
        System.setProperty("daemoxcp.mail.secrets.dir", secrets.toString());
        MailDatabase db = connect();
        TestSessions.auditLogTo(db, dir.resolve("audit.log"));
        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        try {
            run(dir, db);
        } finally {
            db.close();
            try (var walk = Files.walk(dir)) {
                for (Path p : walk.sorted((a, b) -> b.compareTo(a)).toList()) Files.deleteIfExists(p);
            }
        }
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void run(Path dir, MailDatabase db) throws Exception {
        long admin = TestSessions.admin("rita-run");
        String token = Main.sessions.create(admin, UA, "127.0.0.1");

        System.out.println("== 1. The cookies ==");
        check("the session: __Host-, Path=/, HttpOnly, Secure, SameSite=Strict, no expiry in the browser",
                WebSessions.cookieHeader(token).equals("__Host-DaemoxCPMail=" + token + "; Path=/; HttpOnly; Secure; SameSite=Strict"));
        check("removing it: Strict and Max-Age=0", WebSessions.clearCookieHeader().equals("__Host-DaemoxCPMail=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"));
        check("the pre-login cookie: Strict, a browser-session cookie",
                WebSessions.preCookieHeader(token).equals("__Host-DaemoxCPMailPre=" + token + "; Path=/; HttpOnly; Secure; SameSite=Strict"));
        check("the language one: Strict", I18n.cookieHeader("en").endsWith("; SameSite=Strict"));

        System.out.println("\n== 2. The fingerprint in the database ==");
        String stored = "";
        try (PreparedStatement p = TestSql.mysql().prepareStatement("SELECT token_hash FROM panel_sessions WHERE admin_id = ? ORDER BY id DESC LIMIT 1")) {
            p.setLong(1, admin);
            try (ResultSet r = p.executeQuery()) { if (r.next()) stored = r.getString(1); }
        }
        check("it is the one of this start's key", stored.equals(WebSessions.tokenHash(token)) && stored.matches("[0-9a-f]{64}"));
        check("not the token's SHA-256, which anyone reading the database could try", !stored.equals(DataCrypto.sha256Hex(token)));
        check("the session is valid, in this process", Main.sessions.check(token, UA).isPresent());

        System.out.println("\n== 3. The jar started again: another process, the same database ==");
        String pre = WebSessions.newToken();
        Map<String, String> child = restart(token, pre, "no");
        check("it does not recognise the token (" + child.get("CHECK") + ")", "false".equals(child.get("CHECK")));
        check("it computes another CSRF token", child.get("CSRF") != null && !child.get("CSRF").equals(WebSessions.csrfToken(token)));
        check("and another pre-login token", child.get("PRE") != null && !child.get("PRE").equals(WebSessions.preLoginCsrf(pre)));
        check("the row is still there (it did not touch it), but it is of no use", Main.sessions.check(token, UA).isPresent());
        child = restart(token, pre, "yes");
        check("when the server starts (beginRun) the old rows go (" + child.get("BEGIN") + " removed)",
                Integer.parseInt(child.getOrDefault("BEGIN", "-1")) >= 1 && "0".equals(child.get("COUNT")));
        check("and not even the first process finds its session", Main.sessions.check(token, UA).isEmpty());

        System.out.println("\n== 4. On the real server ==");
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
        String base = "https://127.0.0.1:" + https.getAddress().getPort();
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        SSLContext trustAll = SSLContext.getInstance("TLS");
        trustAll.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] x, String a) { }
            public void checkServerTrusted(X509Certificate[] x, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        HttpClient http = HttpClient.newBuilder().sslContext(trustAll).build();
        try {
            String dead = "__Host-DaemoxCPMail=" + token;
            HttpResponse<String> page = send(http, base, "GET", "/home", null, dead, null);
            check("a cookie no longer valid on a page: 302 to /index?session=ended (" + page.statusCode() + " "
                    + page.headers().firstValue("Location").orElse("") + ")", page.statusCode() == 302
                    && "/index?session=ended".equals(page.headers().firstValue("Location").orElse("")));
            check("  and the cookie goes, Strict", page.headers().allValues("Set-Cookie").contains(WebSessions.clearCookieHeader()));
            HttpResponse<String> api = send(http, base, "GET", "/api/domains", null, dead, null);
            check("on an API: 401 with X-Panel-Session: ended", api.statusCode() == 401
                    && "ended".equals(api.headers().firstValue("X-Panel-Session").orElse("")));
            HttpResponse<String> none = send(http, base, "GET", "/home", null, null, null);
            check("without a cookie: /index and nothing else, no cookie to remove", none.statusCode() == 302
                    && "/index".equals(none.headers().firstValue("Location").orElse("")) && none.headers().allValues("Set-Cookie").isEmpty());
            // The database not answering (MySQL restarting, or stopping before the panel while the
            // server reboots) does not mean the session has ended (reperto 185).
            java.util.function.Supplier<java.sql.Connection> real = org.daemoxcp.mail.security.AuthStore.connection;
            org.daemoxcp.mail.security.AuthStore.connection = () -> (java.sql.Connection) java.lang.reflect.Proxy.newProxyInstance(
                    SessionRunTest.class.getClassLoader(), new Class<?>[]{java.sql.Connection.class}, (proxy, method, a) -> {
                        throw new java.sql.SQLException("MySQL is not reachable (test)");
                    });
            try {
                // Until reperto 209 a page went to /index and an API had 401: on the real server, MySQL restarting inside
                // "Update everything" sent an open page to the sign-in page and filled the Updates card with errors.
                HttpResponse<String> downPage = send(http, base, "GET", "/home", null, dead, null);
                check("the database does not answer: a page says so (503, X-Panel-Database) and reloads by itself, not the sign-in; the cookie stays",
                        downPage.statusCode() == 503 && "unavailable".equals(downPage.headers().firstValue("X-Panel-Database").orElse(""))
                        && downPage.headers().firstValue("Location").isEmpty() && downPage.body().contains("http-equiv=\"refresh\"")
                        && downPage.headers().allValues("Set-Cookie").isEmpty() && downPage.headers().firstValue("X-Panel-Session").isEmpty());
                HttpResponse<String> downApi = send(http, base, "GET", "/api/domains", null, dead, null);
                check("  an API: 503 with X-Panel-Database and Retry-After, never 401 nor X-Panel-Session (the page asks again)",
                        downApi.statusCode() == 503 && "unavailable".equals(downApi.headers().firstValue("X-Panel-Database").orElse(""))
                        && downApi.headers().firstValue("Retry-After").isPresent() && downApi.headers().firstValue("X-Panel-Session").isEmpty());
                HttpResponse<String> downNone = send(http, base, "GET", "/home", null, null, null);
                check("  without a cookie it is not a session that could not be read: /index as always", downNone.statusCode() == 302
                        && "/index".equals(downNone.headers().firstValue("Location").orElse("")));
            } finally {
                org.daemoxcp.mail.security.AuthStore.connection = real;
            }
            String fresh = Main.sessions.create(admin, UA, "127.0.0.1");
            String live = "__Host-DaemoxCPMail=" + fresh;
            check("a session of this start opens the page", send(http, base, "GET", "/home", null, live, null).statusCode() == 200);
            HttpResponse<String> wrong = send(http, base, "POST", "/api/account", "{\"action\":\"stepup_code_verify\",\"code\":\"000000\"}",
                    live, WebSessions.csrfToken(fresh));
            check("a wrong confirmation code (" + wrong.statusCode() + "): no X-Panel-Session, the page stays",
                    wrong.statusCode() != 200 && wrong.headers().firstValue("X-Panel-Session").isEmpty());
            check("  and the session is still valid", Main.sessions.check(fresh, UA).isPresent());
            HttpResponse<String> out = send(http, base, "POST", "/api/logout", "{}", live, WebSessions.csrfToken(fresh));
            String csd = out.headers().firstValue("Clear-Site-Data").orElse("");
            check("logout: 200, the cookie removed (Strict) and Clear-Site-Data \"cache\", \"storage\" (" + csd + ")", out.statusCode() == 200
                    && out.headers().allValues("Set-Cookie").contains(WebSessions.clearCookieHeader())
                    && csd.contains("\"cache\"") && csd.contains("\"storage\"") && !csd.contains("cookies"));
            check("  and afterwards the session is gone", Main.sessions.check(fresh, UA).isEmpty());
        } finally {
            https.stop(0);
        }
    }

    static HttpResponse<String> send(HttpClient http, String base, String method, String path, String body, String cookie, String csrf) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA);
        if (cookie != null) b.header("Cookie", cookie);
        if (csrf != null) b.header("X-CSRF-Token", csrf);
        if (body != null) b.header("Content-Type", "application/json");
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Another process, with this one's database and secrets: the jar started again. The "KEY value" lines it prints. */
    static Map<String, String> restart(String token, String pre, String begin) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>(List.of(java));
        for (String k : List.of("mysql.port", "mysql.user", "mysql.password", "mysql.database", "daemoxcp.mail.secrets.dir"))
            if (System.getProperty(k) != null) cmd.add("-D" + k + "=" + System.getProperty(k));
        cmd.addAll(List.of("-cp", System.getProperty("java.class.path"), SessionRunTest.class.getName(), "restarted", token, pre, begin));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Map<String, String> out = new HashMap<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            for (String line; (line = r.readLine()) != null; ) {
                int sp = line.indexOf(' ');
                if (sp > 0 && line.substring(0, sp).matches("[A-Z]+")) out.put(line.substring(0, sp), line.substring(sp + 1));
            }
        }
        p.waitFor();
        return out;
    }

    static void restarted(String token, String pre, String begin) throws Exception {
        MailDatabase db = connect();
        TestSessions.prepare(db);
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        System.out.println("CHECK " + Main.sessions.check(token, UA).isPresent());
        System.out.println("CSRF " + WebSessions.csrfToken(token));
        System.out.println("PRE " + WebSessions.preLoginCsrf(pre));
        if ("yes".equals(begin)) {
            System.out.println("BEGIN " + Main.sessions.beginRun());
            System.out.println("COUNT " + Main.sessions.count());
        }
        db.close();
        System.exit(0);
    }
}
