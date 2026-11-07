package org.mail_panel.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.mail_panel.Main;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.security.AuthStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

/**
 * The two parts of the separated panel together, in one JVM with the
 * test MySQL: a WEB_PART server on a port, a ROOT_PART server without one, the unix socket between them.
 *
 *  1. a signed-in API goes through the web part's checks and reaches the root part, with who asked
 *     (administrator and session ids) and never the cookie, the token or the CSRF token;
 *  2. what the web part refuses never reaches the root: no session, no CSRF token, no permission; the
 *     account API stays in the web part;
 *  3. the root part checks by itself, with requests forged on its socket (what a broken-into web part
 *     could send): a viewer's session asking an administrator's action gets 403; a session with someone
 *     else's administrator id, or a revoked one, gets 401; a public route, the account API, a page, or
 *     a path that is not the route's get 404;
 *  4. a Set-Cookie from the root never reaches the browser; with the root part gone the web answers 503.
 *
 * Usage (on the VM, with the test MySQL of tests/README.md):
 *   java -Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_test \
 *        -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.SeparatedPanelTest
 */
public class SeparatedPanelTest {

    static int failed = 0;
    static HttpClient http;
    static String base;
    static final String UA = "separated-panel-test";

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    record Who(long adminId, long sessionId, String token, String csrf) {}

    static Who session(String name, String role) throws Exception {
        AuthStore.Created c = AuthStore.createAdmin(name, null, role);
        long id = c.id() > 0 ? c.id() : AuthStore.adminByUsername(name).orElseThrow().id();
        AuthStore.setRole(id, role);
        String token = Main.sessions.create(id, UA, "127.0.0.1");
        long sid = Main.sessions.check(token, UA).orElseThrow().id();
        return new Who(id, sid, token, WebSessions.csrfToken(token));
    }

    static HttpResponse<String> send(String method, String path, String body, Who who, boolean csrf) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA).header("Accept-Language", "en");
        if (who != null) b.header("Cookie", WebSessions.COOKIE + "=" + who.token());
        if (who != null && csrf) b.header("X-CSRF-Token", who.csrf());
        if (body != null) b.header("Content-Type", "application/json");
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    static RootChannel.ResponseHead forge(Path sock, String route, String method, String path, String query, String body,
                                          long admin, long session, StringBuilder answer) throws Exception {
        RootChannel.Request r = new RootChannel.Request(route, method, path, query,
                body == null ? Map.of() : Map.of("Content-type", "application/json"), "198.51.100.9", "en", admin, session,
                body == null ? null : body.getBytes(StandardCharsets.UTF_8));
        try (RootChannel.Exchange ex = RootChannel.send(sock, r)) {
            answer.setLength(0);
            answer.append(new String(ex.body().readAllBytes(), StandardCharsets.UTF_8));
            return ex.head();
        }
    }

    public static void main(String[] args) throws Exception {
        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): this test needs the test MySQL.");
            System.exit(1);
        }
        Path dir = Files.createTempDirectory("separated");
        // Before anything touches PanelSeparation: the socket goes in the test folder.
        System.setProperty("mailpanel.run.dir", dir.toString());
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        Path audit = dir.resolve("audit.log");
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "mailpanel_test"));
        check("connected to MySQL", db.connect());
        TestSessions.auditLogTo(db, audit);
        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        TestSessions.prepare(db);

        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        check("test certificate", cert.waitFor() == 0);
        String c = Files.readString(dir.resolve("c.pem")), k = Files.readString(dir.resolve("k.pem"));

        SSLMailServer root = new SSLMailServer(0, c, k, SSLMailServer.Mode.ROOT_PART);
        SSLMailServer web = new SSLMailServer(0, c, k, SSLMailServer.Mode.WEB_PART);
        boolean same = root.routes().keySet().equals(web.routes().keySet());
        for (String p : root.routes().keySet()) {
            Access a = root.routes().get(p), b = web.routes().get(p);
            same &= b != null && a.kind() == b.kind() && java.util.Objects.equals(a.readPermission(), b.readPermission())
                    && java.util.Objects.equals(a.writePermission(), b.writePermission());
        }
        check("the root part has the same routes, with the same permissions, as the web part", same);
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        check("the root part has no HTTPS server at all, not even an unbound socket", f.get(root) == null);
        HttpsServer https = (HttpsServer) f.get(web);
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

        Path sock = org.mail_panel.system.PanelSeparation.socket();
        check("the socket is in the test folder (" + sock + ")", sock.startsWith(dir));
        List<RootChannel.Request> seen = new CopyOnWriteArrayList<>();
        List<String> seenHeaders = new CopyOnWriteArrayList<>();
        RootChannel.Dispatcher recording = (r, ex) -> {
            seen.add(r);
            seenHeaders.addAll(ex.getRequestHeaders().keySet());
            root.serveForwarded(r, ex);
        };
        RootChannel channel = RootChannel.open(sock, null, null, recording);
        try {
            Who boss = session("sep-boss", "superadmin"), vera = session("sep-vera", "viewer");

            System.out.println("\n== 1. Through the web part to the root part ==");
            HttpResponse<String> r = send("GET", "/api/panel_info?action=uptime", null, boss, false);
            check("a signed-in API answers (" + r.statusCode() + " " + r.body() + ")", r.statusCode() == 200 && r.body().contains("\"success\":true"));
            RootChannel.Request got = seen.isEmpty() ? null : seen.get(seen.size() - 1);
            check("it reached the root part, with its route, query and who asked", got != null && got.route().equals("/api/panel_info")
                    && "action=uptime".equals(got.query()) && got.adminId() == boss.adminId() && got.sessionId() == boss.sessionId());
            check("the root part never saw a Cookie, a CSRF token or a Host (" + seenHeaders + ")", seenHeaders.stream().noneMatch(h ->
                    h.equalsIgnoreCase("Cookie") || h.equalsIgnoreCase("X-CSRF-Token") || h.equalsIgnoreCase("Host")));
            String sent = got == null ? "" : got.toString() + new String(got.body(), StandardCharsets.UTF_8);
            check("the session token is nowhere in what the root received", !sent.contains(boss.token()) && !sent.contains(boss.csrf()));
            r = send("GET", "/api/domains", null, boss, false);
            check("the domains list too (" + r.statusCode() + ")", r.statusCode() == 200 && seen.get(seen.size() - 1).route().equals("/api/domains"));
            java.util.List<String> warned = new CopyOnWriteArrayList<>();
            java.util.logging.Handler watch = new java.util.logging.Handler() {
                @Override public void publish(java.util.logging.LogRecord l) {
                    if (l.getLevel().intValue() >= java.util.logging.Level.WARNING.intValue())
                        warned.add(l.getMessage() + (l.getThrown() == null ? "" : " " + l.getThrown()));
                }
                @Override public void flush() { }
                @Override public void close() { }
            };
            java.util.logging.Logger.getLogger("").addHandler(watch);
            r = send("HEAD", "/api/panel_info?action=uptime", null, boss, false);
            Thread.sleep(300);
            java.util.logging.Logger.getLogger("").removeHandler(watch);
            check("a HEAD through both parts: 200 and no body; the root part served it as the GET it is (" + r.statusCode() + ")",
                    r.statusCode() == 200 && r.body().isEmpty() && "/api/panel_info".equals(seen.get(seen.size() - 1).route()));
            // The test has no SQLite: hostAllowed warns that it cannot read the panel's host on every request.
            warned.removeIf(w -> w.startsWith("Cannot read the configured panel host"));
            check("  and nothing logged at WARNING or above" + (warned.isEmpty() ? "" : " " + warned), warned.isEmpty());
            r = send("GET", "/api/admins", null, boss, false);
            check("the administrators API goes to the root part too (" + r.statusCode() + ")", r.statusCode() == 200
                    && seen.get(seen.size() - 1).route().equals("/api/admins") && r.body().contains("sep-boss"));
            check("the root part answered in the request's language", "en".equals(seen.get(seen.size() - 1).lang()));

            System.out.println("\n== 2. What the web part refuses never reaches the root ==");
            int before = seen.size();
            r = send("GET", "/api/domains", null, null, false);
            check("no session: 401 (" + r.statusCode() + ")", r.statusCode() == 401);
            r = send("POST", "/api/theme", "{\"theme\":\"dark\"}", boss, false);
            check("no CSRF token: 403 (" + r.statusCode() + ")", r.statusCode() == 403);
            r = send("POST", "/api/admins", "{\"action\":\"create\",\"username\":\"x\",\"role\":\"viewer\"}", vera, true);
            check("a viewer creating an administrator: 403 (" + r.statusCode() + ")", r.statusCode() == 403);
            r = send("GET", "/api/account", null, boss, false);
            check("the account API answers from the web part (" + r.statusCode() + ")", r.statusCode() == 200);
            check("none of these reached the root part", seen.size() == before);

            System.out.println("\n== 3. The root part checks by itself (forged requests on its socket) ==");
            StringBuilder answer = new StringBuilder();
            RootChannel.ResponseHead h = forge(sock, "/api/admins", "POST", "/api/admins", null,
                    "{\"action\":\"create\",\"username\":\"sep-forged\",\"email\":\"\",\"role\":\"superadmin\"}", vera.adminId(), vera.sessionId(), answer);
            check("a viewer's session asking to create an administrator: 403 (" + h.status() + " " + answer + ")",
                    h.status() == 403 && answer.toString().contains("\"forbidden\":true"));
            check("  and no administrator was created", AuthStore.adminByUsername("sep-forged").isEmpty());
            h = forge(sock, "/api/domains", "GET", "/api/domains", null, null, boss.adminId(), vera.sessionId(), answer);
            check("a session with someone else's administrator id: 401 (" + h.status() + ")", h.status() == 401);
            h = forge(sock, "/api/domains", "GET", "/api/domains", null, null, boss.adminId(), 999_999_999L, answer);
            check("a session that does not exist: 401 (" + h.status() + ")", h.status() == 401);
            for (String[] p : new String[][]{{"/api/login", "/api/login"}, {"/api/account", "/api/account"}, {"/index", "/index"},
                    {"/", "/"}, {"/home", "/home"}, {"/api/webmail", "/api/webmail/open"}}) {
                h = forge(sock, p[0], "GET", p[1], null, null, boss.adminId(), boss.sessionId(), answer);
                check("route " + p[0] + " with path " + p[1] + ": 404 (" + h.status() + ")", h.status() == 404);
            }
            h = forge(sock, "/api/panel_info", "GET", "/api/panel_info", "action=uptime", null, boss.adminId(), boss.sessionId(), answer);
            check("a well-formed request of a live session is served (" + h.status() + ")", h.status() == 200);
            check("the viewer's role comes from the database: promoted to superadmin, the same session may",
                    AuthStore.setRole(vera.adminId(), "superadmin")
                    && forge(sock, "/api/admins", "GET", "/api/admins", null, null, vera.adminId(), vera.sessionId(), answer).status() == 200);
            AuthStore.setRole(vera.adminId(), "viewer");
            Main.sessions.revokeById(vera.sessionId(), vera.adminId());
            h = forge(sock, "/api/domains", "GET", "/api/domains", null, null, vera.adminId(), vera.sessionId(), answer);
            check("a revoked session: 401 (" + h.status() + ")", h.status() == 401);
        } finally {
            channel.close();
        }

        System.out.println("\n== 4. What comes back ==");
        Who boss2 = session("sep-boss", "superadmin");
        RootChannel.Dispatcher cookieSetter = (r, ex) -> {
            byte[] b = "{\"success\":true}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Set-Cookie", WebSessions.COOKIE + "=stolen; Path=/");
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, b.length);
            try (java.io.OutputStream os = ex.getResponseBody()) { os.write(b); }
        };
        try (RootChannel fake = RootChannel.open(sock, null, null, cookieSetter)) {
            HttpResponse<String> r = send("GET", "/api/domains", null, boss2, false);
            check("a Set-Cookie from the root never reaches the browser (" + r.headers().allValues("Set-Cookie") + ")",
                    r.statusCode() == 200 && r.headers().allValues("Set-Cookie").isEmpty());
        }
        HttpResponse<String> gone = send("GET", "/api/domains", null, boss2, false);
        check("with the root part gone: 503 and a sentence (" + gone.statusCode() + " " + gone.body() + ")", gone.statusCode() == 503
                && gone.body().contains(org.mail_panel.i18n.I18n.t("en", "server.rootPart.unavailable").substring(0, 20)));

        https.stop(0);
        db.close();
        for (String n : new String[]{"audit.log", "k.pem", "c.pem"}) Files.deleteIfExists(dir.resolve(n));
        Files.deleteIfExists(dir);
        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
