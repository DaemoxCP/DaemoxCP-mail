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
 *  2. what the web part refuses never reaches the root: no session, no CSRF token, no permission;
 *  2b. the sign-in is decided by the root part: the web checks the
 *     page token and forwards, the root verifies the code and creates the session, its cookie reaches
 *     the browser; the account API and the sign-out go to the root; the web asks the root the session key;
 *  3. the root part checks by itself, with requests forged on its socket (what a broken-into web part
 *     could send): a viewer's session asking an administrator's action gets 403; a session with someone
 *     else's administrator id, or a revoked one, gets 401; a public route, a page, or a path that is not
 *     the route's get 404;
 *  4. a Set-Cookie from the root never reaches the browser, except the session cookie of a sign-in; with
 *     the root part gone the web answers 503.
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

    static HttpResponse<String> signIn(String body, String preCookie) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(base + "/api/login")).header("User-Agent", UA).header("Accept-Language", "en")
                .header("Content-Type", "application/json").header("Cookie", WebSessions.PRE_COOKIE + "=" + preCookie)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
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
        // Before anything touches PanelSeparation: the socket goes in the test folder; and root's SSH keys
        // (RootSshKeys) too, never the real ones.
        System.setProperty("mailpanel.run.dir", dir.toString());
        System.setProperty("mailpanel.root.ssh.dir", dir.resolve("ssh").toString());
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
        java.util.Set<String> forwarded = new java.util.TreeSet<>();
        root.routes().forEach((p, a) -> { if (a.kind() == Access.Kind.API && !SSLMailServer.WEB_LOCAL_API.contains(p)) forwarded.add(p); });
        forwarded.add("/api/login");
        check("the root's closed list has exactly the routes the web part forwards, the sign-in too (" + forwarded.size() + ")",
                forwarded.equals(new java.util.TreeSet<>(RootGate.METHODS.keySet())));
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
            check("the root part never saw a Cookie or a CSRF token (" + seenHeaders + ")", seenHeaders.stream().noneMatch(h ->
                    h.equalsIgnoreCase("Cookie") || h.equalsIgnoreCase("X-CSRF-Token")));
            check("  the Host passes, checked by the web part (the passkeys' rpId)", seenHeaders.stream().anyMatch(h -> h.equalsIgnoreCase("Host")));
            String sent = got == null ? "" : got.toString() + new String(got.body(), StandardCharsets.UTF_8);
            check("the session token is nowhere in what the root received", !sent.contains(boss.token()) && !sent.contains(boss.csrf()));
            int beforeLocal = seen.size();
            r = send("GET", "/api/domains", null, boss, false);
            check("the domains list answers from the web part, without the root part (" + r.statusCode() + ")",
                    r.statusCode() == 200 && seen.size() == beforeLocal);
            r = send("GET", "/api/logs", null, boss, false);
            check("the logs go to the root part (" + r.statusCode() + ")", r.statusCode() == 200 && seen.get(seen.size() - 1).route().equals("/api/logs"));
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
            r = send("GET", "/api/logs", null, null, false);
            check("no session: 401 (" + r.statusCode() + ")", r.statusCode() == 401);
            r = send("POST", "/api/theme", "{\"theme\":\"dark\"}", boss, false);
            check("no CSRF token: 403 (" + r.statusCode() + ")", r.statusCode() == 403);
            r = send("POST", "/api/admins", "{\"action\":\"create\",\"username\":\"x\",\"role\":\"viewer\"}", vera, true);
            check("a viewer creating an administrator: 403 (" + r.statusCode() + ")", r.statusCode() == 403);
            check("none of these reached the root part", seen.size() == before);

            System.out.println("\n== 2b. The sign-in is decided by the root part ==");
            r = send("GET", "/api/account", null, boss, false);
            check("the account API answers from the root part (" + r.statusCode() + ")", r.statusCode() == 200
                    && seen.size() == before + 1 && "/api/account".equals(seen.get(seen.size() - 1).route()) && r.body().contains("sep-boss"));
            String pre = WebSessions.preLoginCookieValue(null), pageToken = WebSessions.preLoginCsrf(pre);
            String code = org.mail_panel.security.LoginCodes.issueConsoleCode(AuthStore.adminById(boss.adminId()).orElseThrow());
            String signIn = "{\"action\":\"console_verify\",\"code\":\"" + code + "\",\"csrf_token\":\"";
            int beforeSignIn = seen.size();
            r = signIn(signIn + "x\"}", pre);
            check("a sign-in without the page's token: 403 from the web part, not sent (" + r.statusCode() + ")",
                    r.statusCode() == 403 && seen.size() == beforeSignIn);
            r = signIn(signIn + pageToken + "\"}", pre);
            String cookie = r.headers().allValues("Set-Cookie").stream().filter(v -> v.startsWith(WebSessions.COOKIE + "=")).findFirst().orElse("");
            check("a sign-in with a console code through the web part: 200 and the session cookie (" + r.statusCode() + ")",
                    r.statusCode() == 200 && r.body().contains("\"success\":true") && !cookie.isEmpty());
            RootChannel.Request asked = seen.get(seen.size() - 1);
            check("  the root part decided it, asked without an administrator", "/api/login".equals(asked.route())
                    && asked.adminId() == 0 && asked.sessionId() == 0);
            String token = cookie.substring((WebSessions.COOKIE + "=").length(), cookie.indexOf(';'));
            Who signedIn = new Who(boss.adminId(), Main.sessions.check(token, UA).map(WebSessions.Current::id).orElse(-1L), token,
                    WebSessions.csrfToken(token));
            check("  the session the root created works through the web part", signedIn.sessionId() > 0
                    && send("GET", "/api/domains", null, signedIn, false).statusCode() == 200);
            r = send("POST", "/api/logout", "{}", signedIn, true);
            check("the sign-out: 200, and the root part removed the session (" + r.statusCode() + ")", r.statusCode() == 200
                    && "/op/logout".equals(seen.get(seen.size() - 1).route()) && Main.sessions.check(token, UA).isEmpty());

            System.out.println("\n== 3. The root part checks by itself (forged requests on its socket) ==");
            StringBuilder answer = new StringBuilder();
            RootChannel.ResponseHead h = forge(sock, "/api/admins", "POST", "/api/admins", null,
                    "{\"action\":\"create\",\"username\":\"sep-forged\",\"email\":\"\",\"role\":\"superadmin\"}", vera.adminId(), vera.sessionId(), answer);
            check("a viewer's session asking to create an administrator: 403 (" + h.status() + " " + answer + ")",
                    h.status() == 403 && answer.toString().contains("\"forbidden\":true"));
            check("  and no administrator was created", AuthStore.adminByUsername("sep-forged").isEmpty());
            int beforeGate = seen.size();
            r = send("POST", "/api/roundcube-domain", "{\"action\":\"check\",\"domain\":\"-f /etc/master.passwd\"}", boss, true);
            check("through the web part, a host name that is an option of dig: refused by the root's list, 400 (" + r.statusCode() + ")",
                    r.statusCode() == 400 && seen.size() == beforeGate + 1
                    && r.body().contains(org.mail_panel.i18n.I18n.t("en", "server.rootPart.refused").substring(0, 20)));
            h = forge(sock, "/api/logs", "GET", "/api/logs", null, null, boss.adminId(), vera.sessionId(), answer);
            check("a session with someone else's administrator id: 401 (" + h.status() + ")", h.status() == 401);
            h = forge(sock, "/api/logs", "GET", "/api/logs", null, null, boss.adminId(), 999_999_999L, answer);
            check("a session that does not exist: 401 (" + h.status() + ")", h.status() == 401);
            for (String[] p : new String[][]{{"/api/login", "/api/login"}, {"/index", "/index"},
                    {"/", "/"}, {"/home", "/home"}, {"/api/fail2ban", "/api/fail2ban_health"}, {"/api/domains", "/api/domains"},
                    {"/api/mailboxes", "/api/mailboxes"}}) {
                h = forge(sock, p[0], "GET", p[1], null, null, boss.adminId(), boss.sessionId(), answer);
                check("route " + p[0] + " with path " + p[1] + ": 404 (" + h.status() + ")", h.status() == 404);
            }
            h = forge(sock, "/api/login", "GET", "/api/login", null, null, 0, 0, answer);
            check("a sign-in with GET, without an administrator: refused by the root's list (" + h.status() + ")", h.status() == 400);
            h = forge(sock, "/op/session-key", "POST", "/op/session-key", null, null, 0, 0, answer);
            byte[] key = h.status() == 200 ? java.util.Base64.getDecoder().decode(new org.json.JSONObject(answer.toString()).getString("key")) : new byte[0];
            check("the session key, asked without an administrator: 200, the root's key (" + h.status() + ")",
                    h.status() == 200 && java.util.Arrays.equals(key, WebSessions.runKeyForWebPart()));
            h = forge(sock, "/op/session-key", "POST", "/op/session-key", null, null, boss.adminId(), boss.sessionId(), answer);
            check("  with an administrator: 404 (" + h.status() + ")", h.status() == 404);
            h = forge(sock, "/op/session-key", "POST", "/op/session-key", null, "{}", 0, 0, answer);
            check("  with a body: 404 (" + h.status() + ")", h.status() == 404);
            h = forge(sock, "/api/logs", "GET", "/api/logs", null, null, 0, 0, answer);
            check("a signed-in route without an administrator: refused as a malformed request, 400 (" + h.status() + " " + answer + ")",
                    h.status() == 400 && answer.toString().contains("bad forwarded request"));
            h = forge(sock, "/op/mail-folders", "POST", "/op/mail-folders", null, null, vera.adminId(), vera.sessionId(), answer);
            check("the mail-folders operation asked by a viewer: 403 (" + h.status() + ")", h.status() == 403);
            h = forge(sock, "/op/mail-folders", "GET", "/op/mail-folders", null, null, boss.adminId(), boss.sessionId(), answer);
            check("the mail-folders operation with GET: 404 (" + h.status() + ")", h.status() == 404);
            h = forge(sock, "/op/mail-folders", "POST", "/op/mail-folders", null, "{\"x\":1}", boss.adminId(), boss.sessionId(), answer);
            check("the mail-folders operation with a body: 404, it takes nothing (" + h.status() + ")", h.status() == 404);
            h = forge(sock, "/op/run-anything", "POST", "/op/run-anything", null, null, boss.adminId(), boss.sessionId(), answer);
            check("an operation that is not in the list: 404 (" + h.status() + ")", h.status() == 404);
            h = forge(sock, "/op/mail-folders", "POST", "/op/mail-folders", null, null, boss.adminId(), 999_999_999L, answer);
            check("the mail-folders operation without a live session: 401 (" + h.status() + ")", h.status() == 401);
            h = forge(sock, "/api/panel_info", "GET", "/api/panel_info", "action=uptime", null, boss.adminId(), boss.sessionId(), answer);
            check("a well-formed request of a live session is served (" + h.status() + ")", h.status() == 200);
            check("the viewer's role comes from the database: promoted to superadmin, the same session may",
                    AuthStore.setRole(vera.adminId(), "superadmin")
                    && forge(sock, "/api/admins", "GET", "/api/admins", null, null, vera.adminId(), vera.sessionId(), answer).status() == 200);
            AuthStore.setRole(vera.adminId(), "viewer");

            System.out.println("\n== 3b. Root's SSH keys, through both parts (in a test folder) ==");
            r = send("GET", "/api/ssh-keys", null, boss, false);
            check("the superadmin lists root's keys: none yet (" + r.statusCode() + " " + r.body() + ")",
                    r.statusCode() == 200 && r.body().contains("\"keys\":[]"));
            String sshKey = org.mail_panel.system.RootSshKeysTest.ed25519() + " sep-test";
            String addKey = new org.json.JSONObject().put("action", "add").put("key", sshKey).toString();
            r = send("POST", "/api/ssh-keys", addKey, boss, true);
            check("adding without a recent confirmation: the panel asks for it (" + r.body() + ")",
                    r.statusCode() == 200 && r.body().contains("\"needs_reauth\":true"));
            Main.sessions.markReauthenticated(boss.sessionId());
            r = send("POST", "/api/ssh-keys", addKey, boss, true);
            check("after the confirmation the key is added (" + r.body() + ")", r.statusCode() == 200 && r.body().contains("\"success\":true")
                    && Files.readString(dir.resolve("ssh").resolve("authorized_keys")).contains(sshKey));
            r = send("GET", "/api/ssh-keys", null, vera, false);
            check("a viewer does not even see them: 403 (" + r.statusCode() + ")", r.statusCode() == 403);
            r = send("POST", "/api/ssh-keys", "{\"action\":\"remove\",\"fingerprint\":\"x; rm -rf /\"}", boss, true);
            check("a fingerprint that is not one: refused by the root's list, 400 (" + r.statusCode() + ")", r.statusCode() == 400);
            org.mail_panel.util.Shell.run("rm", "-rf", dir.resolve("ssh").toString());

            Main.sessions.revokeById(vera.sessionId(), vera.adminId());
            h = forge(sock, "/api/logs", "GET", "/api/logs", null, null, vera.adminId(), vera.sessionId(), answer);
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
            HttpResponse<String> r = send("GET", "/api/logs", null, boss2, false);
            check("a Set-Cookie from the root never reaches the browser (" + r.headers().allValues("Set-Cookie") + ")",
                    r.statusCode() == 200 && r.headers().allValues("Set-Cookie").isEmpty());
        }
        RootChannel.Dispatcher signInCookies = (r, ex) -> {
            byte[] b = "{\"success\":true}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Set-Cookie", WebSessions.COOKIE + "=from-the-root; Path=/");
            ex.getResponseHeaders().add("Set-Cookie", "other=x; Path=/");
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, b.length);
            try (java.io.OutputStream os = ex.getResponseBody()) { os.write(b); }
        };
        try (RootChannel fake = RootChannel.open(sock, null, null, signInCookies)) {
            String pre = WebSessions.preLoginCookieValue(null);
            HttpResponse<String> r = signIn("{\"action\":\"console_verify\",\"code\":\"0\",\"csrf_token\":\""
                    + WebSessions.preLoginCsrf(pre) + "\"}", pre);
            List<String> cookies = r.headers().allValues("Set-Cookie");
            check("on a sign-in only the session cookie passes (" + cookies + ")", r.statusCode() == 200 && cookies.size() == 1
                    && cookies.get(0).startsWith(WebSessions.COOKIE + "=from-the-root"));
        }
        HttpResponse<String> gone = send("GET", "/api/logs", null, boss2, false);
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
