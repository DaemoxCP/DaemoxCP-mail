package org.mail_panel.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.json.JSONObject;
import org.mail_panel.Main;
import org.mail_panel.content.MailPanelContent;
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
import java.util.Comparator;
import java.util.HexFormat;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The languages on the REAL server (SSLMailServer), over HTTPS, with the test MySQL: the script
 * dictionary, the language of a page (saved in the account, then the cookie, then the browser), the
 * frame around the pages, and /api/language before and after logging in, always with a CSRF token.
 *
 * Usage (with the test MySQL of README.md, tables already created by AddressConversionTest):
 *   java -Dmysql.porta=33062 -Dmysql.utente=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova \
 *        -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.LanguageRoutesTest
 */
public class LanguageRoutesTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String UA = "LanguageRoutesTest/1.0";
    static String base;
    static SSLContext trustAll;

    /** One request on its own connection: the server closes some of them after answering. */
    static HttpResponse<String> ask(String method, String path, String body, String... headers) throws Exception {
        try (HttpClient client = HttpClient.newBuilder().sslContext(trustAll).build()) {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA);
            for (int i = 0; i + 1 < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
            if (body != null) b.header("Content-Type", "application/json");
            b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
            return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
        }
    }

    static String langOf(HttpResponse<String> r) {
        Matcher m = Pattern.compile("<html lang=\"([a-z]+)\"").matcher(r.body());
        return m.find() ? m.group(1) : "?";
    }

    static String setCookie(HttpResponse<String> r) {
        return String.join(" | ", r.headers().allValues("Set-Cookie"));
    }

    public static void main(String[] args) throws Exception {
        String port = System.getProperty("mysql.porta");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.porta=...): this test needs the test MySQL, skipping it.");
            return;
        }
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        Path dir = Files.createTempDirectory("language-routes");

        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.utente", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "mailpanel_prova"));
        check("connected to MySQL", db.connect());
        TestSessions.prepare(db);
        db.ensureLanguageColumn();
        db.ensureLanguageColumn();   // twice: an installation that already has it
        String admin = "langtest" + HexFormat.of().formatHex(SecureRandom.getInstanceStrong().generateSeed(3));
        long adminId = TestSessions.admin(admin);
        check("a new admin has no saved language", db.getAdminLanguage(admin) == null);
        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        String session = Main.sessions.create(adminId, UA, "127.0.0.1");
        String csrf = WebSessions.csrfToken(session);
        String sessionCookie = "__Host-MailPanel=" + session;

        // The pages are read from admin/ next to the jar: written here, removed at the end.
        Path jarDir = Path.of(MailPanelContent.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getParent();
        Path adminDir = jarDir.resolve("admin");
        boolean adminDirExisted = Files.exists(adminDir);
        MailPanelContent.generateAllContent();

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
        trustAll = SSLContext.getInstance("TLS");
        trustAll.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) { }
            public void checkServerTrusted(X509Certificate[] c, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());

        try {
            System.out.println("\n== /i18n/(language).js ==");
            HttpResponse<String> en = ask("GET", "/i18n/en.js", null);
            check("English: 200, JavaScript, kept in cache, with the English texts", en.statusCode() == 200
                    && en.headers().firstValue("Content-Type").orElse("").startsWith("application/javascript")
                    && en.headers().firstValue("Cache-Control").orElse("").contains("immutable")
                    && en.body().startsWith("window.I18N_LANG=\"en\";") && en.body().contains("\"nav.queue\":\"Mail queue\""));
            check("an unknown language: 404", ask("GET", "/i18n/fr.js", null).statusCode() == 404);
            check("a path outside the dictionary: 404", ask("GET", "/i18n/../index", null).statusCode() == 404);

            System.out.println("\n== The login page ==");
            HttpResponse<String> login = ask("GET", "/index", null, "Accept-Language", "en-US,en;q=0.9");
            check("an English browser gets it in English (lang, Content-Language, EN pressed)", "en".equals(langOf(login))
                    && "en".equals(login.headers().firstValue("Content-Language").orElse(""))
                    && login.body().contains("data-set-lang=\"en\" lang=\"en\" aria-pressed=\"true\""));
            check("no frame before logging in", !login.body().contains("id=\"sidebar\""));
            check("no placeholder left", !login.body().contains("{{"));
            check("the cookie wins over the browser", "it".equals(langOf(ask("GET", "/index", null,
                    "Accept-Language", "en", "Cookie", "__Host-lang=it"))));
            check("a German browser gets English", "en".equals(langOf(ask("GET", "/index", null, "Accept-Language", "de-DE,de;q=0.9"))));
            Matcher token = Pattern.compile("id=\"csrf_token\" value=\"([^\"]+)\"").matcher(login.body());
            String loginToken = token.find() ? token.group(1) : "";
            check("the login page carries a CSRF token", loginToken.length() >= 16);
            Matcher preCookie = Pattern.compile("__Host-MailPanelPre=([A-Za-z0-9_-]{43}); Path=/; HttpOnly; Secure; SameSite=Lax").matcher(setCookie(login));
            String pre = preCookie.find() ? "__Host-MailPanelPre=" + preCookie.group(1) : "";
            check("and the pre-login cookie the token is tied to (no session on the server)", !pre.isEmpty());

            System.out.println("\n== /api/language before logging in ==");
            HttpResponse<String> ok = ask("POST", "/api/language", "{\"language\":\"en\",\"csrf_token\":\"" + loginToken + "\"}", "Cookie", pre);
            check("the login page token without its cookie: 403", ask("POST", "/api/language",
                    "{\"language\":\"en\",\"csrf_token\":\"" + loginToken + "\"}").statusCode() == 403);
            check("with the login page token and its cookie: 200 and the cookie", ok.statusCode() == 200 && new JSONObject(ok.body()).getBoolean("success")
                    && setCookie(ok).contains("__Host-lang=en; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax"));
            check("without a token: 403", ask("POST", "/api/language", "{\"language\":\"en\"}").statusCode() == 403);
            check("with a wrong token: 403", ask("POST", "/api/language", "{\"language\":\"en\",\"csrf_token\":\"" + "x".repeat(loginToken.length()) + "\"}").statusCode() == 403);
            check("with the token of a logged-in session, from outside it: 403", ask("POST", "/api/language",
                    "{\"language\":\"en\",\"csrf_token\":\"" + csrf + "\"}").statusCode() == 403);
            check("an unknown language: 400", ask("POST", "/api/language", "{\"language\":\"fr\",\"csrf_token\":\"" + loginToken + "\"}", "Cookie", pre).statusCode() == 400);
            check("GET: 405", ask("GET", "/api/language", null).statusCode() == 405);
            check("a body that is not JSON: 400", ask("POST", "/api/language", "nope").statusCode() == 400);

            System.out.println("\n== Logged in ==");
            HttpResponse<String> queue = ask("GET", "/queue", null, "Cookie", sessionCookie, "Accept-Language", "en");
            check("nothing saved: the browser language", "en".equals(langOf(queue)));
            check("the frame: sidebar, the queue marked, the title", queue.body().contains("id=\"sidebar\"")
                    && queue.body().contains("class=\"sidebar-link active\" aria-current=\"page\" href=\"/queue\"")
                    && queue.body().contains("<title>Mail queue - Mail Control Panel</title>")
                    && queue.body().contains("<span class=\"topbar-section\">Mail</span>"));
            check("the session CSRF token is in the page", queue.body().contains("id=\"csrf_token\" value=\"" + csrf + "\""));
            check("no placeholder left in the frame", !queue.body().contains("{{t:") && !queue.body().contains("{{LAYOUT"));
            check("a wrong token: 403, nothing saved", ask("POST", "/api/language", "{\"language\":\"it\",\"csrf_token\":\"" + loginToken + "\"}",
                    "Cookie", sessionCookie).statusCode() == 403 && db.getAdminLanguage(admin) == null);
            HttpResponse<String> save = ask("POST", "/api/language", "{\"language\":\"it\",\"csrf_token\":\"" + csrf + "\"}", "Cookie", sessionCookie);
            check("the session token: 200, saved in the account, and the cookie", save.statusCode() == 200
                    && "it".equals(db.getAdminLanguage(admin)) && setCookie(save).contains("__Host-lang=it"));
            HttpResponse<String> home = ask("GET", "/home", null, "Cookie", sessionCookie, "Accept-Language", "en");
            check("the saved choice wins over the browser", "it".equals(langOf(home)) && home.body().contains("<title>Dashboard - Mail Control Panel</title>")
                    && home.body().contains("<span class=\"topbar-page\">Dashboard</span>") && home.body().contains("Vai al contenuto"));
            check("and a browser without the cookie gets it aligned", setCookie(home).contains("__Host-lang=it"));
            HttpResponse<String> aligned = ask("GET", "/home", null, "Cookie", sessionCookie + "; __Host-lang=it", "Accept-Language", "en");
            check("a cookie already aligned is not sent again", !setCookie(aligned).contains("__Host-lang"));
            check("a session that does not exist does not save anything", ask("POST", "/api/language",
                    "{\"language\":\"en\",\"csrf_token\":\"" + csrf + "\"}", "Cookie", "__Host-MailPanel=nope").statusCode() == 403
                    && "it".equals(db.getAdminLanguage(admin)));
            check("the database refuses a language that is not ours", !db.setAdminLanguage(admin, "fr") && "it".equals(db.getAdminLanguage(admin)));
        } finally {
            https.stop(0);
            try (var st = db.getConnection().prepareStatement("DELETE FROM panel_admin WHERE username = ?")) {
                st.setString(1, admin);
                st.executeUpdate();
            }
            db.close();
            if (!adminDirExisted && Files.exists(adminDir)) {
                try (var files = Files.walk(adminDir)) {
                    for (Path p : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) Files.delete(p);
                }
            }
            Files.deleteIfExists(dir.resolve("k.pem"));
            Files.deleteIfExists(dir.resolve("c.pem"));
            Files.deleteIfExists(dir);
        }

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
