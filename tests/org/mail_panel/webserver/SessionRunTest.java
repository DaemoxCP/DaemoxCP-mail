package org.mail_panel.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.mail_panel.Main;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.i18n.I18n;
import org.mail_panel.security.DataCrypto;

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
 * Le sessioni del pannello valgono per un avvio solo del jar, coi cookie Strict (reperto 184).
 *
 *  1. I cookie: sessione, pre-accesso e lingua SameSite=Strict, __Host-, HttpOnly, Secure; quello
 *     della sessione senza Max-Age ne' Expires: un cookie di sessione del browser.
 *  2. Nel database l'impronta del token non e' il suo SHA-256: chi legge il database non puo'
 *     nemmeno provare un token. E' quella di tokenHash, con la chiave di questo avvio.
 *  3. Il riavvio: un secondo processo col database di questo (il jar ripartito) non riconosce il
 *     token, ne calcola un altro token CSRF e un altro token di prima dell'accesso; poi beginRun
 *     (quello che fa SSLMailServer.start) toglie le righe, e nemmeno questo processo la ritrova.
 *  4. Sul server vero, in HTTPS: un cookie che non vale su una pagina, 302 a /index?session=ended
 *     e il cookie tolto (Strict); su un'API, 401 con X-Panel-Session: ended; senza cookie, /index e
 *     basta; un codice di conferma sbagliato (anche lui 401) senza X-Panel-Session; l'uscita col
 *     cookie tolto e Clear-Site-Data; col database che non risponde il cookie resta e niente
 *     X-Panel-Session (reperto 185).
 *
 * Uso (col MySQL di prova di README.md, sulla VM):
 *   java -Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova \
 *        -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.SessionRunTest
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
        db.setCredentials(System.getProperty("mysql.user", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(System.getProperty("mysql.port")), System.getProperty("mysql.database", "mailpanel_prova"));
        if (!db.connect()) throw new IllegalStateException("MySQL not reachable");
        return db;
    }

    public static void main(String[] args) throws Exception {
        if (System.getProperty("mysql.port") == null) {
            System.out.println("SALTATA: serve il MySQL di prova (-Dmysql.port=...).");
            System.exit(0);
        }
        if (args.length > 0 && args[0].equals("restarted")) { restarted(args[1], args[2], args[3]); return; }
        Path dir = Files.createTempDirectory("session-run");
        Path secrets = Files.createDirectories(dir.resolve("secrets"));
        System.setProperty("mailpanel.secrets.dir", secrets.toString());
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
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void run(Path dir, MailDatabase db) throws Exception {
        long admin = TestSessions.admin("rita-run");
        String token = Main.sessions.create(admin, UA, "127.0.0.1");

        System.out.println("== 1. I cookie ==");
        check("la sessione: __Host-, Path=/, HttpOnly, Secure, SameSite=Strict, senza scadenza nel browser",
                WebSessions.cookieHeader(token).equals("__Host-MailPanel=" + token + "; Path=/; HttpOnly; Secure; SameSite=Strict"));
        check("toglierla: Strict e Max-Age=0", WebSessions.clearCookieHeader().equals("__Host-MailPanel=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"));
        check("il cookie di prima dell'accesso: Strict, di sessione del browser",
                WebSessions.preCookieHeader(token).equals("__Host-MailPanelPre=" + token + "; Path=/; HttpOnly; Secure; SameSite=Strict"));
        check("quello della lingua: Strict", I18n.cookieHeader("en").endsWith("; SameSite=Strict"));

        System.out.println("\n== 2. L'impronta nel database ==");
        String stored = "";
        try (PreparedStatement p = db.getConnection().prepareStatement("SELECT token_hash FROM panel_sessions WHERE admin_id = ? ORDER BY id DESC LIMIT 1")) {
            p.setLong(1, admin);
            try (ResultSet r = p.executeQuery()) { if (r.next()) stored = r.getString(1); }
        }
        check("e' quella della chiave di questo avvio", stored.equals(WebSessions.tokenHash(token)) && stored.matches("[0-9a-f]{64}"));
        check("non lo SHA-256 del token, che chiunque legga il database potrebbe provare", !stored.equals(DataCrypto.sha256Hex(token)));
        check("la sessione vale, in questo processo", Main.sessions.check(token, UA).isPresent());

        System.out.println("\n== 3. Il jar riavviato: un altro processo, lo stesso database ==");
        String pre = WebSessions.newToken();
        Map<String, String> child = restart(token, pre, "no");
        check("non riconosce il token (" + child.get("CHECK") + ")", "false".equals(child.get("CHECK")));
        check("ne calcola un altro token CSRF", child.get("CSRF") != null && !child.get("CSRF").equals(WebSessions.csrfToken(token)));
        check("e un altro token della pagina d'accesso", child.get("PRE") != null && !child.get("PRE").equals(WebSessions.preLoginCsrf(pre)));
        check("la riga c'e' ancora (non l'ha toccata), ma non serve a niente", Main.sessions.check(token, UA).isPresent());
        child = restart(token, pre, "yes");
        check("all'avvio del server (beginRun) le righe di prima se ne vanno (" + child.get("BEGIN") + " tolte)",
                Integer.parseInt(child.getOrDefault("BEGIN", "-1")) >= 1 && "0".equals(child.get("COUNT")));
        check("e nemmeno il processo di prima ritrova la sua sessione", Main.sessions.check(token, UA).isEmpty());

        System.out.println("\n== 4. Sul server vero ==");
        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        check("certificato di prova", cert.waitFor() == 0);
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
            String dead = "__Host-MailPanel=" + token;
            HttpResponse<String> page = send(http, base, "GET", "/home", null, dead, null);
            check("un cookie che non vale su una pagina: 302 a /index?session=ended (" + page.statusCode() + " "
                    + page.headers().firstValue("Location").orElse("") + ")", page.statusCode() == 302
                    && "/index?session=ended".equals(page.headers().firstValue("Location").orElse("")));
            check("  e il cookie se ne va, Strict", page.headers().allValues("Set-Cookie").contains(WebSessions.clearCookieHeader()));
            HttpResponse<String> api = send(http, base, "GET", "/api/domains", null, dead, null);
            check("su un'API: 401 con X-Panel-Session: ended", api.statusCode() == 401
                    && "ended".equals(api.headers().firstValue("X-Panel-Session").orElse("")));
            HttpResponse<String> none = send(http, base, "GET", "/home", null, null, null);
            check("senza cookie: /index e basta, nessun cookie da togliere", none.statusCode() == 302
                    && "/index".equals(none.headers().firstValue("Location").orElse("")) && none.headers().allValues("Set-Cookie").isEmpty());
            // Il database che non risponde (MySQL che si riavvia, o che si ferma prima del pannello
            // durante un riavvio del server): non vuol dire che la sessione e' finita (reperto 185).
            java.util.function.Supplier<java.sql.Connection> real = org.mail_panel.security.AuthStore.connection;
            org.mail_panel.security.AuthStore.connection = () -> (java.sql.Connection) java.lang.reflect.Proxy.newProxyInstance(
                    SessionRunTest.class.getClassLoader(), new Class<?>[]{java.sql.Connection.class}, (proxy, method, a) -> {
                        throw new java.sql.SQLException("MySQL is not reachable (test)");
                    });
            try {
                HttpResponse<String> downPage = send(http, base, "GET", "/home", null, dead, null);
                check("il database non risponde: una pagina va a /index senza dire che la sessione e' finita, e il cookie resta",
                        downPage.statusCode() == 302 && "/index".equals(downPage.headers().firstValue("Location").orElse(""))
                        && downPage.headers().allValues("Set-Cookie").isEmpty());
                HttpResponse<String> downApi = send(http, base, "GET", "/api/domains", null, dead, null);
                check("  un'API: 401 senza X-Panel-Session (la pagina aperta non va all'accesso)", downApi.statusCode() == 401
                        && downApi.headers().firstValue("X-Panel-Session").isEmpty());
            } finally {
                org.mail_panel.security.AuthStore.connection = real;
            }
            String fresh = Main.sessions.create(admin, UA, "127.0.0.1");
            String live = "__Host-MailPanel=" + fresh;
            check("una sessione di questo avvio apre la pagina", send(http, base, "GET", "/home", null, live, null).statusCode() == 200);
            HttpResponse<String> wrong = send(http, base, "POST", "/api/account", "{\"action\":\"stepup_code_verify\",\"code\":\"000000\"}",
                    live, WebSessions.csrfToken(fresh));
            check("un codice di conferma sbagliato (" + wrong.statusCode() + "): niente X-Panel-Session, la pagina resta",
                    wrong.statusCode() != 200 && wrong.headers().firstValue("X-Panel-Session").isEmpty());
            check("  e la sessione vale ancora", Main.sessions.check(fresh, UA).isPresent());
            HttpResponse<String> out = send(http, base, "POST", "/api/logout", "{}", live, WebSessions.csrfToken(fresh));
            String csd = out.headers().firstValue("Clear-Site-Data").orElse("");
            check("l'uscita: 200, il cookie tolto (Strict) e Clear-Site-Data \"cache\", \"storage\" (" + csd + ")", out.statusCode() == 200
                    && out.headers().allValues("Set-Cookie").contains(WebSessions.clearCookieHeader())
                    && csd.contains("\"cache\"") && csd.contains("\"storage\"") && !csd.contains("cookies"));
            check("  e dopo la sessione non c'e' piu'", Main.sessions.check(fresh, UA).isEmpty());
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

    /** Un altro processo, col database e i segreti di questo: il jar riavviato. Le righe "CHIAVE valore" che stampa. */
    static Map<String, String> restart(String token, String pre, String begin) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>(List.of(java));
        for (String k : List.of("mysql.port", "mysql.user", "mysql.password", "mysql.database", "mailpanel.secrets.dir"))
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
