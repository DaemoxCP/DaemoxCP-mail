package org.mail_panel.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.Main;
import org.mail_panel.content.MailPanelContent;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.security.AuthStore;
import org.mail_panel.security.DataCrypto;
import org.mail_panel.security.LoginCodes;
import org.mail_panel.security.PasskeyService;

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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The login routes on the REAL server, over HTTPS, with the test MySQL: /index, /api/login,
 * /api/account, /api/admins, /api/logout, /api/setup.
 *
 * What must hold: the login page creates nothing on the server; every pre-login request needs the
 * page token tied to the browser cookie; asking a code for an address of nobody answers exactly
 * like for a real one (status, body, time); a wrong code too; a right code, a console code or a
 * passkey (signed by a software authenticator) opens a session in the database with a __Host-
 * cookie; the account routes want the session CSRF token; the vault wants a recent confirmation;
 * the admins have an email and no password; logout closes the session in the database; the old
 * password and TOTP routes are gone.
 *
 * Usage (with the test MySQL of README.md):
 *   java -Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova \
 *        -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.LoginRoutesTest
 */
public class LoginRoutesTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String UA = "LoginRoutesTest/1.0";
    static final String HOST = "panel.example.test";
    static String base;
    static int port;
    static SSLContext trustAll;
    static final List<String[]> MAIL = new ArrayList<>();

    /** One request on its own connection, with the Host of the panel name (passkeys want a name). */
    static HttpResponse<String> ask(String method, String path, String body, String... headers) throws Exception {
        try (HttpClient client = HttpClient.newBuilder().sslContext(trustAll).build()) {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path));
            java.util.Map<String, String> h = new java.util.LinkedHashMap<>();
            h.put("User-Agent", UA);
            h.put("Host", HOST + ":" + port);
            for (int i = 0; i + 1 < headers.length; i += 2) h.put(headers[i], headers[i + 1]);
            h.forEach(b::header);
            if (body != null) b.header("Content-Type", "application/json");
            b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
            return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
        }
    }

    static String setCookie(HttpResponse<String> r) {
        return String.join(" | ", r.headers().allValues("Set-Cookie"));
    }

    static String cookieValue(HttpResponse<String> r, String name) {
        Matcher m = Pattern.compile(Pattern.quote(name) + "=([A-Za-z0-9_-]+);").matcher(setCookie(r));
        return m.find() ? m.group(1) : null;
    }

    static String lastCode() {
        Matcher m = Pattern.compile("\\b(\\d{6})\\b").matcher(MAIL.get(MAIL.size() - 1)[2]);
        return m.find() ? m.group(1) : null;
    }

    static int count(String query, Object... params) throws Exception {
        try (PreparedStatement p = Main.mailDatabase.getConnection().prepareStatement(query)) {
            for (int i = 0; i < params.length; i++) p.setObject(i + 1, params[i]);
            try (ResultSet r = p.executeQuery()) {
                return r.next() ? r.getInt(1) : -1;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        String mysqlPort = System.getProperty("mysql.port");
        if (mysqlPort == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): this test needs the test MySQL, skipped.");
            return;
        }
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        System.setProperty("jdk.httpclient.allowRestrictedHeaders", "host");
        Path dir = Files.createTempDirectory("login-routes");
        // Il file dei segreti va scelto ADESSO, prima che qualunque cosa tocchi PanelSecrets:
        // quella classe legge questa proprieta' una volta sola, quando viene caricata, e
        // TestSessions.prepare la rispetta se c'e' gia'. Spostare la cartella DOPO -- com'era
        // in un primo giro -- vuol dire creare gli amministratori con una chiave e cercarli
        // con un'altra: il blind index dell'email non combacia piu', adminByEmail non trova
        // nessuno, e la prova cade su "only the real one gets an email" senza che niente dica
        // perche'.
        System.setProperty("mailpanel.secrets.dir", dir.resolve("secrets").toString());

        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(mysqlPort), System.getProperty("mysql.database", "mailpanel_prova"));
        check("connected to MySQL", db.connect());
        // Lo schema PRIMA della voce, e la voce riletta: vedi TestSessions.auditLogTo.
        // Scritta prima che le tabelle esistessero, non si salvava e il pannello
        // scriveva nel registro vero.
        TestSessions.auditLogTo(db, dir.resolve("audit.log"));
        TestSessions.prepare(db);
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        AuthHandlers.codeRequestMinMs = 400;
        LoginCodes.mailer = (to, subject, body) -> MAIL.add(new String[]{to, subject, body});
        LoginCodes.synchronousMail = true;
        LoginCodes.resetLimits();
        // An administrator with an email, superadmin; a second one with role admin.
        String suffix = Long.toString(System.nanoTime() % 1_000_000);
        AuthStore.Created boss = AuthStore.createAdmin("boss" + suffix, "boss" + suffix + "@example.org", "superadmin");
        AuthStore.Created plain = AuthStore.createAdmin("plain" + suffix, "plain" + suffix + "@example.org", "admin");
        check("two test administrators", boss.id() > 0 && plain.id() > 0);
        String bossEmail = "boss" + suffix + "@example.org";

        Path jarDir = Path.of(MailPanelContent.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getParent();
        Path adminDir = jarDir.resolve("admin");
        boolean adminDirExisted = Files.exists(adminDir);
        MailPanelContent.generateAllContent();

        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        check("test certificate", cert.waitFor() == 0);

        // Il pannello adesso guarda l'intestazione Host (HostCheck), e queste richieste
        // arrivano col NOME -- panel.example.test, che e' anche l'rpId delle passkey, e per
        // questo non puo' essere un indirizzo. Quel nome va dichiarato, perche' e' quello che
        // un pannello raggiunto per nome ha scritto nella propria configurazione: prima
        // nessuno lo chiedeva e la prova girava senza. update_panel_config mette la chiave TLS
        // nel file dei segreti, che e' gia' nella cartella di prova scelta in cima.
        Main.dbManager = new org.mail_panel.sqli.dataBaseManager();
        Main.dbManager.create_tables();
        Main.dbManager.insert_data_default();
        Main.dbManager.update_panel_config(HOST, "0", Files.readString(dir.resolve("c.pem")),
                Files.readString(dir.resolve("k.pem")), "", "mailpanel-");

        SSLMailServer srv = new SSLMailServer(0, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();
        port = https.getAddress().getPort();
        base = "https://127.0.0.1:" + port;
        trustAll = SSLContext.getInstance("TLS");
        trustAll.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) { }
            public void checkServerTrusted(X509Certificate[] c, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());

        try {
            System.out.println("\n== The login page ==");
            int sessionsBefore = count("SELECT COUNT(*) FROM panel_sessions");
            HttpResponse<String> page = ask("GET", "/index", null, "Accept-Language", "en");
            String pre = cookieValue(page, WebSessions.PRE_COOKIE);
            Matcher tm = Pattern.compile("id=\"csrf_token\" value=\"([^\"]+)\"").matcher(page.body());
            String token = tm.find() ? tm.group(1) : "";
            check("200, with the pre-login cookie (HttpOnly, Secure, __Host-)", page.statusCode() == 200 && pre != null
                    && setCookie(page).contains(WebSessions.PRE_COOKIE + "=" + pre + "; Path=/; HttpOnly; Secure"));
            check("the page token is the HMAC of that cookie", token.equals(WebSessions.preLoginCsrf(pre)));
            check("viewing the login page creates no session", count("SELECT COUNT(*) FROM panel_sessions") == sessionsBefore);
            check("no password field, no username step: passkey, email code, console code", !page.body().contains("type=\"password\"")
                    && page.body().contains("id=\"btnPasskey\"") && page.body().contains("id=\"emailForm\"") && page.body().contains("id=\"consoleForm\""));
            HttpResponse<String> again = ask("GET", "/index", null, "Cookie", WebSessions.PRE_COOKIE + "=" + pre);
            check("with the cookie already there: no new cookie, same token", cookieValue(again, WebSessions.PRE_COOKIE) == null
                    && again.body().contains("value=\"" + token + "\""));
            String preCookie = WebSessions.PRE_COOKIE + "=" + pre;

            System.out.println("\n== /api/login: the page token ==");
            String req = "{\"action\":\"code_request\",\"email\":\"" + bossEmail + "\"";
            check("without the token: 403", ask("POST", "/api/login", req + "}", "Cookie", preCookie).statusCode() == 403);
            check("the token without its cookie: 403", ask("POST", "/api/login", req + ",\"csrf_token\":\"" + token + "\"}").statusCode() == 403);
            check("the token with another browser's cookie: 403", ask("POST", "/api/login", req + ",\"csrf_token\":\"" + token + "\"}",
                    "Cookie", WebSessions.PRE_COOKIE + "=" + "z".repeat(43)).statusCode() == 403);
            check("GET: 405", ask("GET", "/api/login", null).statusCode() == 405);
            check("an unknown action: 400", ask("POST", "/api/login", "{\"action\":\"password\",\"csrf_token\":\"" + token + "\"}",
                    "Cookie", preCookie).statusCode() == 400);

            System.out.println("\n== /api/login: asking a code says nothing about the address ==");
            MAIL.clear();
            long t0 = System.currentTimeMillis();
            HttpResponse<String> real = ask("POST", "/api/login", req + ",\"csrf_token\":\"" + token + "\"}", "Cookie", preCookie, "Accept-Language", "en");
            long tReal = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            HttpResponse<String> nobody = ask("POST", "/api/login", "{\"action\":\"code_request\",\"email\":\"nobody" + suffix + "@example.org\",\"csrf_token\":\""
                    + token + "\"}", "Cookie", preCookie, "Accept-Language", "en");
            long tNobody = System.currentTimeMillis() - t0;
            check("an administrator's address and nobody's: the same status and the same body",
                    real.statusCode() == 200 && real.statusCode() == nobody.statusCode() && real.body().equals(nobody.body()));
            check("both take at least the minimum time (" + tReal + " ms, " + tNobody + " ms)", tReal >= 400 && tNobody >= 400);
            check("only the real one gets an email", MAIL.size() == 1 && MAIL.get(0)[0].equals(bossEmail));
            check("an address that is not an address: 400 (its shape only)", ask("POST", "/api/login",
                    "{\"action\":\"code_request\",\"email\":\"<script>\",\"csrf_token\":\"" + token + "\"}", "Cookie", preCookie).statusCode() == 400);
            String code = lastCode();
            String wrong = code.equals("000000") ? "111111" : "000000";
            HttpResponse<String> wrongReal = ask("POST", "/api/login", "{\"action\":\"code_verify\",\"email\":\"" + bossEmail + "\",\"code\":\"" + wrong
                    + "\",\"csrf_token\":\"" + token + "\"}", "Cookie", preCookie);
            HttpResponse<String> wrongNobody = ask("POST", "/api/login", "{\"action\":\"code_verify\",\"email\":\"nobody" + suffix + "@example.org\",\"code\":\""
                    + wrong + "\",\"csrf_token\":\"" + token + "\"}", "Cookie", preCookie);
            check("a wrong code, real address or not: the same 401 and the same body", wrongReal.statusCode() == 401
                    && wrongReal.statusCode() == wrongNobody.statusCode() && wrongReal.body().equals(wrongNobody.body())
                    && setCookie(wrongReal).isEmpty());

            System.out.println("\n== /api/login: a right code opens a session ==");
            HttpResponse<String> ok = ask("POST", "/api/login", "{\"action\":\"code_verify\",\"email\":\"" + bossEmail + "\",\"code\":\"" + code
                    + "\",\"csrf_token\":\"" + token + "\"}", "Cookie", preCookie);
            String session = cookieValue(ok, WebSessions.COOKIE);
            // Strict e senza Max-Age: un cookie di sessione del browser, mai mandato da un altro sito (reperto 184).
            check("200 and the session cookie: __Host-, HttpOnly, Secure, SameSite=Strict, a browser-session cookie", ok.statusCode() == 200 && session != null
                    && setCookie(ok).contains(WebSessions.COOKIE + "=" + session + "; Path=/; HttpOnly; Secure; SameSite=Strict")
                    && !setCookie(ok).contains("Max-Age=43200") && !setCookie(ok).contains("Expires"));
            JSONObject okJson = new JSONObject(ok.body());
            check("no passkey yet: sent to Account to create one", "/account?setup=passkey".equals(okJson.optString("redirect")));
            check("the session is in the database, by its hash", count("SELECT COUNT(*) FROM panel_sessions WHERE token_hash = ? AND admin_id = ?",
                    WebSessions.tokenHash(session), boss.id()) == 1);
            String sc = WebSessions.COOKIE + "=" + session;
            String csrf = WebSessions.csrfToken(session);
            check("the answer carries the session CSRF token", csrf.equals(okJson.optString("csrf_token")));
            HttpResponse<String> home = ask("GET", "/home", null, "Cookie", sc);
            check("with the cookie: the protected pages open, with the session token", home.statusCode() == 200
                    && home.body().contains("id=\"csrf_token\" value=\"" + csrf + "\""));
            check("another browser with the same cookie: back to the login", ask("GET", "/home", null, "Cookie", sc, "User-Agent", "Other/1.0").statusCode() == 302);
            check("the same code a second time: refused", ask("POST", "/api/login", "{\"action\":\"code_verify\",\"email\":\"" + bossEmail
                    + "\",\"code\":\"" + code + "\",\"csrf_token\":\"" + token + "\"}", "Cookie", preCookie).statusCode() == 401);

            System.out.println("\n== The Content-Security-Policy, and scripts and styles as files (reperto 178) ==");
            String policy = SecurityHeaders.CONTENT_SECURITY_POLICY;
            check("the login page and the home send the policy, without unsafe-inline", policy.equals(page.headers().firstValue("Content-Security-Policy").orElse(""))
                    && policy.equals(home.headers().firstValue("Content-Security-Policy").orElse("")) && !policy.contains("unsafe-"));
            for (HttpResponse<String> r : List.of(page, home)) {
                String b = r.body();
                check("no inline script, style block, handler or style attribute in " + r.uri().getPath(),
                        !Pattern.compile("<script(?![^>]*\\bsrc=)").matcher(b).find() && !b.contains("<style")
                        && !Pattern.compile("\\son[a-z]+=\"").matcher(b).find() && !Pattern.compile("\\sstyle=\"").matcher(b).find());
            }
            List<String> openAssets = new ArrayList<>(), ownAssets = new ArrayList<>();
            for (String b : List.of(page.body(), home.body())) {
                Matcher am = Pattern.compile("(?:src|href)=\"(/assets/[^\"]+)\"").matcher(b);
                while (am.find()) (am.group(1).startsWith("/assets/open/") ? openAssets : ownAssets).add(am.group(1));
            }
            check("the pages load their scripts and styles from /assets/ (" + openAssets.size() + " shared, " + ownAssets.size() + " of protected pages)",
                    openAssets.size() >= 3 && !ownAssets.isEmpty());
            boolean openOk = true;
            for (String a : openAssets) {
                HttpResponse<String> r = ask("GET", a, null);
                openOk &= r.statusCode() == 200 && r.headers().firstValue("Content-Type").orElse("").startsWith(a.endsWith(".css") ? "text/css" : "text/javascript")
                        && r.headers().firstValue("Cache-Control").orElse("").equals("public, max-age=31536000, immutable")
                        && r.headers().firstValue("X-Content-Type-Options").orElse("").equals("nosniff");
            }
            check("the shared files: to anybody, with their type, nosniff and a year of cache", openOk);
            boolean ownOk = true;
            for (String a : ownAssets) {
                ownOk &= ask("GET", a, null).statusCode() == 404;
                HttpResponse<String> r = ask("GET", a, null, "Cookie", sc);
                ownOk &= r.statusCode() == 200 && r.headers().firstValue("Cache-Control").orElse("").startsWith("private,");
            }
            check("the files of protected pages: 404 without a session, 200 (private) with it", ownOk);
            String one = openAssets.isEmpty() ? "/assets/open/x.js" : openAssets.get(0);
            check("a name that is not a fingerprint, a path outside, a POST: 404", ask("GET", "/assets/open/ABCDEF.js", null).statusCode() == 404
                    && ask("GET", "/assets/open/../../admin/home.html", null).statusCode() == 404
                    && ask("GET", "/assets/%2e%2e/admin/home.html", null, "Cookie", sc).statusCode() == 404
                    && ask("POST", one, "{}").statusCode() == 404);

            System.out.println("\n== /api/account ==");
            HttpResponse<String> info = ask("GET", "/api/account", null, "Cookie", sc);
            JSONObject infoJson = new JSONObject(info.body());
            check("GET: name, email, no passkeys, this session in the list", info.statusCode() == 200
                    && infoJson.getString("email").equals(bossEmail) && infoJson.getJSONArray("passkeys").isEmpty()
                    && infoJson.getJSONArray("sessions").length() >= 1 && infoJson.getBoolean("passkeysAvailable"));
            check("without a session: 401", ask("GET", "/api/account", null).statusCode() == 401);
            check("a POST without the CSRF token: 403 (the route filter)", ask("POST", "/api/account",
                    "{\"action\":\"revoke_other_sessions\"}", "Cookie", sc).statusCode() == 403);

            // A passkey over HTTP, signed by the software authenticator, with the origin of the page.
            String origin = "https://" + HOST + ":" + port;
            org.mail_panel.security.SoftAuthenticator key = new org.mail_panel.security.SoftAuthenticator();
            JSONObject regOpt = new JSONObject(ask("POST", "/api/account", "{\"action\":\"passkey_register_options\"}", "Cookie", sc, "X-CSRF-Token", csrf).body());
            check("registration options for the panel name (rpId " + HOST + ")", regOpt.optBoolean("success")
                    && regOpt.getJSONObject("options").getJSONObject("publicKey").getJSONObject("rp").getString("id").equals(HOST));
            String credential = key.register(regOpt.getJSONObject("options").toString(), origin);
            HttpResponse<String> badName = ask("POST", "/api/account", new JSONObject().put("action", "passkey_register").put("request", regOpt.getString("request"))
                    .put("credential", new JSONObject(credential)).put("name", "<img src=x>").toString(), "Cookie", sc, "X-CSRF-Token", csrf);
            check("a passkey name outside the whitelist: 400", badName.statusCode() == 400);
            regOpt = new JSONObject(ask("POST", "/api/account", "{\"action\":\"passkey_register_options\"}", "Cookie", sc, "X-CSRF-Token", csrf).body());
            credential = key.register(regOpt.getJSONObject("options").toString(), origin);
            HttpResponse<String> reg = ask("POST", "/api/account", new JSONObject().put("action", "passkey_register").put("request", regOpt.getString("request"))
                    .put("credential", new JSONObject(credential)).put("name", "Laptop").toString(), "Cookie", sc, "X-CSRF-Token", csrf);
            check("the passkey is registered", reg.statusCode() == 200 && AuthStore.passkeysOf(boss.id()).size() == 1);

            System.out.println("\n== /api/login with the passkey ==");
            JSONObject opt = new JSONObject(ask("POST", "/api/login", "{\"action\":\"passkey_options\",\"csrf_token\":\"" + token + "\"}", "Cookie", preCookie).body());
            check("options without a list of credentials", opt.optBoolean("success") && !opt.getJSONObject("options").toString().contains("allowCredentials\":[{"));
            String assertion = key.assertion(opt.getJSONObject("options").toString(), origin);
            HttpResponse<String> pk = ask("POST", "/api/login", new JSONObject().put("action", "passkey_verify").put("request", opt.getString("request"))
                    .put("credential", new JSONObject(assertion)).put("csrf_token", token).toString(), "Cookie", preCookie);
            String pkSession = cookieValue(pk, WebSessions.COOKIE);
            check("a valid passkey: a new session, straight to the home", pk.statusCode() == 200 && pkSession != null
                    && "/home".equals(new JSONObject(pk.body()).optString("redirect")));
            HttpResponse<String> pkAgain = ask("POST", "/api/login", new JSONObject().put("action", "passkey_verify").put("request", opt.getString("request"))
                    .put("credential", new JSONObject(assertion)).put("csrf_token", token).toString(), "Cookie", preCookie);
            check("the same assertion again: 401, no cookie", pkAgain.statusCode() == 401 && cookieValue(pkAgain, WebSessions.COOKIE) == null);
            // Aperto per INDIRIZZO invece che col nome. Da quando il pannello guarda l'Host
            // (HostCheck) sono due cose distinte, e qui si provano entrambe.
            //
            // 1) Col nome configurato, un Host che e' un indirizzo non arriva nemmeno al
            //    gestore: 421, e il corpo non e' JSON. Prima questa riga ci costruiva sopra un
            //    JSONObject e la prova si spaccava con "A JSONObject text must begin with '{'".
            String body = "{\"action\":\"passkey_options\",\"csrf_token\":\"" + token + "\"}";
            HttpResponse<String> byAddress = ask("POST", "/api/login", body,
                    "Cookie", preCookie, "Host", "127.0.0.1:" + port);
            check("opened by IP address while the panel answers to a name: 421, before the handler",
                    byAddress.statusCode() == 421);

            // 2) E con l'indirizzo configurato a wildcard -- quello che scrive l'installatore --
            //    un Host che e' un indirizzo viene servito, e allora e' il gestore delle
            //    passkey a dire che gli serve un nome. E' la proprieta' che questa riga
            //    provava da sempre, e va provata nella condizione in cui esiste ancora.
            Main.dbManager.update_panel_config("0.0.0.0", "0", Files.readString(dir.resolve("c.pem")),
                    Files.readString(dir.resolve("k.pem")), "", "mailpanel-");
            try {
                JSONObject ipOpt = new JSONObject(ask("POST", "/api/login", body,
                        "Cookie", preCookie, "Host", "127.0.0.1:" + port).body());
                check("opened by IP address, panel listening everywhere: the passkey needs a name"
                        + " (the server says so)", !ipOpt.optBoolean("success"));
            } finally {
                Main.dbManager.update_panel_config(HOST, "0", Files.readString(dir.resolve("c.pem")),
                        Files.readString(dir.resolve("k.pem")), "", "mailpanel-");
            }

            System.out.println("\n== /api/login with the console code ==");
            String console = LoginCodes.issueConsoleCode(AuthStore.adminById(plain.id()).orElseThrow());
            HttpResponse<String> cons = ask("POST", "/api/login", "{\"action\":\"console_verify\",\"code\":\"" + console.substring(0, 4) + " " + console.substring(4)
                    + "\",\"csrf_token\":\"" + token + "\"}", "Cookie", preCookie);
            String plainSession = cookieValue(cons, WebSessions.COOKIE);
            check("the console code: a session for that administrator", cons.statusCode() == 200 && plainSession != null
                    && count("SELECT COUNT(*) FROM panel_sessions WHERE token_hash = ? AND admin_id = ?", WebSessions.tokenHash(plainSession), plain.id()) == 1);

            System.out.println("\n== /api/admins: emails, no passwords ==");
            String pc = WebSessions.COOKIE + "=" + plainSession;
            check("an admin without the admins.manage permission: 403", ask("GET", "/api/admins?action=list", null, "Cookie", pc).statusCode() == 403);
            JSONObject list = new JSONObject(ask("GET", "/api/admins?action=list", null, "Cookie", sc).body());
            JSONArray admins = list.getJSONArray("admins");
            boolean emails = false, noSecrets = true;
            for (int i = 0; i < admins.length(); i++) {
                JSONObject a = admins.getJSONObject(i);
                if (a.getLong("id") == boss.id()) emails = a.getString("email").equals(bossEmail) && a.getBoolean("is_current");
                noSecrets &= !a.has("password_hash") && !a.has("totp_enabled");
            }
            check("the superadmin sees the list: emails, no password or TOTP fields", list.getBoolean("success") && emails && noSecrets);
            JSONObject noEmail = new JSONObject(ask("POST", "/api/admins", "{\"action\":\"create\",\"username\":\"new" + suffix + "\",\"role\":\"admin\"}",
                    "Cookie", sc, "X-CSRF-Token", csrf).body());
            check("a new administrator without an email: refused", !noEmail.getBoolean("success"));
            JSONObject created = new JSONObject(ask("POST", "/api/admins", "{\"action\":\"create\",\"username\":\"new" + suffix + "\",\"email\":\"new" + suffix
                    + "@example.org\",\"role\":\"admin\",\"password\":\"ignored\"}", "Cookie", sc, "X-CSRF-Token", csrf).body());
            check("with an email: created (a password field is ignored)", created.getBoolean("success")
                    && AuthStore.adminByEmail("new" + suffix + "@example.org").isPresent());
            JSONObject dup = new JSONObject(ask("POST", "/api/admins", "{\"action\":\"create\",\"username\":\"dup" + suffix + "\",\"email\":\"" + bossEmail
                    + "\",\"role\":\"admin\"}", "Cookie", sc, "X-CSRF-Token", csrf).body());
            check("an email already used: refused", !dup.getBoolean("success"));
            check("deleting yourself: refused", !new JSONObject(ask("POST", "/api/admins", "{\"action\":\"delete\",\"id\":" + boss.id() + "}",
                    "Cookie", sc, "X-CSRF-Token", csrf).body()).getBoolean("success"));
            check("changing your own role: refused", !new JSONObject(ask("POST", "/api/admins", "{\"action\":\"update\",\"id\":" + boss.id()
                    + ",\"role\":\"viewer\"}", "Cookie", sc, "X-CSRF-Token", csrf).body()).getBoolean("success"));
            long newId = created.getLong("id");
            check("deleting another administrator: done, and its sessions go with it", new JSONObject(ask("POST", "/api/admins",
                    "{\"action\":\"delete\",\"id\":" + newId + "}", "Cookie", sc, "X-CSRF-Token", csrf).body()).getBoolean("success")
                    && count("SELECT COUNT(*) FROM panel_admin WHERE id = ?", newId) == 0);

            System.out.println("\n== The vault wants a recent confirmation ==");
            JSONObject vault = new JSONObject(ask("POST", "/api/admins", "{\"action\":\"vault_backup_key\"}", "Cookie", sc, "X-CSRF-Token", csrf).body());
            check("without a confirmation: needs_reauth, no key", !vault.getBoolean("success") && vault.optBoolean("needs_reauth") && !vault.has("key_base64"));
            check("the old way (current_password) does not count", new JSONObject(ask("POST", "/api/admins",
                    "{\"action\":\"vault_backup_key\",\"current_password\":\"anything\"}", "Cookie", sc, "X-CSRF-Token", csrf).body()).optBoolean("needs_reauth"));
            check("an admin without the vault.manage permission: 403", ask("POST", "/api/admins", "{\"action\":\"vault_backup_key\"}",
                    "Cookie", pc, "X-CSRF-Token", WebSessions.csrfToken(plainSession)).statusCode() == 403);
            JSONObject suReq = new JSONObject(ask("POST", "/api/account", "{\"action\":\"stepup_code_request\"}", "Cookie", sc, "X-CSRF-Token", csrf).body());
            String su = lastCode();
            check("the confirmation code goes to the own email", suReq.getBoolean("success") && MAIL.get(MAIL.size() - 1)[0].equals(bossEmail));
            check("a wrong confirmation code: 401", ask("POST", "/api/account", "{\"action\":\"stepup_code_verify\",\"code\":\""
                    + (su.equals("000000") ? "111111" : "000000") + "\"}", "Cookie", sc, "X-CSRF-Token", csrf).statusCode() == 401);
            check("the right one: confirmed, for this session", ask("POST", "/api/account", "{\"action\":\"stepup_code_verify\",\"code\":\"" + su + "\"}",
                    "Cookie", sc, "X-CSRF-Token", csrf).statusCode() == 200
                    && new JSONObject(ask("GET", "/api/account", null, "Cookie", sc).body()).getBoolean("reauthenticated")
                    && !new JSONObject(ask("GET", "/api/account", null, "Cookie", WebSessions.COOKIE + "=" + pkSession).body()).getBoolean("reauthenticated"));

            System.out.println("\n== Sessions and logout ==");
            JSONObject others = new JSONObject(ask("POST", "/api/account", "{\"action\":\"revoke_other_sessions\"}", "Cookie", sc, "X-CSRF-Token", csrf).body());
            check("close the other sessions: the passkey one is gone", others.getBoolean("success")
                    && ask("GET", "/home", null, "Cookie", WebSessions.COOKIE + "=" + pkSession).statusCode() == 302);
            check("logout without the token: 403, still in", ask("POST", "/api/logout", "{}", "Cookie", sc).statusCode() == 403
                    && ask("GET", "/home", null, "Cookie", sc).statusCode() == 200);
            HttpResponse<String> out = ask("POST", "/api/logout", "{}", "Cookie", sc, "X-CSRF-Token", csrf);
            check("logout: the cookie is cleared and the session is gone from the database", out.statusCode() == 200
                    && setCookie(out).contains(WebSessions.COOKIE + "=; ") && setCookie(out).contains("Max-Age=0")
                    && count("SELECT COUNT(*) FROM panel_sessions WHERE token_hash = ?", WebSessions.tokenHash(session)) == 0
                    && ask("GET", "/home", null, "Cookie", sc).statusCode() == 302);
            check("logout by GET does nothing (no state change via GET)", ask("GET", "/api/logout", null, "Cookie", pc).statusCode() == 405
                    && ask("GET", "/home", null, "Cookie", pc).statusCode() == 200);

            System.out.println("\n== The old routes are gone ==");
            for (String old : List.of("/login_check", "/api/auth/check", "/api/2fa", "/api/passkey/login/start")) {
                HttpResponse<String> r = ask("POST", old, "{\"username\":\"boss" + suffix + "\"}", "Cookie", preCookie);
                check(old + ": not a login route any more (" + r.statusCode() + ")", (r.statusCode() == 302 || r.statusCode() == 404)
                        && !r.body().contains("success"));
            }

            System.out.println("\n== The first administrator is not created from the web ==");
            HttpResponse<String> setup = ask("POST", "/api/setup", "{\"action\":\"auto_setup\",\"admin_username\":\"intruder" + suffix
                    + "\",\"admin_email\":\"intruder" + suffix + "@example.org\",\"csrf_token\":\"" + token + "\"}", "Cookie", preCookie);
            check("/api/setup is gone: no administrator created (" + setup.statusCode() + ")", (setup.statusCode() == 302 || setup.statusCode() == 404)
                    && !setup.body().contains("success") && AuthStore.adminByUsername("intruder" + suffix).isEmpty());
            HttpResponse<String> setupPage = ask("GET", "/setup", null);
            check("/setup with an administrator already there: to the login", setupPage.statusCode() == 302
                    && "/index".equals(setupPage.headers().firstValue("Location").orElse("")));
            Main.setupRequired = true;
            HttpResponse<String> root = ask("GET", "/", null);
            check("a panel waiting for its first administrator notices it at the next request", root.statusCode() == 302
                    && "/index".equals(root.headers().firstValue("Location").orElse("")) && !Main.setupRequired);
        } finally {
            https.stop(0);
            for (long id : new long[]{boss.id(), plain.id()}) AuthStore.deleteAdmin(id);
            db.close();
            if (!adminDirExisted && Files.exists(adminDir)) {
                try (var files = Files.walk(adminDir)) {
                    for (Path p : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) Files.delete(p);
                }
            }
            try (var files = Files.walk(dir)) {
                for (Path p : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) Files.delete(p);
            }
        }
        System.out.println(failed == 0 ? "\nAll checks passed." : "\nFailed checks: " + failed);
        if (failed > 0) System.exit(1);
    }
}
