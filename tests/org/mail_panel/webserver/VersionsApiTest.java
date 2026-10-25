package org.mail_panel.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.json.JSONObject;
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
 * /api/versioni e /api/service sul server VERO (SSLMailServer), via HTTPS, con una sessione come
 * quella del login e il MySQL di prova. Non parte nient'altro del pannello: si accende solo il
 * server HTTP con le sue rotte, senza i gestori (ACME, DKIM, rapporto) che toccherebbero il sistema.
 *
 * Si controlla: senza sessione 401; con la sessione le versioni, con MySQL letto dal server vero;
 * la lettura tenuta trenta secondi e "fresco" che non rilegge prima di tre; parametri e metodi
 * sbagliati rifiutati; /api/service senza token CSRF o con un token sbagliato 403, scritto nel
 * registro di audit; con il token giusto la richiesta passa (e un servizio sconosciuto e' 400);
 * un'azione su un servizio finisce nel registro e fa rileggere le versioni.
 *
 * Il servizio usato per l'azione e' redis, e l'esito del restart NON si pretende: redis lo
 * installa l'installatore di questo stesso pannello, quindi su una macchina col server di posta
 * installato quel restart riesce, mentre su una macchina nuda fallisce. Si pretende invece la
 * cosa che deve valere sempre: che la risposta e il registro di audit dicano lo stesso esito.
 *
 * Uso (con il MySQL di prova del README.md; lo schema se lo prepara da sola):
 *   java -Dmysql.port=33062 -Dmysql.utente=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova \
 *        -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.VersionsApiTest
 */
public class VersionsApiTest {

    static int failed = 0;

    static void real(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
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
        if (withSession) b.header("Cookie", "__Host-MailPanel=" + code);
        if (body != null) b.header("Content-Type", "application/json");
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Una POST a cui il server risponde prima di leggerne il corpo (405, 401: come in tutto il
     * pannello) su una connessione tutta sua. Sulla connessione condivisa la richiesta successiva
     * a volte trovava il socket chiuso dal server e il client, su una POST, non riprova: "HTTP/1.1
     * header parser received no bytes", una volta su venti. Non e' quello che si sta provando.
     */
    static HttpResponse<String> askSeparately(String method, String path, String body, boolean withSession) throws Exception {
        try (HttpClient onlyOne = HttpClient.newBuilder().sslContext(http.sslContext()).build()) {
            return ask(onlyOne, method, path, body, withSession);
        }
    }

    /**
     * L'esito che il registro attribuisce a quell'azione: il pannello scrive
     * {@code service=<nome>} e ci aggiunge {@code (failed)} solo se non e' riuscita
     * (SSLMailServer, "service=" + service + (success ? "" : " (failed)")). Quindi l'assenza
     * di quella parola E' il "riuscito", e va letta sulla riga, non su tutto il file: un
     * {@code contains("service=redis")} sarebbe vero anche per "service=redis (failed)".
     */
    static boolean outcomeInRegistry(Path log, String action) throws Exception {
        for (String line : Files.readString(log).split("\n"))
            if (line.contains(action)) return !line.contains("(failed)");
        throw new IllegalStateException("nel registro non c'e' nessuna riga " + action);
    }

    static boolean waitForLine(Path log, String text) throws Exception {
        for (int i = 0; i < 40; i++) {
            if (Files.exists(log) && Files.readString(log).contains(text)) return true;
            Thread.sleep(50);
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        String port = System.getProperty("mysql.porta");
        if (port == null) {
            System.out.println("MySQL non indicato (-Dmysql.porta=...): questa prova ha bisogno del MySQL di prova, la salto.");
            return;
        }
        // Prima di creare il client: il certificato di prova e' per localhost, si chiama 127.0.0.1.
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        Path folder = Files.createTempDirectory("api-versioni");
        Path log = folder.resolve("audit.log");

        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.utente", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "mailpanel_prova"));
        real("connessione a MySQL", db.connect());
        // Lo schema PRIMA della voce, e la voce riletta: vedi TestSessions.auditLogTo.
        // Scritta prima che le tabelle esistessero, non si salvava e il pannello
        // scriveva nel registro vero.
        TestSessions.auditLogTo(db, log);
        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        String[] login = TestSessions.open(db, "versions-test", UA);
        code = login[0];
        String csrf = login[1];

        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", folder.resolve("k.pem").toString(), "-out", folder.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        real("certificato di prova", cert.waitFor() == 0);
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
            System.out.println("\n== /api/versioni ==");
            real("senza sessione: 401", ask("GET", "/api/versioni", null, false).statusCode() == 401);
            HttpResponse<String> r = ask("GET", "/api/versioni", null, true);
            JSONObject j = new JSONObject(r.body());
            String mysql = db.serverVersion();
            JSONObject line = j.getJSONObject("services").getJSONObject("mysql");
            real("con la sessione: 200 e le sette righe dei servizi", r.statusCode() == 200 && j.getBoolean("success")
                    && j.getJSONObject("services").length() == 7);
            real("MySQL letto dal server vero, in esecuzione: " + line.optString("version"),
                    mysql != null && mysql.equals(line.optString("version")) && line.optBoolean("running"));
            String read = j.getString("readAt");
            real("seconda richiesta: la stessa lettura (" + read + ")",
                    new JSONObject(ask("GET", "/api/versioni", null, true).body()).getString("readAt").equals(read));
            real("\"fresco\" entro tre secondi: la stessa lettura",
                    new JSONObject(ask("GET", "/api/versioni?fresco=1", null, true).body()).getString("readAt").equals(read));
            real("fresco=2: 400", ask("GET", "/api/versioni?fresco=2", null, true).statusCode() == 400);
            // Il token CSRF si guarda prima di tutto (il filtro di ogni rotta): senza, 403; con, il 405 del gestore
            real("POST without the CSRF token: 403", askSeparately("POST", "/api/versioni", "{}", true).statusCode() == 403);
            real("POST with the token: 405", askSeparately("POST", "/api/versioni", "{\"csrf_token\":\"" + csrf + "\"}", true).statusCode() == 405);

            System.out.println("\n== /api/service: il token CSRF ==");
            HttpResponse<String> without = ask("POST", "/api/service", "{\"service\":\"redis\",\"action\":\"stop\"}", true);
            real("senza token: 403", without.statusCode() == 403);
            real("con un token sbagliato: 403", ask("POST", "/api/service",
                    "{\"service\":\"redis\",\"action\":\"stop\",\"csrf_token\":\"sbagliato\"}", true).statusCode() == 403);
            // sendCsrfError risponde e POI scrive il registro: si aspetta la riga, al massimo due secondi.
            real("e il registro di audit lo dice (CSRF_FAILURE)", waitForLine(log, "CSRF_FAILURE"));
            HttpResponse<String> unknown = ask("POST", "/api/service",
                    "{\"service\":\"sshd\",\"action\":\"stop\",\"csrf_token\":\"" + csrf + "\"}", true);
            real("con il token giusto passa: un servizio che non si governa da qui e' 400", unknown.statusCode() == 400
                    && unknown.body().contains("Invalid service"));
            real("senza sessione, anche con il token: 401", askSeparately("POST", "/api/service",
                    "{\"service\":\"redis\",\"action\":\"restart\",\"csrf_token\":\"" + csrf + "\"}", false).statusCode() == 401);

            System.out.println("\n== Un'azione: registro e versioni rilette ==");
            Thread.sleep(1100);   // letteAlle ha i secondi: una nuova lettura deve potersi distinguere
            HttpResponse<String> action = ask("POST", "/api/service",
                    "{\"service\":\"redis\",\"action\":\"restart\",\"csrf_token\":\"" + csrf + "\"}", true);
            // Non si pretende che redis FALLISCA. Lo pretendeva, con il commento "qui non
            // c'e' redis": ma redis lo installa l'installatore di questo stesso pannello, e
            // su una macchina con il server di posta installato "service redis restart"
            // riesce. Due controlli su due cadevano, su un difetto che non c'era.
            //
            // L'invariante vero e' un altro, e vale su qualunque macchina: la risposta e il
            // registro devono dire LA STESSA COSA. Se divergessero, chi legge l'audit log
            // crederebbe riuscito quello che e' fallito, o il contrario.
            boolean succeeded = new JSONObject(action.body()).getBoolean("success");
            real("redis restart: risposta 200, esito " + (succeeded ? "riuscito" : "non riuscito")
                    + " (dipende da questa macchina, e va bene)", action.statusCode() == 200);
            real("nel registro c'e' SERVICE_RESTART di redis", waitForLine(log, "SERVICE_RESTART")
                    && waitForLine(log, "service=redis"));
            real("e il registro dice lo STESSO esito della risposta",
                    outcomeInRegistry(log, "SERVICE_RESTART") == succeeded);
            String after = new JSONObject(ask("GET", "/api/versioni", null, true).body()).getString("readAt");
            real("dopo l'azione le versioni si rileggono, anche senza fresco: " + after, !after.equals(read));
        } finally {
            https.stop(0);
            db.close();
            Files.deleteIfExists(log);
            Files.deleteIfExists(folder.resolve("k.pem"));
            Files.deleteIfExists(folder.resolve("c.pem"));
            Files.deleteIfExists(folder);
        }

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
