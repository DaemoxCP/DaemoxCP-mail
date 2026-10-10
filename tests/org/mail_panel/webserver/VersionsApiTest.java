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
 * Il servizio usato per l'azione e' redis, che qui non c'e': "service redis restart" fallisce
 * senza toccare niente, ed e' quello che serve.
 *
 * Uso (con il MySQL di prova del README.md, gia' con le tabelle create da AddressConversionTest):
 *   java -Dmysql.porta=33062 -Dmysql.utente=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova \
 *        -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.VersionsApiTest
 */
public class VersionsApiTest {

    static int falliti = 0;

    static void vero(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }

    static HttpClient http;
    static String base, codice;
    static final String UA = "VersionsApiTest/1.0";

    static HttpResponse<String> chiedi(String metodo, String percorso, String corpo, boolean conSessione) throws Exception {
        return chiedi(http, metodo, percorso, corpo, conSessione);
    }

    static HttpResponse<String> chiedi(HttpClient client, String metodo, String percorso, String corpo, boolean conSessione) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + percorso)).header("User-Agent", UA);
        if (conSessione) b.header("Cookie", "__Host-MailPanel=" + codice);
        if (corpo != null) b.header("Content-Type", "application/json");
        b.method(metodo, corpo == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(corpo));
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Una POST a cui il server risponde prima di leggerne il corpo (405, 401: come in tutto il
     * pannello) su una connessione tutta sua. Sulla connessione condivisa la richiesta successiva
     * a volte trovava il socket chiuso dal server e il client, su una POST, non riprova: "HTTP/1.1
     * header parser received no bytes", una volta su venti. Non e' quello che si sta provando.
     */
    static HttpResponse<String> chiediAParte(String metodo, String percorso, String corpo, boolean conSessione) throws Exception {
        try (HttpClient solo = HttpClient.newBuilder().sslContext(http.sslContext()).build()) {
            return chiedi(solo, metodo, percorso, corpo, conSessione);
        }
    }

    static boolean aspettaRiga(Path registro, String testo) throws Exception {
        for (int i = 0; i < 40; i++) {
            if (Files.exists(registro) && Files.readString(registro).contains(testo)) return true;
            Thread.sleep(50);
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        String porta = System.getProperty("mysql.porta");
        if (porta == null) {
            System.out.println("MySQL non indicato (-Dmysql.porta=...): questa prova ha bisogno del MySQL di prova, la salto.");
            return;
        }
        // Prima di creare il client: il certificato di prova e' per localhost, si chiama 127.0.0.1.
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        Path cartella = Files.createTempDirectory("api-versioni");
        Path registro = cartella.resolve("audit.log");

        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.utente", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(porta), System.getProperty("mysql.database", "mailpanel_prova"));
        vero("connessione a MySQL", db.connect());
        db.setSetting("audit_log_file_path", registro.toString());
        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        String[] login = TestSessions.open(db, "versions-test", UA);
        codice = login[0];
        String csrf = login[1];

        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", cartella.resolve("k.pem").toString(), "-out", cartella.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        vero("certificato di prova", cert.waitFor() == 0);
        SSLMailServer srv = new SSLMailServer(0, Files.readString(cartella.resolve("c.pem")), Files.readString(cartella.resolve("k.pem")));
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();
        base = "https://127.0.0.1:" + https.getAddress().getPort();

        SSLContext fidati = SSLContext.getInstance("TLS");
        fidati.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) { }
            public void checkServerTrusted(X509Certificate[] c, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        http = HttpClient.newBuilder().sslContext(fidati).build();

        try {
            System.out.println("\n== /api/versioni ==");
            vero("senza sessione: 401", chiedi("GET", "/api/versioni", null, false).statusCode() == 401);
            HttpResponse<String> r = chiedi("GET", "/api/versioni", null, true);
            JSONObject j = new JSONObject(r.body());
            String mysql = db.versioneServer();
            JSONObject riga = j.getJSONObject("servizi").getJSONObject("mysql");
            vero("con la sessione: 200 e le sette righe dei servizi", r.statusCode() == 200 && j.getBoolean("success")
                    && j.getJSONObject("servizi").length() == 7);
            vero("MySQL letto dal server vero, in esecuzione: " + riga.optString("versione"),
                    mysql != null && mysql.equals(riga.optString("versione")) && riga.optBoolean("inEsecuzione"));
            String lette = j.getString("letteAlle");
            vero("seconda richiesta: la stessa lettura (" + lette + ")",
                    new JSONObject(chiedi("GET", "/api/versioni", null, true).body()).getString("letteAlle").equals(lette));
            vero("\"fresco\" entro tre secondi: la stessa lettura",
                    new JSONObject(chiedi("GET", "/api/versioni?fresco=1", null, true).body()).getString("letteAlle").equals(lette));
            vero("fresco=2: 400", chiedi("GET", "/api/versioni?fresco=2", null, true).statusCode() == 400);
            // Il token CSRF si guarda prima di tutto (il filtro di ogni rotta): senza, 403; con, il 405 del gestore
            vero("POST without the CSRF token: 403", chiediAParte("POST", "/api/versioni", "{}", true).statusCode() == 403);
            vero("POST with the token: 405", chiediAParte("POST", "/api/versioni", "{\"csrf_token\":\"" + csrf + "\"}", true).statusCode() == 405);

            System.out.println("\n== /api/service: il token CSRF ==");
            HttpResponse<String> senza = chiedi("POST", "/api/service", "{\"service\":\"redis\",\"action\":\"stop\"}", true);
            vero("senza token: 403", senza.statusCode() == 403);
            vero("con un token sbagliato: 403", chiedi("POST", "/api/service",
                    "{\"service\":\"redis\",\"action\":\"stop\",\"csrf_token\":\"sbagliato\"}", true).statusCode() == 403);
            // sendCsrfError risponde e POI scrive il registro: si aspetta la riga, al massimo due secondi.
            vero("e il registro di audit lo dice (CSRF_FAILURE)", aspettaRiga(registro, "CSRF_FAILURE"));
            HttpResponse<String> ignoto = chiedi("POST", "/api/service",
                    "{\"service\":\"sshd\",\"action\":\"stop\",\"csrf_token\":\"" + csrf + "\"}", true);
            vero("con il token giusto passa: un servizio che non si governa da qui e' 400", ignoto.statusCode() == 400
                    && ignoto.body().contains("Servizio non valido"));
            vero("senza sessione, anche con il token: 401", chiediAParte("POST", "/api/service",
                    "{\"service\":\"redis\",\"action\":\"restart\",\"csrf_token\":\"" + csrf + "\"}", false).statusCode() == 401);

            System.out.println("\n== Un'azione: registro e versioni rilette ==");
            Thread.sleep(1100);   // letteAlle ha i secondi: una nuova lettura deve potersi distinguere
            HttpResponse<String> azione = chiedi("POST", "/api/service",
                    "{\"service\":\"redis\",\"action\":\"restart\",\"csrf_token\":\"" + csrf + "\"}", true);
            vero("redis restart: risposta 200 (qui fallisce, non c'e' redis)", azione.statusCode() == 200
                    && !new JSONObject(azione.body()).getBoolean("success"));
            vero("nel registro: SERVICE_RESTART di redis, non riuscito", aspettaRiga(registro, "SERVICE_RESTART")
                    && aspettaRiga(registro, "Servizio: redis (non riuscito)"));
            String dopo = new JSONObject(chiedi("GET", "/api/versioni", null, true).body()).getString("letteAlle");
            vero("dopo l'azione le versioni si rileggono, anche senza fresco: " + dopo, !dopo.equals(lette));
        } finally {
            https.stop(0);
            db.close();
            Files.deleteIfExists(registro);
            Files.deleteIfExists(cartella.resolve("k.pem"));
            Files.deleteIfExists(cartella.resolve("c.pem"));
            Files.deleteIfExists(cartella);
        }

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        System.exit(falliti == 0 ? 0 : 1);
    }
}
