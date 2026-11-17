package org.daemoxcp.mail.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.daemoxcp.mail.Main;

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
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * HEAD on the real server, without MySQL. Before, every handler sent the body's length and then wrote
 * the body: with HEAD, Java's HTTP server logged "being invoked with a content length for a HEAD
 * request" and refused the write ("stream closed"), which the sign-in page's handler logged as SEVERE.
 * Seen on the real server on 07/11/2026 with a single `curl -I`. Now (HeadExchange, the first filter of
 * every route) a HEAD gets the same status and headers as the GET, Content-Length included, and no
 * body:
 *
 *  - the sign-in page, a script of it, a Font Awesome file, a protected page (the GET sends to the
 *    sign-in: so must the HEAD, not answer 401), an API without a session, a wrong Host (421);
 *  - for each: the same status as the GET, no body, the GET's length in Content-Length where the GET
 *    has a body;
 *  - and nothing logged at WARNING or above about it.
 *
 * Usage (on the VM):
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.webserver.HeadRequestTest
 */
public class HeadRequestTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        // The wrong-Host case needs the Host header, which the HTTP client lets through only with this.
        System.setProperty("jdk.httpclient.allowRestrictedHeaders", "host");
        List<String> logged = new CopyOnWriteArrayList<>();
        Logger root = Logger.getLogger("");
        Handler watch = new Handler() {
            @Override public void publish(LogRecord r) {
                if (r.getLevel().intValue() >= Level.WARNING.intValue())
                    logged.add(r.getLevel() + " " + r.getMessage() + (r.getThrown() == null ? "" : " " + r.getThrown()));
            }
            @Override public void flush() { }
            @Override public void close() { }
        };
        Path dir = Files.createTempDirectory("head");
        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        check("test certificate", cert.waitFor() == 0);
        // The pages and their scripts next to the jar, as the panel writes them at start.
        org.daemoxcp.mail.content.MailPanelContent.generateAllContent();
        Main.mysqlAvailable = false;
        Main.setupRequired = false;
        SSLMailServer srv = new SSLMailServer(0, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();
        String base = "https://127.0.0.1:" + https.getAddress().getPort();
        SSLContext trustAll = SSLContext.getInstance("TLS");
        trustAll.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] x, String a) { }
            public void checkServerTrusted(X509Certificate[] x, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        HttpClient http = HttpClient.newBuilder().sslContext(trustAll).build();

        try {
            // A script of the sign-in page, as written next to the jar (without MySQL /index is the
            // "unavailable" page, which has none).
            Path open = Path.of(org.daemoxcp.mail.Main.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                    .getParent().resolve("admin/assets/open");
            String script = "/assets/open/" + Files.list(open).map(p -> p.getFileName().toString())
                    .filter(n -> n.endsWith(".js")).findFirst().orElse("none.js");
            root.addHandler(watch);
            String[][] cases = {{"/index", null}, {script, null}, {"/fa/css/all.min.css", null}, {"/home", null},
                    {"/api/domains", null}, {"/index", "evil.example"}};
            for (String[] c : cases) {
                HttpRequest.Builder g = HttpRequest.newBuilder(URI.create(base + c[0]));
                HttpRequest.Builder h = HttpRequest.newBuilder(URI.create(base + c[0])).method("HEAD", HttpRequest.BodyPublishers.noBody());
                if (c[1] != null) { g.header("Host", c[1]); h.header("Host", c[1]); }
                HttpResponse<byte[]> get = http.send(g.build(), HttpResponse.BodyHandlers.ofByteArray());
                HttpResponse<byte[]> head = http.send(h.build(), HttpResponse.BodyHandlers.ofByteArray());
                String length = head.headers().firstValue("Content-Length").orElse("none");
                String what = "HEAD " + c[0] + (c[1] == null ? "" : " (Host " + c[1] + ")") + ": " + head.statusCode()
                        + " like GET " + get.statusCode() + ", body " + head.body().length + ", Content-Length " + length
                        + " for a GET body of " + get.body().length;
                check(what, head.statusCode() == get.statusCode() && head.body().length == 0
                        && (get.body().length == 0 || length.equals(String.valueOf(get.body().length))));
            }
            Thread.sleep(300);
            // Without SQLite hostAllowed warns, on every request, that it cannot read the panel's host.
            logged.removeIf(l -> l.contains("Cannot read the configured panel host"));
            check("nothing logged at WARNING or above about the HEAD requests" + (logged.isEmpty() ? "" : " " + logged),
                    logged.stream().noneMatch(l -> l.contains("HEAD") || l.contains("stream closed") || l.contains("Error in")));
        } finally {
            root.removeHandler(watch);
            https.stop(0);
            for (String n : new String[]{"k.pem", "c.pem"}) Files.deleteIfExists(dir.resolve(n));
            Files.deleteIfExists(dir);
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
