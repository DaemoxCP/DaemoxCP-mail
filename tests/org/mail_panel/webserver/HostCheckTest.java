package org.mail_panel.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.mail_panel.Main;
import org.mail_panel.sqli.dataBaseManager;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.concurrent.Executors;

/**
 * Il controllo dell'intestazione Host, che nel pannello mail non c'era affatto.
 *
 * Non e' una formalita': da Host vengono l'rpId e l'origine delle passkey, e PasskeyService
 * controlla che l'Host SOMIGLI a un nome DNS, non che sia il nome di questo pannello.
 *
 * Quello che va provato qui, e che compilare non direbbe:
 *  - il confronto e' ESATTO. Con panel.esempio.it configurato, "contiene" farebbe passare
 *    panel.esempio.it.qualcunaltro.com, che e' un nome che registra chi vuole;
 *  - due indirizzi IP si confrontano come INDIRIZZI: ::1 e 0:0:0:0:0:0:0:1 sono lo stesso
 *    indirizzo e come testo sembrano diversi;
 *  - non si risolve MAI un nome col DNS. Risolvere vorrebbe dire far passare qualunque nome
 *    fatto puntare a questa macchina, cioe' il rebinding da cui il controllo difende;
 *  - con l'indirizzo a 0.0.0.0 -- che e' proprio quello che l'installatore scrive -- il
 *    pannello deve restare raggiungibile, da localhost e dai propri indirizzi;
 *  - e soprattutto che il controllo sia DAVVERO in mezzo alle richieste. Qui parte un
 *    SSLMailServer vero e gli si parla in TLS cambiando solo l'Host: le funzioni pure si
 *    possono scrivere giuste e non collegarle a niente.
 *
 * Si lancia da una cartella vuota (ci crea database/ suo):
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.HostCheckTest
 */
public class HostCheckTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        OUT.println("\n== Che cosa vuol dire \"ascolta ovunque\" ==");
        for (String w : new String[]{"", "0.0.0.0", "::", "[::]", "*", "0:0:0:0:0:0:0:0", " 0.0.0.0 "})
            check("wildcard: [" + w + "]", HostCheck.isWildcardHost(w));
        check("wildcard: null", HostCheck.isWildcardHost(null));
        for (String n : new String[]{"panel.esempio.it", "127.0.0.1", "::1", "localhost"})
            check("NON wildcard: " + n, !HostCheck.isWildcardHost(n));

        OUT.println("\n== Il nome dentro l'intestazione Host ==");
        check("la porta si toglie", "panel.esempio.it".equals(HostCheck.hostName("panel.esempio.it:2096")));
        check("le maiuscole no", "panel.esempio.it".equals(HostCheck.hostName("PANEL.Esempio.IT")));
        check("il punto della radice DNS si toglie", "panel.esempio.it".equals(HostCheck.hostName("panel.esempio.it.")));
        check("un IPv6 fra parentesi con la porta", "::1".equals(HostCheck.hostName("[::1]:2096")));
        check("un IPv6 fra parentesi senza porta", "::1".equals(HostCheck.hostName("[::1]")));
        check("un IPv6 nudo non si spezza sui due punti", "::1".equals(HostCheck.hostName("::1")));
        check("gli spazi ai bordi", "panel.esempio.it".equals(HostCheck.hostName("  panel.esempio.it  ")));
        check("niente Host", "".equals(HostCheck.hostName(null)));

        OUT.println("\n== Con un nome configurato, il confronto e' esatto ==");
        String name = "panel.esempio.it";
        for (String ok : new String[]{"panel.esempio.it", "panel.esempio.it:2096", "panel.esempio.it:443",
                                      "PANEL.ESEMPIO.IT", "panel.esempio.it."})
            check("passa: " + ok, HostCheck.allowed(ok, name));
        for (String no : new String[]{"panel.esempio.it.qualcunaltro.com", "qualcunaltro.com",
                                      "panel.esempio", "xpanel.esempio.it", "evil.panel.esempio.it",
                                      "panel.esempio.it.evil", "127.0.0.1", "localhost", "", null})
            check("rifiutato: " + no, !HostCheck.allowed(no, name));

        OUT.println("\n== Due indirizzi IP si confrontano come indirizzi ==");
        check("::1 configurato, Host 0:0:0:0:0:0:0:1", HostCheck.allowed("0:0:0:0:0:0:0:1", "::1"));
        check("::1 configurato, Host [::1]:2096", HostCheck.allowed("[::1]:2096", "::1"));
        check("0:0:0:0:0:0:0:1 configurato, Host ::1", HostCheck.allowed("::1", "0:0:0:0:0:0:0:1"));
        check("127.0.0.1 configurato, Host 127.0.0.1:2096", HostCheck.allowed("127.0.0.1:2096", "127.0.0.1"));
        check("127.0.0.1 configurato, Host 127.0.0.2 NO", !HostCheck.allowed("127.0.0.2", "127.0.0.1"));
        check("127.0.0.1 configurato, Host localhost NO (sono due cose diverse, e risolverlo"
                + " vorrebbe dire interrogare il DNS)", !HostCheck.allowed("localhost", "127.0.0.1"));

        OUT.println("\n== Nessuna risoluzione DNS, mai ==");
        // "localhost" risolve ovunque a 127.0.0.1: se qui tornasse un indirizzo vorrebbe dire
        // che il nome e' passato dal resolver, ed e' proprio quello che non deve succedere.
        check("un nome che risolve davvero non diventa un indirizzo: localhost",
                HostCheck.literalIp("localhost") == null);
        check("ne' uno che somiglia a un indirizzo senza esserlo: 1.2.3.4.5",
                HostCheck.literalIp("1.2.3.4.5") == null);
        check("ne' 999.1.1.1", HostCheck.literalIp("999.1.1.1") == null);
        check("un indirizzo invece si', e in forma normale",
                "0:0:0:0:0:0:0:1".equals(HostCheck.literalIp("::1")));

        OUT.println("\n== Con 0.0.0.0, che e' quello che scrive l'installatore ==");
        check("localhost passa", HostCheck.allowed("localhost", "0.0.0.0"));
        check("127.0.0.1 passa", HostCheck.allowed("127.0.0.1:2096", "0.0.0.0"));
        check("::1 passa", HostCheck.allowed("[::1]:2096", "0.0.0.0"));
        int addresses = 0, refused = 0;
        for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces()))
            for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                addresses++;
                String h = a.getHostAddress().replaceAll("%.*$", "");
                if (!HostCheck.allowed(h.indexOf(':') >= 0 ? "[" + h + "]:2096" : h + ":2096", "0.0.0.0")) {
                    refused++;
                    OUT.println("      rifiutato " + h);
                }
            }
        check("tutti i " + addresses + " indirizzi veri di questa macchina passano", refused == 0);
        check("un nome qualunque NO (sarebbe il rebinding)", !HostCheck.allowed("qualcunaltro.com", "0.0.0.0"));
        check("un indirizzo che non e' di questa macchina NO", !HostCheck.allowed("203.0.113.5:2096", "0.0.0.0"));

        OUT.println("\n== E adesso contro un pannello acceso davvero ==");
        Path home = Files.createTempDirectory("host-check");
        Cert cert = selfSigned(home);
        if (cert == null) {
            check("openssl c'e' per fare il certificato (questa prova va lanciata sulla VM)", false);
            OUT.println("\n" + failed + " CONTROLLI FALLITI");
            System.exit(1);
        }
        // Il file dei segreti in una cartella di prova: update_panel_config ci mette la chiave
        // TLS, e il percorso vero e' /usr/local/etc/mail-panel, che una prova non deve toccare.
        Field secretsDir = org.mail_panel.security.PanelSecrets.class.getDeclaredField("dir");
        secretsDir.setAccessible(true);
        secretsDir.set(null, home.resolve("secrets"));

        Main.dbManager = new dataBaseManager();
        Main.dbManager.create_tables();
        Main.dbManager.insert_data_default();
        int port = freePort();
        Main.dbManager.update_panel_config(name, String.valueOf(port), cert.certificate(), cert.key(), "", "mailpanel-");

        SSLMailServer panel = new SSLMailServer(port, cert.certificate(), cert.key());
        // Si avvia l'HttpsServer sotto, non SSLMailServer.start(): quello mette anche in piedi
        // fail2ban e tocca /etc/pf.conf, che una prova non deve fare.
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(panel);
        https.setExecutor(Executors.newFixedThreadPool(4));
        https.start();
        try {
            String base = "127.0.0.1";
            check("l'Host configurato e' servito: /index con Host " + name + " -> "
                    + status(base, port, "/index", name), status(base, port, "/index", name) != 421);
            check("con la porta dentro l'Host, uguale",
                    status(base, port, "/index", name + ":" + port) != 421);
            int evil = status(base, port, "/index", "qualcunaltro.com");
            check("un Host altrui riceve 421 (ricevuto " + evil + ")", evil == 421);
            int almost = status(base, port, "/index", name + ".qualcunaltro.com");
            check("e " + name + ".qualcunaltro.com pure (" + almost + "): era il buco del"
                    + " confronto per contenimento", almost == 421);
            check("anche una rotta protetta si ferma prima, sull'Host",
                    status(base, port, "/home", "qualcunaltro.com") == 421);
            check("e una API pure", status(base, port, "/api/status", "qualcunaltro.com") == 421);
            // Le rotte esentate: il loro Host e' un dominio di posta o il loopback della
            // webmail, e si difendono da se'. Non devono prendere 421.
            check("/mta-sts/policy con un dominio di posta NON prende 421 (prende "
                    + status(base, port, "/mta-sts/policy", "mta-sts.esempio.it") + ")",
                    status(base, port, "/mta-sts/policy", "mta-sts.esempio.it") != 421);
            check("/autoconfig/mail/config-v1.1.xml nemmeno",
                    status(base, port, "/autoconfig/mail/config-v1.1.xml", "autoconfig.esempio.it") != 421);
            check("e la rotta interna della webmail, chiamata a 127.0.0.1, nemmeno",
                    status(base, port, "/api/internal/mailbox-vault", "127.0.0.1:" + port) != 421);

            OUT.println("\n== Lo stesso pannello con l'indirizzo a 0.0.0.0 ==");
            Main.dbManager.update_panel_config("0.0.0.0", String.valueOf(port), cert.certificate(), cert.key(), "", "mailpanel-");
            check("127.0.0.1 torna a essere servito",
                    status(base, port, "/index", "127.0.0.1:" + port) != 421);
            check("localhost anche", status(base, port, "/index", "localhost:" + port) != 421);
            check("ma qualcunaltro.com resta fuori",
                    status(base, port, "/index", "qualcunaltro.com") == 421);
        } finally {
            https.stop(0);
        }

        OUT.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        System.exit(failed == 0 ? 0 : 1);
    }

    /**
     * Il codice di stato di una GET con QUELL'Host.
     *
     * <p>HTTP scritto a mano su un socket TLS, invece che con HttpClient, perche' "Host" per
     * HttpClient e' un'intestazione riservata: la rifiuta, a meno di avviare la JVM con
     * -Djdk.httpclient.allowRestrictedHeaders=host. Una prova che dipende da un parametro
     * della riga di comando e' una prova che un giorno gira senza e non misura piu' niente.
     */
    static int status(String address, int port, String path, String host) throws Exception {
        SSLContext ctx = trustingContext();
        try (javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket)
                ctx.getSocketFactory().createSocket(address, port)) {
            socket.setSoTimeout(10_000);
            socket.startHandshake();
            String request = "GET " + path + " HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "User-Agent: HostCheckTest/1.0\r\n"
                    + "Connection: close\r\n\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
            socket.getOutputStream().flush();
            java.io.BufferedReader in = new java.io.BufferedReader(
                    new java.io.InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));
            String statusLine = in.readLine();
            if (statusLine == null) throw new IllegalStateException("nessuna risposta per Host " + host);
            String[] parts = statusLine.split(" ");
            if (parts.length < 2) throw new IllegalStateException("riga di stato strana: " + statusLine);
            return Integer.parseInt(parts[1]);
        }
    }

    static int freePort() throws Exception {
        try (ServerSocket s = new ServerSocket(0)) { return s.getLocalPort(); }
    }

    record Cert(String certificate, String key) {}

    /** Un certificato autofirmato con openssl, che su FreeBSD sta in base. */
    static Cert selfSigned(Path dir) throws Exception {
        Path crt = dir.resolve("cert.pem"), key = dir.resolve("key.pem");
        ProcessBuilder pb = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-nodes", "-keyout", key.toString(), "-out", crt.toString(), "-days", "2",
                "-subj", "/CN=panel.esempio.it",
                "-addext", "subjectAltName=DNS:panel.esempio.it,DNS:localhost,IP:127.0.0.1");
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (p.waitFor() != 0) { OUT.println(out); return null; }
        return new Cert(Files.readString(crt, StandardCharsets.UTF_8), Files.readString(key, StandardCharsets.UTF_8));
    }

    /**
     * Un contesto TLS che si fida di quel certificato senza guardarlo: qui si misura l'Host,
     * non il TLS, e il nome sul certificato non c'entra con la domanda.
     */
    static SSLContext trustingContext() throws Exception {
        TrustManager[] all = new TrustManager[]{ new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, all, new SecureRandom());
        return ctx;
    }
}
