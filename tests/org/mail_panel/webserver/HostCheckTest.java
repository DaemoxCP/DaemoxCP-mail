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
 * The check of the Host header, which was not in the mail panel at all.
 *
 * It is not a formality: the passkeys' rpId and origin come from Host, and PasskeyService checks
 * that the Host LOOKS LIKE a DNS name, not that it is this panel's name.
 *
 * What must be tested here, and that compiling would not tell:
 *  - the comparison is EXACT. With panel.example.org configured, "contains" would let through
 *    panel.example.org.someoneelse.com, which is a name anybody can register;
 *  - two IP addresses are compared as ADDRESSES: ::1 and 0:0:0:0:0:0:0:1 are the same address and
 *    look different as text;
 *  - a name is NEVER resolved with DNS. Resolving would mean letting through any name made to point
 *    to this machine, that is the rebinding the check defends from;
 *  - with the address at 0.0.0.0 -- which is just what the installer writes -- the panel must stay
 *    reachable, from localhost and from its own addresses;
 *  - and above all that the check REALLY sits in the middle of the requests. Here a real
 *    SSLMailServer starts and is spoken to over TLS changing only the Host: the pure functions can
 *    be written right and connected to nothing.
 *
 * It runs from an empty folder (it creates its own database/ there):
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.HostCheckTest
 */
public class HostCheckTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        OUT.println("\n== What \"listen everywhere\" means ==");
        for (String w : new String[]{"", "0.0.0.0", "::", "[::]", "*", "0:0:0:0:0:0:0:0", " 0.0.0.0 "})
            check("wildcard: [" + w + "]", HostCheck.isWildcardHost(w));
        check("wildcard: null", HostCheck.isWildcardHost(null));
        for (String n : new String[]{"panel.example.org", "127.0.0.1", "::1", "localhost"})
            check("NOT wildcard: " + n, !HostCheck.isWildcardHost(n));

        OUT.println("\n== The name inside the Host header ==");
        check("the port is removed", "panel.example.org".equals(HostCheck.hostName("panel.example.org:2096")));
        check("upper case too", "panel.example.org".equals(HostCheck.hostName("PANEL.Example.ORG")));
        check("the dot of the DNS root is removed", "panel.example.org".equals(HostCheck.hostName("panel.example.org.")));
        check("an IPv6 in brackets with the port", "::1".equals(HostCheck.hostName("[::1]:2096")));
        check("an IPv6 in brackets without a port", "::1".equals(HostCheck.hostName("[::1]")));
        check("a bare IPv6 is not split on the colons", "::1".equals(HostCheck.hostName("::1")));
        check("the spaces at the edges", "panel.example.org".equals(HostCheck.hostName("  panel.example.org  ")));
        check("no Host", "".equals(HostCheck.hostName(null)));

        OUT.println("\n== With a configured name, the comparison is exact ==");
        String name = "panel.example.org";
        for (String ok : new String[]{"panel.example.org", "panel.example.org:2096", "panel.example.org:443",
                                      "PANEL.EXAMPLE.ORG", "panel.example.org."})
            check("passes: " + ok, HostCheck.allowed(ok, name));
        for (String no : new String[]{"panel.example.org.someoneelse.com", "someoneelse.com",
                                      "panel.example", "xpanel.example.org", "evil.panel.example.org",
                                      "panel.example.org.evil", "127.0.0.1", "localhost", "", null})
            check("refused: " + no, !HostCheck.allowed(no, name));

        OUT.println("\n== Two IP addresses are compared as addresses ==");
        check("::1 configured, Host 0:0:0:0:0:0:0:1", HostCheck.allowed("0:0:0:0:0:0:0:1", "::1"));
        check("::1 configured, Host [::1]:2096", HostCheck.allowed("[::1]:2096", "::1"));
        check("0:0:0:0:0:0:0:1 configured, Host ::1", HostCheck.allowed("::1", "0:0:0:0:0:0:0:1"));
        check("127.0.0.1 configured, Host 127.0.0.1:2096", HostCheck.allowed("127.0.0.1:2096", "127.0.0.1"));
        check("127.0.0.1 configured, Host 127.0.0.2 NO", !HostCheck.allowed("127.0.0.2", "127.0.0.1"));
        check("127.0.0.1 configured, Host localhost NO (they are two different things, and resolving it"
                + " would mean asking the DNS)", !HostCheck.allowed("localhost", "127.0.0.1"));

        OUT.println("\n== No DNS resolution, ever ==");
        // "localhost" resolves to 127.0.0.1 everywhere: if an address came back here it would mean
        // the name went through the resolver, and that is exactly what must not happen.
        check("a name that really resolves does not become an address: localhost",
                HostCheck.literalIp("localhost") == null);
        check("nor one that looks like an address without being one: 1.2.3.4.5",
                HostCheck.literalIp("1.2.3.4.5") == null);
        check("nor 999.1.1.1", HostCheck.literalIp("999.1.1.1") == null);
        check("an address instead does, and in normal form",
                "0:0:0:0:0:0:0:1".equals(HostCheck.literalIp("::1")));

        OUT.println("\n== With 0.0.0.0, which is what the installer writes ==");
        check("localhost passes", HostCheck.allowed("localhost", "0.0.0.0"));
        check("127.0.0.1 passes", HostCheck.allowed("127.0.0.1:2096", "0.0.0.0"));
        check("::1 passes", HostCheck.allowed("[::1]:2096", "0.0.0.0"));
        int addresses = 0, refused = 0;
        for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces()))
            for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                addresses++;
                String h = a.getHostAddress().replaceAll("%.*$", "");
                if (!HostCheck.allowed(h.indexOf(':') >= 0 ? "[" + h + "]:2096" : h + ":2096", "0.0.0.0")) {
                    refused++;
                    OUT.println("      refused " + h);
                }
            }
        check("all the " + addresses + " real addresses of this machine pass", refused == 0);
        check("any name NO (it would be the rebinding)", !HostCheck.allowed("someoneelse.com", "0.0.0.0"));
        check("an address that is not this machine's NO", !HostCheck.allowed("203.0.113.5:2096", "0.0.0.0"));

        OUT.println("\n== And now against a panel really running ==");
        Path home = Files.createTempDirectory("host-check");
        Cert cert = selfSigned(home);
        if (cert == null) {
            check("openssl is there to make the certificate (this test must be run on the VM)", false);
            OUT.println("\n" + failed + " CHECKS FAILED");
            System.exit(1);
        }
        // The secrets file in a test folder: update_panel_config puts the TLS key there, and the
        // real path is /usr/local/etc/mail-panel, which a test must not touch.
        Field secretsDir = org.mail_panel.security.PanelSecrets.class.getDeclaredField("dir");
        secretsDir.setAccessible(true);
        secretsDir.set(null, home.resolve("secrets"));

        Main.dbManager = new dataBaseManager();
        Main.dbManager.create_tables();
        Main.dbManager.insert_data_default();
        int port = freePort();
        Main.dbManager.update_panel_config(name, String.valueOf(port), cert.certificate(), cert.key(), "", "mailpanel-");

        SSLMailServer panel = new SSLMailServer(port, cert.certificate(), cert.key());
        // The HttpsServer underneath is started, not SSLMailServer.start(): that one also sets up
        // fail2ban and touches /etc/pf.conf, which a test must not do.
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(panel);
        https.setExecutor(Executors.newFixedThreadPool(4));
        https.start();
        try {
            String base = "127.0.0.1";
            check("the configured Host is served: /index with Host " + name + " -> "
                    + status(base, port, "/index", name), status(base, port, "/index", name) != 421);
            check("with the port inside the Host, the same",
                    status(base, port, "/index", name + ":" + port) != 421);
            int evil = status(base, port, "/index", "someoneelse.com");
            check("someone else's Host gets 421 (got " + evil + ")", evil == 421);
            int almost = status(base, port, "/index", name + ".someoneelse.com");
            check("and " + name + ".someoneelse.com too (" + almost + "): it was the hole of the"
                    + " containment comparison", almost == 421);
            check("a protected route stops before too, on the Host",
                    status(base, port, "/home", "someoneelse.com") == 421);
            check("and an API too", status(base, port, "/api/status", "someoneelse.com") == 421);
            // The exempted routes: their Host is a mail domain or the webmail's loopback, and they
            // defend themselves. They must not get 421.
            check("/mta-sts/policy with a mail domain does NOT get 421 (it gets "
                    + status(base, port, "/mta-sts/policy", "mta-sts.example.org") + ")",
                    status(base, port, "/mta-sts/policy", "mta-sts.example.org") != 421);
            check("/autoconfig/mail/config-v1.1.xml neither",
                    status(base, port, "/autoconfig/mail/config-v1.1.xml", "autoconfig.example.org") != 421);
            check("nor the webmail's internal route, called at 127.0.0.1",
                    status(base, port, "/api/internal/mailbox-vault", "127.0.0.1:" + port) != 421);

            OUT.println("\n== The same panel with the address at 0.0.0.0 ==");
            Main.dbManager.update_panel_config("0.0.0.0", String.valueOf(port), cert.certificate(), cert.key(), "", "mailpanel-");
            check("127.0.0.1 is served again",
                    status(base, port, "/index", "127.0.0.1:" + port) != 421);
            check("localhost too", status(base, port, "/index", "localhost:" + port) != 421);
            check("but someoneelse.com stays out",
                    status(base, port, "/index", "someoneelse.com") == 421);
        } finally {
            https.stop(0);
        }

        OUT.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }

    /**
     * The status code of a GET with THAT Host.
     *
     * <p>HTTP written by hand on a TLS socket, instead of with HttpClient, because "Host" is a
     * restricted header for HttpClient: it refuses it, unless the JVM is started with
     * -Djdk.httpclient.allowRestrictedHeaders=host. A test that depends on a command-line parameter
     * is a test that one day runs without it and no longer measures anything.
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
            if (statusLine == null) throw new IllegalStateException("no answer for Host " + host);
            String[] parts = statusLine.split(" ");
            if (parts.length < 2) throw new IllegalStateException("odd status line: " + statusLine);
            return Integer.parseInt(parts[1]);
        }
    }

    static int freePort() throws Exception {
        try (ServerSocket s = new ServerSocket(0)) { return s.getLocalPort(); }
    }

    record Cert(String certificate, String key) {}

    /** A self-signed certificate with openssl, which on FreeBSD is in base. */
    static Cert selfSigned(Path dir) throws Exception {
        Path crt = dir.resolve("cert.pem"), key = dir.resolve("key.pem");
        ProcessBuilder pb = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-nodes", "-keyout", key.toString(), "-out", crt.toString(), "-days", "2",
                "-subj", "/CN=panel.example.org",
                "-addext", "subjectAltName=DNS:panel.example.org,DNS:localhost,IP:127.0.0.1");
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (p.waitFor() != 0) { OUT.println(out); return null; }
        return new Cert(Files.readString(crt, StandardCharsets.UTF_8), Files.readString(key, StandardCharsets.UTF_8));
    }

    /**
     * A TLS context that trusts that certificate without looking at it: here the Host is measured,
     * not TLS, and the name on the certificate has nothing to do with the question.
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
