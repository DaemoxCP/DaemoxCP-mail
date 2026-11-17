package org.daemoxcp.mail.security;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;

/**
 * The look the certificate deploy now takes at the end (AcmeManager.reloadAndVerify): which certificate a port really
 * presents, compared with the file just installed. A real local TLS server with a certificate made by keytool, so the
 * serial read over the wire is compared with the one in the key store and in the PEM file.
 *
 * It needs keytool (any JDK) and runs anywhere:
 *   java -cp "tests:daemoxcp-mail-1.0.jar" org.daemoxcp.mail.security.AcmeServedCertificateTest
 */
public class AcmeServedCertificateTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("acme-served-test");
        Path store = dir.resolve("server.p12"), pem = dir.resolve("server.pem");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        run(keytool, "-genkeypair", "-alias", "server", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=mail.example.test",
                "-ext", "SAN=dns:mail.example.test,dns:mta-sts.example.test", "-validity", "2", "-storetype", "PKCS12",
                "-keystore", store.toString(), "-storepass", "changeit", "-keypass", "changeit");
        run(keytool, "-exportcert", "-rfc", "-alias", "server", "-keystore", store.toString(), "-storepass", "changeit", "-file", pem.toString());

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(store.toFile())) { ks.load(in, "changeit".toCharArray()); }
        String expected = ((X509Certificate) ks.getCertificate("server")).getSerialNumber().toString(16).toUpperCase(Locale.ROOT);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        SSLServerSocket server = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0);
        int port = server.getLocalPort();
        Thread serve = new Thread(() -> {
            while (!server.isClosed()) {
                try (SSLSocket s = (SSLSocket) server.accept()) {
                    s.startHandshake();
                } catch (Exception ignored) { }
            }
        });
        serve.setDaemon(true);
        serve.start();

        try {
            System.out.println("== What a port presents ==");
            String seen = AcmeManager.servedSerial("127.0.0.1", port, "mail.example.test", 5000);
            check("the serial read over the wire is the one in the key store (" + seen + ")", expected.equals(seen));
            check("with an SNI too (" + AcmeManager.servedSerial("127.0.0.1", port, "mta-sts.example.test", 5000) + ")",
                    expected.equals(AcmeManager.servedSerial("127.0.0.1", port, "mta-sts.example.test", 5000)));
            check("the same as the PEM file's (" + AcmeManager.serialOf(pem) + ")", expected.equals(AcmeManager.serialOf(pem)));

            System.out.println("\n== Nothing to read: null, never a guess ==");
            int closed;
            try (java.net.ServerSocket s = new java.net.ServerSocket(0)) { closed = s.getLocalPort(); }
            check("a closed port", AcmeManager.servedSerial("127.0.0.1", closed, null, 2000) == null);
            check("a file that is not a certificate", AcmeManager.serialOf(dir.resolve("missing.pem")) == null);

            System.out.println("\n== The name to ask nginx on 443 ==");
            check("an mta-sts name the certificate covers",
                    "mta-sts.example.test".equals(AcmeManager.sniFor443(List.of("mail.example.test", "autoconfig.example.test", "mta-sts.example.test"))));
            check("none: 443 is not looked at", AcmeManager.sniFor443(List.of("mail.example.test")) == null
                    && AcmeManager.sniFor443(List.of()) == null && AcmeManager.sniFor443(null) == null);
        } finally {
            server.close();
            Files.deleteIfExists(store);
            Files.deleteIfExists(pem);
            Files.deleteIfExists(dir);
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    static void run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        if (p.waitFor() != 0) throw new IllegalStateException(String.join(" ", cmd) + ": " + out);
    }
}
