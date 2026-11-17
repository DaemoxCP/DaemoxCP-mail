package org.daemoxcp.mail.security;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;

/**
 * A certificate renewal's deploy, for real, on the test machine with Dovecot 2.4 (the real server's case of
 * 17/11/2026): a new certificate where acme.sh would leave it, AcmeManager.deployCertificate as the renewal calls it,
 * then what the machine says.
 *
 *   1. The deploy reports success.
 *   2. Dovecot's conf.d/10-ssl.conf is byte for byte as before (the old deploy rewrote it with Dovecot 2.3's syntax).
 *   3. doveconf accepts the configuration.
 *   4. Dovecot (993) and Postfix (465) present the new certificate.
 *   At the end everything goes back: the certificate files, 10-ssl.conf, the services reloaded on them, and 993
 *   presents the original certificate again.
 *
 * ONLY on a test machine, -De2e.vm=yes, as root, from the panel's folder:
 *   java -De2e.vm=yes -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.security.AcmeDeployVmTest
 */
public class AcmeDeployVmTest {

    static int failed = 0;
    static final Duration T = Duration.ofSeconds(60);

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("SKIPPED: it needs -De2e.vm=yes (a test machine, as root): it replaces the mail certificate for a moment.");
            return;
        }
        I18n.setCurrent("en");
        Path ssl = Path.of("/usr/local/etc/ssl/mail"), conf = Path.of("/usr/local/etc/dovecot/conf.d/10-ssl.conf");
        Path work = Path.of("/var/tmp/acme-deploy-test"), saved = work.resolve("saved"), acme = work.resolve("acme");
        String host = Shell.run(T, "postconf", "-h", "myhostname").outputTrim();
        Shell.run(T, "rm", "-rf", work.toString());
        Files.createDirectories(saved);
        Files.createDirectories(acme);
        for (String f : new String[]{"fullchain.pem", "privkey.pem", "ca.pem"})
            if (Files.exists(ssl.resolve(f))) Files.copy(ssl.resolve(f), saved.resolve(f), StandardCopyOption.COPY_ATTRIBUTES);
        Files.copy(conf, saved.resolve("10-ssl.conf"), StandardCopyOption.COPY_ATTRIBUTES);
        String before = serialOf(ssl.resolve("fullchain.pem"));
        String beforeSeen = servedSerial("127.0.0.1", 993, null, 5000);
        check("before: 993 presents the installed certificate (" + beforeSeen + ")", before != null && before.equals(beforeSeen));

        try {
            // What acme.sh leaves: <host>.cer, <host>.key, fullchain.cer, ca.cer.
            Shell.Result made = Shell.runShell(T, "cd " + acme + " && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"
                    + " -days 2 -subj /CN=" + host + " -addext subjectAltName=DNS:" + host
                    + " -keyout " + host + ".key -out " + host + ".cer 2>&1 && cp " + host + ".cer fullchain.cer && cp " + host + ".cer ca.cer");
            check("a new certificate where acme.sh would leave it", made.success());
            String fresh = serialOf(acme.resolve(host + ".cer"));

            System.out.println("\n== The deploy, as the renewal calls it ==");
            AcmeManager.DeployResult r = new AcmeManager(null).deployCertificate(host, "Your cert is in: " + acme.resolve(host + ".cer"));
            System.out.println("  (" + r.message + ")");
            if (r.output != null) for (String l : r.output.split("\n")) if (!l.isBlank()) System.out.println("    " + l);
            check("the deploy reports success", r.success);
            check("Dovecot's 10-ssl.conf is byte for byte as before",
                    java.util.Arrays.equals(Files.readAllBytes(conf), Files.readAllBytes(saved.resolve("10-ssl.conf"))));
            check("doveconf accepts the configuration", Shell.runShell(T, "doveconf -n >/dev/null").success());
            check("Dovecot (993) presents the new certificate", fresh != null && fresh.equals(servedSerial("127.0.0.1", 993, null, 5000)));
            check("Postfix (465) presents the new certificate", fresh != null && fresh.equals(servedSerial("127.0.0.1", 465, null, 5000)));

            System.out.println("\n== A Dovecot configuration that does not pass its check: said, not \"deployed\" ==");
            // What the old deploy wrote: Dovecot 2.3's name, which 2.4 refuses.
            Files.writeString(conf, Files.readString(saved.resolve("10-ssl.conf")) + "ssl_cert = </usr/local/etc/ssl/mail/fullchain.pem\n");
            AcmeManager.DeployResult broken = new AcmeManager(null).deployCertificate(host, "Your cert is in: " + acme.resolve(host + ".cer"));
            System.out.println("  (" + broken.message + ")");
            check("the deploy does not report success", !broken.success);
            check("and says it is Dovecot's configuration", broken.message != null && broken.message.contains("Dovecot")
                    && broken.message.contains("its own check"));
        } finally {
            System.out.println("\n== Everything back ==");
            for (String f : new String[]{"fullchain.pem", "privkey.pem", "ca.pem"})
                if (Files.exists(saved.resolve(f))) Files.copy(saved.resolve(f), ssl.resolve(f), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
            Files.copy(saved.resolve("10-ssl.conf"), conf, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
            Shell.runShell(T, "service dovecot reload; service postfix reload; service nginx reload");
            String seen = null;
            for (int i = 0; i < 15 && !(before != null && before.equals(seen)); i++) {
                seen = servedSerial("127.0.0.1", 993, null, 5000);
                Thread.sleep(1000);
            }
            check("993 presents the original certificate again", before != null && before.equals(seen));
            check("doveconf accepts the configuration", Shell.runShell(T, "doveconf -n >/dev/null").success());
            Shell.run(T, "rm", "-rf", work.toString());
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    // Copies of the deploy's own readers, so that this test also runs against the code from before the fix (whose
    // AcmeManager does not have them) and shows it red.
    static String serialOf(Path pem) {
        try (java.io.InputStream in = Files.newInputStream(pem)) {
            return ((java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(in)).getSerialNumber().toString(16).toUpperCase(java.util.Locale.ROOT);
        } catch (Exception e) {
            return null;
        }
    }

    static String servedSerial(String host, int port, String sni, int timeoutMs) {
        try {
            javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
            ctx.init(null, new javax.net.ssl.TrustManager[]{new javax.net.ssl.X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) { }
                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) { }
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
            }}, null);
            try (javax.net.ssl.SSLSocket s = (javax.net.ssl.SSLSocket) ctx.getSocketFactory().createSocket(host, port)) {
                s.setSoTimeout(timeoutMs);
                s.startHandshake();
                return ((java.security.cert.X509Certificate) s.getSession().getPeerCertificates()[0])
                        .getSerialNumber().toString(16).toUpperCase(java.util.Locale.ROOT);
            }
        } catch (Exception e) {
            return null;
        }
    }
}
