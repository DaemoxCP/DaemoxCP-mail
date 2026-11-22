package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * The Apple profile signed with the mail server's certificate (23/11/2026).
 *
 * An unsigned profile is shown as "Not Verified" on the iPhone. The panel signs it with the certificate of the
 * mail name (CMS, through the system's openssl) when a phone would trust it, and says why when it does not. Here,
 * in a test folder, with a test authority made with openssl:
 *   - which certificate signs: not a self-signed one, not an expired one, only for a name it covers (wildcard
 *     included), only when it leads to a trusted authority, not when it cannot be read;
 *   - the signed file: DER, it verifies against the test authority and gives back exactly the profile, it carries
 *     the certificate chain; a changed byte makes the verification fail;
 *   - no signature with a key that is not the certificate's, or a key that cannot be read.
 *
 * Needs openssl at /usr/bin/openssl (FreeBSD base; the expired case needs -not_after, OpenSSL 3.4 or later):
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.AppleProfileSigningTest
 */
public class AppleProfileSigningTest {

    private static int failed = 0;
    private static Path d;

    public static void main(String[] args) throws Exception {
        d = Files.createTempDirectory(Path.of(System.getProperty("java.io.tmpdir")), "apple-sign");
        try {
            run();
        } finally {
            try (var s = Files.walk(d)) {
                s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> { try { Files.delete(p); } catch (Exception ignored) { } });
            }
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void run() throws Exception {
        String ec = "-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes";
        openssl("req -x509 " + ec + " -keyout ca.key -out ca.pem -days 30 -subj /CN=Signing-Test-CA"
                + " -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign");
        Files.writeString(d.resolve("leaf.ext"), "subjectAltName=DNS:mail.signing.test,DNS:*.other.test\n"
                + "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n");
        openssl("req " + ec + " -keyout leaf.key -out leaf.csr -subj /CN=mail.signing.test");
        openssl("x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf.pem -days 10 -extfile leaf.ext");
        Files.writeString(d.resolve("fullchain.pem"), Files.readString(d.resolve("leaf.pem")) + Files.readString(d.resolve("ca.pem")));
        openssl("req -x509 " + ec + " -keyout self.key -out self.pem -days 10 -subj /CN=mail.signing.test"
                + " -addext subjectAltName=DNS:mail.signing.test");
        boolean expiredMade = openssl("x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out old.pem"
                + " -not_before 20200101000000Z -not_after 20200102000000Z -extfile leaf.ext") == 0;

        KeyStore testCa = KeyStore.getInstance("PKCS12");
        testCa.load(null, null);
        testCa.setCertificateEntry("test-ca", cert("ca.pem"));
        String host = "mail.signing.test";

        System.out.println("== Which certificate signs ==");
        AppleProfile.certificate = d.resolve("self.pem");
        AppleProfile.trusted = testCa;
        AppleProfile.Signer s = AppleProfile.signer(host);
        check("the installation's self-signed certificate does not sign, and it says so",
                !s.ok() && I18n.tr("server.appleprof.sign.selfSigned").equals(s.why()));
        if (expiredMade) {
            Files.writeString(d.resolve("old-chain.pem"), Files.readString(d.resolve("old.pem")) + Files.readString(d.resolve("ca.pem")));
            AppleProfile.certificate = d.resolve("old-chain.pem");
            s = AppleProfile.signer(host);
            check("an expired certificate does not sign", !s.ok() && I18n.tr("server.appleprof.sign.expired").equals(s.why()));
        } else {
            System.out.println("  (the expired case needs openssl with -not_after: not made here)");
        }
        AppleProfile.certificate = d.resolve("fullchain.pem");
        AppleProfile.trusted = null;
        s = AppleProfile.signer(host);
        check("a certificate of an authority the Java list does not know does not sign",
                !s.ok() && I18n.tr("server.appleprof.sign.notTrusted").equals(s.why()));
        AppleProfile.trusted = testCa;
        s = AppleProfile.signer(host);
        check("with the authority trusted, the mail name's certificate signs", s.ok() && host.equals(s.name())
                && s.notAfter() != null && s.notAfter().matches("\\d{4}-\\d{2}-\\d{2}"));
        check("a name under the wildcard is covered", AppleProfile.signer("mx.other.test").ok());
        check("a name two labels under the wildcard is not",
                !AppleProfile.signer("a.mx.other.test").ok());
        s = AppleProfile.signer("mail.elsewhere.test");
        check("a name the certificate does not cover does not sign, and it names it", !s.ok()
                && I18n.tr("server.appleprof.sign.otherName", java.util.Map.of("h", "mail.elsewhere.test")).equals(s.why()));
        check("no mail name, no signature", !AppleProfile.signer("").ok());
        JSONObject j = AppleProfile.signer(host).json();
        check("the state says signed, by which name and until when",
                j.optBoolean("signed") && host.equals(j.optString("name")) && !j.optString("notAfter").isEmpty() && !j.has("why"));
        AppleProfile.certificate = d.resolve("missing.pem");
        s = AppleProfile.signer(host);
        check("a certificate that cannot be read does not sign",
                !s.ok() && I18n.tr("server.appleprof.sign.unreadable").equals(s.why()) && !s.json().optBoolean("signed"));

        System.out.println("\n== The signed profile ==");
        AppleProfile.certificate = d.resolve("fullchain.pem");
        AppleProfile.key = d.resolve("leaf.key");
        byte[] profile = AppleProfile.mobileconfig("alice@signing.test", "Alice", host, host).getBytes(StandardCharsets.UTF_8);
        byte[] der = AppleProfile.sign(profile);
        check("it is signed: DER", der != null && der.length > profile.length && der[0] == 0x30);
        if (der == null) return;
        Files.write(d.resolve("signed.mobileconfig"), der);
        byte[] back = opensslOut("cms -verify -binary -inform DER -in signed.mobileconfig -CAfile ca.pem -purpose any");
        check("it verifies against the authority and gives back exactly the profile", Arrays.equals(back, profile));
        check("and the profile inside is still a good one",
                back != null && AppleProfile.wellFormed(new String(back, StandardCharsets.UTF_8)));
        byte[] printed = opensslOut("cms -cmsout -print -inform DER -in signed.mobileconfig");
        String p = printed == null ? "" : new String(printed, StandardCharsets.UTF_8);
        check("it carries the certificate chain: the mail name's certificate and the authority",
                p.contains("CN=mail.signing.test") && p.contains("CN=Signing-Test-CA"));
        byte[] changed = der.clone();
        int at = indexOf(der, "alice@signing.test".getBytes(StandardCharsets.UTF_8));
        if (at >= 0) changed[at] = 'b';
        Files.write(d.resolve("changed.mobileconfig"), changed);
        check("a changed byte makes the verification fail",
                at >= 0 && opensslOut("cms -verify -binary -inform DER -in changed.mobileconfig -CAfile ca.pem -purpose any") == null);

        System.out.println("\n== No signature with the wrong key ==");
        AppleProfile.key = d.resolve("self.key");
        check("a key that is not the certificate's: no signature", AppleProfile.sign(profile) == null);
        AppleProfile.key = d.resolve("missing.key");
        check("a key that cannot be read: no signature", AppleProfile.sign(profile) == null);
    }

    static X509Certificate cert(String name) throws Exception {
        try (var in = Files.newInputStream(d.resolve(name))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    static int indexOf(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int k = 0; k < needle.length; k++) if (hay[i + k] != needle[k]) continue outer;
            return i;
        }
        return -1;
    }

    /** openssl in the test folder: the exit code. */
    static int openssl(String args) throws Exception {
        List<String> cmd = new ArrayList<>(List.of(AppleProfile.openssl));
        cmd.addAll(List.of(args.split(" ")));
        Process p = new ProcessBuilder(cmd).directory(d.toFile()).redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        if (!p.waitFor(60, TimeUnit.SECONDS)) { p.destroyForcibly(); return -1; }
        return p.exitValue();
    }

    /** openssl in the test folder: what it writes on stdout, or null if it does not end well. */
    static byte[] opensslOut(String args) throws Exception {
        List<String> cmd = new ArrayList<>(List.of(AppleProfile.openssl));
        cmd.addAll(List.of(args.split(" ")));
        Process p = new ProcessBuilder(cmd).directory(d.toFile()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        byte[] out = p.getInputStream().readAllBytes();
        if (!p.waitFor(60, TimeUnit.SECONDS)) { p.destroyForcibly(); return null; }
        return p.exitValue() == 0 ? out : null;
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failed++;
    }
}
