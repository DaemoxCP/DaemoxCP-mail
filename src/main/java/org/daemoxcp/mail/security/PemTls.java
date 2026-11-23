package org.daemoxcp.mail.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * The panel's TLS certificate and key in PEM: reading and checking (finding 243).
 *
 * <p>The panel certificate is set only from menu option 2, and the panel used it as it was: a
 * certificate that does not cover the panel's name, expired, or a key that is not its own were discovered only at the first
 * startup, with the server not starting or with the browser (and Cloudflare in Full (strict) mode) rejecting it. Now
 * menu option 2 checks them before saving, and certificate and key can also be given as the path of a file (for
 * example the Cloudflare Origin Certificate copied with scp), instead of pasting them into a three-line box.
 *
 * <p>Reading the key is what the TLS server already did (SSLMailServer), moved here so that the server and
 * the check read the same way: PKCS#8 (RSA or EC), PKCS#1 RSA converted to PKCS#8.
 */
public final class PemTls {

    private PemTls() {}

    /** A PEM file is small: a certificate with its chain fits in a few KB. */
    public static final long MAX_FILE = 64 << 10;

    /** Lines with the normal line ending, without spaces at the edges and without empty lines. */
    public static String normalize(String pem) {
        if (pem == null) return null;
        pem = pem.replace("\r\n", "\n").replace("\r", "\n");
        StringBuilder sb = new StringBuilder();
        for (String line : pem.split("\n")) {
            line = line.trim();
            if (!line.isEmpty()) sb.append(line).append("\n");
        }
        return sb.toString();
    }

    /** True if the text is the path of a file instead of the PEM itself: a single line starting with /. */
    public static boolean isPath(String text) {
        String t = text == null ? "" : text.trim();
        return t.startsWith("/") && !t.contains("\n") && !t.contains("-----BEGIN");
    }

    /**
     * The PEM in a file: a regular file (no links), at most {@link #MAX_FILE}, with a BEGIN line.
     *
     * @throws IOException with a message to show to whoever wrote the path
     */
    public static String readFile(Path file) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
            throw new IOException(file + " is not a file (or it is a link)");
        if (Files.size(file) > MAX_FILE) throw new IOException(file + " is too big for a PEM file");
        String s = Files.readString(file, StandardCharsets.US_ASCII);
        if (!s.contains("-----BEGIN")) throw new IOException(file + " does not contain a PEM block (-----BEGIN ...)");
        return s;
    }

    /** The certificates of the PEM, in order (the first one is the server's). */
    public static List<X509Certificate> certificates(String pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> out = new ArrayList<>();
        try (ByteArrayInputStream in = new ByteArrayInputStream(normalize(pem).getBytes(StandardCharsets.US_ASCII))) {
            Collection<? extends java.security.cert.Certificate> all = cf.generateCertificates(in);
            for (java.security.cert.Certificate c : all) out.add((X509Certificate) c);
        }
        if (out.isEmpty()) throw new IllegalArgumentException("No valid certificates found in certificate content");
        return out;
    }

    /** The private key of the PEM: PKCS#8 (RSA or EC) or PKCS#1 RSA. */
    public static PrivateKey privateKey(String keyContent) throws Exception {
        if (keyContent == null || keyContent.trim().isEmpty())
            throw new IllegalArgumentException("Private key content is empty");
        boolean isRSAFormat = keyContent.contains("-----BEGIN RSA PRIVATE KEY-----");
        boolean isPKCS8Format = keyContent.contains("-----BEGIN PRIVATE KEY-----");
        boolean isECFormat = keyContent.contains("-----BEGIN EC PRIVATE KEY-----");
        if (!isRSAFormat && !isPKCS8Format && !isECFormat)
            throw new IllegalArgumentException("Unsupported private key format. Expected PKCS#8, RSA, or EC format.");

        if (isPKCS8Format) {
            byte[] der = base64(keyContent, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
            try {
                return KeyFactory.getInstance("RSA").generatePrivate(spec);
            } catch (Exception e) {
                return KeyFactory.getInstance("EC").generatePrivate(spec);
            }
        } else if (isRSAFormat) {
            byte[] pkcs1 = base64(keyContent, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----");
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs1ToPkcs8(pkcs1)));
        } else {
            byte[] der = base64(keyContent, "-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----");
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        }
    }

    private static byte[] base64(String pem, String begin, String end) {
        return Base64.getDecoder().decode(pem.replace(begin, "").replace(end, "").replaceAll("\\s", ""));
    }

    /** PKCS#1 RSA inside the PKCS#8 wrapper ({@code rsaEncryption}), as the TLS server used to read it. */
    public static byte[] pkcs1ToPkcs8(byte[] pkcs1Bytes) {
        byte[] pkcs8Header = {
            0x30, (byte) 0x82, 0x00, 0x00, // SEQUENCE, length placeholder
            0x02, 0x01, 0x00,              // INTEGER 0 (version)
            0x30, 0x0d,                    // SEQUENCE
            0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID rsaEncryption
            0x05, 0x00,                    // NULL
            0x04, (byte) 0x82, 0x00, 0x00  // OCTET STRING, length placeholder
        };
        int totalLen = pkcs8Header.length + pkcs1Bytes.length;
        byte[] pkcs8Bytes = new byte[totalLen];
        System.arraycopy(pkcs8Header, 0, pkcs8Bytes, 0, pkcs8Header.length);
        System.arraycopy(pkcs1Bytes, 0, pkcs8Bytes, pkcs8Header.length, pkcs1Bytes.length);
        int seqLen = totalLen - 4;
        pkcs8Bytes[2] = (byte) ((seqLen >> 8) & 0xff);
        pkcs8Bytes[3] = (byte) (seqLen & 0xff);
        int octetLen = pkcs1Bytes.length;
        pkcs8Bytes[pkcs8Header.length - 2] = (byte) ((octetLen >> 8) & 0xff);
        pkcs8Bytes[pkcs8Header.length - 1] = (byte) (octetLen & 0xff);
        return pkcs8Bytes;
    }

    // ===================== The check before saving =====================

    /**
     * The outcome of the check: errors stop the save, warnings are shown in the confirmation, the information
     * lines say what is being saved.
     */
    public record Check(List<String> errors, List<String> warnings, List<String> info) {
        public boolean ok() { return errors.isEmpty(); }
    }

    /** The names the certificate covers: the DNS entries of the Subject Alternative Names, or the CN if there are none. */
    public static List<String> names(X509Certificate c) {
        List<String> out = new ArrayList<>();
        try {
            Collection<List<?>> sans = c.getSubjectAlternativeNames();
            if (sans != null)
                for (List<?> san : sans)
                    if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0)) && san.get(1) instanceof String s)
                        out.add(s.toLowerCase(Locale.ROOT));
        } catch (Exception ignored) {
            // no readable SAN: look at the CN
        }
        if (out.isEmpty()) {
            for (String part : c.getSubjectX500Principal().getName().split(","))
                if (part.trim().startsWith("CN=")) out.add(part.trim().substring(3).toLowerCase(Locale.ROOT));
        }
        return out;
    }

    /** The name is covered by one of the certificate's names: equal, or a * that stands for a single label. */
    public static boolean covers(List<String> names, String host) {
        String h = host.toLowerCase(Locale.ROOT);
        for (String n : names) {
            if (n.equals(h)) return true;
            if (n.startsWith("*.")) {
                int dot = h.indexOf('.');
                if (dot > 0 && h.substring(dot + 1).equals(n.substring(2))) return true;
            }
        }
        return false;
    }

    /** A real DNS name (with at least one dot, not an IP address, not 0.0.0.0). */
    public static boolean dnsName(String host) {
        if (host == null || host.isBlank() || !host.contains(".")) return false;
        if (host.matches("^[0-9.]+$") || host.contains(":")) return false;
        return host.matches("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$");
    }

    /**
     * Certificate and key for the panel with the host name: the certificate can be read, is valid now, covers the name,
     * and the key really is its own (a signature made with the key verifies with the certificate's public key).
     */
    public static Check check(String host, String certPem, String keyPem, Instant now) {
        return check("panel", host, certPem, keyPem, now);
    }

    /** The same check for another name (whose: "panel" or "webmail"), reported in messages in the console language. */
    public static Check check(String whose, String host, String certPem, String keyPem, Instant now) {
        List<String> errors = new ArrayList<>(), warnings = new ArrayList<>(), info = new ArrayList<>();
        List<X509Certificate> chain;
        try {
            chain = certificates(certPem);
        } catch (Exception e) {
            errors.add(org.daemoxcp.mail.i18n.I18n.tr("console.tls.unreadable"));
            return new Check(errors, warnings, info);
        }
        X509Certificate leaf = chain.get(0);
        List<String> names = names(leaf);
        String what = "webmail".equals(whose) ? org.daemoxcp.mail.i18n.I18n.tr("console.tls.webmailName") : org.daemoxcp.mail.i18n.I18n.tr("console.tls.panelName");
        info.add(org.daemoxcp.mail.i18n.I18n.tr("console.tls.for", java.util.Map.of("names", String.join(", ", names))));
        info.add(org.daemoxcp.mail.i18n.I18n.tr("console.tls.issuer", java.util.Map.of("issuer", leaf.getIssuerX500Principal().getName())));
        info.add(org.daemoxcp.mail.i18n.I18n.tr("console.tls.until", java.util.Map.of("date", leaf.getNotAfter().toInstant().toString().substring(0, 10))));
        if (now.isAfter(leaf.getNotAfter().toInstant())) errors.add(org.daemoxcp.mail.i18n.I18n.tr("console.tls.expired"));
        // Ten minutes of tolerance: a freshly issued certificate (the Cloudflare Origin Certificate) starts in the
        // second it is born, and a server clock running a little behind must not reject it.
        if (now.plus(java.time.Duration.ofMinutes(10)).isBefore(leaf.getNotBefore().toInstant()))
            errors.add(org.daemoxcp.mail.i18n.I18n.tr("console.tls.notYet"));
        if (dnsName(host)) {
            if (!covers(names, host))
                errors.add(org.daemoxcp.mail.i18n.I18n.tr("console.tls.notCovered", java.util.Map.of("what", what, "host", host, "names", String.join(", ", names))));
        } else {
            warnings.add("webmail".equals(whose) ? org.daemoxcp.mail.i18n.I18n.tr("console.tls.notDomainWebmail", java.util.Map.of("host", host))
                    : org.daemoxcp.mail.i18n.I18n.tr("console.tls.notDomainPanel", java.util.Map.of("host", host)));
        }
        if (leaf.getIssuerX500Principal().equals(leaf.getSubjectX500Principal()))
            warnings.add(org.daemoxcp.mail.i18n.I18n.tr("console.tls.selfSigned"));
        try {
            PrivateKey key = privateKey(normalize(keyPem));
            String alg = "EC".equals(key.getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA";
            byte[] probe = "daemoxcp-mail-key-check".getBytes(StandardCharsets.US_ASCII);
            Signature s = Signature.getInstance(alg);
            s.initSign(key);
            s.update(probe);
            byte[] sig = s.sign();
            Signature v = Signature.getInstance(alg);
            v.initVerify(leaf.getPublicKey());
            v.update(probe);
            if (v.verify(sig)) info.add(org.daemoxcp.mail.i18n.I18n.tr("console.tls.keyMatches"));
            else errors.add(org.daemoxcp.mail.i18n.I18n.tr("console.tls.keyOther"));
        } catch (Exception e) {
            errors.add(org.daemoxcp.mail.i18n.I18n.tr("console.tls.keyUnreadable", java.util.Map.of("why", e.getClass().getSimpleName())));
        }
        return new Check(errors, warnings, info);
    }
}
