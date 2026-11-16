package org.mail_panel.security;

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
 * Certificato e chiave TLS del pannello in PEM: lettura e controllo (reperto 243).
 *
 * <p>Il certificato del pannello si imposta solo dalla voce 2 del menu, e il pannello lo usava cosi' com'era: un
 * certificato che non copre il nome del pannello, scaduto, o una chiave che non e' la sua si scoprivano solo al primo
 * avvio, col server che non partiva o col browser (e Cloudflare in modalita' Full (strict)) che lo rifiutava. Adesso
 * la voce 2 li controlla prima di salvare, e certificato e chiave si possono dare anche come percorso di un file (per
 * esempio l'Origin Certificate di Cloudflare copiato con scp), invece di incollarli in una casella di tre righe.
 *
 * <p>La lettura della chiave e' quella che il server TLS usava gia' (SSLMailServer), spostata qui perche' il server e
 * il controllo leggano allo stesso modo: PKCS#8 (RSA o EC), PKCS#1 RSA convertita in PKCS#8.
 */
public final class PemTls {

    private PemTls() {}

    /** Un file PEM e' piccolo: un certificato con la sua catena sta in pochi KB. */
    public static final long MAX_FILE = 64 << 10;

    /** Righe col fine riga normale, senza spazi ai bordi e senza righe vuote. */
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

    /** Vero se il testo e' il percorso di un file invece che il PEM stesso: una riga sola che comincia con /. */
    public static boolean isPath(String text) {
        String t = text == null ? "" : text.trim();
        return t.startsWith("/") && !t.contains("\n") && !t.contains("-----BEGIN");
    }

    /**
     * Il PEM in un file: file normale (niente collegamenti), al massimo {@link #MAX_FILE}, con una riga BEGIN.
     *
     * @throws IOException con un messaggio da mostrare a chi ha scritto il percorso
     */
    public static String readFile(Path file) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
            throw new IOException(file + " is not a file (or it is a link)");
        if (Files.size(file) > MAX_FILE) throw new IOException(file + " is too big for a PEM file");
        String s = Files.readString(file, StandardCharsets.US_ASCII);
        if (!s.contains("-----BEGIN")) throw new IOException(file + " does not contain a PEM block (-----BEGIN ...)");
        return s;
    }

    /** I certificati del PEM, nell'ordine (il primo e' quello del server). */
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

    /** La chiave privata del PEM: PKCS#8 (RSA o EC) o PKCS#1 RSA. */
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

    /** PKCS#1 RSA dentro l'involucro PKCS#8 (rsaEncryption), come la leggeva il server TLS. */
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

    // ===================== Il controllo prima di salvare =====================

    /**
     * L'esito del controllo: gli errori fermano il salvataggio, gli avvisi si mostrano nella conferma, le righe di
     * informazione dicono cosa si sta salvando.
     */
    public record Check(List<String> errors, List<String> warnings, List<String> info) {
        public boolean ok() { return errors.isEmpty(); }
    }

    /** I nomi che il certificato copre: i DNS dei Subject Alternative Names, o il CN se non ce ne sono. */
    public static List<String> names(X509Certificate c) {
        List<String> out = new ArrayList<>();
        try {
            Collection<List<?>> sans = c.getSubjectAlternativeNames();
            if (sans != null)
                for (List<?> san : sans)
                    if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0)) && san.get(1) instanceof String s)
                        out.add(s.toLowerCase(Locale.ROOT));
        } catch (Exception ignored) {
            // nessun SAN leggibile: si guarda il CN
        }
        if (out.isEmpty()) {
            for (String part : c.getSubjectX500Principal().getName().split(","))
                if (part.trim().startsWith("CN=")) out.add(part.trim().substring(3).toLowerCase(Locale.ROOT));
        }
        return out;
    }

    /** Il nome e' coperto da uno dei nomi del certificato: uguale, o un * che vale per un'etichetta sola. */
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

    /** Un nome DNS vero (con almeno un punto, non un indirizzo IP, non 0.0.0.0). */
    public static boolean dnsName(String host) {
        if (host == null || host.isBlank() || !host.contains(".")) return false;
        if (host.matches("^[0-9.]+$") || host.contains(":")) return false;
        return host.matches("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$");
    }

    /**
     * Certificato e chiave per il pannello col nome host: il certificato si legge, vale adesso, copre il nome, e la
     * chiave e' proprio la sua (una firma fatta con la chiave si verifica con la chiave pubblica del certificato).
     */
    public static Check check(String host, String certPem, String keyPem, Instant now) {
        return check("panel name", host, certPem, keyPem, now);
    }

    /** Lo stesso controllo per un altro nome (whose: «webmail name»), detto nei messaggi. */
    public static Check check(String whose, String host, String certPem, String keyPem, Instant now) {
        List<String> errors = new ArrayList<>(), warnings = new ArrayList<>(), info = new ArrayList<>();
        List<X509Certificate> chain;
        try {
            chain = certificates(certPem);
        } catch (Exception e) {
            errors.add("The certificate cannot be read: it must be PEM (-----BEGIN CERTIFICATE-----).");
            return new Check(errors, warnings, info);
        }
        X509Certificate leaf = chain.get(0);
        List<String> names = names(leaf);
        info.add("Certificate for: " + String.join(", ", names));
        info.add("Issued by: " + leaf.getIssuerX500Principal().getName());
        info.add("Valid until: " + leaf.getNotAfter().toInstant().toString().substring(0, 10) + " (UTC)");
        if (now.isAfter(leaf.getNotAfter().toInstant())) errors.add("The certificate has expired.");
        // Dieci minuti di tolleranza: un certificato appena emesso (l'Origin Certificate di Cloudflare) comincia nel
        // secondo in cui nasce, e un orologio del server un po' indietro non lo deve rifiutare.
        if (now.plus(java.time.Duration.ofMinutes(10)).isBefore(leaf.getNotBefore().toInstant()))
            errors.add("The certificate is not valid yet.");
        if (dnsName(host)) {
            if (!covers(names, host))
                errors.add("The certificate does not cover the " + whose + " " + host + ": it covers " + String.join(", ", names) + ".");
        } else {
            warnings.add("The " + whose + " " + host + " is not a domain name: Cloudflare and the browsers need one, like "
                    + ("panel name".equals(whose) ? "panel.example.com (passkeys too)." : "webmail.example.com."));
        }
        if (leaf.getIssuerX500Principal().equals(leaf.getSubjectX500Principal()))
            warnings.add("The certificate is self-signed: browsers will warn, and Cloudflare Full (strict) refuses it.");
        try {
            PrivateKey key = privateKey(normalize(keyPem));
            String alg = "EC".equals(key.getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA";
            byte[] probe = "mail-panel-key-check".getBytes(StandardCharsets.US_ASCII);
            Signature s = Signature.getInstance(alg);
            s.initSign(key);
            s.update(probe);
            byte[] sig = s.sign();
            Signature v = Signature.getInstance(alg);
            v.initVerify(leaf.getPublicKey());
            v.update(probe);
            if (v.verify(sig)) info.add("The private key belongs to the certificate.");
            else errors.add("The private key is not the certificate's key.");
        } catch (Exception e) {
            errors.add("The private key cannot be read, or it is not the certificate's key (" + e.getClass().getSimpleName() + ").");
        }
        return new Check(errors, warnings, info);
    }
}
