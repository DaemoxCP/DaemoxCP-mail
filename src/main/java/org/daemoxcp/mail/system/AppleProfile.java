package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.UUID;

/**
 * The configuration profile that sets up a mailbox in Apple Mail, on Mac and on iPhone.
 *
 * Why this route and not the others: **Apple Mail does not use SRV records** (RFC 6186) **nor
 * Thunderbird's XML file**. It relies on an internal list of known providers, and for a
 * server of one's own there is no Apple document describing an automatic discovery
 * mechanism. Trying to guess one would mean building something that cannot be
 * verified against any source.
 *
 * The configuration profile, instead, is documented by Apple, key by key, and it is the
 * intended way to configure Mail without the user touching a setting. The names of the
 * keys below are taken from the official schema (repository apple/device-management,
 * com.apple.mail.managed.yaml and TopLevel.yaml), not from memory.
 *
 * On the outgoing port: 465 is used, not 587. Apple's schema has a single boolean,
 * OutgoingMailServerUseSSL, and no field that distinguishes direct TLS from STARTTLS. On 465
 * Postfix has smtpd_tls_wrappermode=yes, that is TLS from the first byte: the boolean describes that
 * case without ambiguity. With 587 one would have to hope that Apple interprets "SSL" as
 * "STARTTLS", which is what happens in practice but is not written anywhere.
 *
 * The password is NOT included. The profile is a file that ends up in the Downloads folder and
 * can be forwarded by mistake: putting the password in clear text inside it would turn a
 * convenience into a credential leak. Mail asks for it only once, because
 * OutgoingPasswordSameAsIncomingPassword says the outgoing one is the same.
 *
 * WARNING on this last point, verified on the Apple page: that field applies ONLY to
 * interactive installations, that is when the user opens the file in person, which is
 * exactly our case. If one day these profiles were distributed by an MDM,
 * the setting would be ignored and the password would be asked for twice.
 *
 * Another line of the same page must be read and NOT followed: on IncomingMailServerUsername
 * Apple writes "usually the same as the email address up to the '@' character". Here we put
 * the FULL address, because Dovecot queries the database with WHERE email='%s'. The
 * documentation describes what the client does; what the server needs is said by the server.
 */
public class AppleProfile {

    /** IMAP over direct TLS: Dovecot's imaps inet_listener. */
    public static final int IMAP_PORT = 993;
    /** smtps in master.cf, with smtpd_tls_wrappermode=yes. */
    public static final int SMTP_PORT = 465;

    private AppleProfile() {}

    /**
     * The .mobileconfig file for a mailbox.
     *
     * The identifiers are DERIVED from the address, not random: when the profile is reinstalled
     * Apple updates the existing one instead of adding a second identical account.
     */
    public static String mobileconfig(String email, String displayName, String mailHost,
                                      String organization) {
        String e = escape(email);
        String n = escape(displayName == null || displayName.isBlank() ? email : displayName);
        String h = escape(mailHost);
        String org = escape(organization == null || organization.isBlank() ? mailHost : organization);
        String profileId = "org.mail-panel." + email.toLowerCase(Locale.ROOT);
        String profileUuid = deterministic("profile:" + email.toLowerCase(Locale.ROOT));
        String mailUuid = deterministic("mail:" + email.toLowerCase(Locale.ROOT));
        // iOS and macOS recognise a profile by its PayloadIdentifier and its UUID: these two
        // seeds and the ".mail" of the identifier must not be changed any more. Until 2026-10-30 they were
        // in Italian; the owner chose to switch them to English knowing that a profile
        // downloaded earlier gets installed NEXT TO the new one instead of being replaced: the
        // page says to remove the old one (pa.after.html).

        return """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>PayloadType</key>            <string>Configuration</string>
              <key>PayloadVersion</key>         <integer>1</integer>
              <key>PayloadIdentifier</key>      <string>%s</string>
              <key>PayloadUUID</key>            <string>%s</string>
              <key>PayloadDisplayName</key>     <string>%s</string>
              <key>PayloadDescription</key>     <string>%s</string>
              <key>PayloadOrganization</key>    <string>%s</string>
              <key>PayloadContent</key>
              <array>
                <dict>
                  <key>PayloadType</key>        <string>com.apple.mail.managed</string>
                  <key>PayloadVersion</key>     <integer>1</integer>
                  <key>PayloadIdentifier</key>  <string>%s.mail</string>
                  <key>PayloadUUID</key>        <string>%s</string>
                  <key>PayloadDisplayName</key> <string>Account %s</string>

                  <key>EmailAccountType</key>            <string>EmailTypeIMAP</string>
                  <key>EmailAccountDescription</key>     <string>%s</string>
                  <key>EmailAccountName</key>            <string>%s</string>
                  <key>EmailAddress</key>                <string>%s</string>

                  <key>IncomingMailServerHostName</key>       <string>%s</string>
                  <key>IncomingMailServerPortNumber</key>     <integer>%d</integer>
                  <key>IncomingMailServerUseSSL</key>         <true/>
                  <key>IncomingMailServerUsername</key>       <string>%s</string>
                  <key>IncomingMailServerAuthentication</key> <string>EmailAuthPassword</string>

                  <key>OutgoingMailServerHostName</key>       <string>%s</string>
                  <key>OutgoingMailServerPortNumber</key>     <integer>%d</integer>
                  <key>OutgoingMailServerUseSSL</key>         <true/>
                  <key>OutgoingMailServerUsername</key>       <string>%s</string>
                  <key>OutgoingMailServerAuthentication</key> <string>EmailAuthPassword</string>
                  <key>OutgoingPasswordSameAsIncomingPassword</key> <true/>
                </dict>
              </array>
            </dict>
            </plist>
            """.formatted(
                escape(profileId), profileUuid,
                escape(I18n.tr("server.appleprof.displayName", java.util.Map.of("e", String.valueOf(email)))), escape(I18n.tr("server.appleprof.description", java.util.Map.of("e", String.valueOf(email)))), org,
                escape(profileId), mailUuid, e,
                e, n, e,
                h, IMAP_PORT, e,
                h, SMTP_PORT, e);
    }

    /**
     * A UUID that is always the same for the same address. If it were random, every download
     * would generate a "new" profile and Mail would pile up duplicate accounts.
     */
    private static String deterministic(String seed) {
        return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8))
                .toString().toUpperCase(Locale.ROOT);
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    /** Does the mailbox really exist? Whitelist: only what the panel hosts is served. */
    public static ProfileMailbox mailbox(String email) {
        if (email == null || email.isBlank()) return null;
        String searched = email.trim().toLowerCase(Locale.ROOT);
        try {
            for (var d : Main.mailDatabase.getDomains())
                for (var m : Main.mailDatabase.getMailboxes(d.id))
                    if (m.email != null && m.email.equalsIgnoreCase(searched))
                        return new ProfileMailbox(m.email, m.name);
        } catch (Exception ignore) {}
        return null;
    }

    public record ProfileMailbox(String email, String name) {}

    public static String mailHost() {
        try {
            return Main.mailDatabase.getSetting("mail_hostname", "");
        } catch (Exception e) {
            return "";
        }
    }

    /** The list of mailboxes and the general state, for the panel tab. */
    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);
        String host = mailHost();
        r.put("mailHost", host);
        r.put("imapPort", IMAP_PORT).put("smtpPort", SMTP_PORT);
        if (host == null || host.isBlank())
            return r.put("success", false)
                    .put("error", I18n.tr("server.appleprof.noHostnameProfile"));
        JSONArray mailboxes = new JSONArray();
        try {
            for (var d : Main.mailDatabase.getDomains())
                for (var m : Main.mailDatabase.getMailboxes(d.id))
                    if (m.email != null && !m.email.isBlank()) mailboxes.put(m.email);
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.appleprof.mailboxesUnreadable", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("AppleProfile", e))));
        }
        // Whether the downloaded profile will be signed: the certificate says so, which the web part can read (the key
        // it cannot).
        return r.put("mailboxes", mailboxes).put("signing", signer(host).json());
    }

    /** The profile preview, to look at it before downloading it. */
    public static JSONObject preview(String email) {
        ProfileMailbox c = mailbox(email);
        if (c == null)
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.appleprof.noMailbox", java.util.Map.of("e", String.valueOf(email))));
        String host = mailHost();
        if (host == null || host.isBlank())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.appleprof.noHostname"));
        return new JSONObject().put("success", true).put("email", c.email())
                .put("profile", mobileconfig(c.email(), c.name(), host, host));
    }

    /**
     * The profile is parsed before handing it over. If a substitution went wrong, a file
     * would be served that Mail rejects with an incomprehensible message: better a clear
     * error from the panel than a silent failure on the phone.
     *
     * The DOCTYPE refers to Apple's DTD: loading external entities must be switched off, both
     * so as not to depend on the network and so as not to open the door to external entities.
     */
    public static boolean wellFormed(String profile) {
        try {
            javax.xml.parsers.DocumentBuilderFactory f =
                    javax.xml.parsers.DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            f.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(
                    profile.getBytes(StandardCharsets.UTF_8)));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** The file name proposed to the browser. Harmless characters only. */
    public static String fileName(String email) {
        String base = email == null ? "mail" : email.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]", "-");
        return base + ".mobileconfig";
    }

    /*
     * ===================================================================
     * The signature (2026-11-23)
     * ===================================================================
     */

    /*
     * An unsigned profile is shown by the iPhone as "Not Verified", in red: it installs anyway, but whoever opens it
     * thinks of an error (seen by the owner on his iPhone, 2026-11-23). Signed with a certificate the phone trusts, it
     * is shown as "Verified", with the signer's name. The right certificate is already there: the one of the mail name,
     * the same one Postfix and Dovecot present (Let's Encrypt, from acme.sh).
     *
     * It is signed only with a certificate a phone really trusts: valid now, not self-signed (the one
     * from the installation is, until Let's Encrypt arrives), covering the mail name and leading to
     * an authority in Java's list. With a self-signed one the phone would say "Not Verified" anyway, and a
     * signature that serves no purpose is just one more thing that can break: the profile goes out unsigned, and the
     * window says why.
     *
     * Only root reads the key: the profile to download is built and signed by the root part (the /apple-profile route
     * is no longer among those the web part serves by itself), and it signs only the profile it builds itself, from the
     * mailbox in the database. Never content that came from outside: the server key signs nothing else. The signature
     * is made by the openssl of the FreeBSD base system (CMS, as Apple requires); Java has no public interface for CMS.
     * After signing, the file is read back with openssl: if the content does not come back identical, it goes out
     * unsigned.
     */

    /** The certificate and key of the mail name: the same as Postfix's (smtpd_tls_cert_file) and Dovecot's. */
    static java.nio.file.Path certificate = java.nio.file.Path.of("/usr/local/etc/ssl/mail/fullchain.pem");
    static java.nio.file.Path key = java.nio.file.Path.of("/usr/local/etc/ssl/mail/privkey.pem");
    static String openssl = "/usr/bin/openssl";
    /** The trusted authorities: Java's list (null). Tests put in one of their own. */
    static java.security.KeyStore trusted = null;

    /** Whether the profile gets signed, and with what; if not, the reason, already translated. */
    public record Signer(boolean ok, String name, String notAfter, String why) {
        JSONObject json() {
            JSONObject r = new JSONObject().put("signed", ok);
            if (ok) return r.put("name", name).put("notAfter", notAfter);
            return r.put("why", why);
        }
    }

    private static Signer no(String key, java.util.Map<String, String> params) {
        return new Signer(false, null, null, I18n.tr("server.appleprof.sign." + key, params));
    }

    /** Can the mail certificate sign the profile of 'host'? It reads only the certificate, not the key. */
    public static Signer signer(String host) {
        java.util.List<java.security.cert.X509Certificate> chain = new java.util.ArrayList<>();
        try (java.io.InputStream in = java.nio.file.Files.newInputStream(certificate)) {
            for (java.security.cert.Certificate c : java.security.cert.CertificateFactory.getInstance("X.509").generateCertificates(in))
                if (c instanceof java.security.cert.X509Certificate x) chain.add(x);
        } catch (Exception e) {
            chain.clear();
        }
        if (chain.isEmpty()) return no("unreadable", java.util.Map.of());
        java.security.cert.X509Certificate leaf = chain.get(0);
        try {
            leaf.checkValidity();
        } catch (Exception e) {
            return no("expired", java.util.Map.of());
        }
        if (leaf.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) return no("selfSigned", java.util.Map.of());
        if (host == null || host.isBlank() || !covers(leaf, host)) return no("otherName", java.util.Map.of("h", String.valueOf(host)));
        if (!trustedPath(leaf, chain)) return no("notTrusted", java.util.Map.of());
        String until = leaf.getNotAfter().toInstant().atZone(java.time.ZoneOffset.UTC).toLocalDate().toString();
        return new Signer(true, host.toLowerCase(Locale.ROOT), until, null);
    }

    /** The name is among the certificate's names (subjectAltName), even with a * in place of the first label. */
    static boolean covers(java.security.cert.X509Certificate leaf, String host) {
        String h = host.trim().toLowerCase(Locale.ROOT);
        try {
            java.util.Collection<java.util.List<?>> names = leaf.getSubjectAlternativeNames();
            if (names == null) return false;
            for (java.util.List<?> n : names) {
                if (n.size() < 2 || !Integer.valueOf(2).equals(n.get(0))) continue;     // 2 = dNSName
                String d = String.valueOf(n.get(1)).toLowerCase(Locale.ROOT);
                if (d.equals(h)) return true;
                int dot = h.indexOf('.');
                if (d.startsWith("*.") && dot > 0 && d.substring(1).equals(h.substring(dot))) return true;
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    /**
     * From the certificate to an authority in the list, with the intermediates from the file (Let's Encrypt puts more
     * than one, and with cross-signatures the order is not guaranteed): CertPathBuilder lines them up. Without
     * revocation: to decide whether to sign it is enough to know that the chain leads to a known authority.
     */
    static boolean trustedPath(java.security.cert.X509Certificate leaf, java.util.List<java.security.cert.X509Certificate> chain) {
        try {
            java.security.KeyStore ks = trusted;
            // Java's list, with the type recognised from the file (PKCS12 or JKS, depending on how it is built).
            if (ks == null) ks = java.security.KeyStore.getInstance(
                    java.nio.file.Path.of(System.getProperty("java.home"), "lib", "security", "cacerts").toFile(), (char[]) null);
            java.security.cert.X509CertSelector target = new java.security.cert.X509CertSelector();
            target.setCertificate(leaf);
            java.security.cert.PKIXBuilderParameters p = new java.security.cert.PKIXBuilderParameters(ks, target);
            p.setRevocationEnabled(false);
            p.addCertStore(java.security.cert.CertStore.getInstance("Collection",
                    new java.security.cert.CollectionCertStoreParameters(chain)));
            java.security.cert.CertPathBuilder.getInstance("PKIX").build(p);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * The signed profile (CMS in DER, with the content inside and the certificate chain), or null if it was not possible:
     * then the unsigned one is handed over. The result is read back before handing it over: it must contain exactly the
     * profile.
     */
    public static byte[] sign(byte[] profile) {
        byte[] der = run(profile, openssl, "cms", "-sign", "-binary", "-nodetach", "-outform", "DER", "-md", "sha256",
                "-signer", certificate.toString(), "-inkey", key.toString(), "-certfile", certificate.toString());
        if (der == null || der.length == 0 || der[0] != 0x30) return null;
        byte[] back = run(der, openssl, "cms", "-verify", "-binary", "-inform", "DER", "-noverify");
        return back != null && java.util.Arrays.equals(back, profile) ? der : null;
    }

    /** A program with 'in' on standard input: the standard output, or null if it does not finish cleanly within 30 seconds. */
    private static byte[] run(byte[] in, String... cmd) {
        Process p = null;
        try {
            p = new ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            Process proc = p;
            Thread writer = new Thread(() -> {
                try (java.io.OutputStream os = proc.getOutputStream()) { os.write(in); }
                catch (java.io.IOException ignored) { }
            });
            writer.start();
            byte[] out;
            try (java.io.InputStream is = p.getInputStream()) { out = is.readNBytes(1 << 20); }
            if (!p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS) || p.exitValue() != 0) return null;
            writer.join(5000);
            return out;
        } catch (Exception e) {
            return null;
        } finally {
            if (p != null && p.isAlive()) p.destroyForcibly();
        }
    }
}
