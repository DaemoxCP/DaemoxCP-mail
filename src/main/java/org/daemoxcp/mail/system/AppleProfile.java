package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.UUID;

/**
 * Il profilo di configurazione che imposta una casella su Apple Mail, su Mac e su iPhone.
 *
 * Perche' questa strada e non le altre: **Apple Mail non usa i record SRV** (RFC 6186) **ne'
 * il file XML di Thunderbird**. Si appoggia a un elenco interno di provider noti, e per un
 * server proprio non esiste alcun documento Apple che descriva un meccanismo di scoperta
 * automatica. Cercare di indovinarne uno significherebbe costruire qualcosa che non si puo'
 * verificare su nessuna fonte.
 *
 * Il profilo di configurazione invece e' documentato da Apple, chiave per chiave, ed e' il
 * modo previsto per configurare Mail senza che l'utente tocchi un'impostazione. I nomi delle
 * chiavi qui sotto sono presi dallo schema ufficiale (repository apple/device-management,
 * com.apple.mail.managed.yaml e TopLevel.yaml), non dalla memoria.
 *
 * Sulla porta in uscita: si usa la 465, non la 587. Lo schema Apple ha un solo booleano,
 * OutgoingMailServerUseSSL, e non un campo che distingua TLS diretto da STARTTLS. Sulla 465
 * Postfix ha smtpd_tls_wrappermode=yes, cioe' TLS dal primo byte: il booleano descrive quel
 * caso senza ambiguita'. Con la 587 si dovrebbe sperare che Apple interpreti "SSL" come
 * "STARTTLS", che e' cio' che accade in pratica ma non e' scritto da nessuna parte.
 *
 * La password NON viene inclusa. Il profilo e' un file che finisce nella cartella Download e
 * puo' essere inoltrato per sbaglio: metterci dentro la password in chiaro trasformerebbe una
 * comodita' in una fuga di credenziali. Mail la chiede una volta sola, perche'
 * OutgoingPasswordSameAsIncomingPassword dice che quella in uscita e' la stessa.
 *
 * ATTENZIONE su quest'ultimo punto, verificato sulla pagina Apple: quel campo vale SOLO per
 * le installazioni interattive, cioe' quando l'utente apre il file di persona — che e'
 * esattamente il nostro caso. Se un giorno questi profili venissero distribuiti da un MDM,
 * l'impostazione verrebbe ignorata e la password sarebbe chiesta due volte.
 *
 * Un'altra riga della stessa pagina va letta e NON seguita: su IncomingMailServerUsername
 * Apple scrive "usually the same as the email address up to the '@' character". Qui si mette
 * l'indirizzo COMPLETO, perche' Dovecot interroga il database con WHERE email='%s'. La
 * documentazione descrive cosa fa il client; cosa serve al server lo dice il server.
 */
public class AppleProfile {

    /** IMAP su TLS diretto: inet_listener imaps di Dovecot. */
    public static final int IMAP_PORT = 993;
    /** smtps in master.cf, con smtpd_tls_wrappermode=yes. */
    public static final int SMTP_PORT = 465;

    private AppleProfile() {}

    /**
     * Il file .mobileconfig per una casella.
     *
     * Gli identificativi sono DERIVATI dall'indirizzo, non casuali: reinstallando il profilo
     * Apple aggiorna quello esistente invece di aggiungere un secondo account identico.
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
        // iOS e macOS riconoscono un profilo dal suo PayloadIdentifier e dal suo UUID: questi due
        // semi e il ".mail" dell'identificatore non vanno piu' cambiati. Fino al 30/10/2026 erano
        // in italiano; il committente ha scelto di passarli all'inglese sapendo che un profilo
        // scaricato prima si installa ACCANTO a quello nuovo invece di essere sostituito: la
        // pagina dice di togliere quello vecchio (pa.after.html).

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
     * Un UUID sempre uguale per lo stesso indirizzo. Se fosse casuale, ogni download
     * genererebbe un profilo "nuovo" e Mail accumulerebbe account doppioni.
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

    /** La casella esiste davvero? Whitelist: si serve solo cio' che il pannello ospita. */
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

    /** L'elenco delle caselle e lo stato generale, per la scheda del pannello. */
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
        // Se il profilo scaricato sara' firmato: lo dice il certificato, che la parte web puo' leggere (la chiave no).
        return r.put("mailboxes", mailboxes).put("signing", signer(host).json());
    }

    /** L'anteprima del profilo, per guardarlo prima di scaricarlo. */
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
     * Il profilo si analizza prima di consegnarlo. Se una sostituzione andasse storta si
     * servirebbe un file che Mail rifiuta con un messaggio incomprensibile: meglio un errore
     * chiaro dal pannello che un fallimento muto sul telefono.
     *
     * Il DOCTYPE rimanda al DTD di Apple: il caricamento di entita' esterne va spento, sia
     * per non dipendere dalla rete sia per non aprire la porta alle entita' esterne.
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

    /** Il nome del file proposto al browser. Solo caratteri innocui. */
    public static String fileName(String email) {
        String base = email == null ? "mail" : email.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]", "-");
        return base + ".mobileconfig";
    }

    /* ===================================================================
     * La firma (23/11/2026)
     * =================================================================== */

    /*
     * Un profilo non firmato l'iPhone lo mostra «Non verificato», in rosso: si installa lo stesso, ma chi lo apre
     * pensa a un errore (visto dal committente sul suo iPhone, 23/11/2026). Firmato con un certificato di cui il
     * telefono si fida, lo mostra «Verificato», col nome del firmatario. Il certificato giusto c'e' gia': quello del
     * nome della posta, lo stesso che Postfix e Dovecot presentano (Let's Encrypt, da acme.sh).
     *
     * Si firma solo con un certificato di cui un telefono si fida davvero: valido adesso, non autofirmato (quello
     * dell'installazione lo e', finche' non arriva Let's Encrypt), che copre il nome della posta e che porta a
     * un'autorita' dell'elenco della Java. Con uno autofirmato il telefono direbbe «Non verificato» lo stesso, e una
     * firma che non serve a niente e' solo una cosa in piu' che puo' rompersi: il profilo esce non firmato, e la
     * finestra dice perche'.
     *
     * La chiave la legge solo root: il profilo da scaricare lo costruisce e lo firma la parte root (la rotta
     * /apple-profile non e' piu' fra quelle che la parte web serve da se'), e firma solo il profilo che costruisce
     * lei, dalla casella del database. Mai un contenuto arrivato da fuori: la chiave del server non firma altro.
     * La firma la fa openssl della base di FreeBSD (CMS, come chiede Apple); la Java non ha un'interfaccia pubblica
     * per CMS. Dopo la firma il file si rilegge con openssl: se il contenuto non torna identico, esce non firmato.
     */

    /** Il certificato e la chiave del nome della posta: gli stessi di Postfix (smtpd_tls_cert_file) e Dovecot. */
    static java.nio.file.Path certificate = java.nio.file.Path.of("/usr/local/etc/ssl/mail/fullchain.pem");
    static java.nio.file.Path key = java.nio.file.Path.of("/usr/local/etc/ssl/mail/privkey.pem");
    static String openssl = "/usr/bin/openssl";
    /** Le autorita' di cui ci si fida: l'elenco della Java (null). Le prove ne mettono una loro. */
    static java.security.KeyStore trusted = null;

    /** Se il profilo si firma, e con cosa; se no, il perche' gia' tradotto. */
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

    /** Il certificato della posta puo' firmare il profilo di 'host'? Legge solo il certificato, non la chiave. */
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

    /** Il nome e' fra quelli del certificato (subjectAltName), anche con un * al posto della prima etichetta. */
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
     * Dal certificato a un'autorita' dell'elenco, con gli intermedi del file (Let's Encrypt ne mette piu' d'uno, e
     * con le firme incrociate l'ordine non e' detto): li mette in fila CertPathBuilder. Senza revoca: per decidere se
     * firmare basta sapere che la catena porta a un'autorita' nota.
     */
    static boolean trustedPath(java.security.cert.X509Certificate leaf, java.util.List<java.security.cert.X509Certificate> chain) {
        try {
            java.security.KeyStore ks = trusted;
            // L'elenco della Java, col tipo riconosciuto dal file (PKCS12 o JKS, a seconda di come e' costruita).
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
     * Il profilo firmato (CMS in DER, col contenuto dentro e la catena del certificato), o null se non si e' potuto:
     * allora si consegna quello non firmato. Il risultato si rilegge prima di darlo: deve contenere esattamente il
     * profilo.
     */
    public static byte[] sign(byte[] profile) {
        byte[] der = run(profile, openssl, "cms", "-sign", "-binary", "-nodetach", "-outform", "DER", "-md", "sha256",
                "-signer", certificate.toString(), "-inkey", key.toString(), "-certfile", certificate.toString());
        if (der == null || der.length == 0 || der[0] != 0x30) return null;
        byte[] back = run(der, openssl, "cms", "-verify", "-binary", "-inform", "DER", "-noverify");
        return back != null && java.util.Arrays.equals(back, profile) ? der : null;
    }

    /** Un programma con 'in' sullo standard input: lo standard output, o null se non finisce bene entro 30 secondi. */
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
