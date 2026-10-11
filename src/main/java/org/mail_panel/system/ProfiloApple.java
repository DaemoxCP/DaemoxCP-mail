package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.Main;

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
public class ProfiloApple {

    /** IMAP su TLS diretto: inet_listener imaps di Dovecot. */
    public static final int PORTA_IMAP = 993;
    /** smtps in master.cf, con smtpd_tls_wrappermode=yes. */
    public static final int PORTA_SMTP = 465;

    private ProfiloApple() {}

    /**
     * Il file .mobileconfig per una casella.
     *
     * Gli identificativi sono DERIVATI dall'indirizzo, non casuali: reinstallando il profilo
     * Apple aggiorna quello esistente invece di aggiungere un secondo account identico.
     */
    public static String mobileconfig(String email, String nomeVisualizzato, String hostDiPosta,
                                      String organizzazione) {
        String e = esc(email);
        String n = esc(nomeVisualizzato == null || nomeVisualizzato.isBlank() ? email : nomeVisualizzato);
        String h = esc(hostDiPosta);
        String org = esc(organizzazione == null || organizzazione.isBlank() ? hostDiPosta : organizzazione);
        String idProfilo = "org.mail-panel." + email.toLowerCase(Locale.ROOT);
        String uuidProfilo = deterministico("profilo:" + email.toLowerCase(Locale.ROOT));
        String uuidPosta = deterministico("posta:" + email.toLowerCase(Locale.ROOT));

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
                  <key>PayloadIdentifier</key>  <string>%s.posta</string>
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
                esc(idProfilo), uuidProfilo,
                esc(I18n.tr("server.appleprof.displayName", java.util.Map.of("e", String.valueOf(email)))), esc(I18n.tr("server.appleprof.description", java.util.Map.of("e", String.valueOf(email)))), org,
                esc(idProfilo), uuidPosta, e,
                e, n, e,
                h, PORTA_IMAP, e,
                h, PORTA_SMTP, e);
    }

    /**
     * Un UUID sempre uguale per lo stesso indirizzo. Se fosse casuale, ogni download
     * genererebbe un profilo "nuovo" e Mail accumulerebbe account doppioni.
     */
    private static String deterministico(String seme) {
        return UUID.nameUUIDFromBytes(seme.getBytes(StandardCharsets.UTF_8))
                .toString().toUpperCase(Locale.ROOT);
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    /** La casella esiste davvero? Whitelist: si serve solo cio' che il pannello ospita. */
    public static Casella casella(String email) {
        if (email == null || email.isBlank()) return null;
        String cercato = email.trim().toLowerCase(Locale.ROOT);
        try {
            for (var d : Main.mailDatabase.getDomains())
                for (var m : Main.mailDatabase.getMailboxes(d.id))
                    if (m.email != null && m.email.equalsIgnoreCase(cercato))
                        return new Casella(m.email, m.name);
        } catch (Exception ignore) {}
        return null;
    }

    public record Casella(String email, String nome) {}

    public static String hostDiPosta() {
        try {
            return Main.mailDatabase.getSetting("mail_hostname", "");
        } catch (Exception e) {
            return "";
        }
    }

    /** L'elenco delle caselle e lo stato generale, per la scheda del pannello. */
    public static JSONObject stato() {
        JSONObject r = new JSONObject().put("success", true);
        String host = hostDiPosta();
        r.put("hostDiPosta", host);
        r.put("portaImap", PORTA_IMAP).put("portaSmtp", PORTA_SMTP);
        if (host == null || host.isBlank())
            return r.put("success", false)
                    .put("error", I18n.tr("server.appleprof.noHostnameProfile"));
        JSONArray caselle = new JSONArray();
        try {
            for (var d : Main.mailDatabase.getDomains())
                for (var m : Main.mailDatabase.getMailboxes(d.id))
                    if (m.email != null && !m.email.isBlank()) caselle.put(m.email);
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.appleprof.mailboxesUnreadable", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
        return r.put("caselle", caselle);
    }

    /** L'anteprima del profilo, per guardarlo prima di scaricarlo. */
    public static JSONObject anteprima(String email) {
        Casella c = casella(email);
        if (c == null)
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.appleprof.noMailbox", java.util.Map.of("e", String.valueOf(email))));
        String host = hostDiPosta();
        if (host == null || host.isBlank())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.appleprof.noHostname"));
        return new JSONObject().put("success", true).put("email", c.email())
                .put("profilo", mobileconfig(c.email(), c.nome(), host, host));
    }

    /**
     * Il profilo si analizza prima di consegnarlo. Se una sostituzione andasse storta si
     * servirebbe un file che Mail rifiuta con un messaggio incomprensibile: meglio un errore
     * chiaro dal pannello che un fallimento muto sul telefono.
     *
     * Il DOCTYPE rimanda al DTD di Apple: il caricamento di entita' esterne va spento, sia
     * per non dipendere dalla rete sia per non aprire la porta alle entita' esterne.
     */
    public static boolean benFormato(String profilo) {
        try {
            javax.xml.parsers.DocumentBuilderFactory f =
                    javax.xml.parsers.DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            f.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(
                    profilo.getBytes(StandardCharsets.UTF_8)));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** Il nome del file proposto al browser. Solo caratteri innocui. */
    public static String nomeFile(String email) {
        String base = email == null ? "posta" : email.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]", "-");
        return base + ".mobileconfig";
    }
}
