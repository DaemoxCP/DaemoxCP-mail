package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.Main;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Il file di configurazione che Thunderbird cerca da solo quando aggiungi una casella.
 *
 * Perche' esiste questa classe, dato che abbiamo gia' i record SRV: **Thunderbird non li
 * usa.** Le richieste 342242 e 675476 su Bugzilla chiedono RFC 6186 da anni e non sono state
 * implementate; la documentazione Mozilla elenca come unici meccanismi il file XML, il
 * database centrale di Mozilla e infine il tentativo a indovinare. Quindi senza questo file
 * chi aggiunge una casella su Thunderbird continua a doversi ricordare server, porte e
 * cifratura, esattamente come prima.
 *
 * Il file viene generato per OGNI dominio, non uno solo per tutti. La documentazione
 * ufficiale non dice se Thunderbird pretenda che l'elemento &lt;domain&gt; corrisponda al
 * dominio dell'indirizzo: quando la fonte non copre il caso si sceglie l'alternativa che e'
 * giusta comunque, e un file per dominio lo e' in entrambi gli scenari.
 *
 * I valori NON sono scritti a mano qui: porte e cifratura sono quelle che il pannello
 * configura davvero (Dovecot in ascolto su 993 in TLS diretto, Postfix submission su 587 con
 * smtpd_tls_security_level=encrypt), e lo username e' l'indirizzo completo perche' e' cosi'
 * che Dovecot interroga il database (WHERE email='%s').
 */
public class Autoconfig {

    /** Porta IMAP su TLS diretto: inet_listener imaps in DovecotConfig. */
    public static final int PORTA_IMAP = 993;
    /** Submission: "submission inet" in master.cf, con TLS obbligatorio. */
    public static final int PORTA_SMTP = 587;

    private Autoconfig() {}

    /* ===================================================================
     * Il file
     * =================================================================== */

    /**
     * L'XML per un dominio. Funzione pura: stessi ingressi, stesso file, e si puo' provare
     * senza server.
     */
    public static String xml(String dominio, String hostDiPosta) {
        String d = esc(dominio);
        String h = esc(hostDiPosta);
        return """
            <?xml version="1.0" encoding="UTF-8"?>
            <clientConfig version="1.1">
              <emailProvider id="%s">
                <domain>%s</domain>
                <displayName>%s</displayName>
                <displayShortName>%s</displayShortName>

                <incomingServer type="imap">
                  <hostname>%s</hostname>
                  <port>%d</port>
                  <socketType>SSL</socketType>
                  <username>%%EMAILADDRESS%%</username>
                  <authentication>password-cleartext</authentication>
                </incomingServer>

                <outgoingServer type="smtp">
                  <hostname>%s</hostname>
                  <port>%d</port>
                  <socketType>STARTTLS</socketType>
                  <username>%%EMAILADDRESS%%</username>
                  <authentication>password-cleartext</authentication>
                </outgoingServer>
              </emailProvider>
            </clientConfig>
            """.formatted(d, d, d, d, h, PORTA_IMAP, h, PORTA_SMTP);
    }

    /**
     * Escape XML. Con una whitelist a monte i nomi di dominio non conterrebbero mai questi
     * caratteri, ma il file si costruisce concatenando: se un giorno qualcuno ci mette
     * dentro un valore che arriva da fuori, questo lo regge lo stesso.
     */
    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    /** Un dominio e' servito solo se il pannello lo gestisce davvero. Whitelist, non filtro. */
    public static String dominioGestito(String richiesto) {
        if (richiesto == null) return null;
        String r = richiesto.trim().toLowerCase(Locale.ROOT);
        if (r.startsWith("autoconfig.")) r = r.substring("autoconfig.".length());
        int p = r.indexOf(':');
        if (p > 0) r = r.substring(0, p);
        if (r.isEmpty()) return null;
        // Non si interroga il database a ogni richiesta: questa rotta e' pubblica e chiunque
        // puo' chiamarla in continuazione. Vedi DominiInCache.
        return DominiInCache.gestito(r);
    }

    /** Il dominio della casella indicata nel parametro emailaddress, se c'e'. */
    public static String dominioDaIndirizzo(String indirizzo) {
        if (indirizzo == null) return null;
        int a = indirizzo.lastIndexOf('@');
        return a < 0 ? null : indirizzo.substring(a + 1);
    }

    public static String hostDiPosta() {
        try {
            return Main.mailDatabase.getSetting("mail_hostname", "");
        } catch (Exception e) {
            return "";
        }
    }

    /* ===================================================================
     * Lo stato reale del server
     * =================================================================== */

    private static final String[] CONF_CANDIDATI = {
        "/usr/local/etc/nginx/sites-enabled/roundcube.conf",
        "/usr/local/etc/nginx/nginx.conf",
    };

    /** Il file di configurazione nginx che contiene il sito in ascolto su 443. */
    public static String confNginx() {
        for (String c : CONF_CANDIDATI) {
            try {
                Path p = Path.of(c);
                if (!Files.isReadable(p)) continue;
                String t = Files.readString(p);
                // NON si cerca "listen 443": questo server ascolta su 8443, e "listen 8443"
                // non contiene "listen 443". Il controllo scritto cosi' dichiarava introvabile
                // una configurazione che c'era, su una porta scelta apposta.
                if (t.contains("listen ") && t.contains("ssl") && t.contains("server_name")) return c;
            } catch (Exception ignore) {}
        }
        return null;
    }

    private static final String MARCATORE = "# --- autoconfig Thunderbird (pannello di posta) ---";

    /**
     * Cosa manca perche' Thunderbird trovi il file. Si LEGGE, non si tocca niente.
     */
    public static JSONObject stato() {
        JSONObject r = new JSONObject().put("success", true);
        String host = hostDiPosta();
        r.put("hostDiPosta", host);
        if (host == null || host.isBlank())
            return r.put("pronto", false)
                    .put("error", "L'hostname del server di posta non e' configurato: senza, il file "
                            + "direbbe ai client di collegarsi a un server senza nome.");

        String conf = confNginx();
        r.put("conf", conf == null ? JSONObject.NULL : conf);
        if (conf == null)
            return r.put("pronto", false)
                    .put("error", "Non trovo la configurazione di nginx in ascolto su 443. Senza sapere "
                            + "quale file governa il sito, non tocco niente: il rischio e' spegnere la "
                            + "webmail per aggiungere un file di configurazione.");

        String testo = "";
        try { testo = Files.readString(Path.of(conf)); } catch (Exception ignore) {}
        boolean nomeCoperto = testo.contains("autoconfig.") && testo.contains("mta-sts.");
        boolean rottaPresente = testo.contains(MARCATORE);
        r.put("nomeCoperto", nomeCoperto).put("rottaPresente", rottaPresente);
        r.put("serverName", primaRigaCon(testo, "server_name"));

        // Il certificato: se non copre autoconfig.<dominio>, Thunderbird sbatte su un errore
        // TLS prima ancora di leggere il file.
        JSONArray domini = new JSONArray();
        try {
            for (var d : Main.mailDatabase.getDomains()) {
                String nome = "autoconfig." + d.domain;
                JSONObject j = new JSONObject().put("dominio", d.domain).put("nome", nome);
                j.put("dns", risolve(nome));
                j.put("certificato", certificatoCopre(nome));
                // La prova che conta: si CHIEDE il file come lo chiederebbe Thunderbird.
                // Leggere la configurazione di nginx dice cosa dovrebbe succedere; questa
                // dice cosa succede. Non sono la stessa cosa, e quando divergono e' sempre
                // la seconda ad avere ragione.
                j.put("prova", provaScarico(nome, d.domain));
                domini.put(j);
            }
        } catch (Exception ignore) {}
        r.put("domini", domini);

        r.put("pronto", nomeCoperto && rottaPresente);
        return r;
    }

    /**
     * Chiede il file esattamente come farebbe Thunderbird e guarda cosa torna.
     *
     * Gli esiti vengono tenuti distinti apposta: "il certificato non e' valido per quel nome"
     * e "il file non c'e'" sono due guasti diversi con due rimedi opposti, e confonderli
     * manderebbe a rifare la cosa sbagliata.
     */
    private static JSONObject provaScarico(String nome, String dominio) {
        JSONObject r = new JSONObject();
        String url = "https://" + nome + "/mail/config-v1.1.xml?emailaddress=prova@" + dominio;
        r.put("url", url);
        try {
            java.net.http.HttpClient http = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(6))
                    .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
                    .build();
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(url))
                    .timeout(java.time.Duration.ofSeconds(8))
                    .GET().build();
            java.net.http.HttpResponse<String> resp =
                    http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            r.put("codice", resp.statusCode());
            String corpo = resp.body() == null ? "" : resp.body();
            boolean giusto = resp.statusCode() == 200 && corpo.contains("<clientConfig")
                    && corpo.contains("<domain>" + dominio + "</domain>");
            r.put("ok", giusto);
            if (!giusto) {
                if (resp.statusCode() != 200)
                    r.put("errore", "Il server risponde " + resp.statusCode() + " invece di 200: a quel "
                            + "nome il file non viene servito.");
                else if (!corpo.contains("<clientConfig"))
                    r.put("errore", "Risponde 200 ma quello che torna non e' il file di configurazione: "
                            + "probabilmente e' la webmail o una pagina di errore.");
                else
                    r.put("errore", "Il file torna, ma dentro non dichiara il dominio " + dominio
                            + ": e' il file di un altro dominio.");
            }
            return r;
        } catch (javax.net.ssl.SSLException e) {
            return r.put("ok", false).put("tls", true)
                    .put("errore", "Il certificato non e' valido per " + nome + ": Thunderbird si fermerebbe "
                            + "qui, prima ancora di leggere il file. Va rigenerato includendo questo nome.");
        } catch (java.net.UnknownHostException e) {
            return r.put("ok", false)
                    .put("errore", "Il nome " + nome + " non si risolve: manca il record CNAME.");
        } catch (Exception e) {
            return r.put("ok", false)
                    .put("errore", "Non raggiungibile: " + e.getClass().getSimpleName()
                            + (e.getMessage() == null ? "" : " - " + e.getMessage()));
        }
    }

    private static String primaRigaCon(String testo, String ago) {
        for (String r : testo.split("\n")) if (r.contains(ago)) return r.trim();
        return "";
    }

    /** Il nome risolve in DNS (il CNAME autoconfig.* creato dalla pagina DNS). */
    private static boolean risolve(String nome) {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", nome);
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return !out.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    /** Il certificato in uso contiene quel nome fra i suoi SAN. */
    private static boolean certificatoCopre(String nome) {
        try {
            Path cert = Path.of("/usr/local/etc/ssl/mail/fullchain.pem");
            if (!Files.isReadable(cert)) return false;
            ProcessBuilder pb = new ProcessBuilder("openssl", "x509", "-in", cert.toString(),
                    "-noout", "-text");
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            for (String r : out.split("\n")) {
                if (!r.contains("DNS:")) continue;
                for (String pezzo : r.split(",")) {
                    String s = pezzo.trim();
                    if (s.startsWith("DNS:") && s.substring(4).trim().equalsIgnoreCase(nome)) return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /* ===================================================================
     * L'installazione
     * =================================================================== */

    /**
     * Aggiunge a nginx il nome autoconfig e la rotta che gira la richiesta al
     * pannello, che genera l'XML giusto per il dominio chiesto.
     *
     * Si segue la stessa disciplina usata per alzare il livello di Postfix: copia di
     * sicurezza, modifica, VALIDAZIONE con nginx -t, e se la validazione fallisce si
     * ripristina la copia e non si ricarica niente. Una webmail spenta per aggiungere un
     * file di configurazione sarebbe un pessimo scambio.
     */
    public static JSONObject installa() {
        JSONObject r = new JSONObject();
        try {
            JSONObject st = stato();
            if (!st.optBoolean("success", false) || st.has("error"))
                return r.put("success", false).put("error", st.optString("error", "stato non leggibile"));
            if (st.optBoolean("pronto", false))
                return r.put("success", true).put("giaFatto", true)
                        .put("nota", "nginx e' gia' configurato per servire il file: non c'e' niente da fare.");

            String conf = st.getString("conf");
            Path p = Path.of(conf);
            String testo = Files.readString(p);
            r.put("conf", conf);

            Path copia = Path.of("/var/db/mailpanel/nginx-prima-di-autoconfig.conf");
            Files.createDirectories(copia.getParent());
            Files.writeString(copia, testo);
            r.put("copia", copia.toString());

            String nuovo = testo;

            // 1. i nomi: senza, nginx non risponde per autoconfig.<dominio>
            if (!nuovo.contains("autoconfig.") || !nuovo.contains("mta-sts.")) {
                int i = nuovo.indexOf("server_name");
                if (i < 0) return r.put("success", false)
                        .put("error", "Nel file non trovo la riga server_name: non modifico alla cieca.");
                int fine = nuovo.indexOf(';', i);
                if (fine < 0) return r.put("success", false)
                        .put("error", "La riga server_name non finisce con ';': file inatteso, non lo tocco.");
                nuovo = nuovo.substring(0, fine) + " autoconfig.* mta-sts.*" + nuovo.substring(fine);
            }

            // 2. la rotta: la richiesta va al pannello, che sa quali domini esistono e
            //    costruisce l'XML per quello giusto. Un file statico non potrebbe.
            if (!nuovo.contains(MARCATORE)) {
                int i = nuovo.indexOf("location /");
                if (i < 0) return r.put("success", false)
                        .put("error", "Nel file non trovo un blocco location: non modifico alla cieca.");
                // Due rotte, un marcatore solo: entrambe girano la richiesta al pannello, che
                // sa quali domini esistono e genera il contenuto per quello chiesto. Un file
                // statico non potrebbe, perche' il contenuto dipende dal dominio.
                String rotta = MARCATORE + "\n"
                        + "    location = /mail/config-v1.1.xml {\n"
                        + "        proxy_pass https://127.0.0.1:2096/autoconfig/mail/config-v1.1.xml;\n"
                        + "        proxy_set_header Host $host;\n"
                        + "    }\n"
                        + "    location = /.well-known/mta-sts.txt {\n"
                        + "        proxy_pass https://127.0.0.1:2096/mta-sts/policy;\n"
                        + "        proxy_set_header Host $host;\n"
                        + "    }\n\n    ";
                nuovo = nuovo.substring(0, i) + rotta + nuovo.substring(i);
            }

            Files.writeString(p, nuovo);

            // 3. la validazione. Qui si decide se andare avanti o tornare indietro.
            Esito prova = esegui("nginx", "-t");
            if (prova.codice != 0) {
                Files.writeString(p, testo);
                return r.put("success", false).put("ripristinato", true)
                        .put("error", "nginx -t ha bocciato la configurazione, quindi ho rimesso "
                                + "quella di prima e NON ho ricaricato niente. Detto da nginx: "
                                + prova.uscita.trim());
            }

            Esito ric = esegui("service", "nginx", "reload");
            if (ric.codice != 0) {
                Files.writeString(p, testo);
                esegui("service", "nginx", "reload");
                return r.put("success", false).put("ripristinato", true)
                        .put("error", "La configurazione era valida ma il reload e' fallito: ho rimesso "
                                + "quella di prima. Detto dal sistema: " + ric.uscita.trim());
            }

            JSONObject dopo = stato();
            r.put("statoDopo", dopo);
            if (!dopo.optBoolean("pronto", false))
                return r.put("success", false)
                        .put("error", "Ho scritto e ricaricato, ma rileggendo il file la configurazione "
                                + "non risulta applicata. Guarda " + conf + " prima di riprovare.");

            return r.put("success", true)
                    .put("nota", "nginx ora risponde anche per autoconfig.<dominio> e gira la richiesta "
                            + "del file al pannello. Copia di sicurezza in " + copia + ".");
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", "errore durante l'installazione: " + e.getMessage());
        }
    }

    private record Esito(int codice, String uscita) {}

    private static Esito esegui(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return new Esito(p.waitFor(), out);
        } catch (Exception e) {
            return new Esito(-1, String.valueOf(e.getMessage()));
        }
    }

    /** L'anteprima del file, per guardarlo prima di installare qualsiasi cosa. */
    public static JSONObject anteprima() {
        JSONObject r = new JSONObject().put("success", true);
        String host = hostDiPosta();
        if (host == null || host.isBlank())
            return new JSONObject().put("success", false)
                    .put("error", "L'hostname del server di posta non e' configurato.");
        List<String> nomi = new ArrayList<>();
        try { for (var d : Main.mailDatabase.getDomains()) nomi.add(d.domain); } catch (Exception ignore) {}
        if (nomi.isEmpty())
            return new JSONObject().put("success", false).put("error", "Nessun dominio configurato.");
        return r.put("dominio", nomi.get(0)).put("hostDiPosta", host)
                .put("xml", xml(nomi.get(0), host)).put("quantiDomini", nomi.size());
    }
}
