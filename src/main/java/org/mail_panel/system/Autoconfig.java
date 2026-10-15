package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
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
        // puo' chiamarla in continuazione. Vedi DomainCache.
        return DomainCache.gestito(r);
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
                    .put("error", I18n.tr("server.autoconf.noHostnameFile"));

        String conf = confNginx();
        r.put("conf", conf == null ? JSONObject.NULL : conf);
        if (conf == null)
            return r.put("pronto", false)
                    .put("error", I18n.tr("server.autoconf.noNginx443"));

        String testo = "";
        try { testo = Files.readString(Path.of(conf)); } catch (Exception ignore) {}
        boolean nomeCoperto = testo.contains("autoconfig.") && testo.contains("mta-sts.");
        boolean rottaPresente = testo.contains(MARCATORE);
        r.put("nomeCoperto", nomeCoperto).put("rottaPresente", rottaPresente);
        r.put("serverName", primaRigaCon(testo, "server_name"));
        // Se la superficie pubblica sulla 443 e' installata, quei nomi sono suoi e questa
        // scheda non deve nemmeno offrire di toccare nginx: un pulsante che, premuto, si
        // rifiuta, e' un pulsante che non andava mostrato.
        r.put("superficie443", WebProtection.stato().optBoolean("installato", false));

        // Il certificato: se non copre autoconfig.<dominio>, Thunderbird sbatte su un errore
        // TLS prima ancora di leggere il file.
        JSONArray domini = new JSONArray();
        List<String> guai = new ArrayList<>();
        int esaminati = 0, funzionanti = 0;
        boolean elencoLetto = false;
        try {
            var tutti = Main.mailDatabase.getDomains();
            elencoLetto = true;
            for (var d : tutti) {
                String nome = "autoconfig." + d.domain;
                JSONObject j = new JSONObject().put("dominio", d.domain).put("nome", nome);
                j.put("dns", risolve(nome));
                j.put("certificato", certificatoCopre(nome));
                // La prova che conta: si CHIEDE il file come lo chiederebbe Thunderbird.
                // Leggere la configurazione di nginx dice cosa dovrebbe succedere; questa
                // dice cosa succede. Non sono la stessa cosa, e quando divergono e' sempre
                // la seconda ad avere ragione.
                JSONObject prova = provaScarico(nome, d.domain);
                j.put("prova", prova);
                esaminati++;
                if (prova.optBoolean("ok", false)) funzionanti++;
                else guai.add(d.domain + " (" + prova.optString("errore", I18n.tr("server.autoconf.failed")) + ")");
                domini.put(j);
            }
        } catch (Exception e) {
            guai.add(I18n.tr("server.autoconf.domainsUnreadable", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
        r.put("domini", domini).put("esaminati", esaminati).put("funzionanti", funzionanti);

        // Il verdict viene dalla PROVA, non dal testo della configurazione.
        //
        // Prima era "nomeCoperto && rottaPresente", cioe' il risultato di una ricerca dentro
        // nginx.conf del marcatore che questa classe stessa scrive. Ma la rotta puo' stare
        // altrove — e sta altrove: la scheda della 443 la installa in
        // conf.d/mailpanel-pubblico.conf, che serve esattamente questi due file, la politica
        // MTA-STS e questo XML. Risultato: il pannello scaricava il file davvero, lo otteneva,
        // e un attimo dopo dichiarava che nginx non lo serve e che i client devono
        // configurarsi a mano. Il commento qui sopra diceva gia' quale delle due misure ha
        // ragione; il verdict usava l'altra.
        boolean pronto = pronto(elencoLetto, esaminati, funzionanti);
        r.put("pronto", pronto);
        r.put("perche", pronto
                ? I18n.tr("server.autoconf.arrivesAll", java.util.Map.of("n", String.valueOf(esaminati))) + " " + (rottaPresente
                        ? I18n.tr("server.autoconf.routeIn", java.util.Map.of("conf", String.valueOf(conf)))
                        : I18n.tr("server.autoconf.routeElsewhere", java.util.Map.of("conf", String.valueOf(conf))))
                : esaminati == 0
                  ? I18n.tr("server.autoconf.noneTried")
                  : I18n.tr("server.autoconf.notArriving", java.util.Map.of("n", String.valueOf(guai.size()), "tot", String.valueOf(esaminati), "list", String.valueOf(String.join("; ", guai)))));
        return r;
    }

    /**
     * Chiede il file esattamente come farebbe Thunderbird e guarda cosa torna.
     *
     * Gli esiti vengono tenuti distinti apposta: "il certificato non e' valido per quel nome"
     * e "il file non c'e'" sono due guasti diversi con due rimedi opposti, e confonderli
     * manderebbe a rifare la cosa sbagliata.
     */
    /**
     * Il verdict, staccato da stato() perche' un test possa arrivarci.
     *
     * E' la riga che sbagliava: prima diceva "pronto" in base a una ricerca di testo dentro
     * nginx.conf, e cosi' dichiarava che nginx non serviva un file che stava servendo. Ora
     * dipende solo dalle prove, e ha tre condizioni, tutte necessarie:
     *
     *  - l'elenco dei domini si e' potuto leggere: se non si e' letto, non si e' provato nulla;
     *  - almeno un dominio e' stato provato: zero prove tutte riuscite fanno "0 == 0", cioe'
     *    verde. Su zero domini un conteggio dice sempre di si', ed e' il modo piu' silenzioso
     *    di dichiarare funzionante una cosa che non e' stata guardata;
     *  - tutte le prove sono riuscite: una sola che fallisce basta, perche' e' un dominio i
     *    cui client continuano a doversi configurare a mano.
     */
    static boolean pronto(boolean elencoLetto, int esaminati, int funzionanti) {
        return elencoLetto && esaminati > 0 && funzionanti == esaminati;
    }

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
                    r.put("errore", I18n.tr("server.autoconf.status", java.util.Map.of("c", String.valueOf(resp.statusCode()))));
                else if (!corpo.contains("<clientConfig"))
                    r.put("errore", I18n.tr("server.autoconf.notConfigFile"));
                else
                    r.put("errore", I18n.tr("server.autoconf.otherDomain", java.util.Map.of("d", String.valueOf(dominio))));
            }
            return r;
        } catch (javax.net.ssl.SSLException e) {
            return r.put("ok", false).put("tls", true)
                    .put("errore", I18n.tr("server.autoconf.certInvalid", java.util.Map.of("name", String.valueOf(nome))));
        } catch (java.net.UnknownHostException e) {
            return r.put("ok", false)
                    .put("errore", I18n.tr("server.autoconf.noCname", java.util.Map.of("name", String.valueOf(nome))));
        } catch (Exception e) {
            return r.put("ok", false)
                    .put("errore", I18n.tr("server.autoconf.unreachable", java.util.Map.of("err", String.valueOf(e.getClass().getSimpleName() + (e.getMessage() == null ? "" : " - " + e.getMessage())))));
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
                return r.put("success", false).put("error", st.optString("error", I18n.tr("server.autoconf.stateUnreadable")));
            if (st.optBoolean("pronto", false))
                return r.put("success", true).put("giaFatto", true)
                        .put("nota", I18n.tr("server.autoconf.alreadyAll") + " " + st.optString("perche", ""));

            // La guardia che conta, e vale anche quando il file NON arriva.
            //
            // Se la superficie pubblica sulla 443 e' installata, autoconfig.<dominio> e
            // mta-sts.<dominio> li serve gia' lei, ed e' un blocco scritto apposta per questo:
            // due sole location esatte, 404 su tutto il resto, limiti di frequenza, solo GET e
            // HEAD, e un log suo che la jail fail2ban sorveglia.
            //
            // Quel blocco e' dichiarato "server_name _", cioe' vince come default_server solo
            // finche' nessun altro rivendica quei nomi. Aggiungere "autoconfig.* mta-sts.*" al
            // server_name della webmail glieli porterebbe via — in nginx un nome con jolly
            // batte il default_server — e con essi la protezione e il log della jail, che
            // resterebbe "attiva" su un file che nessuno scrive piu'.
            //
            // "nginx -t" non se ne accorgerebbe: e' una rottura di significato, non di
            // sintassi. Quindi la decisione va presa qui, prima di scrivere.
            if (WebProtection.stato().optBoolean("installato", false))
                return r.put("success", false).put("giaAltrove", true)
                        .put("error", I18n.tr("server.autoconf.publicSurface") + " " + st.optString("perche", ""));

            // Quali politiche MTA-STS rispondono PRIMA di toccare qualcosa. Senza questa
            // fotografia, dopo non c'e' modo di sapere se una l'ho rotta io.
            List<String> politichePrima = politicheCheRispondono();
            r.put("politichePrima", new JSONArray(politichePrima));

            String conf = st.getString("conf");
            Path p = Path.of(conf);
            String testo = Files.readString(p);
            r.put("conf", conf);

            Path copia = Path.of("/var/db/mailpanel/nginx-before-autoconfig.conf");
            Files.createDirectories(copia.getParent());
            Files.writeString(copia, testo);
            r.put("copia", copia.toString());

            String nuovo = testo;

            // 1. i nomi: senza, nginx non risponde per autoconfig.<dominio>
            if (!nuovo.contains("autoconfig.") || !nuovo.contains("mta-sts.")) {
                int i = nuovo.indexOf("server_name");
                if (i < 0) return r.put("success", false)
                        .put("error", I18n.tr("server.autoconf.noServerName"));
                int fine = nuovo.indexOf(';', i);
                if (fine < 0) return r.put("success", false)
                        .put("error", I18n.tr("server.autoconf.serverNameNoSemicolon"));
                nuovo = nuovo.substring(0, fine) + " autoconfig.* mta-sts.*" + nuovo.substring(fine);
            }

            // 2. la rotta: la richiesta va al pannello, che sa quali domini esistono e
            //    costruisce l'XML per quello giusto. Un file statico non potrebbe.
            if (!nuovo.contains(MARCATORE)) {
                int i = nuovo.indexOf("location /");
                if (i < 0) return r.put("success", false)
                        .put("error", I18n.tr("server.autoconf.noLocation"));
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
                        .put("error", I18n.tr("server.autoconf.nginxRejected", java.util.Map.of("out", String.valueOf(prova.uscita.trim()))));
            }

            Esito ric = esegui("service", "nginx", "reload");
            if (ric.codice != 0) {
                Files.writeString(p, testo);
                esegui("service", "nginx", "reload");
                return r.put("success", false).put("ripristinato", true)
                        .put("error", I18n.tr("server.autoconf.reloadFailed", java.util.Map.of("out", String.valueOf(ric.uscita.trim()))));
            }

            // Una verifica non puo' guardare solo cio' che volevo ottenere: va guardato anche
            // cio' che potevo aver rotto. Spostare dei nomi fra due server_name sposta le
            // richieste da un blocco all'altro, e il blocco che li perde e' quello che serve la
            // politica MTA-STS. Con i record TXT gia' pubblicati, farla sparire vuol dire
            // lasciare al mondo la dichiarazione di una protezione che non risponde piu'.
            List<String> politicheDopo = politicheCheRispondono();
            List<String> perse = new ArrayList<>(politichePrima);
            perse.removeAll(politicheDopo);
            if (!perse.isEmpty()) {
                Files.writeString(p, testo);
                esegui("service", "nginx", "reload");
                return r.put("success", false).put("ripristinato", true)
                        .put("error", I18n.tr("server.autoconf.stsLost", java.util.Map.of("list", String.valueOf(String.join(", ", perse)))));
            }

            JSONObject dopo = stato();
            r.put("statoDopo", dopo);
            if (!dopo.optBoolean("pronto", false)) {
                Files.writeString(p, testo);
                esegui("service", "nginx", "reload");
                return r.put("success", false).put("ripristinato", true)
                        .put("error", I18n.tr("server.autoconf.stillNotArriving", java.util.Map.of("why", String.valueOf(dopo.optString("perche", "")), "copy", String.valueOf(copia))));
            }

            return r.put("success", true)
                    .put("nota", I18n.tr("server.autoconf.done", java.util.Map.of("copy", String.valueOf(copia))));
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.autoconf.installError", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    /**
     * I domini la cui politica MTA-STS risponde adesso.
     *
     * Serve a fare un prima/dopo attorno a una modifica di nginx: e' l'unico modo per
     * accorgersi di aver rotto una cosa che non si stava cercando di toccare. Un dominio che
     * gia' non rispondeva prima non conta come danno — non lo si e' rotto qui — e includerlo
     * farebbe fallire un'installazione riuscita.
     */
    private static List<String> politicheCheRispondono() {
        List<String> vive = new ArrayList<>();
        try {
            for (var d : Main.mailDatabase.getDomains())
                if (MtaSts.provaPubblica(d.domain).optBoolean("ok", false)) vive.add(d.domain);
        } catch (Exception ignore) {}
        return vive;
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
                    .put("error", I18n.tr("server.autoconf.noHostname"));
        List<String> nomi = new ArrayList<>();
        try { for (var d : Main.mailDatabase.getDomains()) nomi.add(d.domain); } catch (Exception ignore) {}
        if (nomi.isEmpty())
            return new JSONObject().put("success", false).put("error", I18n.tr("server.autoconf.noDomains"));
        return r.put("dominio", nomi.get(0)).put("hostDiPosta", host)
                .put("xml", xml(nomi.get(0), host)).put("quantiDomini", nomi.size());
    }
}
