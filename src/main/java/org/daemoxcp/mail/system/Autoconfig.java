package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.util.Shell;

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
    public static final int IMAP_PORT = 993;
    /** Submission: "submission inet" in master.cf, con TLS obbligatorio. */
    public static final int SMTP_PORT = 587;

    private Autoconfig() {}

    /* ===================================================================
     * Il file
     * =================================================================== */

    /**
     * L'XML per un dominio. Funzione pura: stessi ingressi, stesso file, e si puo' provare
     * senza server.
     */
    public static String xml(String domain, String mailHost) {
        String d = escape(domain);
        String h = escape(mailHost);
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
            """.formatted(d, d, d, d, h, IMAP_PORT, h, SMTP_PORT);
    }

    /**
     * Escape XML. Con una whitelist a monte i nomi di dominio non conterrebbero mai questi
     * caratteri, ma il file si costruisce concatenando: se un giorno qualcuno ci mette
     * dentro un valore che arriva da fuori, questo lo regge lo stesso.
     */
    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    /** Un dominio e' servito solo se il pannello lo gestisce davvero. Whitelist, non filtro. */
    public static String managedDomain(String required) {
        if (required == null) return null;
        String r = required.trim().toLowerCase(Locale.ROOT);
        if (r.startsWith("autoconfig.")) r = r.substring("autoconfig.".length());
        int p = r.indexOf(':');
        if (p > 0) r = r.substring(0, p);
        if (r.isEmpty()) return null;
        // Non si interroga il database a ogni richiesta: questa rotta e' pubblica e chiunque
        // puo' chiamarla in continuazione. Vedi DomainCache.
        return DomainCache.managed(r);
    }

    /** Il dominio della casella indicata nel parametro emailaddress, se c'e'. */
    public static String domainFromAddress(String address) {
        if (address == null) return null;
        int a = address.lastIndexOf('@');
        return a < 0 ? null : address.substring(a + 1);
    }

    public static String mailHost() {
        try {
            return Main.mailDatabase.getSetting("mail_hostname", "");
        } catch (Exception e) {
            return "";
        }
    }

    /* ===================================================================
     * Lo stato reale del server
     * =================================================================== */

    private static final String[] CONF_CANDIDATES = {
        "/usr/local/etc/nginx/sites-enabled/roundcube.conf",
        "/usr/local/etc/nginx/nginx.conf",
    };

    /** Il file di configurazione nginx che contiene il sito in ascolto su 443. */
    public static String confNginx() {
        for (String c : CONF_CANDIDATES) {
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

    static final String MARKER = "# --- autoconfig Thunderbird (mail panel) ---";

    /**
     * Il blocco del pannello c'e' gia', col marcatore di adesso o con quello di prima
     * (legacy-names.json). Il file e' di nginx, non del pannello: il marcatore di prima resta dov'e',
     * e senza riconoscerlo si aggiungerebbe un secondo blocco, che nginx -t rifiuta.
     */
    static boolean hasBlock(String text) {
        for (String m : PanelMarker.forms("autoconfigMarker", MARKER)) if (text.contains(m)) return true;
        return false;
    }

    /**
     * Cosa manca perche' Thunderbird trovi il file. Si LEGGE, non si tocca niente.
     */
    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);
        String host = mailHost();
        r.put("mailHost", host);
        if (host == null || host.isBlank())
            return r.put("ready", false)
                    .put("error", I18n.tr("server.autoconf.noHostnameFile"));

        String conf = confNginx();
        r.put("conf", conf == null ? JSONObject.NULL : conf);
        if (conf == null)
            return r.put("ready", false)
                    .put("error", I18n.tr("server.autoconf.noNginx443"));

        String text = "";
        try { text = Files.readString(Path.of(conf)); } catch (Exception ignore) {}
        boolean coveredName = text.contains("autoconfig.") && text.contains("mta-sts.");
        boolean brokenPresent = hasBlock(text);
        r.put("coveredName", coveredName).put("brokenPresent", brokenPresent);
        r.put("serverName", firstLineWith(text, "server_name"));
        // Se la superficie pubblica sulla 443 e' installata, quei nomi sono suoi e questa
        // scheda non deve nemmeno offrire di toccare nginx: un pulsante che, premuto, si
        // rifiuta, e' un pulsante che non andava mostrato.
        r.put("surface443", WebProtection.state().optBoolean("installed", false));

        // Il certificato: se non copre autoconfig.<dominio>, Thunderbird sbatte su un errore
        // TLS prima ancora di leggere il file.
        JSONArray domains = new JSONArray();
        List<String> troubles = new ArrayList<>();
        int reviewed = 0, working = 0;
        boolean readList = false;
        try {
            var allItems = Main.mailDatabase.getDomains();
            readList = true;
            for (var d : allItems) {
                String name = "autoconfig." + d.domain;
                JSONObject j = new JSONObject().put("domain", d.domain).put("name", name);
                j.put("dns", resolves(name));
                j.put("certificate", certificateCovers(name));
                // La prova che conta: si CHIEDE il file come lo chiederebbe Thunderbird.
                // Leggere la configurazione di nginx dice cosa dovrebbe succedere; questa
                // dice cosa succede. Non sono la stessa cosa, e quando divergono e' sempre
                // la seconda ad avere ragione.
                JSONObject test = testDownload(name, d.domain);
                j.put("test", test);
                reviewed++;
                if (test.optBoolean("ok", false)) working++;
                else troubles.add(d.domain + " (" + test.optString("error", I18n.tr("server.autoconf.failed")) + ")");
                domains.put(j);
            }
        } catch (Exception e) {
            troubles.add(I18n.tr("server.autoconf.domainsUnreadable", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
        r.put("domains", domains).put("reviewed", reviewed).put("working", working);

        // Il verdetto viene dalla PROVA, non dal testo della configurazione.
        //
        // Prima era "nomeCoperto && rottaPresente", cioe' il risultato di una ricerca dentro
        // nginx.conf del marcatore che questa classe stessa scrive. Ma la rotta puo' stare
        // altrove — e sta altrove: la scheda della 443 la installa in
        // conf.d/mailpanel-public.conf, che serve esattamente questi due file, la politica
        // MTA-STS e questo XML. Risultato: il pannello scaricava il file davvero, lo otteneva,
        // e un attimo dopo dichiarava che nginx non lo serve e che i client devono
        // configurarsi a mano. Il commento qui sopra diceva gia' quale delle due misure ha
        // ragione; il verdetto usava l'altra.
        boolean ready = ready(readList, reviewed, working);
        r.put("ready", ready);
        r.put("why", ready
                ? I18n.tr("server.autoconf.arrivesAll", java.util.Map.of("n", String.valueOf(reviewed))) + " " + (brokenPresent
                        ? I18n.tr("server.autoconf.routeIn", java.util.Map.of("conf", String.valueOf(conf)))
                        : I18n.tr("server.autoconf.routeElsewhere", java.util.Map.of("conf", String.valueOf(conf))))
                : reviewed == 0
                  ? I18n.tr("server.autoconf.noneTried")
                  : I18n.tr("server.autoconf.notArriving", java.util.Map.of("n", String.valueOf(troubles.size()), "tot", String.valueOf(reviewed), "list", String.valueOf(String.join("; ", troubles)))));
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
     * Il verdict, staccato da state() perche' un test possa arrivarci.
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
    static boolean ready(boolean readList, int reviewed, int working) {
        return readList && reviewed > 0 && working == reviewed;
    }

    private static JSONObject testDownload(String name, String domain) {
        JSONObject r = new JSONObject();
        String url = "https://" + name + "/mail/config-v1.1.xml?emailaddress=test@" + domain;
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
            r.put("code", resp.statusCode());
            String body = resp.body() == null ? "" : resp.body();
            boolean right = resp.statusCode() == 200 && body.contains("<clientConfig")
                    && body.contains("<domain>" + domain + "</domain>");
            r.put("ok", right);
            if (!right) {
                if (resp.statusCode() != 200)
                    r.put("error", I18n.tr("server.autoconf.status", java.util.Map.of("c", String.valueOf(resp.statusCode()))));
                else if (!body.contains("<clientConfig"))
                    r.put("error", I18n.tr("server.autoconf.notConfigFile"));
                else
                    r.put("error", I18n.tr("server.autoconf.otherDomain", java.util.Map.of("d", String.valueOf(domain))));
            }
            return r;
        } catch (javax.net.ssl.SSLException e) {
            return r.put("ok", false).put("tls", true)
                    .put("error", I18n.tr("server.autoconf.certInvalid", java.util.Map.of("name", String.valueOf(name))));
        } catch (java.net.UnknownHostException e) {
            return r.put("ok", false)
                    .put("error", I18n.tr("server.autoconf.noCname", java.util.Map.of("name", String.valueOf(name))));
        } catch (Exception e) {
            return r.put("ok", false)
                    .put("error", I18n.tr("server.autoconf.unreachable", java.util.Map.of("err", String.valueOf(e.getClass().getSimpleName() + (e.getMessage() == null ? "" : " - " + e.getMessage())))));
        }
    }

    private static String firstLineWith(String text, String ago) {
        for (String r : text.split("\n")) if (r.contains(ago)) return r.trim();
        return "";
    }

    /** Il nome risolve in DNS (il CNAME autoconfig.* creato dalla pagina DNS). */
    private static boolean resolves(String name) {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", name);
            Shell.applyPath(pb);
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
    private static boolean certificateCovers(String name) {
        try {
            Path cert = Path.of("/usr/local/etc/ssl/mail/fullchain.pem");
            if (!Files.isReadable(cert)) return false;
            ProcessBuilder pb = new ProcessBuilder("openssl", "x509", "-in", cert.toString(),
                    "-noout", "-text");
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            for (String r : out.split("\n")) {
                if (!r.contains("DNS:")) continue;
                for (String piece : r.split(",")) {
                    String s = piece.trim();
                    if (s.startsWith("DNS:") && s.substring(4).trim().equalsIgnoreCase(name)) return true;
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
    public static JSONObject install() {
        JSONObject r = new JSONObject();
        try {
            JSONObject st = state();
            if (!st.optBoolean("success", false) || st.has("error"))
                return r.put("success", false).put("error", st.optString("error", I18n.tr("server.autoconf.stateUnreadable")));
            if (st.optBoolean("ready", false))
                return r.put("success", true).put("alreadyDone", true)
                        .put("note", I18n.tr("server.autoconf.alreadyAll") + " " + st.optString("why", ""));

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
            if (WebProtection.state().optBoolean("installed", false))
                return r.put("success", false).put("alreadyElsewhere", true)
                        .put("error", I18n.tr("server.autoconf.publicSurface", java.util.Map.of("file", WebProtection.FILE_NAME)) + " " + st.optString("why", ""));

            // Quali politiche MTA-STS rispondono PRIMA di toccare qualcosa. Senza questa
            // fotografia, dopo non c'e' modo di sapere se una l'ho rotta io.
            List<String> policiesBefore = answeringPolicies();
            r.put("policiesBefore", new JSONArray(policiesBefore));

            String conf = st.getString("conf");
            Path p = Path.of(conf);
            String text = Files.readString(p);
            r.put("conf", conf);

            Path copy = Path.of("/var/db/mailpanel/nginx-before-autoconfig.conf");
            Files.createDirectories(copy.getParent());
            Files.writeString(copy, text);
            r.put("copy", copy.toString());

            String fresh = text;

            // 1. i nomi: senza, nginx non risponde per autoconfig.<dominio>
            if (!fresh.contains("autoconfig.") || !fresh.contains("mta-sts.")) {
                int i = fresh.indexOf("server_name");
                if (i < 0) return r.put("success", false)
                        .put("error", I18n.tr("server.autoconf.noServerName"));
                int end = fresh.indexOf(';', i);
                if (end < 0) return r.put("success", false)
                        .put("error", I18n.tr("server.autoconf.serverNameNoSemicolon"));
                fresh = fresh.substring(0, end) + " autoconfig.* mta-sts.*" + fresh.substring(end);
            }

            // 2. la rotta: la richiesta va al pannello, che sa quali domini esistono e
            //    costruisce l'XML per quello giusto. Un file statico non potrebbe.
            if (!hasBlock(fresh)) {
                int i = fresh.indexOf("location /");
                if (i < 0) return r.put("success", false)
                        .put("error", I18n.tr("server.autoconf.noLocation"));
                // Due rotte, un marcatore solo: entrambe girano la richiesta al pannello, che
                // sa quali domini esistono e genera il contenuto per quello chiesto. Un file
                // statico non potrebbe, perche' il contenuto dipende dal dominio.
                String broken = MARKER + "\n"
                        + "    location = /mail/config-v1.1.xml {\n"
                        + "        proxy_pass https://127.0.0.1:2096/autoconfig/mail/config-v1.1.xml;\n"
                        + "        proxy_set_header Host $host;\n"
                        + "    }\n"
                        + "    location = /.well-known/mta-sts.txt {\n"
                        + "        proxy_pass https://127.0.0.1:2096/mta-sts/policy;\n"
                        + "        proxy_set_header Host $host;\n"
                        + "    }\n\n    ";
                fresh = fresh.substring(0, i) + broken + fresh.substring(i);
            }

            Files.writeString(p, fresh);

            // 3. la validazione. Qui si decide se andare avanti o tornare indietro.
            Outcome test = run("nginx", "-t");
            if (test.code != 0) {
                Files.writeString(p, text);
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.autoconf.nginxRejected", java.util.Map.of("out", String.valueOf(test.output.trim()))));
            }

            Outcome reloadOutcome = run("service", "nginx", "reload");
            if (reloadOutcome.code != 0) {
                Files.writeString(p, text);
                run("service", "nginx", "reload");
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.autoconf.reloadFailed", java.util.Map.of("out", String.valueOf(reloadOutcome.output.trim()))));
            }

            // Una verifica non puo' guardare solo cio' che volevo ottenere: va guardato anche
            // cio' che potevo aver rotto. Spostare dei nomi fra due server_name sposta le
            // richieste da un blocco all'altro, e il blocco che li perde e' quello che serve la
            // politica MTA-STS. Con i record TXT gia' pubblicati, farla sparire vuol dire
            // lasciare al mondo la dichiarazione di una protezione che non risponde piu'.
            List<String> policiesAfter = answeringPolicies();
            List<String> lost = new ArrayList<>(policiesBefore);
            lost.removeAll(policiesAfter);
            if (!lost.isEmpty()) {
                Files.writeString(p, text);
                run("service", "nginx", "reload");
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.autoconf.stsLost", java.util.Map.of("list", String.valueOf(String.join(", ", lost)))));
            }

            JSONObject after = state();
            r.put("stateAfter", after);
            if (!after.optBoolean("ready", false)) {
                Files.writeString(p, text);
                run("service", "nginx", "reload");
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.autoconf.stillNotArriving", java.util.Map.of("why", String.valueOf(after.optString("why", "")), "copy", String.valueOf(copy))));
            }

            return r.put("success", true)
                    .put("note", I18n.tr("server.autoconf.done", java.util.Map.of("copy", String.valueOf(copy))));
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
    private static List<String> answeringPolicies() {
        List<String> liveOnes = new ArrayList<>();
        try {
            for (var d : Main.mailDatabase.getDomains())
                if (MtaSts.publicTest(d.domain).optBoolean("ok", false)) liveOnes.add(d.domain);
        } catch (Exception ignore) {}
        return liveOnes;
    }

    private record Outcome(int code, String output) {}

    private static Outcome run(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return new Outcome(p.waitFor(), out);
        } catch (Exception e) {
            return new Outcome(-1, String.valueOf(e.getMessage()));
        }
    }

    /** L'anteprima del file, per guardarlo prima di installare qualsiasi cosa. */
    public static JSONObject preview() {
        JSONObject r = new JSONObject().put("success", true);
        String host = mailHost();
        if (host == null || host.isBlank())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.autoconf.noHostname"));
        List<String> names = new ArrayList<>();
        try { for (var d : Main.mailDatabase.getDomains()) names.add(d.domain); } catch (Exception ignore) {}
        if (names.isEmpty())
            return new JSONObject().put("success", false).put("error", I18n.tr("server.autoconf.noDomains"));
        return r.put("domain", names.get(0)).put("mailHost", host)
                .put("xml", xml(names.get(0), host)).put("domainCount", names.size());
    }
}
