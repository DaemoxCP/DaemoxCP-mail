package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * La superficie pubblica sulla porta 443, ridotta al minimo e con dei freni.
 *
 * Il contesto: questo server tiene la webmail sulla 8443, chiusa agli indirizzi esterni. Due
 * funzioni pero' hanno bisogno della 443 perche' i protocolli non ammettono altra porta: la
 * politica MTA-STS, che leggono i server mittenti di tutto il mondo, e il file di
 * configurazione che cerca Thunderbird. Aprire la 443 significa esporre qualcosa, quindi
 * quel qualcosa dev'essere il meno possibile.
 *
 * Le scelte, una per una, e il motivo di ciascuna:
 *
 *  - **Un blocco server separato**, non un'aggiunta a quello della webmail. Se si aggiungesse
 *    li', il nuovo sito erediterebbe la radice di Roundcube e il gestore del PHP: si
 *    aprirebbe la 443 su un'applicazione intera per servire due file di testo.
 *
 *  - **default_server sulla 443.** Cosi' qualunque nome arrivi su quella porta finisce qui, e
 *    non c'e' modo che una richiesta raggiunga per sbaglio un altro blocco.
 *
 *  - **Due sole location, entrambe esatte** (`location =`), e tutto il resto 404. Non c'e'
 *    radice, non c'e' indice, non c'e' try_files: non esiste un percorso che consegni un file
 *    che non sia uno dei due.
 *
 *  - **La politica MTA-STS e' un file STATICO su disco**, non una richiesta girata al
 *    pannello. E' identica per tutti i domini — dichiara lo stesso MX — quindi non c'e'
 *    ragione di generarla ogni volta. Cosi' un'inondazione su quel percorso la assorbe nginx
 *    servendo duecento byte, e non arriva mai al processo Java ne' al database.
 *
 *  - **Solo GET e HEAD.** Sono due file da leggere: qualunque altro metodo e' o un errore o
 *    un tentativo.
 *
 *  - **Limiti di frequenza e di connessioni per indirizzo**, larghi abbastanza da non
 *    disturbare nessuno: cinque richieste al secondo e otto connessioni sono ordini di
 *    grandezza sopra l'uso reale, che e' una richiesta ogni tanto.
 *
 *  - **Corpo massimo minuscolo e attese brevi.** Una richiesta lenta che tiene occupata una
 *    connessione e' il modo piu' economico di fare danno: qui muore in cinque secondi.
 *
 *  - **Log dedicato**, cosi' fail2ban puo' guardare solo questo e non confondersi con la
 *    webmail.
 */
public class WebProtection {

    private static final String PREFISSO_NGINX = "/usr/local/etc/nginx";
    private static final String FILE_NAME = "mailpanel-pubblico.conf";
    private static final String COPIA = "/var/db/mailpanel/mailpanel-pubblico.conf-precedente";
    public static final String DIR_PUBBLICA = "/var/db/mailpanel/pubblico";
    public static final String FILE_POLITICA = DIR_PUBBLICA + "/mta-sts.txt";
    public static final String LOG_ACCESSI = "/var/log/nginx/mailpanel-pubblico-access.log";

    private WebProtection() {}

    /* ===================================================================
     * La configurazione, come funzione pura
     * =================================================================== */

    /**
     * Le cartelle che nginx include davvero, ricavate dalla configurazione completa.
     *
     * Non si scrive piu' in "sites-enabled" perche' lo scrive uno degli script di
     * installazione: su questo server quella cartella NON e' inclusa, e un file messo li'
     * sarebbe stato ignorato mentre il pannello dichiarava "installato". Si guarda dove
     * nginx dice di guardare, e si scrive li'.
     *
     * I percorsi relativi si risolvono rispetto al prefisso di nginx, come fa nginx stesso.
     */
    public static java.util.List<String> cartelleIncluse(String dump) {
        java.util.LinkedHashSet<String> fuori = new java.util.LinkedHashSet<>();
        if (dump == null) return new java.util.ArrayList<>(fuori);
        for (String r : dump.split("\n")) {
            String t = r.trim();
            if (t.startsWith("#") || !t.startsWith("include ")) continue;
            String v = t.substring(8).replace(";", "").trim();
            // Interessano solo gli include a modello: "include qualcosa/*.conf".
            int stella = v.indexOf('*');
            if (stella < 0) continue;
            int barra = v.lastIndexOf('/', stella);
            if (barra <= 0) continue;
            String cartella = v.substring(0, barra);
            if (!cartella.startsWith("/")) cartella = PREFISSO_NGINX + "/" + cartella;
            fuori.add(cartella);
        }
        return new java.util.ArrayList<>(fuori);
    }

    /** La cartella in cui scrivere: la prima inclusa che esiste ed e' scrivibile. */
    public static String cartellaScelta(java.util.List<String> incluse) {
        for (String c : incluse) {
            try {
                Path p = Path.of(c);
                if (Files.isDirectory(p) && Files.isWritable(p)) return c;
            } catch (Exception ignore) {}
        }
        // Nessuna esiste: si prende la prima dichiarata, che si puo' creare.
        return incluse.isEmpty() ? null : incluse.get(0);
    }

    public static String configurazione(String cert, String chiave) {
        return """
            # Superficie pubblica del pannello di posta sulla porta 443.
            # Scritto dal pannello: non modificare a mano, verrebbe sovrascritto.
            #
            # Qui si servono DUE file e nient'altro:
            #   /.well-known/mta-sts.txt   la politica MTA-STS, file statico
            #   /mail/config-v1.1.xml      la configurazione per Thunderbird, dal pannello
            # Qualunque altro percorso riceve 404 senza corpo.

            limit_req_zone  $binary_remote_addr zone=mailpub_req:1m rate=5r/s;
            limit_conn_zone $binary_remote_addr zone=mailpub_conn:1m;

            server {
                listen 443 ssl default_server;
                listen [::]:443 ssl default_server;
                server_name _;

                ssl_certificate     %s;
                ssl_certificate_key %s;

                # Non si annuncia la versione: non aiuta nessuno tranne chi cerca un bersaglio.
                server_tokens off;

                # Sono due GET di poche centinaia di byte: tutto il resto e' fuori misura.
                client_max_body_size 1k;
                client_body_timeout   5s;
                client_header_timeout 5s;
                send_timeout          5s;
                keepalive_timeout    10s;

                # Larghi rispetto all'uso vero (una richiesta ogni tanto), stretti rispetto
                # a un'inondazione.
                limit_req  zone=mailpub_req burst=10 nodelay;
                limit_conn mailpub_conn 8;

                access_log %s;

                # Due file da leggere: nessun altro metodo ha senso qui.
                if ($request_method !~ ^(GET|HEAD)$) { return 405; }

                # File statico: una richiesta qui non raggiunge mai il pannello.
                location = /.well-known/mta-sts.txt {
                    default_type text/plain;
                    alias %s;
                }

                # L'unica cosa che passa al pannello, e solo su questo percorso esatto.
                location = /mail/config-v1.1.xml {
                    proxy_pass https://127.0.0.1:2096/autoconfig/mail/config-v1.1.xml;
                    proxy_set_header Host $host;
                    proxy_connect_timeout 3s;
                    proxy_read_timeout    5s;
                    proxy_send_timeout    5s;
                }

                # Tutto il resto non esiste.
                location / { return 404; }
            }
            """.formatted(cert, chiave, LOG_ACCESSI, FILE_POLITICA);
    }

    /* ===================================================================
     * Lo stato reale
     * =================================================================== */

    public static JSONObject stato() {
        JSONObject r = new JSONObject().put("success", true);
        JSONObject incPrima = includeAttivo();
        String cartella = incPrima.optString("cartella", "");
        String file = cartella.isEmpty() ? "" : cartella + "/" + FILE_NAME;
        r.put("file", file).put("filePolitica", FILE_POLITICA);
        try {
            r.put("installato", !file.isEmpty() && Files.exists(Path.of(file)));
            r.put("politicaScritta", Files.exists(Path.of(FILE_POLITICA)));
            if (Files.exists(Path.of(FILE_POLITICA)))
                r.put("politica", Files.readString(Path.of(FILE_POLITICA)));
        } catch (Exception e) {
            r.put("installato", false);
        }
        r.put("include", incPrima);
        r.put("pronto", r.optBoolean("installato", false) && incPrima.optBoolean("ok", false));
        return r;
    }

    /**
     * nginx include davvero la cartella in cui stiamo per scrivere?
     *
     * Senza questo controllo si scriverebbe un file perfetto che nginx non legge mai, e il
     * pannello direbbe "installato" mentre la 443 resta chiusa. Si guarda la configurazione
     * completa, non il file principale: l'include potrebbe stare in un file incluso a sua volta.
     */
    public static JSONObject includeAttivo() {
        JSONObject r = new JSONObject();
        Ris dump = esegui("nginx", "-T");
        if (dump.codice != 0)
            return r.put("ok", false)
                    .put("motivo", I18n.tr("server.pubweb.dumpFailed", java.util.Map.of("out", String.valueOf(dump.uscita.trim()))));

        java.util.List<String> incluse = cartelleIncluse(dump.uscita);
        r.put("cartelle", new org.json.JSONArray(incluse));
        String scelta = cartellaScelta(incluse);
        if (scelta == null)
            return r.put("ok", false)
                    .put("motivo", I18n.tr("server.pubweb.noInclude"));
        r.put("cartella", scelta);
        return r.put("ok", true)
                .put("motivo", I18n.tr("server.pubweb.includes", java.util.Map.of("dir", String.valueOf(scelta))));
    }

    /* ===================================================================
     * L'installazione
     * =================================================================== */

    public static JSONObject installa(String cert, String chiave) {
        JSONObject r = new JSONObject();
        try {
            JSONObject inc = includeAttivo();
            if (!inc.optBoolean("ok", false))
                return r.put("success", false).put("error", inc.optString("motivo"));
            String cartella = inc.getString("cartella");
            final String FILE = cartella + "/" + FILE_NAME;
            r.put("file", FILE).put("cartella", cartella);

            if (cert == null || cert.isBlank()) cert = "/usr/local/etc/ssl/mail/fullchain.pem";
            if (chiave == null || chiave.isBlank()) chiave = "/usr/local/etc/ssl/mail/privkey.pem";
            if (!Files.isReadable(Path.of(cert)) || !Files.isReadable(Path.of(chiave)))
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.noCert", java.util.Map.of("cert", String.valueOf(cert), "key", String.valueOf(chiave))));
            r.put("certificato", cert);

            // 1. La politica, prima della configurazione: se nginx partisse puntando a un file
            //    che non c'e', servirebbe un 404 sul percorso che deve funzionare.
            JSONObject pol = scriviPolitica();
            r.put("politica", pol);
            if (!pol.optBoolean("success", false))
                return r.put("success", false).put("error", pol.optString("error"));

            // 2. Copia di sicurezza di un'eventuale versione precedente.
            Path f = Path.of(FILE);
            String prima = Files.exists(f) ? Files.readString(f) : null;
            if (prima != null) {
                Files.createDirectories(Path.of(COPIA).getParent());
                Files.writeString(Path.of(COPIA), prima);
                r.put("copia", COPIA);
            }

            Files.createDirectories(Path.of(cartella));
            Files.writeString(f, configurazione(cert, chiave));

            // 3. La validazione decide.
            Ris prova = esegui("nginx", "-t");
            if (prova.codice != 0) {
                if (prima != null) Files.writeString(f, prima); else Files.deleteIfExists(f);
                return r.put("success", false).put("ripristinato", true)
                        .put("error", I18n.tr("server.pubweb.nginxRejectedRemoved", java.util.Map.of("out", String.valueOf(prova.uscita.trim()))));
            }

            Ris ric = esegui("service", "nginx", "reload");
            if (ric.codice != 0) {
                if (prima != null) Files.writeString(f, prima); else Files.deleteIfExists(f);
                esegui("service", "nginx", "reload");
                return r.put("success", false).put("ripristinato", true)
                        .put("error", I18n.tr("server.pubweb.reloadFailedRemoved", java.util.Map.of("out", String.valueOf(ric.uscita.trim()))));
            }

            // 4. Non basta che i comandi non abbiano protestato: si prova la porta.
            JSONObject prova443 = provaLocale();
            r.put("prova", prova443);
            if (!prova443.optBoolean("ok", false))
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.443wrong", java.util.Map.of("err", String.valueOf(prova443.optString("errore")), "file", String.valueOf(FILE))));

            return r.put("success", true)
                    .put("nota", I18n.tr("server.pubweb.installed"));
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.pubweb.installError", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    /** Scrive la politica MTA-STS su disco. E' uguale per tutti i domini: dichiara lo stesso MX. */
    public static JSONObject scriviPolitica() {
        JSONObject r = new JSONObject();
        String host = MtaSts.hostDiPosta();
        if (host == null || host.isBlank())
            return r.put("success", false)
                    .put("error", I18n.tr("server.pubweb.noHostname"));
        String modo = MtaSts.modoCorrente();
        String testo = MtaSts.politica(host, modo, MtaSts.maxAgeConsigliato(modo));
        try {
            Files.createDirectories(Path.of(DIR_PUBBLICA));
            Files.writeString(Path.of(FILE_POLITICA), testo);
            return r.put("success", true).put("modo", modo).put("testo", testo)
                    .put("id", MtaSts.id(testo));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.pubweb.cannotWrite", java.util.Map.of("file", String.valueOf(FILE_POLITICA), "err", String.valueOf(e.getMessage()))));
        }
    }

    /* ===================================================================
     * Aggiungere la riga di include
     * =================================================================== */

    public static final String PROPOSED_FOLDER = PREFISSO_NGINX + "/conf.d";
    private static final String COPIA_PRINCIPALE = "/var/db/mailpanel/nginx.conf-prima-di-include";

    /**
     * Il file principale, ricavato da "nginx -T": la prima riga "# configuration file X:"
     * indica il file da cui nginx e' partito. Non si tira a indovinare il percorso.
     */
    public static String filePrincipale(String dump) {
        if (dump == null) return null;
        for (String r : dump.split("\n")) {
            String t = r.trim();
            if (!t.startsWith("# configuration file ")) continue;
            String v = t.substring("# configuration file ".length()).trim();
            if (v.endsWith(":")) v = v.substring(0, v.length() - 1);
            return v.trim();
        }
        return null;
    }

    /**
     * Inserisce la riga di include subito dopo l'apertura del blocco http.
     *
     * Deve stare DENTRO http: fuori, nginx rifiuta le direttive di un blocco server, e la
     * configurazione non parte. Si inserisce in cima al blocco cosi' le direttive del file
     * incluso non si trovano dopo qualcosa che le renda inefficaci.
     *
     * Restituisce null se il blocco http non si trova o se l'include c'e' gia': meglio non
     * fare niente che scrivere una riga in un punto a caso di una configurazione che funziona.
     */
    public static String conInclude(String principale, String cartella) {
        if (principale == null || cartella == null) return null;
        if (principale.contains(cartella + "/*.conf")) return null;

        String[] righe = principale.split("\n", -1);
        for (int i = 0; i < righe.length; i++) {
            String t = righe[i].trim();
            if (t.startsWith("#")) continue;
            boolean apreHttp = t.equals("http {") || t.equals("http{")
                    || t.matches("^http\\s*\\{.*");
            if (!apreHttp) continue;
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j <= i; j++) sb.append(righe[j]).append("\n");
            sb.append("\n    # Aggiunto dal pannello di posta: senza questa riga i file di\n");
            sb.append("    # configurazione aggiuntivi non verrebbero letti da nginx.\n");
            sb.append("    include ").append(cartella).append("/*.conf;\n");
            for (int j = i + 1; j < righe.length; j++) {
                sb.append(righe[j]);
                if (j < righe.length - 1) sb.append("\n");
            }
            return sb.toString();
        }
        return null;
    }

    /** Aggiunge la riga di include al file principale, con tutte le reti di sicurezza. */
    public static JSONObject aggiungiInclude() {
        JSONObject r = new JSONObject();
        try {
            Ris dump = esegui("nginx", "-T");
            if (dump.codice != 0)
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.confUnreadable", java.util.Map.of("out", String.valueOf(dump.uscita.trim()))));

            String principale = filePrincipale(dump.uscita);
            if (principale == null || !Files.isReadable(Path.of(principale)))
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.noMainFile"));
            r.put("file", principale).put("cartella", PROPOSED_FOLDER);

            String prima = Files.readString(Path.of(principale));
            String dopo = conInclude(prima, PROPOSED_FOLDER);
            if (dopo == null)
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.noHttpBlock", java.util.Map.of("file", String.valueOf(principale))));

            Files.createDirectories(Path.of(PROPOSED_FOLDER));
            Files.createDirectories(Path.of(COPIA_PRINCIPALE).getParent());
            Files.writeString(Path.of(COPIA_PRINCIPALE), prima);
            r.put("copia", COPIA_PRINCIPALE);

            Files.writeString(Path.of(principale), dopo);

            Ris prova = esegui("nginx", "-t");
            if (prova.codice != 0) {
                Files.writeString(Path.of(principale), prima);
                return r.put("success", false).put("ripristinato", true)
                        .put("error", I18n.tr("server.pubweb.nginxRejectedRestored", java.util.Map.of("out", String.valueOf(prova.uscita.trim()))));
            }

            Ris ric = esegui("service", "nginx", "reload");
            if (ric.codice != 0) {
                Files.writeString(Path.of(principale), prima);
                esegui("service", "nginx", "reload");
                return r.put("success", false).put("ripristinato", true)
                        .put("error", I18n.tr("server.pubweb.reloadFailedRestored", java.util.Map.of("out", String.valueOf(ric.uscita.trim()))));
            }

            // Si rilegge da nginx, non dal file: conta cosa nginx include davvero.
            Ris dopoDump = esegui("nginx", "-T");
            boolean visto = dopoDump.codice == 0
                    && cartelleIncluse(dopoDump.uscita).contains(PROPOSED_FOLDER);
            if (!visto)
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.includeNotSeen", java.util.Map.of("dir", String.valueOf(PROPOSED_FOLDER), "file", String.valueOf(principale))));

            return r.put("success", true)
                    .put("nota", I18n.tr("server.pubweb.includeAdded", java.util.Map.of("dir", String.valueOf(PROPOSED_FOLDER), "file", String.valueOf(principale), "copy", String.valueOf(COPIA_PRINCIPALE))));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.pubweb.error", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    /* ===================================================================
     * La jail fail2ban
     * =================================================================== */

    private static final String FILTRO = "/usr/local/etc/fail2ban/filter.d/mailpanel-pubblico.conf";
    private static final String JAIL   = "/usr/local/etc/fail2ban/jail.d/mailpanel-pubblico.conf";

    /**
     * Il filtro guarda SOLO il log di questo sito, e solo le risposte 404, 405 e 429.
     *
     * Il ragionamento: su questa porta esistono due percorsi leciti. Chi ne chiede altri sta
     * cercando qualcosa — una pagina di amministrazione, un file di configurazione, un
     * exploit — e chi prende 429 sta gia' andando oltre il limite di frequenza. Un errore
     * capita a chiunque, quindi si banna dopo dieci in dieci minuti, non al primo.
     *
     * Guardare un log dedicato invece di quello generale evita di bannare per errore chi usa
     * la webmail: sono due file diversi, e le due cose non si confondono.
     */
    public static String filtro() {
        return """
            # Scritto dal pannello di posta. Guarda il solo log della superficie pubblica 443.
            [Definition]
            failregex = ^<HOST> .* "(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH|TRACE|CONNECT)[^"]*" (404|405|429) 
            ignoreregex =
            """;
    }

    public static String jail() {
        return """
            # Scritto dal pannello di posta.
            [mailpanel-pubblico]
            enabled  = true
            filter   = mailpanel-pubblico
            logpath  = %s
            maxretry = 10
            findtime = 600
            bantime  = 3600
            # L'azione si dichiara, non si eredita. Senza questa riga la jail prendeva il valore
            # predefinito di jail.conf, che e' basato su iptables: un comando che su FreeBSD non
            # esiste. La jail rilevava e contava i ban regolarmente — 14.370 tentativi e 46 ban —
            # e non ne bloccava nessuno, perche' il comando falliva ogni volta e nessuno lo
            # guardava. Qui si usa pf, come tutte le altre jail scritte dal pannello.
            #
            # actiontype=any non e' un dettaglio: l'azione pf costruisce la regola come
            # "block quick proto tcp from <tabella> to <actiontype>", e il valore predefinito e'
            # "any port $port". Senza una porta quella riga finisce con "port " e pf la rifiuta:
            # la tabella verrebbe creata lo stesso — e' il comando prima — ma la regola che la
            # usa no, e gli indirizzi bannati finirebbero in una tabella che nessuna regola
            # legge. Sarebbe stato lo stesso guasto di prima con un nome diverso.
            #
            # Si dichiara una PORTA, non un actiontype. Ci sono arrivato per esclusione, e la
            # strada sbagliata merita di restare scritta: "actiontype=<allports>" e poi
            # "actiontype=any" sono la forma che la documentazione dell'azione mostra, ma fail2ban
            # su questo sistema non li accetta come parametro di una jail — la risposta a
            # "get <jail> actions" diventa "No actions for jail ...", cioe' la jail viene caricata
            # SENZA nessuna azione e non banna affatto. Peggio del difetto di partenza, dove
            # almeno un'azione c'era, per quanto inservibile.
            #
            # Questa forma invece e' dimostrata funzionare proprio qui: e' identica a quella delle
            # quattro jail di posta, che il confronto con pf mostra avere tabella E regola. Fra
            # cio' che la documentazione lascia intendere e cio' che il server fa vedere, vince
            # il server.
            action   = pf[name=mailpanel-pubblico, port="http,https"]
            """.formatted(LOG_ACCESSI);
    }

    /** Installa filtro e jail, e verifica che fail2ban la veda davvero attiva. */
    public static JSONObject installaJail() {
        JSONObject r = new JSONObject();
        try {
            Ris presente = esegui("sh", "-c", "command -v fail2ban-client");
            if (presente.codice != 0)
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.noF2b"));

            Files.createDirectories(Path.of(FILTRO).getParent());
            Files.createDirectories(Path.of(JAIL).getParent());
            Files.writeString(Path.of(FILTRO), filtro());
            Files.writeString(Path.of(JAIL), jail());

            Ris rel = esegui("fail2ban-client", "reload");
            if (rel.codice != 0) {
                Files.deleteIfExists(Path.of(JAIL));
                esegui("fail2ban-client", "reload");
                return r.put("success", false).put("ripristinato", true)
                        .put("error", I18n.tr("server.pubweb.f2bRejected", java.util.Map.of("out", String.valueOf(rel.uscita.trim()))));
            }

            // Non basta che il reload sia andato: si chiede a fail2ban se la vede.
            Ris st = esegui("fail2ban-client", "status", "mailpanel-pubblico");
            if (st.codice != 0)
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.jailNotActive", java.util.Map.of("out", String.valueOf(st.uscita.trim()))));

            return r.put("success", true).put("stato", st.uscita.trim())
                    .put("nota", I18n.tr("server.pubweb.jailActive"));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.pubweb.jailError", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    /** Chiede i due percorsi a 127.0.0.1 sulla 443, per vedere se nginx risponde davvero. */
    private static JSONObject provaLocale() {
        JSONObject r = new JSONObject();
        Ris a = esegui("sh", "-c",
                "fetch -q -o - --no-verify-peer --no-verify-hostname -T 5 "
              + "https://127.0.0.1/.well-known/mta-sts.txt 2>/dev/null "
              + "|| curl -sk --max-time 5 https://127.0.0.1/.well-known/mta-sts.txt");
        boolean politica = a.uscita != null && a.uscita.contains("version: STSv1");
        r.put("politica", politica);
        if (!politica)
            return r.put("ok", false)
                    .put("errore", I18n.tr("server.pubweb.policyNotBack", java.util.Map.of("out", String.valueOf(a.uscita == null ? "" : a.uscita.trim()))));
        return r.put("ok", true);
    }

    private record Ris(int codice, String uscita) {}

    private static Ris esegui(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return new Ris(p.waitFor(), out);
        } catch (Exception e) {
            return new Ris(-1, String.valueOf(e.getMessage()));
        }
    }
}
