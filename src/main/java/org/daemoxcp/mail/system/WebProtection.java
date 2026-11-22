package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

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

    /**
     * Il nome della superficie pubblica sul sistema: il file di nginx, il suo log, il filtro e
     * la jail di fail2ban, e quindi l'ancora e la tabella di pf (f2b/NAME, f2b-NAME). Viaggia
     * fra tre servizi: nginx scrive il log che fail2ban legge. Fino al 30/10/2026 era
     * "mailpanel-pubblico": i server installati prima li sposta PublicSurfaceRename all'avvio.
     */
    public static final String NAME = Product.SLUG + "-public";

    private static final String NGINX_PREFIX = "/usr/local/etc/nginx";
    static final String FILE_NAME = NAME + ".conf";
    private static final String COPY = "/var/db/daemoxcp-mail/" + NAME + ".conf-previous";
    public static final String PUBLIC_DIR = "/var/db/daemoxcp-mail/public";
    public static final String POLICY_FILE = PUBLIC_DIR + "/mta-sts.txt";
    static final String LOG_DIR = "/var/log/nginx";
    public static final String ACCESS_LOG = LOG_DIR + "/" + NAME + "-access.log";

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
    public static java.util.List<String> includedFolders(String dump) {
        java.util.LinkedHashSet<String> outside = new java.util.LinkedHashSet<>();
        if (dump == null) return new java.util.ArrayList<>(outside);
        for (String r : dump.split("\n")) {
            String t = r.trim();
            if (t.startsWith("#") || !t.startsWith("include ")) continue;
            String v = t.substring(8).replace(";", "").trim();
            // Interessano solo gli include a modello: "include qualcosa/*.conf".
            int star = v.indexOf('*');
            if (star < 0) continue;
            int slash = v.lastIndexOf('/', star);
            if (slash <= 0) continue;
            String folder = v.substring(0, slash);
            if (!folder.startsWith("/")) folder = NGINX_PREFIX + "/" + folder;
            outside.add(folder);
        }
        return new java.util.ArrayList<>(outside);
    }

    /** La cartella in cui scrivere: la prima inclusa che esiste ed e' scrivibile. */
    public static String chosenFolder(java.util.List<String> included) {
        for (String c : included) {
            try {
                Path p = Path.of(c);
                if (Files.isDirectory(p) && Files.isWritable(p)) return c;
            } catch (Exception ignore) {}
        }
        // Nessuna esiste: si prende la prima dichiarata, che si puo' creare.
        return included.isEmpty() ? null : included.get(0);
    }

    public static String configuration(String cert, String key) {
        String text = """
            # DaemoxCP Mail's public surface on port 443.
            # Written by DaemoxCP Mail: do not edit by hand, it would be overwritten.
            #
            # TWO files are served here and nothing else:
            #   /.well-known/mta-sts.txt   the MTA-STS policy, a static file
            #   /mail/config-v1.1.xml      the configuration for Thunderbird, from the panel
            # Any other path gets 404 without a body.

            limit_req_zone  $binary_remote_addr zone=mailpub_req:1m rate=5r/s;
            limit_conn_zone $binary_remote_addr zone=mailpub_conn:1m;

            server {
                listen 443 ssl default_server;
                listen [::]:443 ssl default_server;
                server_name _;

                ssl_certificate     %s;
                ssl_certificate_key %s;

                # The version is not announced: it helps nobody but whoever looks for a target.
                server_tokens off;

                # These are two GETs of a few hundred bytes: anything else is out of proportion.
                client_max_body_size 1k;
                client_body_timeout   5s;
                client_header_timeout 5s;
                send_timeout          5s;
                keepalive_timeout    10s;

                # Wide compared with real use (a request now and then), narrow compared
                # with a flood.
                limit_req  zone=mailpub_req burst=10 nodelay;
                limit_conn mailpub_conn 8;

                access_log %s;

                # Two files to read: no other method makes sense here.
                if ($request_method !~ ^(GET|HEAD)$) { return 405; }

                # Static file: a request here never reaches the panel.
                location = /.well-known/mta-sts.txt {
                    default_type text/plain;
                    alias %s;
                }

                # The only thing passed to the panel, and only on this exact path.
                location = /mail/config-v1.1.xml {
                    proxy_pass https://127.0.0.1:2096/autoconfig/mail/config-v1.1.xml;
                    proxy_set_header Host $host;
                    proxy_connect_timeout 3s;
                    proxy_read_timeout    5s;
                    proxy_send_timeout    5s;
                }

                # Everything else does not exist.
                location / { return 404; }
            }
            """.formatted(cert, key, ACCESS_LOG, POLICY_FILE);
        // Le righe listen della famiglia scelta nelle Impostazioni (IpFamily); senza scelta, IPv4 e IPv6 come sempre.
        return IpFamily.withNginxListen(text, 443, IpFamily.chosen());
    }

    /* ===================================================================
     * Lo stato reale
     * =================================================================== */

    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);
        JSONObject incBefore = activeInclude();
        String folder = incBefore.optString("folder", "");
        String file = folder.isEmpty() ? "" : folder + "/" + FILE_NAME;
        r.put("file", file).put("policyFile", POLICY_FILE);
        try {
            r.put("installed", !file.isEmpty() && Files.exists(Path.of(file)));
            r.put("policyWritten", Files.exists(Path.of(POLICY_FILE)));
            if (Files.exists(Path.of(POLICY_FILE)))
                r.put("policy", Files.readString(Path.of(POLICY_FILE)));
        } catch (Exception e) {
            r.put("installed", false);
        }
        r.put("include", incBefore);
        r.put("ready", r.optBoolean("installed", false) && incBefore.optBoolean("ok", false));
        return r;
    }

    /**
     * nginx include davvero la cartella in cui stiamo per scrivere?
     *
     * Senza questo controllo si scriverebbe un file perfetto che nginx non legge mai, e il
     * pannello direbbe "installato" mentre la 443 resta chiusa. Si guarda la configurazione
     * completa, non il file principale: l'include potrebbe stare in un file incluso a sua volta.
     */
    public static JSONObject activeInclude() {
        JSONObject r = new JSONObject();
        RunResult dump = run("nginx", "-T");
        if (dump.code != 0)
            return r.put("ok", false)
                    .put("reason", I18n.tr("server.pubweb.dumpFailed", java.util.Map.of("out", String.valueOf(dump.output.trim()))));

        java.util.List<String> included = includedFolders(dump.output);
        r.put("folders", new org.json.JSONArray(included));
        String choice = chosenFolder(included);
        if (choice == null)
            return r.put("ok", false)
                    .put("reason", I18n.tr("server.pubweb.noInclude"));
        r.put("folder", choice);
        return r.put("ok", true)
                .put("reason", I18n.tr("server.pubweb.includes", java.util.Map.of("dir", String.valueOf(choice))));
    }

    /* ===================================================================
     * L'installazione
     * =================================================================== */

    public static JSONObject install(String cert, String key) {
        JSONObject r = new JSONObject();
        try {
            JSONObject inclusion = activeInclude();
            if (!inclusion.optBoolean("ok", false))
                return r.put("success", false).put("error", inclusion.optString("reason"));
            String folder = inclusion.getString("folder");
            final String FILE = folder + "/" + FILE_NAME;
            r.put("file", FILE).put("folder", folder);

            if (cert == null || cert.isBlank()) cert = "/usr/local/etc/ssl/mail/fullchain.pem";
            if (key == null || key.isBlank()) key = "/usr/local/etc/ssl/mail/privkey.pem";
            if (!Files.isReadable(Path.of(cert)) || !Files.isReadable(Path.of(key)))
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.noCert", java.util.Map.of("cert", String.valueOf(cert), "key", String.valueOf(key))));
            r.put("certificate", cert);

            // 1. La politica, prima della configurazione: se nginx partisse puntando a un file
            //    che non c'e', servirebbe un 404 sul percorso che deve funzionare.
            JSONObject pol = writePolicy();
            r.put("policy", pol);
            if (!pol.optBoolean("success", false))
                return r.put("success", false).put("error", pol.optString("error"));

            // 2. Copia di sicurezza di un'eventuale versione precedente.
            Path f = Path.of(FILE);
            String before = Files.exists(f) ? Files.readString(f) : null;
            if (before != null) {
                Files.createDirectories(Path.of(COPY).getParent());
                Files.writeString(Path.of(COPY), before);
                r.put("copy", COPY);
            }

            Files.createDirectories(Path.of(folder));
            Files.writeString(f, configuration(cert, key));

            // 3. La validazione decide.
            RunResult test = run("nginx", "-t");
            if (test.code != 0) {
                if (before != null) Files.writeString(f, before); else Files.deleteIfExists(f);
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.pubweb.nginxRejectedRemoved", java.util.Map.of("out", String.valueOf(test.output.trim()))));
            }

            RunResult reloadOutcome = run("service", "nginx", "reload");
            if (reloadOutcome.code != 0) {
                if (before != null) Files.writeString(f, before); else Files.deleteIfExists(f);
                run("service", "nginx", "reload");
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.pubweb.reloadFailedRemoved", java.util.Map.of("out", String.valueOf(reloadOutcome.output.trim()))));
            }

            // 4. Non basta che i comandi non abbiano protestato: si prova la porta.
            JSONObject test443 = localTest();
            r.put("test", test443);
            if (!test443.optBoolean("ok", false))
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.443wrong", java.util.Map.of("err", String.valueOf(test443.optString("error")), "file", String.valueOf(FILE))));

            return r.put("success", true)
                    .put("note", I18n.tr("server.pubweb.installed"));
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.pubweb.installError", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("WebProtection", e))));
        }
    }

    /** Scrive la politica MTA-STS su disco. E' uguale per tutti i domini: dichiara lo stesso MX. */
    public static JSONObject writePolicy() {
        JSONObject r = new JSONObject();
        String host = MtaSts.mailHost();
        if (host == null || host.isBlank())
            return r.put("success", false)
                    .put("error", I18n.tr("server.pubweb.noHostname"));
        String mode = MtaSts.currentMode();
        String text = MtaSts.policy(host, mode, MtaSts.recommendedMaxAge(mode));
        try {
            // Coi permessi scritti, non con l'umask del servizio: nginx (www) deve poterla leggere (reperto 250)
            PublicPolicyAccess.write(Path.of(PUBLIC_DIR), Path.of(POLICY_FILE), text);
            return r.put("success", true).put("mode", mode).put("text", text)
                    .put("id", MtaSts.id(text));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.pubweb.cannotWrite", java.util.Map.of("file", String.valueOf(POLICY_FILE), "err", org.daemoxcp.mail.util.ErrorText.detail("WebProtection", e))));
        }
    }

    /* ===================================================================
     * Aggiungere la riga di include
     * =================================================================== */

    public static final String PROPOSED_FOLDER = NGINX_PREFIX + "/conf.d";
    private static final String MAIN_COPY = "/var/db/daemoxcp-mail/nginx.conf-before-include";

    /**
     * Il file principale, ricavato da "nginx -T": la prima riga "# configuration file X:"
     * indica il file da cui nginx e' partito. Non si tira a indovinare il percorso.
     */
    public static String mainFile(String dump) {
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
    public static String withInclude(String main, String folder) {
        if (main == null || folder == null) return null;
        if (main.contains(folder + "/*.conf")) return null;

        String[] lines = main.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String t = lines[i].trim();
            if (t.startsWith("#")) continue;
            boolean opensHttp = t.equals("http {") || t.equals("http{")
                    || t.matches("^http\\s*\\{.*");
            if (!opensHttp) continue;
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j <= i; j++) sb.append(lines[j]).append("\n");
            sb.append("\n    # Added by " + Product.NAME + ": without this line the additional\n");
            sb.append("    # configuration files would not be read by nginx.\n");
            sb.append("    include ").append(folder).append("/*.conf;\n");
            for (int j = i + 1; j < lines.length; j++) {
                sb.append(lines[j]);
                if (j < lines.length - 1) sb.append("\n");
            }
            return sb.toString();
        }
        return null;
    }

    /** Aggiunge la riga di include al file principale, con tutte le reti di sicurezza. */
    public static JSONObject addInclude() {
        JSONObject r = new JSONObject();
        try {
            RunResult dump = run("nginx", "-T");
            if (dump.code != 0)
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.confUnreadable", java.util.Map.of("out", String.valueOf(dump.output.trim()))));

            String main = mainFile(dump.output);
            if (main == null || !Files.isReadable(Path.of(main)))
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.noMainFile"));
            r.put("file", main).put("folder", PROPOSED_FOLDER);

            String before = Files.readString(Path.of(main));
            String after = withInclude(before, PROPOSED_FOLDER);
            if (after == null)
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.noHttpBlock", java.util.Map.of("file", String.valueOf(main))));

            Files.createDirectories(Path.of(PROPOSED_FOLDER));
            Files.createDirectories(Path.of(MAIN_COPY).getParent());
            Files.writeString(Path.of(MAIN_COPY), before);
            r.put("copy", MAIN_COPY);

            Files.writeString(Path.of(main), after);

            RunResult test = run("nginx", "-t");
            if (test.code != 0) {
                Files.writeString(Path.of(main), before);
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.pubweb.nginxRejectedRestored", java.util.Map.of("out", String.valueOf(test.output.trim()))));
            }

            RunResult reloadOutcome = run("service", "nginx", "reload");
            if (reloadOutcome.code != 0) {
                Files.writeString(Path.of(main), before);
                run("service", "nginx", "reload");
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.pubweb.reloadFailedRestored", java.util.Map.of("out", String.valueOf(reloadOutcome.output.trim()))));
            }

            // Si rilegge da nginx, non dal file: conta cosa nginx include davvero.
            RunResult afterDump = run("nginx", "-T");
            boolean seen = afterDump.code == 0
                    && includedFolders(afterDump.output).contains(PROPOSED_FOLDER);
            if (!seen)
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.includeNotSeen", java.util.Map.of("dir", String.valueOf(PROPOSED_FOLDER), "file", String.valueOf(main))));

            return r.put("success", true)
                    .put("note", I18n.tr("server.pubweb.includeAdded", java.util.Map.of("dir", String.valueOf(PROPOSED_FOLDER), "file", String.valueOf(main), "copy", String.valueOf(MAIN_COPY))));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.pubweb.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("WebProtection", e))));
        }
    }

    /* ===================================================================
     * La jail fail2ban
     * =================================================================== */

    static final String F2B_DIR = "/usr/local/etc/fail2ban";
    static final String FILTER = F2B_DIR + "/filter.d/" + NAME + ".conf";
    public static final String JAIL = F2B_DIR + "/jail.d/" + NAME + ".conf";

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
    public static String filter() {
        return """
            # Written by DaemoxCP Mail. It watches only the log of the 443 public surface.
            [Definition]
            failregex = ^<HOST> .* "(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH|TRACE|CONNECT)[^"]*" (404|405|429) 
            ignoreregex =
            """;
    }

    public static String jail() {
        return """
            # Written by DaemoxCP Mail.
            [%1$s]
            enabled  = true
            filter   = %1$s
            logpath  = %2$s
            maxretry = 10
            findtime = 600
            bantime  = 3600
            # The action is declared, not inherited. Without this line the jail took the default
            # of jail.conf, which is based on iptables: a command that does not exist on
            # FreeBSD. The jail detected and counted bans regularly — 14,370 attempts and 46 bans —
            # and blocked none of them, because the command failed every time and nobody
            # looked. pf is used here, like all the other jails the panel writes.
            #
            # actiontype=any is not a detail: the pf action builds the rule as
            # "block quick proto tcp from <table> to <actiontype>", and the default value is
            # "any port $port". Without a port that line ends with "port " and pf refuses it:
            # the table would be created anyway — it is the command before — but the rule using
            # it would not, and the banned addresses would end up in a table no rule
            # reads. It would have been the same fault as before under another name.
            #
            # A PORT is declared, not an actiontype. It was found by elimination, and the
            # wrong road deserves to stay written: "actiontype=<allports>" and then
            # "actiontype=any" are the form the action's documentation shows, but fail2ban
            # on this system does not accept them as a jail parameter — the answer to
            # "get <jail> actions" becomes "No actions for jail ...", that is the jail is loaded
            # WITHOUT any action and does not ban at all. Worse than the starting fault, where
            # at least an action was there, however useless.
            #
            # This form instead is proven to work right here: it is the same as that of the
            # four mail jails, which the comparison with pf shows to have a table AND a rule. Between
            # what the documentation implies and what the server shows, the server
            # wins.
            action   = pf[name=%1$s, port="http,https"]
            """.formatted(NAME, ACCESS_LOG);
    }

    /** Installa filtro e jail, e verifica che fail2ban la veda davvero attiva. */
    public static JSONObject installJail() {
        JSONObject r = new JSONObject();
        try {
            RunResult present = run("sh", "-c", "command -v fail2ban-client");
            if (present.code != 0)
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.noF2b"));

            Files.createDirectories(Path.of(FILTER).getParent());
            Files.createDirectories(Path.of(JAIL).getParent());
            Files.writeString(Path.of(FILTER), filter());
            Files.writeString(Path.of(JAIL), jail());

            RunResult rel = run("fail2ban-client", "reload");
            if (rel.code != 0) {
                Files.deleteIfExists(Path.of(JAIL));
                run("fail2ban-client", "reload");
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.pubweb.f2bRejected", java.util.Map.of("out", String.valueOf(rel.output.trim()))));
            }

            // Non basta che il reload sia andato: si chiede a fail2ban se la vede.
            RunResult st = run("fail2ban-client", "status", NAME);
            if (st.code != 0)
                return r.put("success", false)
                        .put("error", I18n.tr("server.pubweb.jailNotActive", java.util.Map.of("out", String.valueOf(st.output.trim()))));

            return r.put("success", true).put("state", st.output.trim())
                    .put("note", I18n.tr("server.pubweb.jailActive"));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.pubweb.jailError", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("WebProtection", e))));
        }
    }

    /** Chiede i due percorsi a 127.0.0.1 sulla 443, per vedere se nginx risponde davvero. */
    private static JSONObject localTest() {
        JSONObject r = new JSONObject();
        RunResult a = run("sh", "-c",
                "fetch -q -o - --no-verify-peer --no-verify-hostname -T 5 "
              + "https://127.0.0.1/.well-known/mta-sts.txt 2>/dev/null "
              + "|| curl -sk --max-time 5 https://127.0.0.1/.well-known/mta-sts.txt");
        boolean policy = a.output != null && a.output.contains("version: STSv1");
        r.put("policy", policy);
        if (!policy)
            return r.put("ok", false)
                    .put("error", I18n.tr("server.pubweb.policyNotBack", java.util.Map.of("out", String.valueOf(a.output == null ? "" : a.output.trim()))));
        return r.put("ok", true);
    }

    private record RunResult(int code, String output) {}

    private static RunResult run(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return new RunResult(p.waitFor(), out);
        } catch (Exception e) {
            return new RunResult(-1, String.valueOf(e.getMessage()));
        }
    }
}
