package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * Il file principale di nginx (/usr/local/etc/nginx/nginx.conf): una sola fonte.
 *
 * Installando dal README su una VM pulita il 20/11/2026 i modelli erano due, diversi: quello dell'installatore
 * (FullMailServerScript) senza il blocco default_server, per cui la 8443 rispondeva con Roundcube a qualunque nome e
 * all'indirizzo nudo; e quello del pannello (cambio di dominio o di certificati della webmail), che riscriveva il file
 * da capo, cancellando la riga di include della superficie pubblica sulla 443 (WebProtection: MTA-STS e la
 * configurazione di Thunderbird), senza nginx -t prima e senza copia. Tutti e due mostravano la versione di nginx
 * (Server: nginx/1.30.6, contro la regola r19) e alla webmail mancavano HSTS, nosniff e Referrer-Policy (r15).
 *
 * Qui il contenuto e' uno: lo usano l'installatore (con dei segnaposto che lo script riempie), il pannello quando
 * cambia la webmail, e la riparazione all'avvio dei server installati prima, che aggiunge solo le righe che mancano.
 * Le intestazioni stanno nel blocco della webmail e nessuna location ne aggiunge altre: in nginx un add_header in una
 * location cancella quelli del blocco sopra. X-Frame-Options lo manda gia' Roundcube (sameorigin), e una CSP
 * rompeva Roundcube, che ha codice in linea: non si mettono.
 */
public final class NginxMain {

    private static final Logger LOGGER = Logger.getLogger(NginxMain.class.getName());

    static Path conf = Path.of("/usr/local/etc/nginx/nginx.conf");

    /** Le intestazioni di sicurezza della webmail, con always: anche sulle risposte di errore. */
    static final String HEADERS = """
                    # Sicurezza della webmail (r15): solo HTTPS per un anno, niente indovinare il tipo dei file, e
                    # l'indirizzo della webmail non esce verso i siti che si aprono dai messaggi.
                    add_header Strict-Transport-Security "max-age=31536000" always;
                    add_header X-Content-Type-Options "nosniff" always;
                    add_header Referrer-Policy "same-origin" always;
            """;

    static final String TOKENS = """
                # La versione di nginx non si dice a nessuno (r19).
                server_tokens off;
            """;

    private NginxMain() {}

    /**
     * Il file intero. Gli argomenti sono gia' controllati da chi chiama (nome, porta, percorsi); il pool PHP e' quello
     * di Roundcube (RoundcubeUser.fastcgiPass).
     */
    public static String content(String domain, String port, String cert, String key, String rcRoot, String fastcgiPass) {
        return """
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    client_max_body_size 50M;
__TOKENS__
    # Default server: reject requests on non-matching hostnames
    server {
        listen %s ssl default_server;
        server_name _;

        ssl_certificate %s;
        ssl_certificate_key %s;

        return 444;
    }

    # Roundcube webmail: responds ONLY to the configured domain
    server {
        listen %s ssl;
        server_name %s;
        root %s;
        index index.php;

        ssl_certificate %s;
        ssl_certificate_key %s;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
__HEADERS__
        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        # Roundcube 1.7 serve gli asset come /static.php/percorso/al/file.css: uno script PHP
        # con un percorso attaccato. Un location che chiede .php in fondo all'URI non lo prende,
        # e il foglio di stile torna come pagina HTML: la webmail si apre senza grafica.
        # Configurazione dal wiki ufficiale di Roundcube (pagina Installation).
        location ~ \\.php {
            include fastcgi_params;
            fastcgi_index index.php;
            fastcgi_split_path_info ^(.+\\.php)(/.+)$;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param PATH_INFO $fastcgi_path_info;
            fastcgi_pass %s;
        }

        location ~ /\\. { deny all; }
    }
}
""".replace("__TOKENS__\n", "\n" + TOKENS).replace("__HEADERS__\n", "\n" + HEADERS)
                .formatted(port, cert, key, port, domain, rcRoot, cert, key, fastcgiPass);
    }

    /** I segnaposto dell'installatore: lo script li sostituisce con i valori dei suoi argomenti. */
    public static final String P_DOMAIN = "__RC_DOMAIN__", P_PORT = "__RC_PORT__", P_CERT = "__RC_CERT__",
            P_KEY = "__RC_KEY__", P_ROOT = "__RC_ROOT__";

    /** Il file per l'installatore, coi segnaposto. */
    public static String template() {
        return content(P_DOMAIN, P_PORT, P_CERT, P_KEY, P_ROOT, "unix:" + RoundcubeUser.SOCKET);
    }

    /**
     * Il file nuovo con le righe che altre parti del pannello hanno messo nel vecchio: l'include della superficie
     * pubblica sulla 443 (WebProtection). Riscrivere da capo la toglieva.
     */
    public static String keepIncludes(String next, String current) {
        if (current == null || next == null) return next;
        String folder = WebProtection.PROPOSED_FOLDER;
        if (!current.contains("include " + folder + "/*.conf;") || next.contains(folder + "/*.conf")) return next;
        String with = WebProtection.withInclude(next, folder);
        return with == null ? next : with;
    }

    /**
     * Le righe che mancano a un file del pannello gia' sul server: server_tokens off nel blocco http; il blocco
     * default_server che risponde 444 agli altri nomi, se nessun listen della porta della webmail lo e' gia' (con le
     * stesse righe listen e lo stesso certificato del blocco della webmail); le intestazioni nel blocco della webmail,
     * se non ne ha gia'. Null se non c'e' niente da aggiungere, o se il file non ha la forma che il pannello scrive (un
     * blocco http e un server col nome della webmail). Funzione pura.
     */
    static String harden(String current, String webmailDomain) {
        if (current == null || webmailDomain == null || webmailDomain.isBlank()) return null;
        String[] lines = current.split("\n", -1);
        String nameLine = "server_name " + webmailDomain + ";";
        // Il blocco della webmail: dalla riga «server {» che lo apre alla graffa che lo chiude.
        int name = -1;
        for (int i = 0; i < lines.length; i++) if (lines[i].trim().equals(nameLine)) { name = i; break; }
        if (name < 0 || !current.matches("(?s).*(^|\\n)\\s*http\\s*\\{.*")) return null;
        int open = -1;
        for (int i = name; i >= 0; i--) if (lines[i].trim().matches("server\\s*\\{")) { open = i; break; }
        if (open < 0) return null;
        int depth = 0, close = -1;
        for (int i = open; i < lines.length; i++) {
            depth += count(lines[i], '{') - count(lines[i], '}');
            if (depth == 0) { close = i; break; }
        }
        if (close < 0) return null;
        java.util.List<String> listens = new java.util.ArrayList<>();
        String cert = null, key = null;
        boolean headers = false;
        for (int i = open; i <= close; i++) {
            String t = lines[i].trim();
            if (t.startsWith("#")) continue;
            if (t.startsWith("listen ")) listens.add(t);
            if (t.startsWith("ssl_certificate ")) cert = t;
            if (t.startsWith("ssl_certificate_key ")) key = t;
            if (t.startsWith("add_header")) headers = true;
        }
        boolean tokens = current.matches("(?s).*(^|\\n)\\s*server_tokens\\s.*");
        boolean defaultServer = false;
        for (String l : lines) {
            String t = l.trim();
            if (t.startsWith("listen ") && t.contains("default_server")) defaultServer = true;
        }
        boolean addDefault = !defaultServer && !listens.isEmpty() && cert != null && key != null;
        if (tokens && headers && !addDefault) return null;

        StringBuilder out = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            String l = lines[i], t = l.trim();
            if (i == open && addDefault) {
                out.append("    # Default server: reject requests on non-matching hostnames\n    server {\n");
                for (String li : listens) out.append("        ").append(li.replaceAll("\\s*;\\s*$", "")).append(" default_server;\n");
                out.append("        server_name _;\n\n        ").append(cert).append("\n        ").append(key)
                   .append("\n\n        return 444;\n    }\n\n");
            }
            out.append(l);
            if (i < lines.length - 1) out.append("\n");
            if (t.startsWith("#")) continue;
            if (!tokens && (t.equals("http {") || t.equals("http{"))) {
                out.append("\n").append(TOKENS.stripTrailing()).append("\n");
                tokens = true;
            }
            if (!headers && i == name) {
                out.append("\n").append(HEADERS.stripTrailing()).append("\n");
                headers = true;
            }
        }
        return out.toString();
    }

    private static int count(String s, char c) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == c) n++;
        return n;
    }

    /**
     * Mette il file al suo posto solo se nginx lo accetta: si scrive accanto (le include relative come mime.types si
     * risolvono dalla stessa cartella), si prova con nginx -t -c, e solo allora si sposta, tenendo una copia del vecchio
     * (ConfigBackups). Non ricarica: lo fa chi chiama. Null se e' andato bene, altrimenti cosa non va.
     */
    public static String write(String next) {
        try {
            Path candidate = conf.resolveSibling(".nginx.conf.panel-new");
            Files.writeString(candidate, next, StandardCharsets.UTF_8);
            Files.setPosixFilePermissions(candidate, PosixFilePermissions.fromString("rw-r--r--"));
            Shell.Result test = Shell.run(Duration.ofSeconds(30), "nginx", "-t", "-c", candidate.toString());
            if (!test.success()) {
                Files.deleteIfExists(candidate);
                return "nginx -t refuses it: " + firstLine(test.outputTrim());
            }
            if (Files.exists(conf)) ConfigBackups.copy(conf, StandardCopyOption.COPY_ATTRIBUTES);
            Files.move(candidate, conf, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            return null;
        } catch (Exception e) {
            return "nginx.conf not written: " + e.getMessage();
        }
    }

    /**
     * Sui server installati prima: le righe che mancano, poi reload e la prova dal vivo (le intestazioni arrivano e la
     * versione non c'e'). Se qualcosa non torna, il file di prima e un altro reload.
     */
    public static void ensureAtBoot() {
        try {
            if (!Files.isRegularFile(conf) || org.daemoxcp.mail.Main.dbManager == null) return;
            String domain = org.daemoxcp.mail.Main.dbManager.getRoundcubeDomain();
            String port = org.daemoxcp.mail.Main.dbManager.getRoundcubePort();
            if (domain == null || !domain.matches("[A-Za-z0-9.-]{1,253}") || port == null || !port.trim().matches("[0-9]{1,5}")) return;
            String current = Files.readString(conf, StandardCharsets.UTF_8);
            String next = harden(current, domain);
            if (next == null) return;
            if (!Shell.run(Duration.ofSeconds(15), "service", "nginx", "status").success()) {
                LOGGER.info("[NginxMain] nginx is not running: nginx.conf left as it is, retrying at the next start");
                return;
            }
            String problem = write(next);
            if (problem != null) {
                LOGGER.warning("[NginxMain] ROLLED_BACK: " + problem + ": nothing changed");
                return;
            }
            String check = reloadAndCheck(domain, port.trim());
            if (check != null) {
                Files.writeString(conf, current, StandardCharsets.UTF_8);
                Shell.run(Duration.ofSeconds(30), "service", "nginx", "reload");
                LOGGER.warning("[NginxMain] ROLLED_BACK: " + check + "; nginx.conf put back as it was");
                return;
            }
            LOGGER.info("[NginxMain] DONE: nginx no longer says its version, other names get no answer on the webmail's"
                    + " port, and the webmail sends HSTS, nosniff and Referrer-Policy (" + conf + ")");
        } catch (Throwable t) {
            LOGGER.warning("[NginxMain] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /** Reload, poi una richiesta vera alla webmail: le intestazioni nuove ci sono, la versione di nginx no. */
    static String reloadAndCheck(String domain, String port) throws InterruptedException {
        if (!Shell.run(Duration.ofSeconds(30), "service", "nginx", "reload").success()) return "service nginx reload failed";
        String last = "the webmail did not answer";
        for (int i = 0; i < 10; i++) {
            Thread.sleep(500);
            Shell.Result r = Shell.run(Duration.ofSeconds(15), "curl", "-skI", "--max-time", "8", "--resolve",
                    domain + ":" + port + ":127.0.0.1", "https://" + domain + ":" + port + "/");
            String h = r.output().toLowerCase(java.util.Locale.ROOT);
            if (!h.startsWith("http/")) { last = "the webmail did not answer"; continue; }
            if (!h.contains("x-content-type-options: nosniff")) { last = "the webmail's answer has no nosniff header"; continue; }
            if (h.matches("(?s).*\\nserver: nginx/[0-9].*")) { last = "nginx still says its version"; continue; }
            // Un altro nome sulla stessa porta: il blocco default_server chiude senza risposta (444), niente Roundcube.
            Shell.Result other = Shell.run(Duration.ofSeconds(15), "curl", "-skI", "--max-time", "8", "--resolve",
                    "not-the-webmail.invalid:" + port + ":127.0.0.1", "https://not-the-webmail.invalid:" + port + "/");
            if (other.output().toLowerCase(java.util.Locale.ROOT).startsWith("http/")) {
                last = "another name still gets an answer on port " + port; continue;
            }
            return null;
        }
        return last;
    }

    private static String firstLine(String s) {
        if (s == null) return "";
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
