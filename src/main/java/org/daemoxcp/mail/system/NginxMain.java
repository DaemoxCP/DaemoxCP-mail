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
 * The main nginx file (/usr/local/etc/nginx/nginx.conf): a single source.
 *
 * Installing from the README on a clean VM on 2026-11-20 there were two different templates: the installer's
 * (FullMailServerScript) without the default_server block, so 8443 answered with Roundcube to any name and to the
 * bare address; and the panel's (change of domain or of webmail certificates), which rewrote the file from scratch,
 * deleting the include line of the public surface on 443 (WebProtection: MTA-STS and the Thunderbird
 * configuration), without nginx -t first and without a copy. Both showed the nginx version (Server: nginx/1.30.6,
 * against rule r19) and the webmail lacked HSTS, nosniff and Referrer-Policy (r15).
 *
 * Here there is one content: it is used by the installer (with placeholders the script fills in), by the panel when
 * it changes the webmail, and by the boot repair of servers installed before, which adds only the missing lines.
 * The headers are in the webmail block and no location adds others: in nginx an add_header in a location cancels
 * those of the block above. X-Frame-Options is already sent by Roundcube (sameorigin), and a CSP broke Roundcube,
 * which has inline code: they are not set.
 */
public final class NginxMain {

    private static final Logger LOGGER = Logger.getLogger(NginxMain.class.getName());

    static Path conf = Path.of("/usr/local/etc/nginx/nginx.conf");

    /** The webmail security headers, with always: also on error responses. */
    static final String HEADERS = """
                    # Webmail security (r15): HTTPS only for a year, no guessing of file types, and
                    # the webmail's address does not leak to the sites opened from messages.
                    add_header Strict-Transport-Security "max-age=31536000" always;
                    add_header X-Content-Type-Options "nosniff" always;
                    add_header Referrer-Policy "same-origin" always;
            """;

    static final String TOKENS = """
                # nginx's version is told to nobody (r19).
                server_tokens off;
            """;

    private NginxMain() {}

    /**
     * The whole file. The arguments are already checked by the caller (name, port, paths); the PHP pool is
     * Roundcube's (RoundcubeUser.fastcgiPass).
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

        # Roundcube 1.7 serves its assets as /static.php/path/to/file.css: a PHP script
        # with a path attached. A location that wants .php at the end of the URI does not catch it,
        # and the style sheet comes back as an HTML page: the webmail opens without its look.
        # Configuration from Roundcube's official wiki (Installation page).
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

    /** The installer's placeholders: the script replaces them with the values of its arguments. */
    public static final String P_DOMAIN = "__RC_DOMAIN__", P_PORT = "__RC_PORT__", P_CERT = "__RC_CERT__",
            P_KEY = "__RC_KEY__", P_ROOT = "__RC_ROOT__";

    /** The file for the installer, with the placeholders. */
    public static String template() {
        return content(P_DOMAIN, P_PORT, P_CERT, P_KEY, P_ROOT, "unix:" + RoundcubeUser.SOCKET);
    }

    /**
     * The new file with the lines other parts of the panel put in the old one: the include of the public surface on
     * 443 (WebProtection). Rewriting from scratch removed it.
     */
    public static String keepIncludes(String next, String current) {
        if (current == null || next == null) return next;
        String folder = WebProtection.PROPOSED_FOLDER;
        if (!current.contains("include " + folder + "/*.conf;") || next.contains(folder + "/*.conf")) return next;
        String with = WebProtection.withInclude(next, folder);
        return with == null ? next : with;
    }

    /**
     * The lines missing from a panel file already on the server: server_tokens off in the http block; the
     * default_server block that answers 444 to other names, if no listen of the webmail port already is one (with the
     * same listen lines and the same certificate as the webmail block); the headers in the webmail block, if it does
     * not have them already. Null if there is nothing to add, or if the file does not have the shape the panel writes
     * (an http block and a server with the webmail name). Pure function.
     */
    static String harden(String current, String webmailDomain) {
        if (current == null || webmailDomain == null || webmailDomain.isBlank()) return null;
        String[] lines = current.split("\n", -1);
        String nameLine = "server_name " + webmailDomain + ";";
        // The webmail block: from the "server {" line that opens it to the brace that closes it.
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
     * Puts the file in place only if nginx accepts it: it is written alongside (relative includes such as mime.types
     * are resolved from the same folder), tested with nginx -t -c, and only then moved, keeping a copy of the old one
     * (ConfigBackups). It does not reload: the caller does. Null if it went well, otherwise what is wrong.
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
     * On servers installed before: the missing lines, then reload and the live test (the headers arrive and the
     * version is absent). If something does not match, the previous file and another reload.
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

    /** Reload, then a real request to the webmail: the new headers are there, the nginx version is not. */
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
            // Another name on the same port: the default_server block closes without an answer (444), no Roundcube.
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
