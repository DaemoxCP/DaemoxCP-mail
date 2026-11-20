package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * nginx.conf from one source (NginxMain). Found on 20/11/2026 installing from the README on a clean VM: the installer
 * and the panel wrote two different files (the installer's without the default_server that answers 444 to other
 * names); the panel's rewrite dropped the include of the public surface on 443 (MTA-STS) and wrote without nginx -t;
 * both said nginx's version, and the webmail had no HSTS, nosniff or Referrer-Policy.
 *  1. the file: default_server 444 first, server_tokens off in http, the three headers in the webmail's block and no
 *     add_header in any location (it would cancel the block's);
 *  2. the repair of an existing file: the installer's old file gets server_tokens, the default_server block (with the
 *     webmail's listen lines and certificate) and the headers, once; a file that has its default_server keeps one; the
 *     panel's own file needs nothing; a file whose webmail block already has headers keeps them; a file without the webmail's
 *     name is not touched;
 *  3. the include of the public surface survives a rewrite, and is not doubled;
 *  4. the installer writes the same file: its shell fragment, run for real with paths full of & | and \, gives exactly
 *     what the panel writes with the same values.
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.NginxMainTest
 */
public class NginxMainTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The installer's nginx.conf of 0.9.0 build 786, as found on the clean VM. */
    static final String OLD_INSTALLER = """
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

                server {
                    listen 8443 ssl;
                    server_name webmail.example.com;
                    root /usr/local/www/roundcube/public_html;
                    index index.php;

                    ssl_certificate /usr/local/etc/ssl/webmail/webmail-origin.pem;
                    ssl_certificate_key /usr/local/etc/ssl/webmail/webmail-origin.key;

                    location / {
                        try_files $uri $uri/ /index.php?$args;
                    }
                    location ~ /\\. { deny all; }
                }
            }
            """;

    public static void main(String[] a) throws Exception {
        System.out.println("== 1. The file");
        String c = NginxMain.content("webmail.example.com", "8443", "/etc/c.pem", "/etc/k.pem", "/usr/local/www/roundcube/public_html",
                "unix:/var/run/php-fpm-roundcube.sock");
        int def = c.indexOf("listen 8443 ssl default_server;"), web = c.indexOf("server_name webmail.example.com;");
        check("default_server answers 444, before the webmail's block", def > 0 && c.indexOf("return 444;") > def && def < web);
        check("server_tokens off in http", c.indexOf("server_tokens off;") > c.indexOf("http {") && c.indexOf("server_tokens off;") < def);
        String block = c.substring(web);
        check("HSTS, nosniff and Referrer-Policy in the webmail's block, with always",
                block.contains("add_header Strict-Transport-Security \"max-age=31536000\" always;")
                && block.contains("add_header X-Content-Type-Options \"nosniff\" always;")
                && block.contains("add_header Referrer-Policy \"same-origin\" always;"));
        check("no add_header inside a location", !inLocation(c, "add_header"));
        check("no CSP and no X-Frame-Options (Roundcube sends its own)", !c.contains("Content-Security-Policy") && !c.contains("X-Frame-Options"));
        check("the PHP pool and the root as given", c.contains("fastcgi_pass unix:/var/run/php-fpm-roundcube.sock;")
                && c.contains("root /usr/local/www/roundcube/public_html;"));

        System.out.println("\n== 2. The repair of an existing file");
        String fixed = NginxMain.harden(OLD_INSTALLER, "webmail.example.com");
        check("the installer's old file gets server_tokens off and the three headers", fixed != null && fixed.contains("server_tokens off;")
                && fixed.contains("add_header X-Content-Type-Options \"nosniff\" always;"));
        check("  and the default_server block, before the webmail's, with its listen and its certificate", fixed != null
                && fixed.contains("    server {\n        listen 8443 ssl default_server;\n        server_name _;\n\n"
                        + "        ssl_certificate /usr/local/etc/ssl/webmail/webmail-origin.pem;\n"
                        + "        ssl_certificate_key /usr/local/etc/ssl/webmail/webmail-origin.key;\n\n        return 444;\n    }\n")
                && fixed.indexOf("return 444;") < fixed.indexOf("server_name webmail.example.com;"));
        check("  once: a second pass finds nothing", fixed != null && NginxMain.harden(fixed, "webmail.example.com") == null);
        check("  the rest of the file is the same", fixed != null && fixed.replaceAll("(?s)    # Default server.*?return 444;\\n    }\\n\\n", "")
                .replaceAll("(?m)^\\s*(# .*|server_tokens off;|add_header .*)\\n", "")
                .replaceAll("\\n{2,}", "\n").equals(OLD_INSTALLER.replaceAll("\\n{2,}", "\n")));
        String dual = OLD_INSTALLER.replace("listen 8443 ssl;", "listen 8443 ssl;\n        listen [::]:8443 ssl;");
        String dualFixed = NginxMain.harden(dual, "webmail.example.com");
        check("IPv4 and IPv6: the default_server listens on both", dualFixed != null && dualFixed.contains(
                "listen 8443 ssl default_server;\n        listen [::]:8443 ssl default_server;\n"));
        String withDefault = c.replace("    server_tokens off;\n", "").replaceAll("(?m)^\\s*add_header .*\\n", "");
        String prodFixed = NginxMain.harden(withDefault, "webmail.example.com");
        check("a file that already has its default_server (the real server's) gets only server_tokens and the headers",
                prodFixed != null && prodFixed.indexOf("default_server") == prodFixed.lastIndexOf("default_server")
                && prodFixed.contains("server_tokens off;") && prodFixed.contains("nosniff"));
        check("the panel's own file needs nothing", NginxMain.harden(c, "webmail.example.com") == null);
        String own = OLD_INSTALLER.replace("server_name webmail.example.com;", "server_name webmail.example.com;\n        add_header X-Frame-Options DENY;");
        String ownFixed = NginxMain.harden(own, "webmail.example.com");
        check("a webmail block with headers of its own keeps them, only server_tokens is added",
                ownFixed != null && ownFixed.contains("server_tokens off;") && !ownFixed.contains("nosniff"));
        check("a file without the webmail's name is not touched", NginxMain.harden(OLD_INSTALLER, "other.example.com") == null);

        System.out.println("\n== 3. The include of the public surface");
        String include = "include " + WebProtection.PROPOSED_FOLDER + "/*.conf;";
        String withInclude = WebProtection.withInclude(OLD_INSTALLER, WebProtection.PROPOSED_FOLDER);
        String kept = NginxMain.keepIncludes(c, withInclude);
        check("a rewrite keeps it", kept.contains(include));
        check("  inside http, once", kept.indexOf(include) > kept.indexOf("http {") && kept.indexOf(include) == kept.lastIndexOf(include));
        check("  and is not added where it was not", NginxMain.keepIncludes(c, OLD_INSTALLER).equals(c));

        System.out.println("\n== 4. The installer writes the same file");
        String script = new org.daemoxcp.mail.scripts.FullMailServerScript().getScriptContent();
        int from = script.indexOf("cat > /usr/local/etc/nginx/nginx.conf << 'NGINX_CONF'");
        int to = script.indexOf("still has a placeholder", from);
        check("the installer's fragment is there", from > 0 && to > from);
        if (from > 0 && to > from) {
            String fragment = script.substring(from, script.indexOf("fi\n", to) + 3);
            check("  it writes NginxMain's template", fragment.contains(NginxMain.template()));
            if (System.getProperty("os.name", "").toLowerCase().contains("freebsd")) {
                Path dir = Files.createTempDirectory("nginx-main-");
                Path out = dir.resolve("nginx.conf");
                String cert = "/etc/ssl/a&b|c\\d.pem", key = "/etc/ssl/k&|\\.key";
                String sh = "ROUNDCUBE_DOMAIN='webmail.example.com'; ROUNDCUBE_PORT='8443'; RC_SSL_CERT='" + cert + "'; RC_SSL_KEY='" + key
                        + "'; RED=''; NC=''\n" + fragment.replace("/usr/local/etc/nginx/nginx.conf", out.toString());
                Process p = new ProcessBuilder("sh", "-c", sh).redirectErrorStream(true).start();
                String said = new String(p.getInputStream().readAllBytes());
                int rc = p.waitFor();
                String root = Files.isDirectory(Path.of("/usr/local/www/roundcube/public_html"))
                        ? "/usr/local/www/roundcube/public_html" : "/usr/local/www/roundcube";
                String expected = NginxMain.content("webmail.example.com", "8443", cert, key, root, "unix:" + RoundcubeUser.SOCKET);
                String got = Files.readString(out);
                check("  run with paths full of & | and \\: exactly the panel's file (exit " + rc + ")",
                        rc == 0 && got.equals(expected) && !said.contains("placeholder"));
                Files.deleteIfExists(out);
                Files.deleteIfExists(dir);
            } else {
                System.out.println("  (the run of the fragment needs FreeBSD's sed: skipped here)");
            }
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** True when a line starting with the word is inside a location block. */
    static boolean inLocation(String conf, String word) {
        int depth = 0, location = -1;
        for (String l : conf.split("\n")) {
            String t = l.trim();
            if (t.startsWith("#")) continue;
            if (location >= 0 && depth > location && t.startsWith(word)) return true;
            if (location < 0 && t.startsWith("location ")) location = depth;
            for (char ch : t.toCharArray()) { if (ch == '{') depth++; if (ch == '}') depth--; }
            if (location >= 0 && depth <= location) location = -1;
        }
        return false;
    }
}
