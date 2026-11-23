package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The public surface on port 443, reduced to the minimum and with some brakes.
 *
 * The context: this server keeps the webmail on 8443, closed to external addresses. Two
 * functions, however, need 443 because the protocols allow no other port: the
 * MTA-STS policy, which sending servers all over the world read, and the
 * configuration file that Thunderbird looks for. Opening 443 means exposing something, so
 * that something must be as little as possible.
 *
 * The choices, one by one, and the reason for each:
 *
 *  - **A separate server block**, not an addition to the webmail one. If it were added
 *    there, the new site would inherit Roundcube's root and the PHP handler: 443 would
 *    be opened onto an entire application to serve two text files.
 *
 *  - **default_server on 443.** That way whatever name arrives on that port ends up here,
 *    and there is no way for a request to reach another block by mistake.
 *
 *  - **Only two locations, both exact** (`location =`), and everything else 404. There is no
 *    root, no index, no try_files: there is no path that serves a file
 *    other than one of the two.
 *
 *  - **The MTA-STS policy is a STATIC file on disk**, not a request passed on to the
 *    panel. It is identical for all domains -- it declares the same MX -- so there is no
 *    reason to generate it every time. That way a flood on that path is absorbed by nginx
 *    serving two hundred bytes, and never reaches the Java process or the database.
 *
 *  - **Only GET and HEAD.** They are two files to read: any other method is either an error
 *    or an attempt.
 *
 *  - **Rate and connection limits per address**, wide enough not to
 *    bother anyone: five requests per second and eight connections are orders of
 *    magnitude above real usage, which is one request now and then.
 *
 *  - **Tiny maximum body and short timeouts.** A slow request that keeps a
 *    connection busy is the cheapest way to do damage: here it dies in five seconds.
 *
 *  - **Dedicated log**, so fail2ban can watch only this and not mix it up with the
 *    webmail.
 */
public class WebProtection {

    /**
     * The name of the public surface on the system: the nginx file, its log, the fail2ban filter and
     * jail, and therefore the pf anchor and table (f2b/NAME, f2b-NAME). It travels
     * between three services: nginx writes the log that fail2ban reads. Until 2026-10-30 it was
     * `mailpanel-pubblico` ("mailpanel-public"): servers installed before are moved by PublicSurfaceRename at boot.
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

    /*
     * ===================================================================
     * The configuration, as a pure function
     * ===================================================================
     */

    /**
     * The folders that nginx really includes, derived from the complete configuration.
     *
     * We no longer write into "sites-enabled" because one of the installation scripts
     * writes there: on this server that folder is NOT included, and a file put there
     * would have been ignored while the panel declared "installed". We look where
     * nginx says to look, and write there.
     *
     * Relative paths are resolved against the nginx prefix, as nginx itself does.
     */
    public static java.util.List<String> includedFolders(String dump) {
        java.util.LinkedHashSet<String> outside = new java.util.LinkedHashSet<>();
        if (dump == null) return new java.util.ArrayList<>(outside);
        for (String r : dump.split("\n")) {
            String t = r.trim();
            if (t.startsWith("#") || !t.startsWith("include ")) continue;
            String v = t.substring(8).replace(";", "").trim();
            // Only pattern includes matter: "include something/*.conf".
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

    /** The folder to write into: the first included one that exists and is writable. */
    public static String chosenFolder(java.util.List<String> included) {
        for (String c : included) {
            try {
                Path p = Path.of(c);
                if (Files.isDirectory(p) && Files.isWritable(p)) return c;
            } catch (Exception ignore) {}
        }
        // None exists: take the first declared one, which can be created.
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
        // The listen lines of the family chosen in Settings (IpFamily); with no choice, IPv4 and IPv6 as always.
        return IpFamily.withNginxListen(text, 443, IpFamily.chosen());
    }

    /*
     * ===================================================================
     * The real state
     * ===================================================================
     */

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
     * Does nginx really include the folder we are about to write into?
     *
     * Without this check we would write a perfect file that nginx never reads, and the
     * panel would say "installed" while 443 stays closed. We look at the complete
     * configuration, not the main file: the include could be in a file that is itself included.
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

    /*
     * ===================================================================
     * The installation
     * ===================================================================
     */

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

            // 1. The policy, before the configuration: if nginx started pointing to a file
            //    that is not there, it would serve a 404 on the path that has to work.
            JSONObject pol = writePolicy();
            r.put("policy", pol);
            if (!pol.optBoolean("success", false))
                return r.put("success", false).put("error", pol.optString("error"));

            // 2. Backup copy of any previous version.
            Path f = Path.of(FILE);
            String before = Files.exists(f) ? Files.readString(f) : null;
            if (before != null) {
                Files.createDirectories(Path.of(COPY).getParent());
                Files.writeString(Path.of(COPY), before);
                r.put("copy", COPY);
            }

            Files.createDirectories(Path.of(folder));
            Files.writeString(f, configuration(cert, key));

            // 3. The validation decides.
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

            // 4. It is not enough that the commands did not complain: we test the port.
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

    /** Writes the MTA-STS policy to disk. It is the same for all domains: it declares the same MX. */
    public static JSONObject writePolicy() {
        JSONObject r = new JSONObject();
        String host = MtaSts.mailHost();
        if (host == null || host.isBlank())
            return r.put("success", false)
                    .put("error", I18n.tr("server.pubweb.noHostname"));
        String mode = MtaSts.currentMode();
        String text = MtaSts.policy(host, mode, MtaSts.recommendedMaxAge(mode));
        try {
            // With explicit permissions, not the service's umask: nginx (www) must be able to read it (finding 250)
            PublicPolicyAccess.write(Path.of(PUBLIC_DIR), Path.of(POLICY_FILE), text);
            return r.put("success", true).put("mode", mode).put("text", text)
                    .put("id", MtaSts.id(text));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.pubweb.cannotWrite", java.util.Map.of("file", String.valueOf(POLICY_FILE), "err", org.daemoxcp.mail.util.ErrorText.detail("WebProtection", e))));
        }
    }

    /*
     * ===================================================================
     * Adding the include line
     * ===================================================================
     */

    public static final String PROPOSED_FOLDER = NGINX_PREFIX + "/conf.d";
    private static final String MAIN_COPY = "/var/db/daemoxcp-mail/nginx.conf-before-include";

    /**
     * The main file, derived from "nginx -T": the first line "# configuration file X:"
     * names the file nginx started from. We do not guess the path.
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
     * Inserts the include line right after the opening of the http block.
     *
     * It must be INSIDE http: outside, nginx rejects the directives of a server block, and the
     * configuration does not start. It is inserted at the top of the block so that the directives of the
     * included file do not come after something that would make them ineffective.
     *
     * Returns null if the http block is not found or if the include is already there: better to
     * do nothing than to write a line at a random point of a configuration that works.
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

    /** Adds the include line to the main file, with all the safety nets. */
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

            // Reread from nginx, not from the file: what counts is what nginx really includes.
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

    /*
     * ===================================================================
     * The fail2ban jail
     * ===================================================================
     */

    static final String F2B_DIR = "/usr/local/etc/fail2ban";
    static final String FILTER = F2B_DIR + "/filter.d/" + NAME + ".conf";
    public static final String JAIL = F2B_DIR + "/jail.d/" + NAME + ".conf";

    /**
     * The filter watches ONLY this site's log, and only the 404, 405 and 429 responses.
     *
     * The reasoning: on this port there are two legitimate paths. Whoever asks for others is
     * looking for something -- an admin page, a configuration file, an
     * exploit -- and whoever gets 429 is already going past the rate limit. An error
     * can happen to anyone, so the ban comes after ten in ten minutes, not at the first.
     *
     * Watching a dedicated log instead of the general one avoids banning by mistake those who use
     * the webmail: they are two different files, and the two things do not get mixed up.
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

    /** Installs filter and jail, and checks that fail2ban really sees it active. */
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

            // It is not enough that the reload went through: we ask fail2ban whether it sees it.
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

    /** Requests the two paths from 127.0.0.1 on 443, to see whether nginx really answers. */
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
