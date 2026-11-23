package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.util.Shell;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * What the web server really exposes, read from the server and not inferred from the scripts.
 *
 * Why a diagnostic is needed instead of looking at the code: the panel contains TWO
 * installation scripts that write different nginx configurations. One adds a
 * "listen 80" block with server_name _ that serves the webmail IN CLEARTEXT; the other writes a file in
 * sites-enabled with only "listen 443 ssl". Looking at the code you cannot know which
 * of the two built this machine -- and on nginx in production, inferring is not enough.
 *
 * Here we read "nginx -T", which prints the COMPLETE configuration as nginx really sees it,
 * including all the included files. It is the only source that does not lie: if a file was left
 * lying around but is not included, it does not appear there; if someone edited by hand, it shows there.
 *
 * This class changes nothing. It reads, and when a command fails it says so instead of
 * drawing a conclusion: "I could not look" and "everything is fine" are two opposite answers.
 */
public class WebDiagnostics {

    private WebDiagnostics() {}

    /*
     * ===================================================================
     * The parser, as a pure function
     * ===================================================================
     */

    public static class Block {
        public final List<String> listens = new ArrayList<>();
        public String names = "";
        public String root = "";
        public boolean encrypted;          // has "ssl" among the listen parameters
        public boolean servePhp;
        public boolean serveFile;        // has a root and a location that serves something
        public boolean onlyRedirect;     // does nothing but redirect elsewhere
        public int line;
    }

    /**
     * The "server" blocks of the configuration, with what they listen on and what they serve.
     *
     * The parser counts braces instead of looking for the end with a regular expression: inside
     * a server there are other blocks (location, if) and a regex would stop at the first
     * closing brace, assigning half of the directives to the wrong block.
     */
    public static List<Block> blocks(String dump) {
        List<Block> outside = new ArrayList<>();
        if (dump == null) return outside;
        String[] lines = dump.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String t = lines[i].trim();
            if (t.startsWith("#")) continue;
            if (!t.equals("server {") && !t.startsWith("server {") && !t.equals("server")) continue;

            Block b = new Block();
            b.line = i + 1;
            int depth = countBraces(lines[i]);
            int j = i + 1;
            StringBuilder body = new StringBuilder();
            while (j < lines.length && depth > 0) {
                body.append(lines[j]).append("\n");
                depth += countBraces(lines[j]);
                j++;
            }
            readBody(b, body.toString());
            outside.add(b);
            i = j - 1;
        }
        return outside;
    }

    private static int countBraces(String line) {
        int n = 0;
        boolean comment = false;
        for (char c : line.toCharArray()) {
            if (c == '#') comment = true;
            if (comment) continue;
            if (c == '{') n++;
            else if (c == '}') n--;
        }
        return n;
    }

    private static void readBody(Block b, String body) {
        boolean hasLocationWithContent = false, haReturn = false;
        for (String r : body.split("\n")) {
            String t = r.trim();
            if (t.startsWith("#")) continue;
            String lower = t.toLowerCase(Locale.ROOT);

            if (lower.startsWith("listen ")) {
                String v = t.substring(7).replace(";", "").trim();
                b.listens.add(v);
                if (v.toLowerCase(Locale.ROOT).contains("ssl")) b.encrypted = true;
            } else if (lower.startsWith("server_name ")) {
                b.names = t.substring(12).replace(";", "").trim();
            } else if (lower.startsWith("root ")) {
                b.root = t.substring(5).replace(";", "").trim();
            } else if (lower.contains("fastcgi_pass") || lower.matches("location\\s+~\\s*\\\\?\\.php.*")) {
                b.servePhp = true;
            } else if (lower.startsWith("try_files") || lower.startsWith("index ")
                    || lower.startsWith("alias ")) {
                hasLocationWithContent = true;
            } else if (lower.startsWith("return ") || lower.startsWith("rewrite ")) {
                haReturn = true;
            }
        }
        b.serveFile = !b.root.isEmpty() && (hasLocationWithContent || b.servePhp);
        b.onlyRedirect = haReturn && !b.serveFile && !b.servePhp;
    }

    /** The block listens on the given port. */
    public static boolean listensOn(Block b, int port) {
        for (String a : b.listens) {
            String p = a.split("\\s+")[0];
            int i = p.lastIndexOf(':');
            String portOnly = i >= 0 ? p.substring(i + 1) : p;
            if (portOnly.equals(String.valueOf(port))) return true;
        }
        return false;
    }

    /*
     * ===================================================================
     * Measurements on the server
     * ===================================================================
     */

    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);

        RunResult dump = run("nginx", "-T");
        if (dump.code != 0) {
            r.put("nginxReadable", false)
             .put("nginxProblem", I18n.tr("server.webdiag.dumpFailed", java.util.Map.of("out", String.valueOf(firstLines(dump.output, 3)))));
        } else {
            r.put("nginxReadable", true);
            List<Block> bl = blocks(dump.output);
            JSONArray sites = new JSONArray();
            boolean inPlain = false, eighty = false;
            for (Block b : bl) {
                boolean on80 = listensOn(b, 80);
                boolean on443 = listensOn(b, 443);
                if (on80) eighty = true;
                boolean dangerous = on80 && !b.encrypted && (b.serveFile || b.servePhp);
                if (dangerous) inPlain = true;
                sites.put(new JSONObject()
                        .put("listens", String.join(", ", b.listens))
                        .put("names", b.names)
                        .put("root", b.root)
                        .put("encrypted", b.encrypted)
                        .put("servePhp", b.servePhp)
                        .put("serveFile", b.serveFile)
                        .put("onlyRedirect", b.onlyRedirect)
                        .put("on80", on80).put("on443", on443)
                        .put("inPlain", dangerous));
            }
            boolean four43 = false;
            for (Block b : bl) if (listensOn(b, 443)) four43 = true;
            r.put("sites", sites).put("port80Present", eighty).put("plainContents", inPlain)
             .put("port443Present", four43);

            boolean limReq = dump.output.contains("limit_req"), limConn = dump.output.contains("limit_conn");
            r.put("limitReq", limReq).put("limitConn", limConn);
            r.put("sslProtocols", firstLineWith(dump.output, "ssl_protocols"));
            r.put("workerConnections", firstLineWith(dump.output, "worker_connections"));
        }

        // Who is really listening on the machine, regardless of nginx.
        RunResult sock = run("sh", "-c", "sockstat -4 -6 -l 2>/dev/null | awk 'NR==1 || $6 ~ /:(80|443)$/'");
        r.put("listening", sock.code == 0 ? sock.output.trim() : "")
         .put("listeningRead", sock.code == 0);

        // The firewall: are the web ports filtered?
        RunResult pf = run("sh", "-c", "pfctl -sr 2>/dev/null");
        if (pf.code == 0 && !pf.output.isBlank()) {
            r.put("pfRead", true).put("pfRules", pf.output.trim().split("\n").length);
            r.put("pfMentions80", pf.output.contains(" 80") || pf.output.contains("{ 80"));
            r.put("pfMentions443", pf.output.contains("443"));
        } else {
            r.put("pfRead", false);
        }

        // fail2ban: is there a jail that watches an nginx log?
        //
        // Before, the question was asked of the NAME: "does the jail list contain the word nginx?".
        // It was wrong in both directions. On this server the jail that protects 443
        // is called "daemoxcp-mail-public" and watches /var/log/nginx/daemoxcp-mail-public-access.log:
        // an nginx log in every respect, but without that word in its name -- and the diagnosis
        // announced that nobody is banned on the web ports, while they were being banned.
        // Conversely, a jail called "nginx-something" but pointed elsewhere would have passed
        // as good. The name of a thing is not the thing: now fail2ban is asked WHICH FILES
        // each jail watches.
        RunResult f2b = run("sh", "-c", "fail2ban-client status 2>/dev/null");
        if (f2b.code == 0) {
            r.put("fail2banRead", true).put("jail", f2b.output.trim());

            List<String> names = new ArrayList<>();
            for (String line : f2b.output.split("\n")) {
                int i = line.toLowerCase(Locale.ROOT).indexOf("jail list:");
                if (i < 0) continue;
                for (String x : line.substring(i + "jail list:".length()).split(","))
                    if (!x.trim().isEmpty()) names.add(x.trim());
            }

            JSONArray watch = new JSONArray();
            boolean watchNginx = false;
            boolean allRead = true;
            for (String name : names) {
                RunResult lp = run("sh", "-c", "fail2ban-client get "
                        + name.replace("\"", "") + " logpath 2>/dev/null");
                if (lp.code != 0) { allRead = false; continue; }
                boolean onNginx = lp.output.contains("/nginx/") || lp.output.contains("nginx-");
                if (onNginx) watchNginx = true;

                // Which port it protects. It is not a property of the jail but of the ACTION
                // (fail2ban-client(1): "get <JAIL> actions", then "get <JAIL> action <ACT>
                // <property>"), so we go through there. A jail can have several actions and
                // each its own port.
                String actions = "";
                RunResult ac = run("sh", "-c", "fail2ban-client get " + safe(name) + " actions 2>/dev/null");
                if (ac.code == 0) actions = ac.output.trim();
                java.util.LinkedHashSet<String> ports = new java.util.LinkedHashSet<>();
                boolean readPorts = false;
                for (String az : actions.replaceAll("(?s).*?:", "").split(",")) {
                    String a = az.trim();
                    if (a.isEmpty()) continue;
                    RunResult pr = run("sh", "-c", "fail2ban-client get " + safe(name)
                            + " action " + safe(a) + " port 2>/dev/null");
                    if (pr.code != 0) continue;
                    String v = pr.output.trim();
                    if (!v.isEmpty() && !v.toLowerCase(Locale.ROOT).contains("not ")) {
                        ports.add(v); readPorts = true;
                    }
                }
                watch.put(new JSONObject().put("jail", name)
                        .put("log", lp.output.trim()).put("onNginx", onNginx)
                        .put("actions", actions)
                        .put("ports", String.join(", ", ports))
                        // "Not declared" is not "none": with pf's default action the
                        // ban applies to the address, not to a single port. Say so instead of
                        // leaving the cell empty, which reads as "protects nothing".
                        .put("declaredPort", readPorts));
            }
            r.put("jailWatch", watch);
            r.put("jailNginx", watchNginx);
            // "I could not ask all of them" is not "none watches nginx".
            r.put("allJailsRead", allRead);
        } else {
            r.put("fail2banRead", false);
        }

        r.put("verdict", verdict(r));
        return r;
    }

    /**
     * A name that ends up inside a shell line: only the characters of a jail
     *  or action name are accepted. A command is never built from what comes from outside.
     */
    private static String safe(String s) {
        return s == null ? "" : s.replaceAll("[^A-Za-z0-9._-]", "");
    }

    /** The summary, built only on what could be measured. */
    private static String verdict(JSONObject r) {
        List<String> p = new ArrayList<>();
        if (!r.optBoolean("nginxReadable", false))
            p.add(I18n.tr("server.webdiag.nginxUnreadable"));
        else {
            if (r.optBoolean("plainContents", false))
                p.add(I18n.tr("server.webdiag.plain80"));
            else if (r.optBoolean("port80Present", false))
                p.add(I18n.tr("server.webdiag.port80NoContent"));
            else
                p.add(I18n.tr("server.webdiag.httpsOnly"));

            if (!r.optBoolean("port443Present", false))
                p.add(I18n.tr("server.webdiag.no443"));

            if (!r.optBoolean("limitReq", false) && !r.optBoolean("limitConn", false))
                p.add(I18n.tr("server.webdiag.noLimits"));
        }
        if (r.optBoolean("fail2banRead", false)) {
            if (r.optBoolean("jailNginx", false)) {
                // We say WHICH one, so that whoever reads it can verify the statement.
                StringBuilder which = new StringBuilder();
                JSONArray sv = r.optJSONArray("jailWatch");
                for (int i = 0; sv != null && i < sv.length(); i++) {
                    JSONObject j = sv.optJSONObject(i);
                    if (j == null || !j.optBoolean("onNginx", false)) continue;
                    if (which.length() > 0) which.append(", ");
                    which.append(j.optString("jail", "?"));
                }
                p.add(I18n.tr("server.webdiag.jailWatches", java.util.Map.of("which", String.valueOf(which))));
            } else if (!r.optBoolean("allJailsRead", true)) {
                p.add(I18n.tr("server.webdiag.jailsUnknown"));
            } else {
                p.add(I18n.tr("server.webdiag.noNginxJail"));
            }
        }
        if (!r.optBoolean("pfRead", false))
            p.add(I18n.tr("server.webdiag.pfUnread"));
        return String.join(" ", p);
    }

    private static String firstLineWith(String text, String ago) {
        if (text == null) return "";
        for (String r : text.split("\n")) {
            String t = r.trim();
            if (t.startsWith("#")) continue;
            if (t.contains(ago)) return t;
        }
        return "";
    }

    private static String firstLines(String t, int n) {
        if (t == null) return "";
        String[] r = t.split("\n");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(n, r.length); i++) sb.append(r[i].trim()).append(" ");
        return sb.toString().trim();
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
