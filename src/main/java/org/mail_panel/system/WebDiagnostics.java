package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.util.Shell;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Cosa espone davvero il web server, letto dal server e non dedotto dagli script.
 *
 * Perche' serve una diagnostica invece di guardare il codice: il pannello contiene DUE
 * script di installazione che scrivono configurazioni nginx diverse. Uno mette un blocco
 * "listen 80" con server_name _ che serve la webmail IN CHIARO; l'altro scrive un file in
 * sites-enabled con il solo "listen 443 ssl". Guardando il codice non si puo' sapere quale
 * dei due abbia costruito questa macchina — e su nginx in produzione dedurre non basta.
 *
 * Qui si legge "nginx -T", che stampa la configurazione COMPLETA come nginx la vede davvero,
 * inclusi tutti i file inclusi. E' la sola fonte che non mente: se un file e' rimasto in giro
 * ma non e' incluso, li' dentro non compare; se qualcuno ha modificato a mano, li' si vede.
 *
 * Questa classe non modifica nulla. Legge, e quando un comando fallisce lo dice invece di
 * concludere: "non ho potuto guardare" e "va tutto bene" sono due risposte opposte.
 */
public class WebDiagnostics {

    private WebDiagnostics() {}

    /* ===================================================================
     * Il parser, come funzione pura
     * =================================================================== */

    public static class Block {
        public final List<String> listens = new ArrayList<>();
        public String names = "";
        public String root = "";
        public boolean encrypted;          // ha "ssl" fra i parametri di listen
        public boolean servePhp;
        public boolean serveFile;        // ha una root e un location che consegna qualcosa
        public boolean soloRedirect;     // non fa altro che rimandare altrove
        public int line;
    }

    /**
     * I blocchi "server" della configurazione, con cosa ascoltano e cosa servono.
     *
     * Il parser conta le graffe invece di cercare la fine con un'espressione regolare: dentro
     * un server ci sono altri blocchi (location, if) e una regex si fermerebbe alla prima
     * graffa chiusa, attribuendo al blocco sbagliato meta' delle direttive.
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
            String basso = t.toLowerCase(Locale.ROOT);

            if (basso.startsWith("listen ")) {
                String v = t.substring(7).replace(";", "").trim();
                b.listens.add(v);
                if (v.toLowerCase(Locale.ROOT).contains("ssl")) b.encrypted = true;
            } else if (basso.startsWith("server_name ")) {
                b.names = t.substring(12).replace(";", "").trim();
            } else if (basso.startsWith("root ")) {
                b.root = t.substring(5).replace(";", "").trim();
            } else if (basso.contains("fastcgi_pass") || basso.matches("location\\s+~\\s*\\\\?\\.php.*")) {
                b.servePhp = true;
            } else if (basso.startsWith("try_files") || basso.startsWith("index ")
                    || basso.startsWith("alias ")) {
                hasLocationWithContent = true;
            } else if (basso.startsWith("return ") || basso.startsWith("rewrite ")) {
                haReturn = true;
            }
        }
        b.serveFile = !b.root.isEmpty() && (hasLocationWithContent || b.servePhp);
        b.soloRedirect = haReturn && !b.serveFile && !b.servePhp;
    }

    /** Il blocco ascolta sulla porta indicata. */
    public static boolean listensOn(Block b, int port) {
        for (String a : b.listens) {
            String p = a.split("\\s+")[0];
            int i = p.lastIndexOf(':');
            String portOnly = i >= 0 ? p.substring(i + 1) : p;
            if (portOnly.equals(String.valueOf(port))) return true;
        }
        return false;
    }

    /* ===================================================================
     * Le misure sul server
     * =================================================================== */

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
                boolean su80 = listensOn(b, 80);
                boolean su443 = listensOn(b, 443);
                if (su80) eighty = true;
                boolean dangerous = su80 && !b.encrypted && (b.serveFile || b.servePhp);
                if (dangerous) inPlain = true;
                sites.put(new JSONObject()
                        .put("listens", String.join(", ", b.listens))
                        .put("names", b.names)
                        .put("root", b.root)
                        .put("encrypted", b.encrypted)
                        .put("servePhp", b.servePhp)
                        .put("serveFile", b.serveFile)
                        .put("soloRedirect", b.soloRedirect)
                        .put("su80", su80).put("su443", su443)
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

        // Chi e' davvero in ascolto sulla macchina, indipendentemente da nginx.
        RunResult sock = run("sh", "-c", "sockstat -4 -6 -l 2>/dev/null | awk 'NR==1 || $6 ~ /:(80|443)$/'");
        r.put("listening", sock.code == 0 ? sock.output.trim() : "")
         .put("listeningRead", sock.code == 0);

        // Il firewall: le porte web sono filtrate?
        RunResult pf = run("sh", "-c", "pfctl -sr 2>/dev/null");
        if (pf.code == 0 && !pf.output.isBlank()) {
            r.put("pfRead", true).put("pfRules", pf.output.trim().split("\n").length);
            r.put("pfMentions80", pf.output.contains(" 80") || pf.output.contains("{ 80"));
            r.put("pfMentions443", pf.output.contains("443"));
        } else {
            r.put("pfRead", false);
        }

        // fail2ban: c'e' una jail che guarda un log di nginx?
        //
        // Prima la domanda era posta al NOME: "l'elenco delle jail contiene la parola nginx?".
        // Sbagliava in tutte e due le direzioni. Su questo server la jail che protegge la 443
        // si chiama "mailpanel-pubblico" e guarda /var/log/nginx/mailpanel-pubblico-access.log:
        // un log di nginx a tutti gli effetti, ma senza quella parola nel nome — e la diagnosi
        // annunciava che nessuno viene bannato sulle porte web, mentre veniva bannato. Al
        // contrario, una jail chiamata "nginx-qualcosa" ma puntata altrove sarebbe passata per
        // buona. Il nome di una cosa non e' la cosa: adesso si chiede a fail2ban QUALI FILE
        // ogni jail sorveglia.
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
                boolean suNginx = lp.output.contains("/nginx/") || lp.output.contains("nginx-");
                if (suNginx) watchNginx = true;

                // Quale porta protegge. Non e' una proprieta' della jail ma dell'AZIONE
                // (fail2ban-client(1): "get <JAIL> actions", poi "get <JAIL> action <ACT>
                // <proprieta'>"), quindi si passa di li'. Una jail puo' avere piu' azioni e
                // ognuna la sua porta.
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
                        .put("log", lp.output.trim()).put("suNginx", suNginx)
                        .put("actions", actions)
                        .put("ports", String.join(", ", ports))
                        // "Non dichiarata" non e' "nessuna": con l'azione predefinita di pf il
                        // ban vale per l'indirizzo, non per una porta sola. Dirlo invece di
                        // lasciare la casella vuota, che si legge come "non protegge niente".
                        .put("declaredPort", readPorts));
            }
            r.put("jailWatch", watch);
            r.put("jailNginx", watchNginx);
            // "Non sono riuscito a chiedere a tutte" non e' "nessuna guarda nginx".
            r.put("allJailsRead", allRead);
        } else {
            r.put("fail2banRead", false);
        }

        r.put("verdict", verdict(r));
        return r;
    }

    /** Un nome che finisce dentro una riga di shell: si accettano solo i caratteri di un
     *  nome di jail o di azione. Non si costruisce un comando con quello che arriva da fuori. */
    private static String safe(String s) {
        return s == null ? "" : s.replaceAll("[^A-Za-z0-9._-]", "");
    }

    /** Il riassunto, costruito solo su cio' che si e' potuto misurare. */
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
                // Si dice QUALE, cosi' l'affermazione e' verificabile da chi legge.
                StringBuilder which = new StringBuilder();
                JSONArray sv = r.optJSONArray("jailWatch");
                for (int i = 0; sv != null && i < sv.length(); i++) {
                    JSONObject j = sv.optJSONObject(i);
                    if (j == null || !j.optBoolean("suNginx", false)) continue;
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
