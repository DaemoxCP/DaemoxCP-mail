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

    public static class Blocco {
        public final List<String> ascolta = new ArrayList<>();
        public String nomi = "";
        public String radice = "";
        public boolean cifrato;          // ha "ssl" fra i parametri di listen
        public boolean servePhp;
        public boolean serveFile;        // ha una root e un location che consegna qualcosa
        public boolean soloRedirect;     // non fa altro che rimandare altrove
        public int riga;
    }

    /**
     * I blocchi "server" della configurazione, con cosa ascoltano e cosa servono.
     *
     * Il parser conta le graffe invece di cercare la fine con un'espressione regolare: dentro
     * un server ci sono altri blocchi (location, if) e una regex si fermerebbe alla prima
     * graffa chiusa, attribuendo al blocco sbagliato meta' delle direttive.
     */
    public static List<Blocco> blocchi(String dump) {
        List<Blocco> fuori = new ArrayList<>();
        if (dump == null) return fuori;
        String[] righe = dump.split("\n");
        for (int i = 0; i < righe.length; i++) {
            String t = righe[i].trim();
            if (t.startsWith("#")) continue;
            if (!t.equals("server {") && !t.startsWith("server {") && !t.equals("server")) continue;

            Blocco b = new Blocco();
            b.riga = i + 1;
            int profondita = contaGraffe(righe[i]);
            int j = i + 1;
            StringBuilder corpo = new StringBuilder();
            while (j < righe.length && profondita > 0) {
                corpo.append(righe[j]).append("\n");
                profondita += contaGraffe(righe[j]);
                j++;
            }
            leggiCorpo(b, corpo.toString());
            fuori.add(b);
            i = j - 1;
        }
        return fuori;
    }

    private static int contaGraffe(String riga) {
        int n = 0;
        boolean commento = false;
        for (char c : riga.toCharArray()) {
            if (c == '#') commento = true;
            if (commento) continue;
            if (c == '{') n++;
            else if (c == '}') n--;
        }
        return n;
    }

    private static void leggiCorpo(Blocco b, String corpo) {
        boolean haLocationConContenuto = false, haReturn = false;
        for (String r : corpo.split("\n")) {
            String t = r.trim();
            if (t.startsWith("#")) continue;
            String basso = t.toLowerCase(Locale.ROOT);

            if (basso.startsWith("listen ")) {
                String v = t.substring(7).replace(";", "").trim();
                b.ascolta.add(v);
                if (v.toLowerCase(Locale.ROOT).contains("ssl")) b.cifrato = true;
            } else if (basso.startsWith("server_name ")) {
                b.nomi = t.substring(12).replace(";", "").trim();
            } else if (basso.startsWith("root ")) {
                b.radice = t.substring(5).replace(";", "").trim();
            } else if (basso.contains("fastcgi_pass") || basso.matches("location\\s+~\\s*\\\\?\\.php.*")) {
                b.servePhp = true;
            } else if (basso.startsWith("try_files") || basso.startsWith("index ")
                    || basso.startsWith("alias ")) {
                haLocationConContenuto = true;
            } else if (basso.startsWith("return ") || basso.startsWith("rewrite ")) {
                haReturn = true;
            }
        }
        b.serveFile = !b.radice.isEmpty() && (haLocationConContenuto || b.servePhp);
        b.soloRedirect = haReturn && !b.serveFile && !b.servePhp;
    }

    /** Il blocco ascolta sulla porta indicata. */
    public static boolean ascoltaSu(Blocco b, int porta) {
        for (String a : b.ascolta) {
            String p = a.split("\\s+")[0];
            int i = p.lastIndexOf(':');
            String soloPorta = i >= 0 ? p.substring(i + 1) : p;
            if (soloPorta.equals(String.valueOf(porta))) return true;
        }
        return false;
    }

    /* ===================================================================
     * Le misure sul server
     * =================================================================== */

    public static JSONObject stato() {
        JSONObject r = new JSONObject().put("success", true);

        Ris dump = esegui("nginx", "-T");
        if (dump.codice != 0) {
            r.put("nginxLeggibile", false)
             .put("nginxProblema", I18n.tr("server.webdiag.dumpFailed", java.util.Map.of("out", String.valueOf(primeRighe(dump.uscita, 3)))));
        } else {
            r.put("nginxLeggibile", true);
            List<Blocco> bl = blocchi(dump.uscita);
            JSONArray siti = new JSONArray();
            boolean inChiaro = false, ottanta = false;
            for (Blocco b : bl) {
                boolean su80 = ascoltaSu(b, 80);
                boolean su443 = ascoltaSu(b, 443);
                if (su80) ottanta = true;
                boolean pericoloso = su80 && !b.cifrato && (b.serveFile || b.servePhp);
                if (pericoloso) inChiaro = true;
                siti.put(new JSONObject()
                        .put("ascolta", String.join(", ", b.ascolta))
                        .put("nomi", b.nomi)
                        .put("radice", b.radice)
                        .put("cifrato", b.cifrato)
                        .put("servePhp", b.servePhp)
                        .put("serveFile", b.serveFile)
                        .put("soloRedirect", b.soloRedirect)
                        .put("su80", su80).put("su443", su443)
                        .put("inChiaro", pericoloso));
            }
            boolean quattro43 = false;
            for (Blocco b : bl) if (ascoltaSu(b, 443)) quattro43 = true;
            r.put("siti", siti).put("porta80Presente", ottanta).put("contenutiInChiaro", inChiaro)
             .put("porta443Presente", quattro43);

            boolean limReq = dump.uscita.contains("limit_req"), limConn = dump.uscita.contains("limit_conn");
            r.put("limitReq", limReq).put("limitConn", limConn);
            r.put("sslProtocols", primaRigaCon(dump.uscita, "ssl_protocols"));
            r.put("workerConnections", primaRigaCon(dump.uscita, "worker_connections"));
        }

        // Chi e' davvero in ascolto sulla macchina, indipendentemente da nginx.
        Ris sock = esegui("sh", "-c", "sockstat -4 -6 -l 2>/dev/null | awk 'NR==1 || $6 ~ /:(80|443)$/'");
        r.put("inAscolto", sock.codice == 0 ? sock.uscita.trim() : "")
         .put("inAscoltoLetto", sock.codice == 0);

        // Il firewall: le porte web sono filtrate?
        Ris pf = esegui("sh", "-c", "pfctl -sr 2>/dev/null");
        if (pf.codice == 0 && !pf.uscita.isBlank()) {
            r.put("pfLetto", true).put("pfRegole", pf.uscita.trim().split("\n").length);
            r.put("pfCita80", pf.uscita.contains(" 80") || pf.uscita.contains("{ 80"));
            r.put("pfCita443", pf.uscita.contains("443"));
        } else {
            r.put("pfLetto", false);
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
        Ris f2b = esegui("sh", "-c", "fail2ban-client status 2>/dev/null");
        if (f2b.codice == 0) {
            r.put("fail2banLetto", true).put("jail", f2b.uscita.trim());

            List<String> nomi = new ArrayList<>();
            for (String riga : f2b.uscita.split("\n")) {
                int i = riga.toLowerCase(Locale.ROOT).indexOf("jail list:");
                if (i < 0) continue;
                for (String x : riga.substring(i + "jail list:".length()).split(","))
                    if (!x.trim().isEmpty()) nomi.add(x.trim());
            }

            JSONArray sorveglianza = new JSONArray();
            boolean guardaNginx = false;
            boolean tutteLette = true;
            for (String nome : nomi) {
                Ris lp = esegui("sh", "-c", "fail2ban-client get "
                        + nome.replace("\"", "") + " logpath 2>/dev/null");
                if (lp.codice != 0) { tutteLette = false; continue; }
                boolean suNginx = lp.uscita.contains("/nginx/") || lp.uscita.contains("nginx-");
                if (suNginx) guardaNginx = true;

                // Quale porta protegge. Non e' una proprieta' della jail ma dell'AZIONE
                // (fail2ban-client(1): "get <JAIL> actions", poi "get <JAIL> action <ACT>
                // <proprieta'>"), quindi si passa di li'. Una jail puo' avere piu' azioni e
                // ognuna la sua porta.
                String azioni = "";
                Ris ac = esegui("sh", "-c", "fail2ban-client get " + sicuro(nome) + " actions 2>/dev/null");
                if (ac.codice == 0) azioni = ac.uscita.trim();
                java.util.LinkedHashSet<String> porte = new java.util.LinkedHashSet<>();
                boolean porteLette = false;
                for (String az : azioni.replaceAll("(?s).*?:", "").split(",")) {
                    String a = az.trim();
                    if (a.isEmpty()) continue;
                    Ris pr = esegui("sh", "-c", "fail2ban-client get " + sicuro(nome)
                            + " action " + sicuro(a) + " port 2>/dev/null");
                    if (pr.codice != 0) continue;
                    String v = pr.uscita.trim();
                    if (!v.isEmpty() && !v.toLowerCase(Locale.ROOT).contains("not ")) {
                        porte.add(v); porteLette = true;
                    }
                }
                sorveglianza.put(new JSONObject().put("jail", nome)
                        .put("log", lp.uscita.trim()).put("suNginx", suNginx)
                        .put("azioni", azioni)
                        .put("porte", String.join(", ", porte))
                        // "Non dichiarata" non e' "nessuna": con l'azione predefinita di pf il
                        // ban vale per l'indirizzo, non per una porta sola. Dirlo invece di
                        // lasciare la casella vuota, che si legge come "non protegge niente".
                        .put("portaDichiarata", porteLette));
            }
            r.put("jailSorveglianza", sorveglianza);
            r.put("jailNginx", guardaNginx);
            // "Non sono riuscito a chiedere a tutte" non e' "nessuna guarda nginx".
            r.put("jailTutteLette", tutteLette);
        } else {
            r.put("fail2banLetto", false);
        }

        r.put("verdetto", verdetto(r));
        return r;
    }

    /** Un nome che finisce dentro una riga di shell: si accettano solo i caratteri di un
     *  nome di jail o di azione. Non si costruisce un comando con quello che arriva da fuori. */
    private static String sicuro(String s) {
        return s == null ? "" : s.replaceAll("[^A-Za-z0-9._-]", "");
    }

    /** Il riassunto, costruito solo su cio' che si e' potuto misurare. */
    private static String verdetto(JSONObject r) {
        List<String> p = new ArrayList<>();
        if (!r.optBoolean("nginxLeggibile", false))
            p.add(I18n.tr("server.webdiag.nginxUnreadable"));
        else {
            if (r.optBoolean("contenutiInChiaro", false))
                p.add(I18n.tr("server.webdiag.plain80"));
            else if (r.optBoolean("porta80Presente", false))
                p.add(I18n.tr("server.webdiag.port80NoContent"));
            else
                p.add(I18n.tr("server.webdiag.httpsOnly"));

            if (!r.optBoolean("porta443Presente", false))
                p.add(I18n.tr("server.webdiag.no443"));

            if (!r.optBoolean("limitReq", false) && !r.optBoolean("limitConn", false))
                p.add(I18n.tr("server.webdiag.noLimits"));
        }
        if (r.optBoolean("fail2banLetto", false)) {
            if (r.optBoolean("jailNginx", false)) {
                // Si dice QUALE, cosi' l'affermazione e' verificabile da chi legge.
                StringBuilder quali = new StringBuilder();
                JSONArray sv = r.optJSONArray("jailSorveglianza");
                for (int i = 0; sv != null && i < sv.length(); i++) {
                    JSONObject j = sv.optJSONObject(i);
                    if (j == null || !j.optBoolean("suNginx", false)) continue;
                    if (quali.length() > 0) quali.append(", ");
                    quali.append(j.optString("jail", "?"));
                }
                p.add(I18n.tr("server.webdiag.jailWatches", java.util.Map.of("which", String.valueOf(quali))));
            } else if (!r.optBoolean("jailTutteLette", true)) {
                p.add(I18n.tr("server.webdiag.jailsUnknown"));
            } else {
                p.add(I18n.tr("server.webdiag.noNginxJail"));
            }
        }
        if (!r.optBoolean("pfLetto", false))
            p.add(I18n.tr("server.webdiag.pfUnread"));
        return String.join(" ", p);
    }

    private static String primaRigaCon(String testo, String ago) {
        if (testo == null) return "";
        for (String r : testo.split("\n")) {
            String t = r.trim();
            if (t.startsWith("#")) continue;
            if (t.contains(ago)) return t;
        }
        return "";
    }

    private static String primeRighe(String t, int n) {
        if (t == null) return "";
        String[] r = t.split("\n");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(n, r.length); i++) sb.append(r[i].trim()).append(" ");
        return sb.toString().trim();
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
