package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * MTA-STS: la dichiarazione che i server di questo dominio parlano sempre TLS.
 *
 * A cosa serve. Fra due server di posta il TLS e' opportunistico: il mittente chiede
 * STARTTLS e se il destinatario non lo offre, consegna IN CHIARO. Un attaccante in mezzo puo'
 * cancellare quell'offerta mentre passa, e il mittente non ha modo di accorgersene: vede solo
 * un server che dice di non parlare TLS. MTA-STS chiude quella porta dicendo in anticipo
 * "i miei server il TLS ce l'hanno sempre: se non ci riesci, NON consegnare".
 *
 * Perche' non basta un record DNS, che e' il punto su cui questo lavoro si e' arenato a lungo.
 * RFC 8461 divide la cosa in due:
 *
 *   §3.1  il TXT su _mta-sts.<dominio> contiene solo "v=STSv1; id=..." — l'id serve ai
 *         mittenti per accorgersi che la politica e' cambiata. NON contiene la politica.
 *   §3.2  la politica vera sta su https://mta-sts.<dominio>/.well-known/mta-sts.txt, servita
 *         con un certificato valido PER QUEL NOME. E' quel certificato a dimostrare che la
 *         politica viene dal proprietario del dominio: MTA-STS non usa DNSSEC.
 *
 * Da qui la regola che governa questa classe: **il record TXT non si pubblica finche' la
 * politica non risponde davvero.** Pubblicarlo prima significa dichiarare pubblicamente una
 * protezione che non c'e', e i mittenti che vanno a leggerla trovano un 404. Il pannello
 * quindi va a CHIEDERE il file prima di permettere la pubblicazione, invece di fidarsi di
 * aver scritto la configurazione giusta.
 */
public class MtaSts {

    /** Il percorso fisso previsto da RFC 8461 §3.2. */
    public static final String PATH = "/.well-known/mta-sts.txt";

    private MtaSts() {}

    /* ===================================================================
     * Il file, come funzione pura
     * =================================================================== */

    /**
     * La politica. Campi e valori ammessi da §3.2: version, mode, mx (ripetibile), max_age.
     *
     * L'ABNF ammette sia LF sia CRLF come terminatore di riga (sts-policy-term = LF / CRLF):
     * si usa LF, che e' quello che il resto del pannello scrive.
     */
    public static String policy(String mailHost, String mode, int maxAge) {
        return "version: STSv1\n"
             + "mode: " + mode + "\n"
             + "mx: " + mailHost + "\n"
             + "max_age: " + maxAge + "\n";
    }

    /** I modi previsti dalla specifica. */
    public static boolean validMode(String m) {
        return m != null && List.of("testing", "enforce", "none").contains(m.trim().toLowerCase(Locale.ROOT));
    }

    /**
     * Quanto a lungo i mittenti tengono in memoria la politica.
     *
     * In "testing" si sta bassi: se qualcosa e' sbagliato, l'errore scade in un giorno invece
     * che in una settimana. In "enforce" si sta alti, perche' una politica che scade e non
     * viene riscaricata fa perdere la protezione proprio quando serve.
     */
    public static int recommendedMaxAge(String mode) {
        return "enforce".equalsIgnoreCase(mode) ? 604800 : 86400;
    }

    /**
     * L'id da mettere nel record TXT. §3.1 lo vuole di 1..32 caratteri alfanumerici.
     *
     * Si ricava dal CONTENUTO della politica, non dall'orologio: cosi' cambia se e solo se la
     * politica e' cambiata davvero. Un id che cambia a ogni lettura farebbe riscaricare la
     * politica di continuo a tutti i mittenti del mondo; uno che non cambia mai impedirebbe
     * loro di accorgersi di una modifica.
     */
    public static String id(String policy) {
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(policy.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 10; i++) sb.append(String.format("%02x", h[i]));
            return sb.toString();
        } catch (Exception e) {
            return "0000000000000000";
        }
    }

    /** Il contenuto del record TXT su _mta-sts.<dominio>. §3.1 */
    public static String recordTxt(String policy) {
        return "v=STSv1; id=" + id(policy);
    }

    /** Il dominio e' ospitato da questo pannello? Whitelist, come per autoconfig. */
    public static String managedDomain(String required) {
        if (required == null) return null;
        String r = required.trim().toLowerCase(Locale.ROOT);
        if (r.startsWith("mta-sts.")) r = r.substring("mta-sts.".length());
        int p = r.indexOf(':');
        if (p > 0) r = r.substring(0, p);
        if (r.isEmpty()) return null;
        // Stessa ragione dell'autoconfig: rotta pubblica, nessuna query per richiesta.
        return DomainCache.managed(r);
    }

    public static String mailHost() {
        try {
            return Main.mailDatabase.getSetting("mail_hostname", "");
        } catch (Exception e) {
            return "";
        }
    }

    /** Il modo scelto, conservato fra i settaggi. Si parte da "testing". */
    public static String currentMode() {
        try {
            String m = Main.mailDatabase.getSetting("mta_sts_mode", "testing");
            return validMode(m) ? m.toLowerCase(Locale.ROOT) : "testing";
        } catch (Exception e) {
            return "testing";
        }
    }

    public static JSONObject setMode(String mode) {
        if (!validMode(mode))
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.mtasts.badMode"));
        try {
            Main.mailDatabase.setSetting("mta_sts_mode", mode.toLowerCase(Locale.ROOT));
            return new JSONObject().put("success", true).put("mode", mode.toLowerCase(Locale.ROOT))
                    .put("note", "enforce".equalsIgnoreCase(mode)
                        ? I18n.tr("server.mtasts.modeEnforce")
                        : "none".equalsIgnoreCase(mode)
                        ? I18n.tr("server.mtasts.modeNone")
                        : I18n.tr("server.mtasts.modeTesting"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.mtasts.saveFailed", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("MtaSts", e))));
        }
    }

    /* ===================================================================
     * Lo stato reale, dominio per dominio
     * =================================================================== */

    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);
        String host = mailHost();
        String mode = currentMode();
        r.put("mailHost", host).put("mode", mode).put("path", PATH);
        if (host == null || host.isBlank())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.mtasts.noHostname"));

        String pol = policy(host, mode, recommendedMaxAge(mode));
        r.put("policy", pol).put("id", id(pol)).put("recordTxt", recordTxt(pol));

        JSONArray domains = new JSONArray();
        try {
            for (var d : Main.mailDatabase.getDomains()) {
                JSONObject j = new JSONObject().put("domain", d.domain)
                        .put("webName", "mta-sts." + d.domain)
                        .put("txtName", "_mta-sts." + d.domain);
                j.put("policyReachable", testPolicy("mta-sts." + d.domain, host, mode));
                domains.put(j);
            }
        } catch (Exception ignore) {}
        r.put("domains", domains);
        return r;
    }

    /**
     * Chiede la politica come farebbe un server mittente, e guarda cosa torna.
     *
     * E' l'unico controllo che conta: leggere la configurazione di nginx dice cosa DOVREBBE
     * succedere, questo dice cosa succede. Gli esiti restano distinti perche' "il certificato
     * non copre quel nome" e "il file non c'e'" hanno due rimedi opposti.
     */
    /** Come testPolicy, ma per un dominio qualsiasi: la usa la verifica DNS. */
    /**
     * Il record TXT che corrisponde alla politica servita ADESSO.
     *
     * Unico posto in cui quel valore si calcola. Ce n'erano due: qui la politica, e in
     * DnsRecordsGenerator un "v=STSv1; id=" + System.currentTimeMillis() che proponeva a chi
     * legge le istruzioni un id preso dall'orologio — diverso a ogni caricamento della pagina,
     * e per sempre scollegato dal contenuto della politica. L'id non e' decorativo: e' il
     * segnale con cui i mittenti si accorgono che la politica e' cambiata, e uno fermo li
     * lascia sulla copia vecchia finche' non scade.
     */
    public static String currentTxtRecord() {
        try {
            String mode = currentMode();
            return recordTxt(policy(mailHost(), mode, recommendedMaxAge(mode))).trim();
        } catch (Exception e) {
            // Meglio niente che un valore inventato: una stringa vuota non fa passare per
            // giusto nessun record, e non suggerisce a nessuno di pubblicare una sciocchezza.
            return "";
        }
    }

    public static JSONObject publicTest(String domain) {
        return testPolicy("mta-sts." + domain, mailHost(), currentMode());
    }

    /**
     * I codici 520-527 non esistono nell'HTTP: li restituisce Cloudflare, e nginx non li
     * emette mai. Se ne arriva uno, la richiesta e' passata dal proxy invece di andare
     * dritta al server — cioe' il nome ha ancora la nuvola arancione.
     * Significati dalla documentazione Cloudflare (Troubleshooting Cloudflare 5xx errors).
     */
    static String explainCode(int code) {
        String what;
        switch (code) {
            case 520: what = I18n.tr("server.mtasts.cf520"); break;
            case 521: what = I18n.tr("server.mtasts.cf521"); break;
            case 522: what = I18n.tr("server.mtasts.cf522"); break;
            case 523: what = I18n.tr("server.mtasts.cf523"); break;
            case 525: what = I18n.tr("server.mtasts.cf525"); break;
            case 526: what = I18n.tr("server.mtasts.cf526"); break;
            default: return "";
        }
        return " " + I18n.tr("server.mtasts.cfCode", java.util.Map.of("c", String.valueOf(code), "what", String.valueOf(what)));
    }

    private static JSONObject testPolicy(String webName, String mailHost, String mode) {
        JSONObject r = new JSONObject();
        String url = "https://" + webName + PATH;
        r.put("url", url);
        try {
            var http = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(6))
                    .followRedirects(java.net.http.HttpClient.Redirect.NEVER).build();
            var req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(url))
                    .timeout(java.time.Duration.ofSeconds(8)).GET().build();
            var resp = http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            r.put("code", resp.statusCode());
            String body = resp.body() == null ? "" : resp.body();
            boolean ok = resp.statusCode() == 200
                    && body.contains("version: STSv1")
                    && body.contains("mx: " + mailHost);
            r.put("ok", ok);
            if (!ok) {
                if (resp.statusCode() != 200)
                    r.put("error", I18n.tr("server.mtasts.status", java.util.Map.of("c", String.valueOf(resp.statusCode()))) + explainCode(resp.statusCode()));
                else if (!body.contains("version: STSv1"))
                    r.put("error", I18n.tr("server.mtasts.notPolicy"));
                else
                    r.put("error", I18n.tr("server.mtasts.noMx", java.util.Map.of("host", String.valueOf(mailHost))));
            }
            return r;
        } catch (javax.net.ssl.SSLException e) {
            return r.put("ok", false).put("tls", true)
                    .put("error", I18n.tr("server.mtasts.certInvalid", java.util.Map.of("name", String.valueOf(webName))));
        } catch (java.net.UnknownHostException e) {
            return r.put("ok", false).put("dns", true)
                    .put("error", I18n.tr("server.mtasts.noCname", java.util.Map.of("name", String.valueOf(webName))));
        } catch (Exception e) {
            return r.put("ok", false)
                    .put("error", I18n.tr("server.mtasts.unreachable", java.util.Map.of("err", String.valueOf(e.getClass().getSimpleName()))));
        }
    }

    /**
     * Si puo' pubblicare il record TXT per questo dominio?
     *
     * Solo se la politica risponde gia'. E' la regola che tiene onesto tutto il meccanismo:
     * il TXT e' una promessa pubblica, e non si fa una promessa prima di poterla mantenere.
     */
    public static JSONObject publishable(String domain) {
        String host = mailHost();
        String mode = currentMode();
        JSONObject test = testPolicy("mta-sts." + domain, host, mode);
        JSONObject r = new JSONObject().put("domain", domain).put("test", test);
        if (test.optBoolean("ok", false))
            return r.put("publishable", true)
                    .put("value", recordTxt(policy(host, mode, recommendedMaxAge(mode))));
        return r.put("publishable", false)
                .put("reason", I18n.tr("server.mtasts.notYet", java.util.Map.of("url", String.valueOf("https://mta-sts." + domain + PATH), "err", String.valueOf(test.optString("error", I18n.tr("server.mtasts.unknownReason"))))));
    }

    /** I domini gestiti, per l'interfaccia. */
    public static List<String> domains() {
        List<String> l = new ArrayList<>();
        try { for (var d : Main.mailDatabase.getDomains()) l.add(d.domain); } catch (Exception ignore) {}
        return l;
    }
}
