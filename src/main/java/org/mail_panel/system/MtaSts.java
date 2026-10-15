package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.Main;

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
    public static String politica(String mailHost, String modo, int maxAge) {
        return "version: STSv1\n"
             + "mode: " + modo + "\n"
             + "mx: " + mailHost + "\n"
             + "max_age: " + maxAge + "\n";
    }

    /** I modi previsti dalla specifica. */
    public static boolean modoValido(String m) {
        return m != null && List.of("testing", "enforce", "none").contains(m.trim().toLowerCase(Locale.ROOT));
    }

    /**
     * Quanto a lungo i mittenti tengono in memoria la politica.
     *
     * In "testing" si sta bassi: se qualcosa e' sbagliato, l'errore scade in un giorno invece
     * che in una settimana. In "enforce" si sta alti, perche' una politica che scade e non
     * viene riscaricata fa perdere la protezione proprio quando serve.
     */
    public static int maxAgeConsigliato(String modo) {
        return "enforce".equalsIgnoreCase(modo) ? 604800 : 86400;
    }

    /**
     * L'id da mettere nel record TXT. §3.1 lo vuole di 1..32 caratteri alfanumerici.
     *
     * Si ricava dal CONTENUTO della politica, non dall'orologio: cosi' cambia se e solo se la
     * politica e' cambiata davvero. Un id che cambia a ogni lettura farebbe riscaricare la
     * politica di continuo a tutti i mittenti del mondo; uno che non cambia mai impedirebbe
     * loro di accorgersi di una modifica.
     */
    public static String id(String politica) {
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(politica.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 10; i++) sb.append(String.format("%02x", h[i]));
            return sb.toString();
        } catch (Exception e) {
            return "0000000000000000";
        }
    }

    /** Il contenuto del record TXT su _mta-sts.<dominio>. §3.1 */
    public static String recordTxt(String politica) {
        return "v=STSv1; id=" + id(politica);
    }

    /** Il dominio e' ospitato da questo pannello? Whitelist, come per autoconfig. */
    public static String dominioGestito(String richiesto) {
        if (richiesto == null) return null;
        String r = richiesto.trim().toLowerCase(Locale.ROOT);
        if (r.startsWith("mta-sts.")) r = r.substring("mta-sts.".length());
        int p = r.indexOf(':');
        if (p > 0) r = r.substring(0, p);
        if (r.isEmpty()) return null;
        // Stessa ragione dell'autoconfig: rotta pubblica, nessuna query per richiesta.
        return DomainCache.gestito(r);
    }

    public static String hostDiPosta() {
        try {
            return Main.mailDatabase.getSetting("mail_hostname", "");
        } catch (Exception e) {
            return "";
        }
    }

    /** Il modo scelto, conservato fra i settaggi. Si parte da "testing". */
    public static String modoCorrente() {
        try {
            String m = Main.mailDatabase.getSetting("mta_sts_mode", "testing");
            return modoValido(m) ? m.toLowerCase(Locale.ROOT) : "testing";
        } catch (Exception e) {
            return "testing";
        }
    }

    public static JSONObject impostaModo(String modo) {
        if (!modoValido(modo))
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.mtasts.badMode"));
        try {
            Main.mailDatabase.setSetting("mta_sts_mode", modo.toLowerCase(Locale.ROOT));
            return new JSONObject().put("success", true).put("modo", modo.toLowerCase(Locale.ROOT))
                    .put("nota", "enforce".equalsIgnoreCase(modo)
                        ? I18n.tr("server.mtasts.modeEnforce")
                        : "none".equalsIgnoreCase(modo)
                        ? I18n.tr("server.mtasts.modeNone")
                        : I18n.tr("server.mtasts.modeTesting"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.mtasts.saveFailed", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    /* ===================================================================
     * Lo stato reale, dominio per dominio
     * =================================================================== */

    public static JSONObject stato() {
        JSONObject r = new JSONObject().put("success", true);
        String host = hostDiPosta();
        String modo = modoCorrente();
        r.put("hostDiPosta", host).put("modo", modo).put("percorso", PATH);
        if (host == null || host.isBlank())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.mtasts.noHostname"));

        String pol = politica(host, modo, maxAgeConsigliato(modo));
        r.put("politica", pol).put("id", id(pol)).put("recordTxt", recordTxt(pol));

        JSONArray domini = new JSONArray();
        try {
            for (var d : Main.mailDatabase.getDomains()) {
                JSONObject j = new JSONObject().put("dominio", d.domain)
                        .put("nomeWeb", "mta-sts." + d.domain)
                        .put("nomeTxt", "_mta-sts." + d.domain);
                j.put("politicaRaggiungibile", provaPolitica("mta-sts." + d.domain, host, modo));
                domini.put(j);
            }
        } catch (Exception ignore) {}
        r.put("domini", domini);
        return r;
    }

    /**
     * Chiede la politica come farebbe un server mittente, e guarda cosa torna.
     *
     * E' l'unico controllo che conta: leggere la configurazione di nginx dice cosa DOVREBBE
     * succedere, questo dice cosa succede. Gli esiti restano distinti perche' "il certificato
     * non copre quel nome" e "il file non c'e'" hanno due rimedi opposti.
     */
    /** Come provaPolitica, ma per un dominio qualsiasi: la usa la verifica DNS. */
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
    public static String recordTxtCorrente() {
        try {
            String modo = modoCorrente();
            return recordTxt(politica(hostDiPosta(), modo, maxAgeConsigliato(modo))).trim();
        } catch (Exception e) {
            // Meglio niente che un valore inventato: una stringa vuota non fa passare per
            // giusto nessun record, e non suggerisce a nessuno di pubblicare una sciocchezza.
            return "";
        }
    }

    public static JSONObject provaPubblica(String dominio) {
        return provaPolitica("mta-sts." + dominio, hostDiPosta(), modoCorrente());
    }

    /**
     * I codici 520-527 non esistono nell'HTTP: li restituisce Cloudflare, e nginx non li
     * emette mai. Se ne arriva uno, la richiesta e' passata dal proxy invece di andare
     * dritta al server — cioe' il nome ha ancora la nuvola arancione.
     * Significati dalla documentazione Cloudflare (Troubleshooting Cloudflare 5xx errors).
     */
    static String spiegaCodice(int codice) {
        String cosa;
        switch (codice) {
            case 520: cosa = I18n.tr("server.mtasts.cf520"); break;
            case 521: cosa = I18n.tr("server.mtasts.cf521"); break;
            case 522: cosa = I18n.tr("server.mtasts.cf522"); break;
            case 523: cosa = I18n.tr("server.mtasts.cf523"); break;
            case 525: cosa = I18n.tr("server.mtasts.cf525"); break;
            case 526: cosa = I18n.tr("server.mtasts.cf526"); break;
            default: return "";
        }
        return " " + I18n.tr("server.mtasts.cfCode", java.util.Map.of("c", String.valueOf(codice), "what", String.valueOf(cosa)));
    }

    private static JSONObject provaPolitica(String nomeWeb, String mailHost, String modo) {
        JSONObject r = new JSONObject();
        String url = "https://" + nomeWeb + PATH;
        r.put("url", url);
        try {
            var http = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(6))
                    .followRedirects(java.net.http.HttpClient.Redirect.NEVER).build();
            var req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(url))
                    .timeout(java.time.Duration.ofSeconds(8)).GET().build();
            var resp = http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            r.put("codice", resp.statusCode());
            String corpo = resp.body() == null ? "" : resp.body();
            boolean ok = resp.statusCode() == 200
                    && corpo.contains("version: STSv1")
                    && corpo.contains("mx: " + mailHost);
            r.put("ok", ok);
            if (!ok) {
                if (resp.statusCode() != 200)
                    r.put("errore", I18n.tr("server.mtasts.status", java.util.Map.of("c", String.valueOf(resp.statusCode()))) + spiegaCodice(resp.statusCode()));
                else if (!corpo.contains("version: STSv1"))
                    r.put("errore", I18n.tr("server.mtasts.notPolicy"));
                else
                    r.put("errore", I18n.tr("server.mtasts.noMx", java.util.Map.of("host", String.valueOf(mailHost))));
            }
            return r;
        } catch (javax.net.ssl.SSLException e) {
            return r.put("ok", false).put("tls", true)
                    .put("errore", I18n.tr("server.mtasts.certInvalid", java.util.Map.of("name", String.valueOf(nomeWeb))));
        } catch (java.net.UnknownHostException e) {
            return r.put("ok", false).put("dns", true)
                    .put("errore", I18n.tr("server.mtasts.noCname", java.util.Map.of("name", String.valueOf(nomeWeb))));
        } catch (Exception e) {
            return r.put("ok", false)
                    .put("errore", I18n.tr("server.mtasts.unreachable", java.util.Map.of("err", String.valueOf(e.getClass().getSimpleName()))));
        }
    }

    /**
     * Si puo' pubblicare il record TXT per questo dominio?
     *
     * Solo se la politica risponde gia'. E' la regola che tiene onesto tutto il meccanismo:
     * il TXT e' una promessa pubblica, e non si fa una promessa prima di poterla mantenere.
     */
    public static JSONObject pubblicabile(String dominio) {
        String host = hostDiPosta();
        String modo = modoCorrente();
        JSONObject prova = provaPolitica("mta-sts." + dominio, host, modo);
        JSONObject r = new JSONObject().put("dominio", dominio).put("prova", prova);
        if (prova.optBoolean("ok", false))
            return r.put("pubblicabile", true)
                    .put("valore", recordTxt(politica(host, modo, maxAgeConsigliato(modo))));
        return r.put("pubblicabile", false)
                .put("motivo", I18n.tr("server.mtasts.notYet", java.util.Map.of("url", String.valueOf("https://mta-sts." + dominio + PATH), "err", String.valueOf(prova.optString("errore", I18n.tr("server.mtasts.unknownReason"))))));
    }

    /** I domini gestiti, per l'interfaccia. */
    public static List<String> domini() {
        List<String> l = new ArrayList<>();
        try { for (var d : Main.mailDatabase.getDomains()) l.add(d.domain); } catch (Exception ignore) {}
        return l;
    }
}
