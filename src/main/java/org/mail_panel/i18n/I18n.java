package org.mail_panel.i18n;

import com.sun.net.httpserver.HttpExchange;
import org.json.JSONObject;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Le lingue dell'interfaccia: italiano e inglese.
 *
 * I testi stanno solo in lang/it.json e lang/en.json, dentro il jar, con le stesse chiavi (lo
 * controlla I18nTest). Le pagine scrivono {{t:chiave}} dove va un testo e il server lo
 * sostituisce a ogni richiesta, gia' come HTML sicuro; gli script chiamano t('chiave') e leggono
 * lo stesso dizionario da /i18n/(lingua).js, che il browser tiene in cache.
 *
 * La lingua di una richiesta: quella salvata nell'account, se c'e' una sessione; poi il cookie
 * __Host-lang (la scelta fatta su questo browser, anche prima di entrare); poi la lingua del
 * browser (Accept-Language); e per un browser che non chiede ne' italiano ne' inglese, l'inglese.
 */
public final class I18n {

    public static final List<String> LANGUAGES = List.of("it", "en");
    /** La lingua in cui il pannello e' scritto: un testo che manca in inglese si mostra in italiano. */
    public static final String SOURCE_LANGUAGE = "it";
    /** Per un browser che non chiede ne' italiano ne' inglese. */
    public static final String FALLBACK_LANGUAGE = "en";
    public static final String COOKIE = "__Host-lang";

    static final Pattern KEY = Pattern.compile("[A-Za-z0-9_.-]{1,120}");
    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{t:([A-Za-z0-9_.-]{1,120})\\}\\}");
    static final Pattern PARAM = Pattern.compile("\\{([A-Za-z0-9_]{1,40})\\}");

    private static final Map<String, Map<String, String>> BUNDLES = new LinkedHashMap<>();
    private static final Map<String, String> SCRIPTS = new LinkedHashMap<>();
    private static final Map<String, String> VERSIONS = new LinkedHashMap<>();
    private static final List<String> PROBLEMS = new ArrayList<>();
    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    static {
        // Prima l'italiano: l'inglese prende da li' i testi che non ha ancora.
        for (String lang : LANGUAGES) BUNDLES.put(lang, load(lang));
        for (String lang : LANGUAGES) {
            String script = buildScript(lang);
            SCRIPTS.put(lang, script);
            VERSIONS.put(lang, sha256(script).substring(0, 12));
        }
    }

    private I18n() {}

    /**
     * Un file di lingua. Se e' rotto il pannello non si ferma: si scrive il problema (le prove lo
     * leggono da problems()) e si va avanti con quello che c'e', mostrando le chiavi al posto dei
     * testi che mancano.
     */
    private static Map<String, String> load(String lang) {
        String path = "/lang/" + lang + ".json";
        Map<String, String> bundle = new TreeMap<>();
        int before = PROBLEMS.size();
        try (InputStream in = I18n.class.getResourceAsStream(path)) {
            if (in == null) {
                PROBLEMS.add(path + ": missing from the jar");
                return Collections.unmodifiableMap(bundle);
            }
            JSONObject json = new JSONObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
            for (String key : json.keySet()) {
                Object value = json.get(key);
                if (!KEY.matcher(key).matches()) PROBLEMS.add(path + ": invalid key \"" + key + "\"");
                else if (!(value instanceof String text)) PROBLEMS.add(path + ": \"" + key + "\" is not a string");
                else bundle.put(key, text);
            }
        } catch (Exception e) {
            PROBLEMS.add(path + ": " + e.getMessage());
        }
        for (String p : PROBLEMS.subList(before, PROBLEMS.size())) System.err.println("[i18n] " + p);
        return Collections.unmodifiableMap(bundle);
    }

    /** I problemi trovati leggendo i file di lingua: vuoto se e' tutto a posto. */
    public static List<String> problems() {
        return List.copyOf(PROBLEMS);
    }

    /** Il dizionario di una lingua, solo i testi che ha davvero (per le prove). */
    public static Map<String, String> bundle(String lang) {
        return BUNDLES.getOrDefault(lang, Map.of());
    }

    /** La lingua se e' una di quelle del pannello, altrimenti quella in cui e' scritto. */
    public static String normalize(String lang) {
        return lang != null && LANGUAGES.contains(lang) ? lang : SOURCE_LANGUAGE;
    }

    /** Un testo nella lingua chiesta; se manca, in italiano; se manca anche li', la chiave stessa. */
    public static String t(String lang, String key) {
        String text = BUNDLES.get(normalize(lang)).get(key);
        if (text == null) text = BUNDLES.get(SOURCE_LANGUAGE).get(key);
        return text != null ? text : key;
    }

    /** Un testo con i suoi valori: {nome} diventa params.get("nome"). Il risultato non e' HTML. */
    public static String t(String lang, String key, Map<String, ?> params) {
        return format(t(lang, key), params);
    }

    static String format(String text, Map<String, ?> params) {
        if (params == null || params.isEmpty()) return text;
        Matcher m = PARAM.matcher(text);
        StringBuilder out = new StringBuilder(text.length() + 32);
        while (m.find()) {
            Object value = params.get(m.group(1));
            m.appendReplacement(out, Matcher.quoteReplacement(value == null ? m.group(0) : String.valueOf(value)));
        }
        m.appendTail(out);
        return out.toString();
    }

    /**
     * Le sostituzioni di ogni pagina: {{t:chiave}} con il testo gia' come HTML sicuro (vale anche
     * dentro un attributo), {{lang}} con la lingua, {{i18nVersion}} con l'impronta del dizionario
     * (per l'indirizzo di /i18n/(lingua).js: quando cambia un testo cambia l'indirizzo, e il
     * browser non usa quello vecchio in cache). Negli script non si usa {{t:...}}: li' t('chiave').
     *
     * Le chiavi che finiscono in ".html" entrano cosi' come sono: sono frasi con dentro un
     * grassetto o un comando (strong, em, code, kbd, br), che non si possono spezzare in pezzi
     * perche' l'ordine delle parole cambia da una lingua all'altra. Stanno nei file di lingua del
     * pannello, non arrivano mai da chi usa il pannello, e I18nTest controlla che non abbiano
     * altri tag.
     */
    public static String render(String html, String lang) {
        String l = normalize(lang);
        Matcher m = PLACEHOLDER.matcher(html);
        StringBuilder out = new StringBuilder(html.length() + 1024);
        while (m.find()) {
            String text = t(l, m.group(1));
            m.appendReplacement(out, Matcher.quoteReplacement(m.group(1).endsWith(".html") ? text : escapeHtml(text)));
        }
        m.appendTail(out);
        return out.toString().replace("{{lang}}", l).replace("{{i18nVersion}}", VERSIONS.get(l));
    }

    /** Il dizionario per gli script della pagina, con t() e tn(): e' quello che serve /i18n/(lingua).js. */
    public static String script(String lang) {
        return SCRIPTS.get(normalize(lang));
    }

    public static String version(String lang) {
        return VERSIONS.get(normalize(lang));
    }

    private static String buildScript(String lang) {
        // Completo: quello che l'inglese non ha ancora lo prende dall'italiano, come t() qui sopra.
        Map<String, String> all = new TreeMap<>(BUNDLES.get(SOURCE_LANGUAGE));
        all.putAll(BUNDLES.get(lang));
        return "window.I18N_LANG=" + JSONObject.quote(lang) + ";\n"
             + "window.I18N=" + new JSONObject(all) + ";\n"
             + T_FUNCTIONS;
    }

    /**
     * t(chiave, valori) e tn(chiave, numero, valori) per gli script. tn sceglie chiave.one o
     * chiave.other: italiano e inglese hanno la stessa regola (uno, altrimenti molti), e il numero
     * e' gia' fra i valori come {n}. I valori entrano cosi' come sono: il risultato e' testo, da
     * mettere con textContent o da passare per escHtml() prima di innerHTML.
     */
    private static final String T_FUNCTIONS = """
        function t(key, params) {
            var text = Object.prototype.hasOwnProperty.call(window.I18N, key) ? window.I18N[key] : key;
            if (!params) return text;
            return text.replace(/\\{([A-Za-z0-9_]{1,40})\\}/g, function (all, name) {
                return Object.prototype.hasOwnProperty.call(params, name) && params[name] != null ? String(params[name]) : all;
            });
        }
        // Un testo dentro dell'HTML costruito a mano (innerHTML, un attributo fra virgolette).
        function escHtml(text) {
            return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }
        function tn(key, count, params) {
            var values = Object.assign({ n: count }, params || {});
            return t(key + (count === 1 ? '.one' : '.other'), values);
        }
        // La frase tradotta come nodi: dove c'e' {nome} e params.nome e' un elemento (un <code>
        // con un percorso, un badge), ci va quell'elemento; il resto e' testo. Cosi' la frase resta
        // intera nella sua lingua e niente diventa HTML: el.append(...tNodes('chiave', { file: code })).
        function tNodes(key, params) {
            var text = Object.prototype.hasOwnProperty.call(window.I18N, key) ? window.I18N[key] : key;
            var nodes = [], re = /\\{([A-Za-z0-9_]{1,40})\\}/g, last = 0, m;
            while ((m = re.exec(text)) !== null) {
                if (m.index > last) nodes.push(document.createTextNode(text.slice(last, m.index)));
                var v = params && Object.prototype.hasOwnProperty.call(params, m[1]) ? params[m[1]] : m[0];
                nodes.push(v instanceof Node ? v : document.createTextNode(String(v)));
                last = re.lastIndex;
            }
            if (last < text.length) nodes.push(document.createTextNode(text.slice(last)));
            return nodes;
        }
        """;

    // ---------- la lingua della richiesta in corso, per i messaggi del server ----------

    /**
     * La lingua della richiesta che questo thread sta servendo: la fissa SSLMailServer all'ingresso
     * di ogni handler (context) e la toglie all'uscita. Cosi' il codice del server traduce i suoi
     * messaggi con tr() senza passarsi la lingua di funzione in funzione. Un lavoro che continua su
     * un altro thread se la porta dietro: current() alla partenza, setCurrent() nel thread nuovo.
     */
    public static void setCurrent(String lang) {
        CURRENT.set(normalize(lang));
    }

    public static void clearCurrent() {
        CURRENT.remove();
    }

    /** La lingua della richiesta in corso; fuori da una richiesta (avvio, prove), l'italiano. */
    public static String current() {
        String lang = CURRENT.get();
        return lang != null ? lang : SOURCE_LANGUAGE;
    }

    /** Un testo nella lingua della richiesta in corso. */
    public static String tr(String key) {
        return t(current(), key);
    }

    /** Un testo con i suoi valori nella lingua della richiesta in corso. Il risultato non e' HTML. */
    public static String tr(String key, Map<String, ?> params) {
        return t(current(), key, params);
    }

    /** Come tn() negli script: chiave.one o chiave.other secondo il numero, che entra come {n}. */
    public static String trn(String key, long count, Map<String, ?> params) {
        Map<String, Object> values = new java.util.HashMap<>(params);
        values.put("n", count);
        return t(current(), key + (count == 1 ? ".one" : ".other"), values);
    }

    /**
     * Il lavoro con la lingua di chi l'ha chiesto, per un thread che parte adesso e finisce dopo
     * (i lavori sul turno dei pacchetti, i lavori lunghi): i suoi messaggi escono in quella lingua.
     */
    public static Runnable withCurrent(Runnable job) {
        String lang = current();
        return () -> {
            setCurrent(lang);
            try {
                job.run();
            } finally {
                clearCurrent();
            }
        };
    }

    // ---------- la lingua di una richiesta ----------

    /**
     * La lingua di questa richiesta. saved e' quella dell'account (null prima di entrare o se non
     * e' mai stata scelta): vince su tutto, cosi' la scelta segue l'amministratore su ogni browser.
     */
    public static String languageOf(HttpExchange exchange, String saved) {
        if (saved != null && LANGUAGES.contains(saved)) return saved;
        String fromCookie = fromCookie(exchange.getRequestHeaders().get("Cookie"));
        if (fromCookie != null) return fromCookie;
        return fromAcceptLanguage(exchange.getRequestHeaders().getFirst("Accept-Language"));
    }

    /** Il valore del cookie della lingua, se e' una lingua del pannello. */
    public static String fromCookie(List<String> cookieHeaders) {
        if (cookieHeaders == null) return null;
        for (String header : cookieHeaders) {
            for (String pair : header.split(";")) {
                int eq = pair.indexOf('=');
                if (eq > 0 && pair.substring(0, eq).trim().equals(COOKIE)) {
                    String value = pair.substring(eq + 1).trim();
                    if (LANGUAGES.contains(value)) return value;
                }
            }
        }
        return null;
    }

    /**
     * La lingua preferita dal browser fra quelle del pannello, secondo i pesi q ("it-IT,it;q=0.9,
     * en;q=0.8"); a parita' vince quella scritta prima. Nessuna delle due: l'inglese.
     */
    public static String fromAcceptLanguage(String header) {
        if (header == null || header.isBlank()) return FALLBACK_LANGUAGE;
        if (header.length() > 1000) header = header.substring(0, 1000);
        String best = null;
        double bestWeight = 0;
        for (String part : header.split(",")) {
            String[] bits = part.trim().split(";");
            String primary = bits[0].trim().toLowerCase(Locale.ROOT).split("-")[0];
            double weight = 1.0;
            for (int i = 1; i < bits.length; i++) {
                String param = bits[i].trim();
                if (param.startsWith("q=")) {
                    try {
                        weight = Double.parseDouble(param.substring(2));
                    } catch (NumberFormatException e) {
                        weight = 0;
                    }
                }
            }
            if (LANGUAGES.contains(primary) && weight > bestWeight) {
                best = primary;
                bestWeight = weight;
            }
        }
        return best != null ? best : FALLBACK_LANGUAGE;
    }

    /** Il cookie della lingua: un anno, solo su HTTPS, mai leggibile dagli script. */
    public static String cookieHeader(String lang) {
        return COOKIE + "=" + normalize(lang) + "; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax";
    }

    // ---------- piccoli attrezzi ----------

    public static String escapeHtml(String text) {
        StringBuilder out = new StringBuilder(text.length() + 16);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "000000000000";
        }
    }
}
