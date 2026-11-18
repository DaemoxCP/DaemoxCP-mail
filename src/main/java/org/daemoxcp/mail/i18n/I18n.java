package org.daemoxcp.mail.i18n;

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
 * Le lingue dell'interfaccia: quelle che hanno un file in lang/ (oggi italiano e inglese).
 *
 * I testi stanno solo in lang/(codice).json, dentro il jar: it.json ed en.json completi e con le stesse chiavi
 * (lo controlla I18nTest), ogni altra lingua anche parziale. Una lingua nuova e' un file in piu' col codice ISO
 * 639-1 (es.json, fr.json): la si trova da sola all'avvio. Un testo che manca in una lingua si mostra in inglese,
 * e se manca anche li' in italiano (la lingua in cui il pannello e' scritto).
 *
 * Le pagine scrivono {{t:chiave}} dove va un testo e il server lo sostituisce a ogni richiesta, gia' come HTML
 * sicuro; gli script chiamano t('chiave') e leggono lo stesso dizionario da /i18n/(lingua).js, che il browser
 * tiene in cache.
 *
 * La lingua di una richiesta: quella salvata nell'account, se c'e' una sessione; poi il cookie
 * __Host-lang (la scelta fatta su questo browser, anche prima di entrare); poi la lingua del
 * browser (Accept-Language); e per un browser che non chiede ne' italiano ne' inglese, l'inglese.
 */
public final class I18n {

    /** La lingua in cui il pannello e' scritto: l'ultima della catena dei testi che mancano. */
    public static final String SOURCE_LANGUAGE = "it";
    /** Per un browser che non chiede nessuna lingua del pannello, e la prima a cui si chiede un testo che manca. */
    public static final String FALLBACK_LANGUAGE = "en";
    /** Un codice di lingua ISO 639-1: due lettere minuscole, e nient'altro arriva mai a un percorso. */
    static final Pattern LANGUAGE_CODE = Pattern.compile("[a-z]{2}");

    /** Le lingue del pannello: italiano e inglese per primi, poi quelle che hanno un file in lang/, in ordine di codice. */
    public static final List<String> LANGUAGES = discover(code -> I18n.class.getResource("/lang/" + code + ".json") != null);
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
     * Le lingue che hanno un file: si provano i codici ISO 639-1 che Java conosce (Locale.getISOLanguages), mai un
     * nome letto da fuori. Italiano e inglese per primi; il loro file c'e' sempre (se manca, problems() lo dice).
     */
    static List<String> discover(java.util.function.Predicate<String> exists) {
        List<String> out = new ArrayList<>(List.of(SOURCE_LANGUAGE, FALLBACK_LANGUAGE));
        java.util.TreeSet<String> others = new java.util.TreeSet<>();
        for (String code : Locale.getISOLanguages())
            if (LANGUAGE_CODE.matcher(code).matches() && !out.contains(code) && exists.test(code)) others.add(code);
        out.addAll(others);
        return List.copyOf(out);
    }

    /** La catena dei testi di una lingua: lei, poi l'inglese, poi l'italiano (senza doppioni). */
    static List<String> chain(String lang) {
        return chain(lang, LANGUAGES);
    }

    /** La catena fra le lingue date: una lingua che non c'e' vale l'italiano, come normalize(). */
    static List<String> chain(String lang, List<String> languages) {
        java.util.LinkedHashSet<String> c = new java.util.LinkedHashSet<>();
        c.add(lang != null && languages.contains(lang) ? lang : SOURCE_LANGUAGE);
        c.add(FALLBACK_LANGUAGE);
        c.add(SOURCE_LANGUAGE);
        return List.copyOf(c);
    }

    /** Il nome di una lingua nella lingua stessa, con la maiuscola («Italiano», «English», «Español»), per il selettore. */
    public static String nativeName(String code) {
        Locale l = Locale.of(code);
        String name = l.getDisplayLanguage(l);
        if (name == null || name.isBlank() || name.equals(code)) return code.toUpperCase(Locale.ROOT);
        return name.substring(0, 1).toUpperCase(l) + name.substring(1);
    }

    /**
     * La categoria del plurale per un numero intero, secondo le regole cardinali di CLDR 49 (unicode.org,
     * cldr-core/supplemental/plurals.json, letto il 18/11/2026): una delle sei, che nei file di lingua sono i
     * suffissi chiave.zero, chiave.one, chiave.two, chiave.few, chiave.many e chiave.other. Il pannello conta solo
     * interi (v = 0, i = n): qui le regole ridotte a quel caso, per le lingue di PLURAL_RULES; ogni altra lingua
     * segue l'inglese, che per molte e' sbagliato (hindi e persiano usano chiave.one anche per 0, il lituano
     * chiave.few per 2..9): per questo I18nTest vuole ogni lingua del pannello in PLURAL_RULES, e la prova nel
     * browser confronta queste risposte con quelle di Intl.PluralRules. Nei file di lingua chiave.(categoria); se
     * una lingua non ha quella forma vale chiave.other. Negli script la stessa scelta la fa il browser.
     */
    public static String pluralCategory(String lang, long count) {
        long n = Math.abs(count), mod10 = n % 10, mod100 = n % 100;
        return switch (lang == null ? "" : lang) {
            // one = i = 1 and v = 0; many = i != 0 and i % 1000000 = 0 (it, es, pt-PT; fr e pt con one = i = 0..1)
            case "it", "es" -> n == 1 ? "one" : n != 0 && n % 1_000_000 == 0 ? "many" : "other";
            case "fr", "pt" -> n <= 1 ? "one" : n % 1_000_000 == 0 ? "many" : "other";
            case "pl" -> n == 1 ? "one" : mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14) ? "few" : "many";
            case "ru", "uk" -> mod10 == 1 && mod100 != 11 ? "one"
                    : mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14) ? "few" : "many";
            case "cs", "sk" -> n == 1 ? "one" : n >= 2 && n <= 4 ? "few" : "other";
            case "ro" -> n == 1 ? "one" : n == 0 || (mod100 >= 1 && mod100 <= 19) ? "few" : "other";
            case "ar" -> n == 0 ? "zero" : n == 1 ? "one" : n == 2 ? "two" : mod100 >= 3 && mod100 <= 10 ? "few"
                    : mod100 >= 11 ? "many" : "other";
            case "he" -> n == 1 ? "one" : n == 2 ? "two" : "other";
            case "ja", "zh", "ko", "vi", "th", "id" -> "other";
            default -> n == 1 ? "one" : "other";
        };
    }

    /**
     * Le lingue di cui pluralCategory conosce la regola: quelle scritte qui sopra e quelle per cui la regola
     * dell'inglese (uno, altrimenti altro) e' giusta anche per CLDR. Una lingua nuova del pannello deve stare qui.
     */
    public static final java.util.Set<String> PLURAL_RULES = java.util.Set.of(
            "it", "es", "fr", "pt", "pl", "ru", "uk", "cs", "sk", "ro", "ar", "he", "ja", "zh", "ko", "vi", "th", "id",
            "en", "de", "nl", "sv", "da", "nb", "fi", "et", "el", "hu", "tr", "bg");

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

    /** Un testo nella lingua chiesta; se manca, in inglese, poi in italiano; se manca anche li', la chiave stessa. */
    public static String t(String lang, String key) {
        for (String l : chain(lang)) {
            String text = BUNDLES.getOrDefault(l, Map.of()).get(key);
            if (text != null) return text;
        }
        return key;
    }

    /** Se la catena della lingua ha un testo per la chiave. */
    static boolean has(String lang, String key) {
        for (String l : chain(lang)) if (BUNDLES.getOrDefault(l, Map.of()).containsKey(key)) return true;
        return false;
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
        // Completo, come t() qui sopra: l'italiano sotto, poi l'inglese, poi la lingua stessa.
        List<String> c = new ArrayList<>(chain(lang));
        java.util.Collections.reverse(c);
        Map<String, String> all = new TreeMap<>();
        for (String l : c) all.putAll(BUNDLES.getOrDefault(l, Map.of()));
        return "window.I18N_LANG=" + JSONObject.quote(lang) + ";\n"
             + "window.I18N=" + new JSONObject(all) + ";\n"
             + T_FUNCTIONS;
    }

    /**
     * t(chiave, valori) e tn(chiave, numero, valori) per gli script. tn sceglie la forma del plurale della lingua
     * della pagina con Intl.PluralRules (le categorie di CLDR: chiave.one, chiave.few, chiave.many...), e se il
     * file non ha quella forma usa chiave.other; il numero e' gia' fra i valori come {n}. I valori entrano cosi'
     * come sono: il risultato e' testo, da mettere con textContent o da passare per escHtml() prima di innerHTML.
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
            var category = count === 1 ? 'one' : 'other';
            try { category = new Intl.PluralRules(window.I18N_LANG).select(count); } catch (e) { /* il browser non lo sa */ }
            var full = key + '.' + category;
            return t(Object.prototype.hasOwnProperty.call(window.I18N, full) ? full : key + '.other', values);
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

    /** Come tn() negli script: la forma del plurale della lingua (pluralCategory), o chiave.other; il numero entra come {n}. */
    public static String trn(String key, long count, Map<String, ?> params) {
        Map<String, Object> values = new java.util.HashMap<>(params);
        values.put("n", count);
        String lang = current(), full = key + "." + pluralCategory(lang, count);
        return t(lang, has(lang, full) ? full : key + ".other", values);
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

    /** Come withCurrent, per un compito che restituisce un valore (CompletableFuture.supplyAsync). */
    public static <T> java.util.function.Supplier<T> withCurrentSupplier(java.util.function.Supplier<T> job) {
        String lang = current();
        return () -> {
            setCurrent(lang);
            try {
                return job.get();
            } finally {
                clearCurrent();
            }
        };
    }

    /** Come withCurrent, per un compito dato a un ExecutorService. */
    public static <T> java.util.concurrent.Callable<T> withCurrentCallable(java.util.concurrent.Callable<T> job) {
        String lang = current();
        return () -> {
            setCurrent(lang);
            try {
                return job.call();
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
     * en;q=0.8"); a parita' vince quella scritta prima. Nessuna del pannello: l'inglese.
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

    /**
     * Il cookie della lingua: un anno (e' una preferenza, non un accesso), solo su HTTPS, mai
     * leggibile dagli script, mai mandato da un altro sito (Strict, come quelli della sessione).
     */
    public static String cookieHeader(String lang) {
        return COOKIE + "=" + normalize(lang) + "; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Strict";
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
