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
 * The interface languages: those that have a file in lang/ (today Italian and English).
 *
 * The texts live only in lang/(code).json, inside the jar: it.json and en.json complete and with the same keys
 * (I18nTest checks it), every other language even partial. A new language is one more file with the ISO
 * 639-1 code (es.json, fr.json): it is found by itself at boot. A text missing in a language is shown in
 * English, and if it is missing there too, in Italian (the language the panel is written in).
 *
 * The pages write {{t:key}} where a text goes and the server replaces it at every request, already as safe
 * HTML; the scripts call t('key') and read the same dictionary from /i18n/(language).js, which the browser
 * caches.
 *
 * The language of a request: the one saved in the account, if there is a session; then the cookie
 * __Host-lang (the choice made on this browser, even before logging in); then the browser's language
 * (Accept-Language); and for a browser that asks for neither Italian nor English, English.
 */
public final class I18n {

    /** The language the panel is written in: the last in the chain for missing texts. */
    public static final String SOURCE_LANGUAGE = "it";
    /** For a browser that asks for none of the panel's languages, and the first one asked for a missing text. */
    public static final String FALLBACK_LANGUAGE = "en";
    /** An ISO 639-1 language code: two lowercase letters, and nothing else ever reaches a path. */
    static final Pattern LANGUAGE_CODE = Pattern.compile("[a-z]{2}");

    /** The panel's languages: Italian and English first, then those that have a file in lang/, in code order. */
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
        // Italian first: English takes from there the texts it does not have yet.
        for (String lang : LANGUAGES) BUNDLES.put(lang, load(lang));
        for (String lang : LANGUAGES) {
            String script = buildScript(lang);
            SCRIPTS.put(lang, script);
            VERSIONS.put(lang, sha256(script).substring(0, 12));
        }
    }

    private I18n() {}

    /**
     * The languages that have a file: the ISO 639-1 codes Java knows (Locale.getISOLanguages) are tried, never a
     * name read from outside. Italian and English first; their file is always there (if it is missing, problems()
     * says so).
     */
    static List<String> discover(java.util.function.Predicate<String> exists) {
        List<String> out = new ArrayList<>(List.of(SOURCE_LANGUAGE, FALLBACK_LANGUAGE));
        java.util.TreeSet<String> others = new java.util.TreeSet<>();
        for (String code : Locale.getISOLanguages())
            if (LANGUAGE_CODE.matcher(code).matches() && !out.contains(code) && exists.test(code)) others.add(code);
        out.addAll(others);
        return List.copyOf(out);
    }

    /** The text chain of a language: itself, then English, then Italian (without duplicates). */
    static List<String> chain(String lang) {
        return chain(lang, LANGUAGES);
    }

    /** The chain among the given languages: a language that does not exist counts as Italian, like normalize(). */
    static List<String> chain(String lang, List<String> languages) {
        java.util.LinkedHashSet<String> c = new java.util.LinkedHashSet<>();
        c.add(lang != null && languages.contains(lang) ? lang : SOURCE_LANGUAGE);
        c.add(FALLBACK_LANGUAGE);
        c.add(SOURCE_LANGUAGE);
        return List.copyOf(c);
    }

    /**
     * The name of a language in the language itself, capitalised (`Italiano`, `English`, `Español`), for the
     * selector.
     */
    public static String nativeName(String code) {
        Locale l = Locale.of(code);
        String name = l.getDisplayLanguage(l);
        if (name == null || name.isBlank() || name.equals(code)) return code.toUpperCase(Locale.ROOT);
        return name.substring(0, 1).toUpperCase(l) + name.substring(1);
    }

    /**
     * The plural category for an integer, according to the cardinal rules of CLDR 49 (unicode.org,
     * cldr-core/supplemental/plurals.json, read on 2026-11-18): one of the six, which in the language files are the
     * suffixes key.zero, key.one, key.two, key.few, key.many and key.other. The panel counts only
     * integers (v = 0, i = n): here the rules reduced to that case, for the languages of PLURAL_RULES; every other
     * language follows English, which for many is wrong (Hindi and Persian use key.one for 0 too, Lithuanian
     * key.few for 2..9): this is why I18nTest wants every panel language in PLURAL_RULES, and the test in the
     * browser compares these answers with those of Intl.PluralRules. In the language files key.(category); if
     * a language does not have that form, key.other applies. In the scripts the browser makes the same choice.
     */
    public static String pluralCategory(String lang, long count) {
        long n = Math.abs(count), mod10 = n % 10, mod100 = n % 100;
        return switch (lang == null ? "" : lang) {
            // one = i = 1 and v = 0; many = i != 0 and i % 1000000 = 0 (it, es, pt-PT; fr and pt with one = i = 0..1)
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
     * The languages whose rule pluralCategory knows: those written above and those for which the English rule
     * (one, otherwise other) is right for CLDR too. A new panel language must be here.
     */
    public static final java.util.Set<String> PLURAL_RULES = java.util.Set.of(
            "it", "es", "fr", "pt", "pl", "ru", "uk", "cs", "sk", "ro", "ar", "he", "ja", "zh", "ko", "vi", "th", "id",
            "en", "de", "nl", "sv", "da", "nb", "fi", "et", "el", "hu", "tr", "bg");

    /**
     * A language file. If it is broken the panel does not stop: the problem is recorded (the tests
     * read it from problems()) and it goes on with what there is, showing the keys in place of the
     * missing texts.
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

    /** The problems found reading the language files: empty if everything is fine. */
    public static List<String> problems() {
        return List.copyOf(PROBLEMS);
    }

    /** The dictionary of a language, only the texts it really has (for the tests). */
    public static Map<String, String> bundle(String lang) {
        return BUNDLES.getOrDefault(lang, Map.of());
    }

    /** The language if it is one of the panel's, otherwise the one it is written in. */
    public static String normalize(String lang) {
        return lang != null && LANGUAGES.contains(lang) ? lang : SOURCE_LANGUAGE;
    }

    /** A text in the requested language; if missing, in English, then in Italian; if missing there too, the key itself. */
    public static String t(String lang, String key) {
        for (String l : chain(lang)) {
            String text = BUNDLES.getOrDefault(l, Map.of()).get(key);
            if (text != null) return text;
        }
        return key;
    }

    /** Whether the language's chain has a text for the key. */
    static boolean has(String lang, String key) {
        for (String l : chain(lang)) if (BUNDLES.getOrDefault(l, Map.of()).containsKey(key)) return true;
        return false;
    }

    /** A text with its values: {name} becomes params.get("name"). The result is not HTML. */
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
     * The substitutions of every page: {{t:key}} with the text already as safe HTML (it also works
     * inside an attribute), {{lang}} with the language, {{i18nVersion}} with the fingerprint of the dictionary
     * (for the address of /i18n/(language).js: when a text changes the address changes, and the
     * browser does not use the old one from its cache). In the scripts {{t:...}} is not used: there, t('key').
     *
     * The keys that end in ".html" go in as they are: they are sentences with something bold
     * or a command inside (strong, em, code, kbd, br), which cannot be split into pieces
     * because the word order changes from one language to another. They are in the panel's language
     * files, never come from those who use the panel, and I18nTest checks that they have no
     * other tags.
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

    /** The dictionary for the page's scripts, with t() and tn(): it is what /i18n/(language).js serves. */
    public static String script(String lang) {
        return SCRIPTS.get(normalize(lang));
    }

    public static String version(String lang) {
        return VERSIONS.get(normalize(lang));
    }

    private static String buildScript(String lang) {
        // Complete, like t() above: Italian underneath, then English, then the language itself.
        List<String> c = new ArrayList<>(chain(lang));
        java.util.Collections.reverse(c);
        Map<String, String> all = new TreeMap<>();
        for (String l : c) all.putAll(BUNDLES.getOrDefault(l, Map.of()));
        return "window.I18N_LANG=" + JSONObject.quote(lang) + ";\n"
             + "window.I18N=" + new JSONObject(all) + ";\n"
             + T_FUNCTIONS;
    }

    /**
     * t(key, values) and tn(key, number, values) for the scripts. tn picks the plural form of the page's language
     * with Intl.PluralRules (the CLDR categories: key.one, key.few, key.many...), and if the file does not
     * have that form it uses key.other; the number is already among the values as {n}. The values go in as they
     * are: the result is text, to be set with textContent or passed through escHtml() before innerHTML.
     */
    private static final String T_FUNCTIONS = """
        function t(key, params) {
            var text = Object.prototype.hasOwnProperty.call(window.I18N, key) ? window.I18N[key] : key;
            if (!params) return text;
            return text.replace(/\\{([A-Za-z0-9_]{1,40})\\}/g, function (all, name) {
                return Object.prototype.hasOwnProperty.call(params, name) && params[name] != null ? String(params[name]) : all;
            });
        }
        // A text inside hand-built HTML (innerHTML, an attribute in quotes).
        function escHtml(text) {
            return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }
        function tn(key, count, params) {
            var values = Object.assign({ n: count }, params || {});
            var category = count === 1 ? 'one' : 'other';
            try { category = new Intl.PluralRules(window.I18N_LANG).select(count); } catch (e) { /* the browser does not know it */ }
            var full = key + '.' + category;
            return t(Object.prototype.hasOwnProperty.call(window.I18N, full) ? full : key + '.other', values);
        }
        // The translated sentence as nodes: where there is `{nome}` and `params.nome` is an element (a <code>
        // with a path, a badge), that element goes there; the rest is text. This way the sentence stays
        // whole in its language and nothing becomes HTML: `el.append(...tNodes('chiave', { file: code }))`.
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

    // ---------- the language of the current request, for the server's messages ----------

    /**
     * The language of the request this thread is serving: SSLMailServer sets it on entering
     * every handler (context) and removes it on exit. This way the server code translates its
     * messages with tr() without passing the language from function to function. A job that continues on
     * another thread carries it along: current() at the start, setCurrent() in the new thread.
     */
    public static void setCurrent(String lang) {
        CURRENT.set(normalize(lang));
    }

    public static void clearCurrent() {
        CURRENT.remove();
    }

    /** The process language outside a request: Italian, except for the console, which sets its own (Main). */
    private static volatile String processLanguage = SOURCE_LANGUAGE;

    /**
     * The language of this process outside a request. The console sets it once (the on-screen menu and the
     * command-line commands, Main), with the panel's language; the service does not: its startup lines are logs.
     */
    public static void setProcessLanguage(String lang) {
        processLanguage = normalize(lang);
    }

    /** The language of the current request; outside a request, that of the process (Italian, or the console's). */
    public static String current() {
        String lang = CURRENT.get();
        return lang != null ? lang : processLanguage;
    }

    /** A text in the language of the current request. */
    public static String tr(String key) {
        return t(current(), key);
    }

    /** A text with its values in the language of the current request. The result is not HTML. */
    public static String tr(String key, Map<String, ?> params) {
        return t(current(), key, params);
    }

    /**
     * Like tn() in the scripts: the plural form of the language (pluralCategory), or key.other; the number goes in
     * as {n}.
     */
    public static String trn(String key, long count, Map<String, ?> params) {
        Map<String, Object> values = new java.util.HashMap<>(params);
        values.put("n", count);
        String lang = current(), full = key + "." + pluralCategory(lang, count);
        return t(lang, has(lang, full) ? full : key + ".other", values);
    }

    /**
     * The job with the language of whoever requested it, for a thread that starts now and ends later
     * (the jobs on the package turn, the long jobs): its messages come out in that language.
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

    /** Like withCurrent, for a task that returns a value (CompletableFuture.supplyAsync). */
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

    /** Like withCurrent, for a task given to an ExecutorService. */
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

    // ---------- the language of a request ----------

    /**
     * The language of this request. saved is the account's one (null before logging in or if it has
     * never been chosen): it wins over everything, so the choice follows the administrator on every browser.
     */
    public static String languageOf(HttpExchange exchange, String saved) {
        if (saved != null && LANGUAGES.contains(saved)) return saved;
        String fromCookie = fromCookie(exchange.getRequestHeaders().get("Cookie"));
        if (fromCookie != null) return fromCookie;
        return fromAcceptLanguage(exchange.getRequestHeaders().getFirst("Accept-Language"));
    }

    /** The value of the language cookie, if it is a panel language. */
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
     * The browser's preferred language among the panel's, according to the q weights ("it-IT,it;q=0.9,
     * en;q=0.8"); on a tie the one written first wins. None of the panel's: English.
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
     * The language cookie: one year (it is a preference, not a login), HTTPS only, never
     * readable by scripts, never sent by another site (Strict, like the session ones).
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
