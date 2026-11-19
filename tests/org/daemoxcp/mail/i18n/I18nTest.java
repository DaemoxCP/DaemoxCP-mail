package org.daemoxcp.mail.i18n;

import org.daemoxcp.mail.content.Layout;
import org.daemoxcp.mail.content.PanelContent;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The interface languages (I18n) and the page frame (Layout) of the mail panel.
 *
 * The language files: they load without problems, have the same keys, no empty text, the same
 * {values} in Italian and in English. The pages: every {{t:key}} and every t('key') of the scripts
 * exists in both languages, no {{t:...}} inside a script (it would not be HTML there), no script
 * hides the dictionary function behind a variable named t, and once completed a page has no
 * placeholder left. The language of a request: Accept-Language with its weights, the cookie, the
 * saved choice. The frame: the sections, every page in the menu, the current page marked.
 */
public class I18nTest {

    static int failed = 0;

    static final Layout.Viewer SUPERADMIN = viewer("boss", "superadmin");

    static Layout.Viewer viewer(String name, String role) {
        return new Layout.Viewer(name, role, org.daemoxcp.mail.security.AuthStore.permissionsOf(role));
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{t:([A-Za-z0-9_.-]+)\\}\\}");
    static final Pattern SCRIPT = Pattern.compile("<script\\b[^>]*>(.*?)</script>", Pattern.DOTALL);
    // (also after "...": el.append(...tNodes('key', ...)))
    static final Pattern T_CALL = Pattern.compile("(?:(?<=\\.\\.\\.)|(?<![A-Za-z0-9_.$]))(tNodes|tn|t)\\('([A-Za-z0-9_.-]+)'");

    public static void main(String[] a) throws Exception {
        Map<String, String> it = I18n.bundle("it"), en = I18n.bundle("en");

        System.out.println("\n== The language files ==");
        check("they load without problems" + (I18n.problems().isEmpty() ? "" : ": " + I18n.problems()), I18n.problems().isEmpty());
        // Every file in lang/ is a language of the panel, and nothing else is: a file named pt-BR.json or ES.json
        // would be ignored without a word, so its name is checked here.
        Set<String> files = new TreeSet<>(), oddNames = new TreeSet<>();
        try (var list = java.nio.file.Files.list(java.nio.file.Path.of("src/main/resources/lang"))) {
            for (var f : (Iterable<java.nio.file.Path>) list::iterator) {
                String name = f.getFileName().toString();
                if (name.matches("[a-z]{2}\\.json")) files.add(name.substring(0, 2));
                else oddNames.add(name);
            }
        }
        check("every file in lang/ is named with its ISO 639-1 code (xx.json)" + (oddNames.isEmpty() ? "" : ": " + oddNames), oddNames.isEmpty());
        check("the panel's languages are the files in lang/, Italian and English first: " + I18n.LANGUAGES,
                new TreeSet<>(I18n.LANGUAGES).equals(files) && I18n.LANGUAGES.subList(0, 2).equals(List.of("it", "en")));
        check("Italian: " + it.size() + " texts", it.size() > 30);
        Set<String> onlyIt = new TreeSet<>(it.keySet()), onlyEn = new TreeSet<>(en.keySet());
        onlyIt.removeAll(en.keySet());
        onlyEn.removeAll(it.keySet());
        check("Italian and English are complete: the same keys" + (onlyIt.isEmpty() ? "" : "; only in Italian: " + onlyIt)
                + (onlyEn.isEmpty() ? "" : "; only in English: " + onlyEn), onlyIt.isEmpty() && onlyEn.isEmpty());
        List<String> plurals = new ArrayList<>();
        for (String k : it.keySet()) {
            if (k.endsWith(".one") && !it.containsKey(k.substring(0, k.length() - 4) + ".other")) plurals.add(k);
            if (k.endsWith(".other") && !it.containsKey(k.substring(0, k.length() - 6) + ".one")) plurals.add(k);
        }
        check("every Italian plural has .one and .other" + (plurals.isEmpty() ? "" : ": " + plurals), plurals.isEmpty());
        // The same rules for every language, Italian included: only keys Italian has, no empty text, the same
        // {values}, only the plural forms the language has, valid date patterns, the .html sentences with the
        // text tags only, the plain texts without < > &. Another language may be partial: what it lacks is
        // shown in English, then in Italian (I18n.t).
        for (String lang : I18n.LANGUAGES) {
            List<String> problems = languageProblems(lang, I18n.bundle(lang), it);
            int size = I18n.bundle(lang).size();
            check(I18n.nativeName(lang) + " (" + lang + "): " + size + " of " + it.size() + " texts"
                    + (size < it.size() ? " (the others in English)" : "") + ", no problem"
                    + (problems.isEmpty() ? "" : ": " + problems.subList(0, Math.min(8, problems.size()))), problems.isEmpty());
            check(lang + ": its plural rule is written (I18n.PLURAL_RULES), it does not borrow the English one",
                    I18n.PLURAL_RULES.contains(lang));
        }
        // No right-to-left language yet: the frame has no dir="rtl", no mirrored Bootstrap, no mirrored icons.
        // An Arabic or Hebrew file would give a page in the wrong direction (see the README, "Languages").
        Set<String> rtl = new TreeSet<>(I18n.LANGUAGES);
        rtl.retainAll(Set.of("ar", "he", "fa", "ur", "yi", "ps", "sd", "ug", "dv", "ku", "ckb"));
        check("no right-to-left language until the frame supports it" + (rtl.isEmpty() ? "" : ": " + rtl), rtl.isEmpty());

        System.out.println("\n== The language file rules can fail ==");
        // The rules above, on files made here: a check that cannot fail checks nothing.
        Map<String, String> good = Map.of("nav.updates", "Actualizaciones", "bulk.selected.one", "{n} seleccionado",
                "bulk.selected.other", "{n} seleccionados", "bulk.selected.many", "{n} de seleccionados");
        check("a good partial Spanish file: no problem " + languageProblems("es", good, it), languageProblems("es", good, it).isEmpty());
        check("(the test plural is in Italian with {n}: bulk.selected)", "{n}".equals(String.join("", values(it.getOrDefault("bulk.selected.other", "")).stream().map(v -> "{" + v + "}").toList())));
        check("a key Italian does not have", fails("es", Map.of("no.such.key", "x"), it, "not in Italian"));
        check("an empty text", fails("es", Map.of("nav.updates", " "), it, "empty"));
        check("other {values} than Italian", fails("es", Map.of("bulk.selected.other", "{count} seleccionados"), it, "{values}"));
        check("a plural form the language does not have (few in Spanish, fine in Polish)",
                fails("es", Map.of("bulk.selected.few", "{n} x", "bulk.selected.other", "{n} y"), it, "has no \"few\" form")
                && languageProblems("pl", Map.of("bulk.selected.few", "{n} x", "bulk.selected.other", "{n} y"), it).isEmpty());
        check("a translated plural without its .other", fails("es", Map.of("bulk.selected.one", "{n} x"), it, "without bulk.selected.other"));
        String htmlKey = it.keySet().stream().filter(k -> k.endsWith(".html")).findFirst().orElseThrow();
        check("a .html sentence with a link (" + htmlKey + ")", fails("es", Map.of(htmlKey, it.get(htmlKey) + " <a href=\"x\">y</a>"), it, "tag <a"));
        check("a plain text with < > &", fails("es", Map.of("nav.updates", "a & b"), it, "< > &"));
        String dateKey = it.entrySet().stream().filter(e -> e.getValue().contains("yyyy")).map(Map.Entry::getKey).findFirst().orElseThrow();
        check("a broken date pattern (" + dateKey + ")", fails("es", Map.of(dateKey, it.get(dateKey) + " {"), it, "not a date pattern"));

        System.out.println("\n== Any number of languages ==");
        Set<String> asked = new TreeSet<>();
        List<String> found = I18n.discover(code -> { asked.add(code); return Set.of("es", "fr", "de").contains(code); });
        check("the languages: the files found, Italian and English first, the others by code: " + found,
                found.equals(List.of("it", "en", "de", "es", "fr")));
        check("only ISO 639-1 codes are tried (" + asked.size() + "), never a name from outside",
                asked.size() > 100 && asked.stream().allMatch(c -> c.matches("[a-z]{2}")) && asked.contains("es"));
        check("no file but Italian and English: those two", I18n.discover(code -> false).equals(List.of("it", "en")));
        List<String> three = List.of("it", "en", "es");
        check("a missing text: the language, then English, then Italian", I18n.chain("es", three).equals(List.of("es", "en", "it"))
                && I18n.chain("en", three).equals(List.of("en", "it")) && I18n.chain("it", three).equals(List.of("it", "en"))
                && I18n.chain("fr", three).equals(List.of("it", "en")) && I18n.chain(null, three).equals(List.of("it", "en")));
        check("the names of the languages in their own language", I18n.nativeName("it").equals("Italiano")
                && I18n.nativeName("en").equals("English") && I18n.nativeName("es").equals("Español")
                && I18n.nativeName("fr").equals("Français") && I18n.nativeName("de").equals("Deutsch"));
        // The plural forms, from CLDR's cardinal rules for whole numbers: the browser test compares them all with
        // Intl.PluralRules; here a few cases written by hand.
        check("plural forms: Italian one/other, many for millions", plural("it", 1, "one") && plural("it", 0, "other")
                && plural("it", 2, "other") && plural("it", 1_000_000, "many") && plural("it", -1, "one"));
        check("plural forms: French 0 and 1 are one", plural("fr", 0, "one") && plural("fr", 1, "one") && plural("fr", 2, "other"));
        check("plural forms: Polish few for 2-4 and 22, many for 5, 12 and 25", plural("pl", 1, "one") && plural("pl", 3, "few")
                && plural("pl", 22, "few") && plural("pl", 5, "many") && plural("pl", 12, "many") && plural("pl", 25, "many"));
        check("plural forms: Russian one for 21, many for 11", plural("ru", 21, "one") && plural("ru", 11, "many")
                && plural("ru", 23, "few") && plural("ru", 0, "many"));
        check("plural forms: Czech few for 2-4, other for 5", plural("cs", 3, "few") && plural("cs", 5, "other"));
        check("plural forms: Romanian few for 0 and 2-19 and 101, other for 20", plural("ro", 0, "few") && plural("ro", 19, "few")
                && plural("ro", 20, "other") && plural("ro", 101, "few"));
        check("plural forms: Arabic zero, one, two, few, many, other", plural("ar", 0, "zero") && plural("ar", 1, "one")
                && plural("ar", 2, "two") && plural("ar", 3, "few") && plural("ar", 11, "many") && plural("ar", 100, "other"));
        check("plural forms: Japanese only other; German like English", plural("ja", 1, "other") && plural("de", 1, "one")
                && plural("de", 0, "other") && plural("en", 1, "one") && plural("en", 0, "other"));
        String buttons = Layout.languageSwitch("it", List.of("it", "en"));
        check("two languages: two buttons, the current one pressed, each named in its language",
                buttons.contains("data-set-lang=\"it\" lang=\"it\" aria-pressed=\"true\" title=\"Italiano\">IT</button>")
                && buttons.contains("data-set-lang=\"en\" lang=\"en\" aria-pressed=\"false\" title=\"English\">EN</button>")
                && !buttons.contains("<select"));
        String menu = Layout.languageSwitch("es", three);
        check("three languages: a menu with its label, each language in its own language, the current one chosen",
                menu.contains("<label class=\"visually-hidden\" for=\"languageSelect\">{{t:layout.language}}</label>")
                && menu.contains("<select id=\"languageSelect\"") && menu.contains("data-set-lang-select")
                && menu.contains("<option value=\"es\" lang=\"es\" selected>Español</option>")
                && menu.contains("<option value=\"it\" lang=\"it\">Italiano</option>") && count(menu, " selected") == 1
                && !menu.contains("data-set-lang=\""));
        check("the frame uses the panel's languages", Layout.expand("<b>{{LANGUAGE_SWITCH}}</b>", "en", Layout.Viewer.NOBODY)
                .contains(Layout.languageSwitch("en", I18n.LANGUAGES)));
        check("the database procedure set_admin_language lists exactly the panel's languages (a new one goes in SqlCatalog too)",
                org.daemoxcp.mail.database.SqlCatalog.WEB_CREATE_SET_ADMIN_LANGUAGE.contains("p_language NOT IN ("
                        + String.join(", ", I18n.LANGUAGES.stream().map(l -> "'" + l + "'").toList()) + ")"));

        System.out.println("\n== The pages ==");
        Set<String> used = new TreeSet<>();
        List<String> missing = new ArrayList<>(), inScripts = new ArrayList<>(), leftovers = new ArrayList<>();
        int pageCount = 0;
        List<String> sources = new ArrayList<>();
        for (Method m : PanelContent.class.getDeclaredMethods()) {
            if (!m.getName().startsWith("get") || !m.getName().endsWith("Html") || m.getParameterCount() != 0
                    || !Modifier.isStatic(m.getModifiers())) continue;
            m.setAccessible(true);
            String html = String.valueOf(m.invoke(null));
            String name = m.getName();
            pageCount++;
            sources.add(html);
            for (String lang : I18n.LANGUAGES) {
                String ready = I18n.render(Layout.expand(html, lang, SUPERADMIN), lang);
                Matcher r = Pattern.compile("\\{\\{(t:[^}]*|LAYOUT:[^}]*|LANGUAGE_SWITCH|lang|i18nVersion)\\}\\}").matcher(ready);
                while (r.find()) leftovers.add(name + " (" + lang + "): " + r.group());
            }
            Matcher s = SCRIPT.matcher(html);
            while (s.find()) if (s.group(1).contains("{{t:")) inScripts.add(name);
        }
        // The frame is a page too: its keys live in Layout
        sources.add(Layout.expand(Layout.placeholder("home"), "it", SUPERADMIN));
        for (String html : sources) {
            Matcher m = PLACEHOLDER.matcher(html);
            while (m.find()) {
                used.add(m.group(1));
                if (!it.containsKey(m.group(1)) || !en.containsKey(m.group(1))) missing.add("{{t:" + m.group(1) + "}}");
            }
            Matcher s = SCRIPT.matcher(html);
            while (s.find()) {
                Matcher c = T_CALL.matcher(s.group(1));
                while (c.find()) {
                    List<String> keys = c.group(1).equals("tn") ? List.of(c.group(2) + ".one", c.group(2) + ".other") : List.of(c.group(2));
                    for (String k : keys) {
                        used.add(k);
                        if (!it.containsKey(k) || !en.containsKey(k)) missing.add(c.group(1) + "('" + c.group(2) + "')");
                    }
                }
            }
        }
        check(pageCount + " pages: every text used exists in both languages" + (missing.isEmpty() ? "" : ": " + new TreeSet<>(missing)), missing.isEmpty());
        check("no {{t:...}} inside a script" + (inScripts.isEmpty() ? "" : ": " + new TreeSet<>(inScripts)), inScripts.isEmpty());
        // A variable or a parameter named t (or tn, tNodes, escHtml) hides the dictionary's
        // function: inside that function t('key') would become an error. No script uses them.
        Pattern shadow = Pattern.compile("\\b(?:let|const|var)\\s+(?:t|tn|tNodes|escHtml)(?:\\s*[=;,)]|\\s+(?:of|in)\\b)"
                + "|function\\s*[A-Za-z0-9_$]*\\s*\\([^)]*\\b(?:t|tn|tNodes|escHtml)\\b[^)]*\\)"
                + "|(?<![A-Za-z0-9_$.])(?:t|tn|tNodes|escHtml)\\s*=>"
                + "|\\(\\s*(?:[A-Za-z0-9_$]+\\s*,\\s*)*(?:t|tn|tNodes|escHtml)\\s*(?:,\\s*[A-Za-z0-9_$]+\\s*)*\\)\\s*=>"
                + "|catch\\s*\\(\\s*(?:t|tn|tNodes|escHtml)\\s*\\)");
        // Nor does it use t as a value (escapeHtml(t), { type: t }): that is a variable renamed
        // halfway. That is how the Kafka page showed the function's code instead of the topics.
        Pattern asValue = Pattern.compile("(?<![A-Za-z0-9_$.'\"#-])t(?![A-Za-z0-9_$'\"(:-])");
        List<String> shadows = new ArrayList<>(), asValues = new ArrayList<>();
        for (Method m : PanelContent.class.getDeclaredMethods()) {
            if (!m.getName().startsWith("get") || !m.getName().endsWith("Html") || m.getParameterCount() != 0
                    || !Modifier.isStatic(m.getModifiers())) continue;
            m.setAccessible(true);
            Matcher s = SCRIPT.matcher(String.valueOf(m.invoke(null)));
            while (s.find()) {
                Matcher o = shadow.matcher(s.group(1));
                while (o.find()) shadows.add(m.getName() + ": " + o.group().trim());
                for (String line : s.group(1).split("\n")) {
                    String r = line.trim();
                    if (r.startsWith("//") || r.startsWith("*") || r.startsWith("/*")) continue;
                    String code = line.replaceAll("'(?:\\\\.|[^'\\\\])*'", "''").replaceAll("\"(?:\\\\.|[^\"\\\\])*\"", "\"\"");
                    if (asValue.matcher(code).find()) asValues.add(m.getName() + ": " + (r.length() > 90 ? r.substring(0, 90) : r));
                }
            }
        }
        check("no script names a variable of its own t (or tn, tNodes, escHtml)" + (shadows.isEmpty() ? "" : ": " + new TreeSet<>(shadows)), shadows.isEmpty());
        check("no script uses t as a value" + (asValues.isEmpty() ? "" : ": " + new TreeSet<>(asValues)), asValues.isEmpty());
        check("once completed, the pages have no placeholders left" + (leftovers.isEmpty() ? "" : ": " + leftovers.subList(0, Math.min(5, leftovers.size()))), leftovers.isEmpty());
        Set<String> unused = new TreeSet<>(it.keySet());
        unused.removeAll(used);
        unused.removeIf(k -> k.startsWith("server.")); // the messages the server writes, not the pages
        System.out.println("  (texts the pages do not use: " + unused.size() + (unused.isEmpty() ? "" : " " + unused) + ")");

        System.out.println("\n== The server messages ==");
        // The keys the server's code writes in full: I18n.tr("..."), jsonError("...") and every
        // "server.something" text (also passed to a method that translates it later). Those ending
        // with a dot are prefixes completed at runtime: the tests of their modules check them
        // (SoftwareVersionsTest for the programs' roles).
        Set<String> serverKeys = new TreeSet<>();
        // (a "server.x" text with a single dot, like Kafka's server.properties, is not a key)
        // (only the calls here: in the mail panel "server.example.com" is a host name, not a key)
        // (ShownException.of("key"): an error written for the page, translated when it is thrown)
        Pattern serverKey = Pattern.compile("(?:I18n\\.tr|jsonError|ShownException\\.of)\\(\"([A-Za-z0-9_.-]*[A-Za-z0-9_-])\"()");
        // I18n.trn("key", n, ...) uses key.one and key.other
        Pattern pluralCall = Pattern.compile("I18n\\.trn\\(\"([A-Za-z0-9_.-]*[A-Za-z0-9_-])\"");
        Set<String> serverPlurals = new TreeSet<>();
        try (var sourceFiles = java.nio.file.Files.walk(java.nio.file.Path.of("src/main/java"))) {
            for (var f : (Iterable<java.nio.file.Path>) sourceFiles.filter(x -> x.toString().endsWith(".java"))::iterator) {
                String source = java.nio.file.Files.readString(f);
                Matcher p = pluralCall.matcher(source);
                while (p.find()) serverPlurals.add(p.group(1));
                Matcher m = serverKey.matcher(source);
                while (m.find()) serverKeys.add(m.group(1) != null ? m.group(1) : m.group(2));
            }
        }
        serverKeys.removeAll(serverPlurals);
        for (String k : serverPlurals) {
            serverKeys.add(k + ".one");
            serverKeys.add(k + ".other");
        }
        List<String> missingServer = new ArrayList<>();
        for (String k : serverKeys) if (!it.containsKey(k) || !en.containsKey(k)) missingServer.add(k);
        check(serverKeys.size() + " texts used by the server: all in both languages" + (missingServer.isEmpty() ? "" : ": missing " + missingServer),
                missingServer.isEmpty());

        System.out.println("\n== The language of a request ==");
        check("it-IT,it;q=0.9,en;q=0.8 -> it", I18n.fromAcceptLanguage("it-IT,it;q=0.9,en;q=0.8").equals("it"));
        check("en-US,en;q=0.9,it;q=0.8 -> en", I18n.fromAcceptLanguage("en-US,en;q=0.9,it;q=0.8").equals("en"));
        check("de,it;q=0.5 -> it (the first of ours)", I18n.fromAcceptLanguage("de,it;q=0.5").equals("it"));
        check("en;q=0.4,it;q=0.6 -> it (the weight counts, not the order)", I18n.fromAcceptLanguage("en;q=0.4,it;q=0.6").equals("it"));
        check("de-DE,de;q=0.9 -> en (none of ours)", I18n.fromAcceptLanguage("de-DE,de;q=0.9").equals("en"));
        check("it;q=0 -> en (q=0 means no)", I18n.fromAcceptLanguage("it;q=0").equals("en"));
        check("EN, upper case -> en; empty or missing -> en", I18n.fromAcceptLanguage("EN").equals("en")
                && I18n.fromAcceptLanguage("").equals("en") && I18n.fromAcceptLanguage(null).equals("en"));
        check("cookie: __Host-lang=en among the others", "en".equals(I18n.fromCookie(List.of("a=1; __Host-lang=en; b=2"))));
        check("cookie: an unknown language does not count", I18n.fromCookie(List.of("__Host-lang=fr")) == null
                && I18n.fromCookie(List.of("x__Host-lang=en")) == null && I18n.fromCookie(null) == null);
        check("the cookie: one year, Secure, HttpOnly, SameSite, Path=/", I18n.cookieHeader("en")
                .equals("__Host-lang=en; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Strict"));
        check("an unknown language becomes Italian", I18n.normalize("fr").equals("it") && I18n.normalize(null).equals("it"));

        System.out.println("\n== The texts ==");
        check("render: the text goes in as safe HTML (D'Amico -> D&#39;Amico)",
                I18n.render("<p>{{t:footer.text}}</p>", "it").contains("D&#39;Amico"));
        check("render: {{lang}} is the language", I18n.render("<html lang=\"{{lang}}\">", "en").equals("<html lang=\"en\">"));
        check("render: a .html key goes in with its tags", I18n.render("{{t:test.html}}", "it").equals("test.html")
                && !I18n.render("{{t:footer.text}}", "it").contains("'"));
        check("t(): a missing key stays the key", I18n.t("en", "no.such.key").equals("no.such.key"));
        check("t() with values: {name} replaced, the value as it is (not HTML)",
                I18n.format("Hello {name}, {other}", Map.of("name", "<x>")).equals("Hello <x>, {other}"));
        String script = I18n.script("en");
        check("the script dictionary: language, texts, t() and tn()", script.startsWith("window.I18N_LANG=\"en\";")
                && script.contains("\"nav.updates\":\"Updates\"") && script.contains("function t(key, params)")
                && script.contains("function tn(key, count, params)"));
        check("the fingerprint changes with the language", !I18n.version("it").equals(I18n.version("en")) && I18n.version("it").length() == 12);

        System.out.println("\n== The frame ==");
        String frame = Layout.expand(Layout.placeholder("queue"), "it", SUPERADMIN);
        check("four sections", frame.contains("{{t:nav.section.mail}}") && frame.contains("{{t:nav.section.dns}}")
                && frame.contains("{{t:nav.section.security}}") && frame.contains("{{t:nav.section.system}}"));
        check("every page served by the panel is in the menu", java.util.stream.Stream.of("/home", "/domains", "/mailboxes", "/aliases",
                "/queue", "/ratelimits", "/statistics", "/dns", "/ssl", "/cloudflare", "/security", "/firewall", "/updates", "/logs",
                "/paths", "/admins", "/settings").allMatch(h -> frame.contains("href=\"" + h + "\"")));
        check("the current page: one item only, with aria-current", count(frame, "aria-current=\"page\"") == 1
                && frame.contains("class=\"sidebar-link active\" aria-current=\"page\" href=\"/queue\""));
        check("in the top bar: Mail > Queue", frame.contains("<span class=\"topbar-section\">{{t:nav.section.mail}}</span>")
                && frame.contains("<span class=\"topbar-page\">{{t:nav.queue}}</span>"));
        check("the active language is pressed", frame.contains("data-set-lang=\"it\" lang=\"it\" aria-pressed=\"true\"")
                && frame.contains("data-set-lang=\"en\" lang=\"en\" aria-pressed=\"false\""));
        check("the theme and logout buttons keep the ids the page script binds", frame.contains("id=\"themeToggle\"")
                && frame.contains("id=\"themeIcon\"") && frame.contains("id=\"logoutButton\""));
        check("the login page gets only the language buttons", Layout.expand("<b>{{LANGUAGE_SWITCH}}</b>", "en", Layout.Viewer.NOBODY).contains("data-set-lang=\"en\" lang=\"en\" aria-pressed=\"true\"")
                && !Layout.expand("<b>{{LANGUAGE_SWITCH}}</b>", "en", Layout.Viewer.NOBODY).contains("sidebar"));
        check("a page without placeholder stays as it is", Layout.expand("<p>nothing</p>", "it", SUPERADMIN).equals("<p>nothing</p>"));

        System.out.println("\n== The frame by role ==");
        String asViewer = Layout.expand(Layout.placeholder("mailboxes"), "it", viewer("guest", "viewer"));
        check("viewer: no administrators or settings in the menu", !asViewer.contains("href=\"/admins\"") && !asViewer.contains("href=\"/settings\""));
        check("viewer: still sees mail, DNS, security and system pages", asViewer.contains("href=\"/mailboxes\"")
                && asViewer.contains("href=\"/dns\"") && asViewer.contains("href=\"/firewall\"") && asViewer.contains("href=\"/updates\""));
        check("viewer on mailboxes: read-only badge", asViewer.contains("{{t:layout.readOnly}}"));
        check("operator on mailboxes: no read-only badge", !Layout.expand(Layout.placeholder("mailboxes"), "it", viewer("op", "operator"))
                .contains("{{t:layout.readOnly}}"));
        check("operator on domains: read-only badge", Layout.expand(Layout.placeholder("domains"), "it", viewer("op", "operator"))
                .contains("{{t:layout.readOnly}}"));
        check("the account button shows the name and the role", frame.contains(">boss</span>") && frame.contains("{{t:adm.rSuperadmin}}")
                && frame.contains("href=\"/account\""));
        String odd = Layout.expand(Layout.placeholder("home"), "it", viewer("<b>{{t:x}}</b>", "viewer"));
        check("the name is escaped: no tags and no {{ for the language step", !odd.contains("<b>") && !odd.contains("{{t:x}}"));
        check("an unknown role: no menu items", !Layout.expand(Layout.placeholder("home"), "it", viewer("x", "nobody")).contains("class=\"sidebar-link"));
        check("no session: no menu items and no account button", !Layout.expand(Layout.placeholder("home"), "it", Layout.Viewer.NOBODY)
                .contains("class=\"sidebar-link") && !Layout.expand(Layout.placeholder("home"), "it", Layout.Viewer.NOBODY).contains("href=\"/account\""));

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }

    static boolean plural(String lang, long n, String category) {
        boolean ok = I18n.pluralCategory(lang, n).equals(category);
        if (!ok) System.out.println("         " + lang + " " + n + ": " + I18n.pluralCategory(lang, n) + ", expected " + category);
        return ok;
    }

    /** True if the language file has a problem whose text contains what (it fails, and for the right reason). */
    static boolean fails(String lang, Map<String, String> bundle, Map<String, String> source, String what) {
        List<String> problems = languageProblems(lang, bundle, source);
        boolean ok = problems.stream().anyMatch(p -> p.contains(what));
        if (!ok) System.out.println("         expected \"" + what + "\", got " + problems);
        return ok;
    }

    static final Set<String> CATEGORIES = Set.of("zero", "one", "two", "few", "many", "other");

    /** The plural forms a language has for whole numbers (I18n.pluralCategory over many numbers). */
    static Set<String> categoriesOf(String lang) {
        Set<String> out = new TreeSet<>();
        for (long n = 0; n <= 1000; n++) out.add(I18n.pluralCategory(lang, n));
        for (long n : new long[]{1_000_000, 2_000_000}) out.add(I18n.pluralCategory(lang, n));
        return out;
    }

    /**
     * What is wrong in a language file, measured against Italian (the language the panel is written in): an empty
     * list if nothing. A key is a plural form when it ends with a CLDR category and Italian has base.other.
     */
    static List<String> languageProblems(String lang, Map<String, String> bundle, Map<String, String> source) {
        List<String> out = new ArrayList<>();
        Set<String> forms = categoriesOf(lang);
        Pattern tag = Pattern.compile("<(/?)([a-zA-Z0-9]+)[^>]*>");
        Set<String> allowedTags = Set.of("strong", "em", "code", "kbd", "br");
        for (Map.Entry<String, String> e : new java.util.TreeMap<>(bundle).entrySet()) {
            String k = e.getKey(), v = e.getValue();
            int dot = k.lastIndexOf('.');
            String last = dot < 0 ? "" : k.substring(dot + 1), base = dot < 0 ? k : k.substring(0, dot);
            boolean pluralForm = CATEGORIES.contains(last) && source.containsKey(base + ".other");
            if (!source.containsKey(k) && !pluralForm) { out.add(k + ": not in Italian"); continue; }
            if (v.isBlank()) out.add(k + ": empty");
            Set<String> expected = new TreeSet<>();
            if (source.containsKey(k)) expected.addAll(values(source.get(k)));
            else for (String c : CATEGORIES) if (source.containsKey(base + "." + c)) expected.addAll(values(source.get(base + "." + c)));
            if (source.containsKey(k) ? !values(v).equals(expected) : !expected.containsAll(values(v)))
                out.add(k + ": {values} " + values(v) + ", Italian " + expected);
            // .other is always there: it is the text used when a form is missing (Polish whole numbers never ask
            // for it, but tn() falls back to it)
            if (pluralForm && !last.equals("other") && !forms.contains(last))
                out.add(k + ": " + lang + " has no \"" + last + "\" form, only " + forms);
            if (pluralForm && !bundle.containsKey(base + ".other")) out.add(k + ": translated without " + base + ".other");
            if (v.contains("yyyy")) {
                try { java.time.format.DateTimeFormatter.ofPattern(v); }
                catch (IllegalArgumentException x) { out.add(k + ": not a date pattern"); }
            }
            if (k.endsWith(".html")) {
                // The .html sentences enter the page as they are: only the text tags, without attributes
                Matcher m = tag.matcher(v);
                while (m.find()) if (!allowedTags.contains(m.group(2).toLowerCase()) || m.group().length() > m.group(2).length() + 3)
                    out.add(k + ": tag " + m.group());
            } else if (!k.startsWith("server.") && v.matches("(?s).*[<>&].*")) {
                // The scripts also put the plain texts inside hand-built HTML: without < > & the text is the same,
                // escaped or not. (The server's messages always go through escape().)
                out.add(k + ": < > & in a plain text");
            }
        }
        return out;
    }

    static Set<String> values(String text) {
        Set<String> v = new TreeSet<>();
        Matcher m = I18n.PARAM.matcher(text);
        while (m.find()) v.add(m.group(1));
        return v;
    }

    static int count(String text, String piece) {
        int n = 0;
        for (int i = text.indexOf(piece); i >= 0; i = text.indexOf(piece, i + 1)) n++;
        return n;
    }
}
