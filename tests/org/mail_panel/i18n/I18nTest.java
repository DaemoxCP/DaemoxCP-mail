package org.mail_panel.i18n;

import org.mail_panel.content.Layout;
import org.mail_panel.content.MailPanelContent;

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
        return new Layout.Viewer(name, role, org.mail_panel.security.AuthStore.permissionsOf(role));
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{t:([A-Za-z0-9_.-]+)\\}\\}");
    static final Pattern SCRIPT = Pattern.compile("<script\\b[^>]*>(.*?)</script>", Pattern.DOTALL);
    // (anche dopo "...": el.append(...tNodes('chiave', ...)))
    static final Pattern T_CALL = Pattern.compile("(?:(?<=\\.\\.\\.)|(?<![A-Za-z0-9_.$]))(tNodes|tn|t)\\('([A-Za-z0-9_.-]+)'");

    public static void main(String[] a) throws Exception {
        Map<String, String> it = I18n.bundle("it"), en = I18n.bundle("en");

        System.out.println("\n== The language files ==");
        check("they load without problems" + (I18n.problems().isEmpty() ? "" : ": " + I18n.problems()), I18n.problems().isEmpty());
        check("Italian: " + it.size() + " texts", it.size() > 30);
        Set<String> onlyIt = new TreeSet<>(it.keySet()), onlyEn = new TreeSet<>(en.keySet());
        onlyIt.removeAll(en.keySet());
        onlyEn.removeAll(it.keySet());
        check("the same keys" + (onlyIt.isEmpty() ? "" : "; only in Italian: " + onlyIt) + (onlyEn.isEmpty() ? "" : "; only in English: " + onlyEn),
                onlyIt.isEmpty() && onlyEn.isEmpty());
        List<String> blank = new ArrayList<>(), differentValues = new ArrayList<>();
        for (String k : it.keySet()) {
            if (it.get(k).isBlank() || (en.containsKey(k) && en.get(k).isBlank())) blank.add(k);
            if (en.containsKey(k) && !values(it.get(k)).equals(values(en.get(k)))) differentValues.add(k);
        }
        check("no empty text" + (blank.isEmpty() ? "" : ": " + blank), blank.isEmpty());
        check("the same {values} in both languages" + (differentValues.isEmpty() ? "" : ": " + differentValues), differentValues.isEmpty());
        List<String> badPatterns = new ArrayList<>();
        for (Map<String, String> bundle : List.of(it, en))
            for (Map.Entry<String, String> e : bundle.entrySet())
                if (e.getValue().contains("yyyy")) {
                    try { java.time.format.DateTimeFormatter.ofPattern(e.getValue()); }
                    catch (IllegalArgumentException x) { badPatterns.add(e.getKey() + " = " + e.getValue()); }
                }
        check("every date pattern is a valid DateTimeFormatter pattern" + (badPatterns.isEmpty() ? "" : ": " + badPatterns), badPatterns.isEmpty());
        List<String> plurals = new ArrayList<>();
        for (String k : it.keySet()) {
            if (k.endsWith(".one") && !it.containsKey(k.substring(0, k.length() - 4) + ".other")) plurals.add(k);
            if (k.endsWith(".other") && !it.containsKey(k.substring(0, k.length() - 6) + ".one")) plurals.add(k);
        }
        check("every plural has .one and .other" + (plurals.isEmpty() ? "" : ": " + plurals), plurals.isEmpty());
        // Le frasi .html entrano nella pagina cosi' come sono: solo i tag di text, nient'altro
        Pattern tag = Pattern.compile("<(/?)([a-zA-Z0-9]+)[^>]*>");
        Set<String> allowed = Set.of("strong", "em", "code", "kbd", "br");
        List<String> oddTags = new ArrayList<>();
        for (Map<String, String> b : List.of(it, en)) {
            for (Map.Entry<String, String> e : b.entrySet()) {
                if (!e.getKey().endsWith(".html")) continue;
                Matcher m = tag.matcher(e.getValue());
                while (m.find()) if (!allowed.contains(m.group(2).toLowerCase()) || m.group().length() > m.group(2).length() + 3)
                    oddTags.add(e.getKey() + " " + m.group());
            }
        }
        check("the .html sentences only have strong, em, code, kbd, br (no attributes)" + (oddTags.isEmpty() ? "" : ": " + oddTags), oddTags.isEmpty());
        // Gli script mettono i testi semplici anche dentro dell'HTML costruito a mano: senza < > &
        // il text e' lo stesso, scappato o no. (I messaggi del server passano sempre da esc().)
        List<String> withSigns = new ArrayList<>();
        for (Map<String, String> b : List.of(it, en)) {
            for (Map.Entry<String, String> e : b.entrySet()) {
                if (e.getKey().endsWith(".html") || e.getKey().startsWith("server.")) continue;
                if (e.getValue().matches("(?s).*[<>&].*")) withSigns.add(e.getKey());
            }
        }
        check("the plain page texts have no < > &" + (withSigns.isEmpty() ? "" : ": " + new TreeSet<>(withSigns)), withSigns.isEmpty());

        System.out.println("\n== The pages ==");
        Set<String> used = new TreeSet<>();
        List<String> missing = new ArrayList<>(), inScripts = new ArrayList<>(), leftovers = new ArrayList<>();
        int pageCount = 0;
        List<String> sources = new ArrayList<>();
        for (Method m : MailPanelContent.class.getDeclaredMethods()) {
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
        // La cornice e' una pagina anche lei: le sue keys stanno in Layout
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
        // Una variabile o un parametro di name t (o tn, tNodes, escHtml) nasconde la funzione del
        // dizionario: dentro quella funzione t('chiave') diventerebbe un errore. Nessuno script li usa.
        Pattern shadow = Pattern.compile("\\b(?:let|const|var)\\s+(?:t|tn|tNodes|escHtml)(?:\\s*[=;,)]|\\s+(?:of|in)\\b)"
                + "|function\\s*[A-Za-z0-9_$]*\\s*\\([^)]*\\b(?:t|tn|tNodes|escHtml)\\b[^)]*\\)"
                + "|(?<![A-Za-z0-9_$.])(?:t|tn|tNodes|escHtml)\\s*=>"
                + "|\\(\\s*(?:[A-Za-z0-9_$]+\\s*,\\s*)*(?:t|tn|tNodes|escHtml)\\s*(?:,\\s*[A-Za-z0-9_$]+\\s*)*\\)\\s*=>"
                + "|catch\\s*\\(\\s*(?:t|tn|tNodes|escHtml)\\s*\\)");
        // Ne' usa t come un asValue (escapeHtml(t), { type: t }): e' una variabile rinominata a
        // meta'. Cosi' la pagina Kafka mostrava il code della funzione al posto dei topic.
        Pattern asValue = Pattern.compile("(?<![A-Za-z0-9_$.'\"#-])t(?![A-Za-z0-9_$'\"(:-])");
        List<String> shadows = new ArrayList<>(), asValues = new ArrayList<>();
        for (Method m : MailPanelContent.class.getDeclaredMethods()) {
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
        unused.removeIf(k -> k.startsWith("server.")); // i messaggi che scrive il server, non le pageCount
        System.out.println("  (texts the pages do not use: " + unused.size() + (unused.isEmpty() ? "" : " " + unused) + ")");

        System.out.println("\n== The server messages ==");
        // Le keys che il code del server scrive per intero: I18n.tr("..."), jsonError("...") e
        // ogni text "server.qualcosa" (anche passato a un metodo che poi lo traduce). Quelle che
        // finiscono con un punto sono prefissi completati a runtime: le controllano le prove dei
        // loro moduli (SoftwareVersionsTest per i ruoli dei programmi).
        Set<String> serverKeys = new TreeSet<>();
        // (un text "server.x" con un punto solo, come server.properties di Kafka, non e' una chiave)
        // (qui solo le chiamate: nel pannello mail "server.example.com" e' un name di host, non una chiave)
        Pattern serverKey = Pattern.compile("(?:I18n\\.tr|jsonError)\\(\"([A-Za-z0-9_.-]*[A-Za-z0-9_-])\"()");
        // I18n.trn("chiave", n, ...) usa chiave.one e chiave.other
        Pattern pluralCall = Pattern.compile("I18n\\.trn\\(\"([A-Za-z0-9_.-]*[A-Za-z0-9_-])\"");
        Set<String> serverPlurals = new TreeSet<>();
        try (var files = java.nio.file.Files.walk(java.nio.file.Path.of("src/main/java"))) {
            for (var f : (Iterable<java.nio.file.Path>) files.filter(x -> x.toString().endsWith(".java"))::iterator) {
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
                .equals("__Host-lang=en; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax"));
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
