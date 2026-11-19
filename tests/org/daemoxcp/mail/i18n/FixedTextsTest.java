package org.daemoxcp.mail.i18n;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Every text a person reads in the web panel comes from the language files: no fixed text left in the pages.
 *
 *  1. The page templates (content/*.java): every text between two tags is a {{t:key}}, or a technical name that is
 *     the same in every language (DNS, TTL, MySQL, a command), listed below one by one.
 *  2. The page scripts (pages/*.js and the scripts inside the templates): a sentence a person reads (two words or
 *     more, once tags and attributes are taken away) goes through t(); the technical ones are listed.
 *  3. The attributes a person reads or hears (title, aria-label, placeholder, alt): a {{t:key}}, or an example
 *     value (a domain, a PEM header), listed.
 *  4. The server's answers (src/main/java): a "message", "error" or "warning" written as a fixed sentence, and an
 *     error page with a fixed text (sendJsonError), are not allowed; short codes (too_large) that the page translates
 *     are.
 *  5. The checks can fail: each one finds the fixed text in a small sample made wrong on purpose.
 *  6. The console (Main and gui/*: the on-screen menu, its windows, and the commands' answers): a window, a label, a
 *     button, a title, a menu item or a dialog never has a fixed text; the console speaks the panel's language.
 *
 * Logs, operation journals and the output of other programs are not checked: they stay in English, the same for
 * everyone (decided on 19/11/2026). A text that is really technical goes in the lists below, with nothing else.
 *
 * Usage (from the project root):
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.i18n.FixedTextsTest
 */
public class FixedTextsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    // ---------- 1. text between two tags ----------

    static final Pattern TEXT_NODE = Pattern.compile(">([^<>{}\\n]*\\p{L}{3,}[^<>{}\\n]*)<");
    static final Pattern CODE_LIKE = Pattern.compile("[;=(){}\"]|\\+ |\\.append|return ");

    /** The same in every language: technical names, products, commands, values. */
    static final Set<String> TECHNICAL_TEXT = Set.of(
            "java -jar daemoxcp-mail.jar --create-admin", "Auto", "Record", "Software", "DNS", "PTR", "IPv4", "Proxy",
            "Server", "TTL", "DKIM", "Password", "Email", "Outlook", "iPhone/Mac", "Android", "Microsoft Outlook",
            "993 / SSL-TLS", "587 / STARTTLS", "iPhone / iPad / Mac", "993 / SSL", "Quota", "TXT", "Blacklist",
            "Cloudflare", "date", "MySQL", "session:", "global:", "system:", "daemoxcp-mail-auth", "5 min", "20 min",
            "30 min", "10 min", "HTTP-01 vs DNS-01", "_acme-challenge.mail.example.com", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "cert.pem", "ca-bundle.crt", "intermediate.crt", "chain.pem", "privkey.pem", "fullchain.pem",
            "openssl rsa -in privkey-encrypted.key -out privkey.pem", "openssl pkcs12 -in cert.pfx -nocerts -nodes -out privkey.pem",
            "openssl pkcs12 -in cert.pfx -nokeys -clcerts -out cert.crt", "openssl pkcs12 -in cert.pfx -nokeys -cacerts -out ca-bundle.crt",
            "Let\\\\'s Encrypt", "Java:", "SQLite", "root →", "Jail", "ISP", "ASN", "Token", "Dovecot", "Postfix",
            "postfix check:", "Rspamd", "rspamadm configtest:", "Java", "Jar", "daemoxcp_mail_enable", "Userland", "PID",
            "task_timeout", "compatibility_level:", "mail", "TTL:", "Hetzner:", "OVH:", "DigitalOcean:", "Vultr:", "Contabo:");

    static List<String> textNodes(String file, String src) {
        List<String> out = new ArrayList<>();
        Matcher m = TEXT_NODE.matcher(src);
        while (m.find()) {
            String text = m.group(1).trim();
            if (text.isEmpty() || text.startsWith("{{") || CODE_LIKE.matcher(text).find()) continue;
            out.add(text + "\t" + file + ":" + line(src, m.start()));
        }
        return out;
    }

    // ---------- 2. sentences in the scripts ----------

    static final Pattern JS_LITERAL = Pattern.compile("(['\"`])((?:\\\\.|(?!\\1).)*?)\\1");
    static final Pattern JS_LITERAL_NO_DOUBLE = Pattern.compile("(['`])((?:\\\\.|(?!\\1).)*?)\\1");
    static final Pattern TRANSLATED_BEFORE = Pattern.compile("\\b(t|tn|tNodes|ipfName)\\(\\s*$");
    static final Pattern NOT_TEXT_BEFORE = Pattern.compile(
            "(querySelector(All)?|getElementById|closest|setAttribute|getAttribute|removeAttribute|classList\\.\\w+|className\\s*=|"
            + "addEventListener|fetch|panelSay|createElement|addrEl|dataset|console\\.(log|warn|error))\\s*\\(?\\s*$");
    static final Pattern WORD = Pattern.compile("\\p{L}{3,}");
    static final Pattern CSS_START = Pattern.compile("^(btn|text|bg|col|row|d|form|badge|small|mb|mt|me|ms|fw|gap|align|flex|card|table|"
            + "alert|spinner|visually|fa|fas|far|fab|list|input|nav|modal|py|px|p|m|w|h|border|rounded|position|lead|font|link|dropdown|touch|upd|"
            + "cert|proc|path|limit|minus|check|times|exclamation|ban|unlock)-?\\b");
    static final Pattern COMMON_WORD = Pattern.compile("\\b(the|and|is|of|to|di|il|la|che|per|non)\\b");

    /** The same in every language: commands, technical names, protocol values. */
    static final Set<String> TECHNICAL_SCRIPT_TEXT = Set.of(
            "TTL   Auto", "OVH:  Manager   Server   IP", "use_secure_urls in Roundcube:", "service daemoxcp_mail rcvar:\\\\n",
            "fail2ban-client status", "$ fail2ban-client get", "freebsd-update -r", "-RELEASE upgrade",
            "Cloudflare IPv4", "Cloudflare IPv6", "(prefers-color-scheme: dark)", "(min-width: 992px)", "Courier New",
            "SASL.*authentication failed", "dovecot.*(auth failed|Disconnected.*auth)", "fail2ban.*(Ban |Found )",
            "SSL_accept error|TLS library problem|lost connection after (STARTTLS|EHLO)|http request",
            "postfix/anvil|max connection", "connect from|disconnect from", "noopener noreferrer",
            "ip.geoip.country ne \"", "ip.geoip.country eq \"", "https://www.openstreetmap.org/?mlat= &mlon= #map=8/ /",
            "4px solid #ffc107", "java -jar daemoxcp-mail.jar --access-code");

    /** The comments taken away (CSS and JS blocks, HTML), with their line breaks kept: an Italian «e'» in a comment
     *  is not the end of a script's text. */
    static String withoutComments(String src) {
        StringBuilder b = new StringBuilder(src);
        for (Pattern c : List.of(Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL), Pattern.compile("<!--.*?-->", Pattern.DOTALL))) {
            Matcher m = c.matcher(b.toString());
            while (m.find()) for (int i = m.start(); i < m.end(); i++) if (b.charAt(i) != '\n') b.setCharAt(i, ' ');
        }
        return b.toString();
    }

    /** A piece of code, not a text: a concatenation, a call, a style. */
    static final Pattern CODE_PIECE = Pattern.compile("\\|\\||&&|=>|\\.replace\\(|\\besc\\w*\\(|\" \\+|\\+ \"|=\\s*\"|^\\s*[+)]|[+(]\\s*$|[a-z-]+:\\s*[^;]*;");

    static List<String> scriptTexts(String file, String src, boolean insideJava) {
        List<String> out = new ArrayList<>();
        String[] lines = withoutComments(src).split("\n", -1);
        Pattern literal = insideJava ? JS_LITERAL_NO_DOUBLE : JS_LITERAL;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i], s = line.strip();
            if (s.startsWith("//") || s.startsWith("*") || s.startsWith("/*")) continue;
            if (line.contains("console.")) continue;                              // the browser's console, for developers
            Matcher m = literal.matcher(line);
            while (m.find()) {
                String before = line.substring(0, m.start());
                if (TRANSLATED_BEFORE.matcher(before).find() || NOT_TEXT_BEFORE.matcher(before).find()) continue;
                if (CODE_PIECE.matcher(m.group(2)).find()) continue;
                String text = visible(m.group(2)).strip();
                if (!text.matches("(?s).*\\s.*")) continue;                      // one token: a name, a key, a code
                if (WORD.matcher(text).results().count() < 2) continue;
                if (text.matches("[A-Z0-9_ .]+")) continue;                      // CONFIRMATION WORDS, CODES
                if (text.matches("[A-Za-z_$][\\w$]*\\(.*\\)")) continue;          // an action: addrMail('both', false)
                if (CSS_START.matcher(text).find() && !COMMON_WORD.matcher(text).find()) continue;
                if (text.contains("application/json") || text.contains("use strict") || text.contains("aria-label=")
                        || text.contains("data-on-") || text.contains("data-style=")) continue;
                out.add(text + "\t" + file + ":" + (i + 1));
            }
        }
        return out;
    }

    static String visible(String v) {
        return v.replaceAll("\\$\\{[^}]*\\}", " ").replaceAll("<[^>]*>", " ").replaceAll("^[^<]*>", " ")
                .replaceAll("<[^>]*$", " ").replaceAll("&[a-z]+;|&#\\d+;", " ");
    }

    // ---------- 3. attributes a person reads or hears ----------

    static final Pattern ATTRIBUTE = Pattern.compile("\\b(title|aria-label|placeholder|alt)=\\\\?\"([^\"{\\\\+]*\\p{L}{3,}[^\"{\\\\+]*)\\\\?\"");
    static final Set<String> EXAMPLE_VALUES = Set.of("Proxy/CDN", "example.com", "info", "Jail", "mail.example.com", "webmail.example.com",
            "-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----", "-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----");

    static List<String> attributes(String file, String src) {
        List<String> out = new ArrayList<>();
        Matcher m = ATTRIBUTE.matcher(src);
        while (m.find()) {
            String text = m.group(2).strip();
            if (text.startsWith("-----BEGIN") && text.contains("\n")) continue;   // a PEM over several lines: a value
            out.add(text + "\t" + file + ":" + line(src, m.start()));
        }
        return out;
    }

    // ---------- 4. the server's answers ----------

    static final Pattern FIXED_ANSWER = Pattern.compile("\\.put\\(\"(message|error|warning)\",\\s*\"([^\"]*)\"");
    static final Pattern FIXED_ERROR_PAGE = Pattern.compile("sendJsonError\\([^,]+,\\s*\\d+,\\s*\"");

    static List<String> answers(String file, String src) {
        List<String> out = new ArrayList<>();
        Matcher m = FIXED_ANSWER.matcher(src);
        while (m.find()) {
            String v = m.group(2);   // a code (too_large) or a sign before a translated text («✅ » + tr(...)) is fine
            if (v.matches(".*\\p{L}.*") && !v.matches("[a-z0-9_]+")) out.add(v + "\t" + file + ":" + line(src, m.start()));
        }
        m = FIXED_ERROR_PAGE.matcher(src);
        while (m.find()) out.add("sendJsonError with a fixed text\t" + file + ":" + line(src, m.start()));
        return out;
    }

    // ---------- 6. the console ----------

    /** A text given to the on-screen menu (Lanterna) or as a command's answer, written as a fixed string. */
    static final Pattern CONSOLE_TEXT = Pattern.compile("(new (Label|Button|BasicWindow|Welcome)\\(|Borders\\.(singleLine|doubleLine)\\(|"
            + "\\.set(Title|Text|Description)\\(|showTextInputDialog(WithDefault)?\\(gui,\\s*|addItem\\(|new ConsoleResult\\((true|false),\\s*|"
            + "message\\(gui,\\s*(title,\\s*)?)\"([^\"]*)\"");
    static final Set<String> CONSOLE_EXAMPLES = Set.of("webmail.example.com, roundcube.example.com");

    static List<String> consoleTexts(String file, String src) {
        List<String> out = new ArrayList<>();
        Matcher m = CONSOLE_TEXT.matcher(src);
        while (m.find()) {
            String text = m.group(m.groupCount());
            if (WORD.matcher(text).find() && !CONSOLE_EXAMPLES.contains(text)) out.add(text + "\t" + file + ":" + line(src, m.start()));
        }
        return out;
    }

    static int line(String src, int at) {
        int n = 1;
        for (int i = 0; i < at; i++) if (src.charAt(i) == '\n') n++;
        return n;
    }

    static List<Path> files(String dir, String suffix) throws Exception {
        try (Stream<Path> s = Files.walk(Path.of(dir))) {
            return s.filter(p -> p.toString().endsWith(suffix)).sorted().toList();
        }
    }

    /** The findings whose text is not in the allowed set. */
    static List<String> unknown(List<String> findings, Set<String> allowed) {
        List<String> out = new ArrayList<>();
        for (String f : findings) if (!allowed.contains(f.substring(0, f.indexOf('\t')))) out.add(f.replace('\t', ' '));
        return out;
    }

    static List<String> stale(Set<String> allowed, List<String> findings) {
        Set<String> found = new TreeSet<>();
        for (String f : findings) found.add(f.substring(0, f.indexOf('\t')));
        List<String> out = new ArrayList<>();
        for (String a : new TreeSet<>(allowed)) if (!found.contains(a)) out.add(a);
        return out;
    }

    static String show(List<String> list) {
        int max = System.getenv("FIXED_TEXTS_ALL") != null ? Integer.MAX_VALUE : 12;
        return list.isEmpty() ? "" : ": " + String.join(" | ", list.subList(0, Math.min(list.size(), max)))
                + (list.size() > max ? " | … " + (list.size() - max) + " more (FIXED_TEXTS_ALL=1 shows them all)" : "");
    }

    public static void main(String[] a) throws Exception {
        System.out.println("\n== 5. The checks can fail ==");
        check("a fixed text between two tags is found",
                unknown(textNodes("x", "<h2><i class=\"fa\"></i>Mail Server Dashboard</h2><td>DNS</td>"), TECHNICAL_TEXT).size() == 1);
        check("a fixed sentence in a script is found, a translated one and a selector are not",
                unknown(scriptTexts("x", "el.textContent = 'Entropy: none yet';\nel.textContent = t('pw.entropyNone');\n"
                        + "document.querySelector('#a .b c');\n", false), TECHNICAL_SCRIPT_TEXT).size() == 1);
        check("a fixed attribute is found", unknown(attributes("x", "<input placeholder=\"mario rossi\">"), EXAMPLE_VALUES).size() == 1);
        check("a fixed text in a console window, label or menu item is found, a translated one is not",
                consoleTexts("x", "new Label(\"Panel Settings\"); new Button(I18n.tr(\"console.save\"), x); actionListBox.addItem(\"1) \" + a, b);"
                        + " new Welcome(\"Information\", text);").size() == 2);
        check("a fixed answer of the server is found, a code is not",
                answers("x", "r.put(\"error\", \"Unknown action\"); r.put(\"error\", \"too_large\");"
                        + " sendJsonError(exchange, 400, \"Bad request\");").size() == 2);

        System.out.println("\n== 1-3. The pages ==");
        List<String> nodes = new ArrayList<>(), scripts = new ArrayList<>(), attrs = new ArrayList<>();
        for (Path p : files("src/main/java/org/daemoxcp/mail/content", ".java")) {
            String src = Files.readString(p), name = p.getFileName().toString();
            nodes.addAll(textNodes(name, src));
            scripts.addAll(scriptTexts(name, src, true));
            attrs.addAll(attributes(name, src));
        }
        for (Path p : files("src/main/resources/pages", ".js")) {
            String src = Files.readString(p), name = p.getFileName().toString();
            // The interpreter of data-on-* (CSP without inline code): its errors go to the browser's console, for
            // whoever writes a page, never to the person using it.
            if (name.equals("panel-actions.js")) continue;
            scripts.addAll(scriptTexts(name, src, false));
            attrs.addAll(attributes(name, src));
        }
        List<String> n = unknown(nodes, TECHNICAL_TEXT), s = unknown(scripts, TECHNICAL_SCRIPT_TEXT), at = unknown(attrs, EXAMPLE_VALUES);
        check("every text between two tags comes from the language files (" + nodes.size() + " technical ones listed)" + show(n), n.isEmpty());
        check("every sentence in the scripts goes through t() (" + scripts.size() + " technical ones listed)" + show(s), s.isEmpty());
        check("every attribute a person reads or hears comes from the language files (" + attrs.size() + " examples listed)" + show(at), at.isEmpty());
        // The lists hold only what is still in the pages: a text that went away (translated, removed) leaves the list too.
        List<String> stale = new ArrayList<>();
        stale.addAll(stale(TECHNICAL_TEXT, nodes));
        stale.addAll(stale(TECHNICAL_SCRIPT_TEXT, scripts));
        stale.addAll(stale(EXAMPLE_VALUES, attrs));
        check("the lists of technical texts hold only texts still in the pages" + show(stale), stale.isEmpty());

        System.out.println("\n== 4. The server's answers ==");
        List<String> ans = new ArrayList<>();
        for (Path p : files("src/main/java", ".java")) ans.addAll(answers(p.toString().replaceFirst("^src/main/java/org/daemoxcp/mail/", ""), Files.readString(p)));
        List<String> shown = new ArrayList<>();
        for (String f : ans) shown.add(f.replace('\t', ' '));
        check("no answer of the server is a fixed sentence" + show(shown), ans.isEmpty());

        System.out.println("\n== 6. The console ==");
        List<String> console = new ArrayList<>();
        console.addAll(consoleTexts("Main.java", Files.readString(Path.of("src/main/java/org/daemoxcp/mail/Main.java"))));
        for (Path p : files("src/main/java/org/daemoxcp/mail/gui", ".java")) console.addAll(consoleTexts(p.getFileName().toString(), Files.readString(p)));
        List<String> c = new ArrayList<>();
        for (String f : console) c.add(f.replace('\t', ' '));
        check("every window, label, button, title and menu item of the console comes from the language files" + show(c), console.isEmpty());

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
