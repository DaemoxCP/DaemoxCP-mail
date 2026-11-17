package org.daemoxcp.mail.content;

import org.daemoxcp.mail.i18n.I18n;

import java.io.*;
import java.lang.reflect.Method;

/**
 * Writes EVERY page of the panel to disk, so that its JavaScript can be checked with a parser and
 * the page can be tried in a browser.
 *
 * Why it exists. The pages are HTML and JavaScript inside Java text blocks, where the backslash-n
 * sequence is a JAVA escape: written once it becomes a REAL newline and breaks the JavaScript
 * string. The browser parser stops there and the WHOLE script block does not run: the page stays
 * with every spinner turning, as if the calls never ended while they never started.
 *
 * The Java compiler does not see this: for it the string is valid. A JavaScript parser on the
 * result is needed, and this class makes that possible.
 *
 * Every page comes out complete, as the server sends it: the frame (Layout) and the texts, in
 * Italian (name.html) and in English (name.en.html). Only {{CSRF_TOKEN}}, {{THEME}} and the other
 * per-request values are left, for the browser tests to fill in. i18n/ holds the two script
 * dictionaries, to be served as /i18n/it.js and /i18n/en.js.
 *
 * Like the panel (PanelContent.generateAllContent), every inline script and style block becomes a
 * file (PageAssets): assets/ holds them, to be served as /assets/..., and csp.txt holds the
 * Content-Security-Policy the panel sends, for the browser tests to send it too.
 *
 * Usage:
 *   javac -cp target/daemoxcp-mail-1.0.jar -d tests tests/org/daemoxcp/mail/content/PageGenerator.java
 *   java  -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.content.PageGenerator /tmp/pages
 *   then the script blocks are extracted and passed to "node --check" (see README.md).
 */
public class PageGenerator {

    /** The pages as a superadmin sees them: every menu item. */
    static final Layout.Viewer SUPERADMIN = new Layout.Viewer("admin", "superadmin",
            org.daemoxcp.mail.security.AuthStore.permissionsOf("superadmin"));
    public static void main(String[] a) throws Exception {
        File dir = new File(a[0]);
        new File(dir, "i18n").mkdirs();
        for (String lang : I18n.LANGUAGES) write(new File(dir, "i18n/" + lang + ".js"), I18n.script(lang));
        int done = 0, skipped = 0;
        for (Method m : PanelContent.class.getDeclaredMethods()) {
            String n = m.getName();
            if (!n.startsWith("get") || !n.endsWith("Html")) continue;
            if (m.getParameterCount() != 0) continue;
            try {
                String name = n.substring(3, n.length() - 4).toLowerCase();
                String html = PageAssets.externalize(String.valueOf(m.invoke(null)), name.equals("index") || name.equals("setup"));
                for (String lang : I18n.LANGUAGES) {
                    String ready = I18n.render(Layout.expand(html, lang, SUPERADMIN), lang);
                    write(new File(dir, name + (lang.equals("it") ? "" : "." + lang) + ".html"), ready);
                }
                System.out.println("  " + name + ".html  " + html.length());
                done++;
            } catch (Throwable t) {
                System.out.println("  SKIPPED " + n + ": " + t.getCause());
                skipped++;
            }
        }
        Layout.registerAssets();
        PageAssets.writeAll(dir.toPath());
        write(new File(dir, "csp.txt"), org.daemoxcp.mail.webserver.SecurityHeaders.CONTENT_SECURITY_POLICY);
        System.out.println("generated " + done + ", skipped " + skipped);
    }

    static void write(File f, String text) throws IOException {
        try (PrintWriter w = new PrintWriter(f, "UTF-8")) {
            w.print(text);
        }
    }
}
