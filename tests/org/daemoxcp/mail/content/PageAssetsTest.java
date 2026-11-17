package org.daemoxcp.mail.content;

import org.daemoxcp.mail.webserver.SecurityHeaders;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The pages without inline code, for the Content-Security-Policy without 'unsafe-inline' (reperto 178).
 *
 *  1. PageAssets.externalize: every &lt;script&gt; without src and every &lt;style&gt; becomes a file
 *     named after its content; scripts with src stay; the same content is the same file;
 *     the sign-in pages go to open/.
 *  2. PageAssets.resolve: the files of the protected pages only to whoever signed in; a name that
 *     is not a fingerprint, a path that leaves, a file that is not there: nothing.
 *  3. PageAssets.writeAll: writes the registered files and removes those of an older version.
 *  4. The policy: no 'unsafe-inline' nor 'unsafe-eval', no sources from outside.
 *  5. Every page of the panel, generated as the server generates it: no inline script, style,
 *     on...= handler or style attribute.
 *  6. The pages' sources (MailPanelContent, Layout, resources/pages, DnsRecordsGenerator): no on...=
 *     nor style= even in the HTML the scripts build later, which check 5 does not see.
 * Check 6 reads the sources: it must be started from the project root.
 *
 * Usage: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.content.PageAssetsTest
 */
public class PageAssetsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final Pattern INLINE_SCRIPT = Pattern.compile("<script(?![^>]*\\bsrc=)");
    static final Pattern HANDLER_ATTR = Pattern.compile("\\son[a-z]+\\s*=\\s*[\"']");
    static final Pattern STYLE_ATTR = Pattern.compile("\\sstyle\\s*=\\s*[\"']");
    /** In the sources: an on...= or style= attribute even inside the scripts' strings ('...style="...'). */
    static final Pattern SOURCE_ATTR = Pattern.compile("(?<![-\\w.])(on(click|change|input|toggle|submit|keyup|keydown|keypress|blur|focus|load|error|dblclick|mouse[a-z]+)|style)=\\\\{0,2}[\"']");

    public static void main(String[] args) throws Exception {
        Path tmp = Files.createTempDirectory("page-assets");
        try {
            run(tmp);
        } finally {
            try (Stream<Path> walk = Files.walk(tmp)) {
                for (Path p : walk.sorted((a, b) -> b.compareTo(a)).toList()) Files.deleteIfExists(p);
            }
        }
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void run(Path tmp) throws Exception {
        System.out.println("== 1. externalize ==");
        String page = "<head><script src=\"/vendor/x.js\"></script><script>var a = 1;</script><style>b{c:d}</style></head>"
                + "<body><script>var a = 1;</script></body>";
        String out = PageAssets.externalize(page, false);
        check("no inline script or style left", !INLINE_SCRIPT.matcher(out).find() && !out.contains("<style"));
        check("the script with src stays as it was", out.contains("<script src=\"/vendor/x.js\"></script>"));
        Matcher js = Pattern.compile("<script src=\"(/assets/[0-9a-f]{20}\\.js)\"></script>").matcher(out);
        List<String> urls = new ArrayList<>();
        while (js.find()) urls.add(js.group(1));
        check("the two equal blocks are the same file", urls.size() == 2 && urls.get(0).equals(urls.get(1)));
        check("the style is a <link> to a .css file", Pattern.compile("<link rel=\"stylesheet\" href=\"/assets/[0-9a-f]{20}\\.css\">").matcher(out).find());
        String open = PageAssets.externalize("<script>var a = 1;</script>", true);
        check("for the sign-in pages the file is in open/", open.contains("src=\"/assets/open/"));

        System.out.println("\n== 2. resolve ==");
        PageAssets.writeAll(tmp);
        String own = urls.get(0), shared = open.replaceAll(".*src=\"([^\"]+)\".*", "$1");
        check("a file of the protected pages: not to whoever has not signed in", PageAssets.resolve(tmp, own, false) == null);
        check("  to whoever signed in, yes", PageAssets.resolve(tmp, own, true) != null);
        check("a file of open/: to everyone", PageAssets.resolve(tmp, shared, false) != null);
        check("a name that is not a fingerprint: nothing", PageAssets.resolve(tmp, "/assets/open/ABCDEF.js", true) == null
                && PageAssets.resolve(tmp, "/assets/open/" + "a".repeat(20) + ".html", true) == null);
        check("a path that leaves: nothing", PageAssets.resolve(tmp, "/assets/../admin/home.html", true) == null
                && PageAssets.resolve(tmp, "/assets/open/../" + own.substring(own.lastIndexOf('/') + 1), false) == null);
        check("a fingerprint that is not there: nothing", PageAssets.resolve(tmp, "/assets/" + "0".repeat(20) + ".js", true) == null);
        check("the type: javascript and css", PageAssets.contentType(Path.of("x.js")).startsWith("text/javascript")
                && PageAssets.contentType(Path.of("x.css")).startsWith("text/css"));

        System.out.println("\n== 3. writeAll ==");
        Path stale = tmp.resolve("assets").resolve("f".repeat(20) + ".js");
        Path staleOpen = tmp.resolve("assets/open").resolve("e".repeat(20) + ".css");
        Files.writeString(stale, "old");
        Files.writeString(staleOpen, "old");
        PageAssets.writeAll(tmp);
        check("the files of an older version go away", !Files.exists(stale) && !Files.exists(staleOpen));
        check("the registered ones stay, with their content", PageAssets.resolve(tmp, own, true) != null
                && Files.readString(PageAssets.resolve(tmp, own, true)).equals("var a = 1;"));
        try (Stream<Path> files = Files.list(tmp.resolve("assets"))) {
            check("no temporary file left", files.noneMatch(f -> f.toString().endsWith(".tmp")));
        }

        System.out.println("\n== 4. The policy ==");
        String csp = SecurityHeaders.CONTENT_SECURITY_POLICY;
        check("no unsafe-inline, unsafe-eval, http(s): or *", !csp.contains("unsafe-") && !csp.contains("http") && !csp.contains("*"));
        check("script-src and style-src only 'self'", csp.contains("script-src 'self';") && csp.contains("style-src 'self';"));
        check("object-src 'none', base-uri 'self', form-action 'self', frame-ancestors 'none'", csp.contains("object-src 'none'")
                && csp.contains("base-uri 'self'") && csp.contains("form-action 'self'") && csp.contains("frame-ancestors 'none'"));

        System.out.println("\n== 5. Every page, as the server generates it ==");
        int pages = 0;
        List<String> dirty = new ArrayList<>();
        for (Method m : MailPanelContent.class.getDeclaredMethods()) {
            String n = m.getName();
            if (!n.startsWith("get") || !n.endsWith("Html") || m.getParameterCount() != 0) continue;
            m.setAccessible(true);
            String name = n.substring(3, n.length() - 4).toLowerCase();
            String html = PageAssets.externalize(String.valueOf(m.invoke(null)), name.equals("index") || name.equals("setup"));
            html = Layout.expand(html, "it", Layout.Viewer.NOBODY);
            pages++;
            if (INLINE_SCRIPT.matcher(html).find()) dirty.add(name + ": <script>");
            if (html.contains("<style")) dirty.add(name + ": <style>");
            if (HANDLER_ATTR.matcher(html).find()) dirty.add(name + ": on...=");
            if (STYLE_ATTR.matcher(html).find()) dirty.add(name + ": style=");
        }
        check("the generated pages are " + pages, pages >= 20);
        check("none with inline code" + (dirty.isEmpty() ? "" : ": " + dirty), dirty.isEmpty());

        System.out.println("\n== 6. The pages' sources ==");
        Path root = Path.of("src/main");
        List<Path> sources = new ArrayList<>(List.of(root.resolve("java/org/daemoxcp/mail/content/MailPanelContent.java"),
                root.resolve("java/org/daemoxcp/mail/content/Layout.java"),
                root.resolve("java/org/daemoxcp/mail/security/DnsRecordsGenerator.java")));
        if (Files.isDirectory(root.resolve("resources/pages"))) {
            try (Stream<Path> s = Files.list(root.resolve("resources/pages"))) {
                s.filter(p -> !p.getFileName().toString().equals("panel-actions.js")).sorted().forEach(sources::add);
            }
        }
        boolean found = sources.stream().allMatch(Files::isRegularFile);
        check("sources found (" + sources.size() + " files, from the project root)", found && sources.size() > 10);
        List<String> hits = new ArrayList<>();
        for (Path f : sources) {
            if (!Files.isRegularFile(f)) continue;
            String text = Files.readString(f);
            Matcher hm = SOURCE_ATTR.matcher(text);
            while (hm.find()) hits.add(f.getFileName() + ":" + (text.substring(0, hm.start()).split("\n", -1).length) + " " + hm.group());
        }
        check("no on...= or style= in the HTML, not even in the one the scripts build" + (hits.isEmpty() ? "" : ": " + hits), hits.isEmpty());
    }
}
