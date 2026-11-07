package org.mail_panel.content;

import org.mail_panel.webserver.SecurityHeaders;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Le pagine senza codice in linea, per la Content-Security-Policy senza 'unsafe-inline' (reperto 178).
 *
 *  1. PageAssets.externalize: ogni &lt;script&gt; senza src e ogni &lt;style&gt; diventa un file col
 *     nome preso dal contenuto; gli script con src restano; lo stesso contenuto e' lo stesso file;
 *     le pagine d'accesso vanno in open/.
 *  2. PageAssets.resolve: i file delle pagine protette solo a chi e' entrato; un nome che non e'
 *     un'impronta, un percorso che esce, un file che non c'e': niente.
 *  3. PageAssets.writeAll: scrive i file registrati e toglie quelli di una versione di prima.
 *  4. La politica: niente 'unsafe-inline' ne' 'unsafe-eval', niente sorgenti da fuori.
 *  5. Ogni pagina del pannello, generata come la genera il server: nessun script, stile, gestore
 *     on...= o attributo style in linea.
 *  6. I sorgenti delle pagine (MailPanelContent, Layout, resources/pages, DnsRecordsGenerator):
 *     nessun on...= ne' style= nemmeno nell'HTML che gli script costruiscono dopo, che la prova 5
 *     non vede.
 * La 6 legge i sorgenti: va lanciata dalla radice del progetto.
 *
 * Uso: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageAssetsTest
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
    /** Nei sorgenti: un attributo on...= o style= anche dentro le stringhe degli script ('...style="...'). */
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
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void run(Path tmp) throws Exception {
        System.out.println("== 1. externalize ==");
        String page = "<head><script src=\"/vendor/x.js\"></script><script>var a = 1;</script><style>b{c:d}</style></head>"
                + "<body><script>var a = 1;</script></body>";
        String out = PageAssets.externalize(page, false);
        check("nessuno script o stile in linea rimasto", !INLINE_SCRIPT.matcher(out).find() && !out.contains("<style"));
        check("lo script con src resta com'era", out.contains("<script src=\"/vendor/x.js\"></script>"));
        Matcher js = Pattern.compile("<script src=\"(/assets/[0-9a-f]{20}\\.js)\"></script>").matcher(out);
        List<String> urls = new ArrayList<>();
        while (js.find()) urls.add(js.group(1));
        check("i due blocchi uguali sono lo stesso file", urls.size() == 2 && urls.get(0).equals(urls.get(1)));
        check("lo stile e' un <link> a un file .css", Pattern.compile("<link rel=\"stylesheet\" href=\"/assets/[0-9a-f]{20}\\.css\">").matcher(out).find());
        String open = PageAssets.externalize("<script>var a = 1;</script>", true);
        check("per le pagine d'accesso il file sta in open/", open.contains("src=\"/assets/open/"));

        System.out.println("\n== 2. resolve ==");
        PageAssets.writeAll(tmp);
        String own = urls.get(0), shared = open.replaceAll(".*src=\"([^\"]+)\".*", "$1");
        check("un file delle pagine protette: non a chi non e' entrato", PageAssets.resolve(tmp, own, false) == null);
        check("  a chi e' entrato si'", PageAssets.resolve(tmp, own, true) != null);
        check("un file di open/: a tutti", PageAssets.resolve(tmp, shared, false) != null);
        check("un nome che non e' un'impronta: niente", PageAssets.resolve(tmp, "/assets/open/ABCDEF.js", true) == null
                && PageAssets.resolve(tmp, "/assets/open/" + "a".repeat(20) + ".html", true) == null);
        check("un percorso che esce: niente", PageAssets.resolve(tmp, "/assets/../admin/home.html", true) == null
                && PageAssets.resolve(tmp, "/assets/open/../" + own.substring(own.lastIndexOf('/') + 1), false) == null);
        check("un'impronta che non c'e': niente", PageAssets.resolve(tmp, "/assets/" + "0".repeat(20) + ".js", true) == null);
        check("il tipo: javascript e css", PageAssets.contentType(Path.of("x.js")).startsWith("text/javascript")
                && PageAssets.contentType(Path.of("x.css")).startsWith("text/css"));

        System.out.println("\n== 3. writeAll ==");
        Path stale = tmp.resolve("assets").resolve("f".repeat(20) + ".js");
        Path staleOpen = tmp.resolve("assets/open").resolve("e".repeat(20) + ".css");
        Files.writeString(stale, "vecchio");
        Files.writeString(staleOpen, "vecchio");
        PageAssets.writeAll(tmp);
        check("i file di una versione di prima se ne vanno", !Files.exists(stale) && !Files.exists(staleOpen));
        check("quelli registrati restano, col loro contenuto", PageAssets.resolve(tmp, own, true) != null
                && Files.readString(PageAssets.resolve(tmp, own, true)).equals("var a = 1;"));
        try (Stream<Path> files = Files.list(tmp.resolve("assets"))) {
            check("nessun file temporaneo rimasto", files.noneMatch(f -> f.toString().endsWith(".tmp")));
        }

        System.out.println("\n== 4. La politica ==");
        String csp = SecurityHeaders.CONTENT_SECURITY_POLICY;
        check("niente unsafe-inline, unsafe-eval, http(s): o *", !csp.contains("unsafe-") && !csp.contains("http") && !csp.contains("*"));
        check("script-src e style-src solo 'self'", csp.contains("script-src 'self';") && csp.contains("style-src 'self';"));
        check("object-src 'none', base-uri 'self', form-action 'self', frame-ancestors 'none'", csp.contains("object-src 'none'")
                && csp.contains("base-uri 'self'") && csp.contains("form-action 'self'") && csp.contains("frame-ancestors 'none'"));

        System.out.println("\n== 5. Ogni pagina, come la genera il server ==");
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
        check("le pagine generate sono " + pages, pages >= 20);
        check("nessuna con codice in linea" + (dirty.isEmpty() ? "" : ": " + dirty), dirty.isEmpty());

        System.out.println("\n== 6. I sorgenti delle pagine ==");
        Path root = Path.of("src/main");
        List<Path> sources = new ArrayList<>(List.of(root.resolve("java/org/mail_panel/content/MailPanelContent.java"),
                root.resolve("java/org/mail_panel/content/Layout.java"),
                root.resolve("java/org/mail_panel/security/DnsRecordsGenerator.java")));
        if (Files.isDirectory(root.resolve("resources/pages"))) {
            try (Stream<Path> s = Files.list(root.resolve("resources/pages"))) {
                s.filter(p -> !p.getFileName().toString().equals("panel-actions.js")).sorted().forEach(sources::add);
            }
        }
        boolean found = sources.stream().allMatch(Files::isRegularFile);
        check("trovati i sorgenti (" + sources.size() + " file, dalla radice del progetto)", found && sources.size() > 10);
        List<String> hits = new ArrayList<>();
        for (Path f : sources) {
            if (!Files.isRegularFile(f)) continue;
            String text = Files.readString(f);
            Matcher hm = SOURCE_ATTR.matcher(text);
            while (hm.find()) hits.add(f.getFileName() + ":" + (text.substring(0, hm.start()).split("\n", -1).length) + " " + hm.group());
        }
        check("nessun on...= o style= nell'HTML, nemmeno in quello costruito dagli script" + (hits.isEmpty() ? "" : ": " + hits), hits.isEmpty());
    }
}
