package org.daemoxcp.mail.content;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The pages' scripts and style sheets as files served by the panel, not inline: the
 * Content-Security-Policy no longer has 'unsafe-inline' (finding 178).
 *
 * <p>The pages stay written as before, with their &lt;script&gt; and &lt;style&gt; blocks in the text
 * blocks: it is {@link #externalize} that, when the pages are generated, puts in place of each block a
 * &lt;script src&gt; or a &lt;link&gt; to a file named after the content (sha-256). This way:
 * <ul>
 *   <li>the name changes only when the content changes, and the file is cached forever;</li>
 *   <li>a block that is the same in all pages (the head, the footer, the theme) is a single file;</li>
 *   <li>the execution order is the same as before: a &lt;script src&gt; without async or defer
 *   blocks the parser at the same point where the inline block blocked it.</li>
 * </ul>
 *
 * <p>The files sit next to the generated pages, in assets/ (those of the protected pages, given only
 * to whoever has logged in) and assets/open/ (those of the login and installation pages and the common ones,
 * given to everyone): the server reads them from disk as it reads the pages, and the files left over from an
 * earlier version are removed at every generation.
 */
public final class PageAssets {

    /** The folder of the files, inside the pages' one, and the prefix of their addresses. */
    public static final String DIR = "assets";
    /** The subfolder of the files that are given out even before logging in. */
    public static final String OPEN = "open";
    /** The name of a file: the fingerprint of the content and the extension. */
    public static final Pattern FILE = Pattern.compile("[0-9a-f]{20}\\.(js|css)");

    private static final Pattern INLINE_SCRIPT = Pattern.compile("<script>(.*?)</script>", Pattern.DOTALL);
    private static final Pattern INLINE_STYLE = Pattern.compile("<style>(.*?)</style>", Pattern.DOTALL);

    /** The registered files, by path relative to assets/ (open/xxx.js or xxx.js). */
    private static final Map<String, byte[]> REGISTERED = new ConcurrentHashMap<>();

    /**
     * The actions and styles without inline code (data-on-*, data-style): it goes in the &lt;head&gt; of
     * every page, before the body.
     */
    public static final String ACTIONS = script(resource("pages/panel-actions.js"), true);

    private PageAssets() {}

    /**
     * The page with every &lt;script&gt; (without src) and &lt;style&gt; block replaced by a file.
     * @param open true for the pages seen before logging in (login, installation)
     */
    public static String externalize(String html, boolean open) {
        html = replace(INLINE_SCRIPT, html, js -> script(js, open));
        return replace(INLINE_STYLE, html, css -> stylesheet(css, open));
    }

    private static String replace(Pattern p, String html, java.util.function.Function<String, String> tag) {
        Matcher m = p.matcher(html);
        StringBuilder out = new StringBuilder();
        while (m.find()) m.appendReplacement(out, Matcher.quoteReplacement(tag.apply(m.group(1))));
        m.appendTail(out);
        return out.toString();
    }

    /** The tag that loads this script, registered as a file. */
    public static String script(String js, boolean open) {
        return "<script src=\"" + register(js, "js", open) + "\"></script>";
    }

    /** The tag that loads this style sheet, registered as a file. */
    public static String stylesheet(String css, boolean open) {
        return "<link rel=\"stylesheet\" href=\"" + register(css, "css", open) + "\">";
    }

    private static String register(String content, String ext, boolean open) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        String name = sha256(bytes).substring(0, 20) + "." + ext;
        String rel = (open ? OPEN + "/" : "") + name;
        REGISTERED.putIfAbsent(rel, bytes);
        return "/" + DIR + "/" + rel;
    }

    /**
     * Writes the registered files into pagesDir/assets and removes those that no longer are (from an
     * earlier version). Every file is written all or nothing.
     */
    public static void writeAll(Path pagesDir) throws IOException {
        Path base = pagesDir.resolve(DIR);
        Files.createDirectories(base.resolve(OPEN));
        // Like the pages (PanelContent.readableByPanel): the web part reads them, never the umask to decide it.
        PanelContent.readableByPanel(base, true);
        PanelContent.readableByPanel(base.resolve(OPEN), true);
        Set<Path> wanted = new HashSet<>();
        for (Map.Entry<String, byte[]> e : REGISTERED.entrySet()) {
            Path target = base.resolve(e.getKey());
            wanted.add(target);
            if (Files.exists(target) && java.util.Arrays.equals(Files.readAllBytes(target), e.getValue())) {
                PanelContent.readableByPanel(target, false);
                continue;
            }
            Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
            Files.write(tmp, e.getValue());
            PanelContent.readableByPanel(tmp, false);
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        }
        for (Path dir : new Path[]{base, base.resolve(OPEN)}) {
            try (Stream<Path> files = Files.list(dir)) {
                for (Path f : files.toList()) {
                    if (Files.isRegularFile(f) && !wanted.contains(f)) Files.deleteIfExists(f);
                }
            }
        }
    }

    /**
     * The file to give for an /assets/... address, or null. Those of the protected pages only to whoever
     * has logged in; the name must be exactly a fingerprint with its extension.
     */
    public static Path resolve(Path pagesDir, String urlPath, boolean authenticated) {
        String prefix = "/" + DIR + "/";
        if (urlPath == null || !urlPath.startsWith(prefix)) return null;
        String rel = urlPath.substring(prefix.length());
        boolean open = rel.startsWith(OPEN + "/");
        String name = open ? rel.substring(OPEN.length() + 1) : rel;
        if (!FILE.matcher(name).matches()) return null;
        if (!open && !authenticated) return null;
        Path f = pagesDir.resolve(DIR).resolve(open ? OPEN : "").resolve(name);
        return Files.isRegularFile(f) ? f : null;
    }

    /** The Content-Type of a served file. */
    public static String contentType(Path f) {
        return f.getFileName().toString().endsWith(".css") ? "text/css; charset=UTF-8" : "text/javascript; charset=UTF-8";
    }

    private static String resource(String path) {
        try (InputStream in = PageAssets.class.getResourceAsStream("/" + path)) {
            if (in == null) throw new IllegalStateException("Missing resource " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read resource " + path, e);
        }
    }

    private static String sha256(byte[] b) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
