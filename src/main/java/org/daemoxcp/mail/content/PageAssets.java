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
 * Gli script e i fogli di stile delle pagine come file serviti dal pannello, non in linea: la
 * Content-Security-Policy non ha piu' 'unsafe-inline' (reperto 178).
 *
 * <p>Le pagine restano scritte come prima, con i loro blocchi &lt;script&gt; e &lt;style&gt; nei text
 * block: e' {@link #externalize} che, quando le pagine si generano, mette al posto di ogni blocco un
 * &lt;script src&gt; o un &lt;link&gt; verso un file col nome preso dal contenuto (sha-256). Cosi':
 * <ul>
 *   <li>il nome cambia solo quando cambia il contenuto, e il file si tiene in cache per sempre;</li>
 *   <li>un blocco uguale in tutte le pagine (la testa, il piede, il tema) e' un file solo;</li>
 *   <li>l'ordine di esecuzione e' quello di prima: un &lt;script src&gt; senza async ne' defer
 *   blocca il parser nello stesso punto in cui lo bloccava il blocco in linea.</li>
 * </ul>
 *
 * <p>I file stanno accanto alle pagine generate, in assets/ (quelli delle pagine protette, dati solo
 * a chi e' entrato) e assets/open/ (quelli delle pagine d'accesso e d'installazione e quelli comuni,
 * dati a tutti): il server li legge dal disco come legge le pagine, e i file rimasti da una versione
 * di prima si tolgono a ogni generazione.
 */
public final class PageAssets {

    /** La cartella dei file, dentro quella delle pagine, e il prefisso dei loro indirizzi. */
    public static final String DIR = "assets";
    /** La sottocartella dei file che si danno anche prima di entrare. */
    public static final String OPEN = "open";
    /** Il nome di un file: l'impronta del contenuto e l'estensione. */
    public static final Pattern FILE = Pattern.compile("[0-9a-f]{20}\\.(js|css)");

    private static final Pattern INLINE_SCRIPT = Pattern.compile("<script>(.*?)</script>", Pattern.DOTALL);
    private static final Pattern INLINE_STYLE = Pattern.compile("<style>(.*?)</style>", Pattern.DOTALL);

    /** I file registrati, per percorso relativo ad assets/ (open/xxx.js o xxx.js). */
    private static final Map<String, byte[]> REGISTERED = new ConcurrentHashMap<>();

    /**
     * Le azioni e gli stili senza codice in linea (data-on-*, data-style): va nella &lt;head&gt; di
     * ogni pagina, prima del corpo.
     */
    public static final String ACTIONS = script(resource("pages/panel-actions.js"), true);

    private PageAssets() {}

    /**
     * La pagina con ogni blocco &lt;script&gt; (senza src) e &lt;style&gt; al posto suo: un file.
     * @param open true per le pagine che si vedono prima di entrare (accesso, installazione)
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

    /** Il tag che carica questo script, registrato come file. */
    public static String script(String js, boolean open) {
        return "<script src=\"" + register(js, "js", open) + "\"></script>";
    }

    /** Il tag che carica questo foglio di stile, registrato come file. */
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
     * Scrive in pagesDir/assets i file registrati e toglie quelli che non lo sono piu' (di una
     * versione di prima). Ogni file si scrive tutto o niente.
     */
    public static void writeAll(Path pagesDir) throws IOException {
        Path base = pagesDir.resolve(DIR);
        Files.createDirectories(base.resolve(OPEN));
        // Come le pagine (MailPanelContent.readableByPanel): le legge la parte web, mai l'umask a deciderlo.
        MailPanelContent.readableByPanel(base, true);
        MailPanelContent.readableByPanel(base.resolve(OPEN), true);
        Set<Path> wanted = new HashSet<>();
        for (Map.Entry<String, byte[]> e : REGISTERED.entrySet()) {
            Path target = base.resolve(e.getKey());
            wanted.add(target);
            if (Files.exists(target) && java.util.Arrays.equals(Files.readAllBytes(target), e.getValue())) {
                MailPanelContent.readableByPanel(target, false);
                continue;
            }
            Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
            Files.write(tmp, e.getValue());
            MailPanelContent.readableByPanel(tmp, false);
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
     * Il file da dare per un indirizzo /assets/..., o null. Quelli delle pagine protette solo a chi
     * e' entrato; il nome deve essere esattamente un'impronta con la sua estensione.
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

    /** Il Content-Type di un file servito. */
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
