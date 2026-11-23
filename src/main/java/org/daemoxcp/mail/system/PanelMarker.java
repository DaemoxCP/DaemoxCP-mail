package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * The signatures with which the panel recognises the files it wrote itself, and their switch to
 * English on the servers already installed (r26, 2026-10-30).
 *
 * <p>The panel puts a comment line in the files it writes in full, and reads it again before
 * touching them: a file without a signature belongs to someone else and is not overwritten. Until
 * the end of October 2026 the signatures were in Italian. Now they are in English, and the earlier
 * ones are in legacy-names.json: whoever reads them again recognises both the current one and the
 * others, so a server installed earlier does not lose ownership of its files.
 *
 * <p>At startup, in the files that still carry an earlier signature, the signature becomes the
 * current one, and the file becomes identical to what the current code would write. ONLY the
 * comment lines are changed, and this is checked before writing: with the comments removed, the
 * new file and the old one must be identical, otherwise nothing is written. A comment does not
 * change what the service does, so neither nginx -t nor reload is needed. The write is atomic
 * (temporary file alongside, same permissions and owner, rename): nginx and fail2ban can re-read
 * the file at any moment.
 *
 * <p>Which files: the three of the public surface on 443 (the nginx file, fail2ban's filter and
 * jail; section "panelSignature") and dovecot.conf (section "dovecotSignature": it is the line that
 * the maintenance looks for to know whether the configuration comes from the single source). The
 * daemoxcp-mail-auth filter is already rewritten by Fail2banAutoSetup when it is not the same as
 * the current one; the autoconfig block sits inside an nginx file that does not belong to the
 * panel, and is not touched.
 */
public final class PanelMarker {

    private static final Logger LOGGER = Logger.getLogger(PanelMarker.class.getName());

    /** The signature of the files the panel writes in full. */
    public static final String WRITTEN = "Written by " + Product.NAME;
    static final String SIGNATURE = "panelSignature";
    static final String DOVECOT = "dovecotSignature";

    private PanelMarker() {}

    /** The current marker, then the ones it had before. */
    public static List<String> forms(String section, String current) {
        List<String> out = new ArrayList<>();
        out.add(current);
        out.addAll(LegacyNames.oldNamesOf(section, current));
        return out;
    }

    /** The file was written by the panel: the current signature or an earlier one is there. */
    public static boolean writtenByPanel(String content) {
        if (content == null) return false;
        for (String f : forms(SIGNATURE, WRITTEN)) if (content.contains(f)) return true;
        return false;
    }

    /**
     * The same text with the current markers in place of the earlier ones, in the comment lines
     * only. The pairs are applied in the file's order: the longest first, because an earlier
     * signature may contain another one.
     */
    public static String current(String content, String section) {
        List<String[]> pairs = LegacyNames.pairs(section);
        if (content == null || pairs.isEmpty()) return content;
        String[] lines = content.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (!comment(lines[i])) continue;
            for (String[] p : pairs) lines[i] = lines[i].replace(p[0], p[1]);
        }
        return String.join("\n", lines);
    }

    /** A comment line: "#" (almost all files), "//" (Roundcube's PHP), ";" (php.ini, the php-fpm pools). */
    static boolean comment(String line) {
        String l = line.stripLeading();
        return l.startsWith("#") || l.startsWith("//") || l.startsWith(";");
    }

    /** The text without the comment lines: what the service really reads. */
    static String withoutComments(String content) {
        StringBuilder b = new StringBuilder();
        for (String l : content.split("\n", -1)) if (!comment(l)) b.append(l).append('\n');
        return b.toString();
    }

    // ===================== the boot migration =====================

    enum Outcome { NOTHING, DONE, PARTIAL, NGINX_UNREADABLE }

    record Report(Outcome outcome, String detail) {}

    /** Where the files are: fixed on the server, temporary folders in the test. */
    record Places(Path f2bDir, Path defaultNginxFolder, Path dovecotConf) {}

    /** The folders that nginx includes (nginx -T): empty without nginx, null if nginx does not answer. */
    interface Services {
        List<String> nginxFolders();
    }

    public static void ensureAtBoot() {
        try {
            Places at = new Places(Path.of(WebProtection.F2B_DIR), Path.of(WebProtection.PROPOSED_FOLDER),
                    Path.of("/usr/local/etc/dovecot/dovecot.conf"));
            Report r = migrate(at, () -> {
                if (Shell.resolve("nginx") == null) return List.of();
                Shell.Result t = Shell.run(Duration.ofSeconds(20), "nginx", "-T");
                return t.success() ? WebProtection.includedFolders(t.output()) : null;
            });
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[PanelMarker] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[PanelMarker] failed: " + t);
        }
    }

    static Report migrate(Places at, Services sv) {
        Path filter = at.f2bDir().resolve("filter.d").resolve(WebProtection.FILE_NAME);
        Path jail = at.f2bDir().resolve("jail.d").resolve(WebProtection.FILE_NAME);
        Path defaultConf = at.defaultNginxFolder().resolve(WebProtection.FILE_NAME);
        boolean surface = stale(filter, SIGNATURE) || stale(jail, SIGNATURE) || stale(defaultConf, SIGNATURE);
        boolean dovecot = stale(at.dovecotConf(), DOVECOT);
        if (!surface && !dovecot) return new Report(Outcome.NOTHING, "");

        List<String> done = new ArrayList<>(), problems = new ArrayList<>();
        if (dovecot) rewrite(at.dovecotConf(), DOVECOT, done, problems);

        boolean unreadable = false;
        if (surface) {
            // The nginx file is in one of the folders nginx includes: we ask nginx which ones.
            // The jail last: as long as it has the earlier signature, at the next startup everything is retried.
            List<String> folders = sv.nginxFolders();
            if (folders == null) {
                unreadable = true;
            } else {
                Set<Path> order = new LinkedHashSet<>();
                for (String f : folders) order.add(Path.of(f).resolve(WebProtection.FILE_NAME));
                order.add(defaultConf);
                order.add(filter);
                order.add(jail);
                for (Path p : order) {
                    if (!stale(p, SIGNATURE)) continue;
                    if (!rewrite(p, SIGNATURE, done, problems)) break;
                }
            }
        }

        String detail = (done.isEmpty() ? "" : "signature updated in " + String.join(", ", done))
                + (problems.isEmpty() ? "" : (done.isEmpty() ? "" : "; ") + String.join("; ", problems));
        if (unreadable)
            return new Report(Outcome.NGINX_UNREADABLE, "nginx -T failed: the 443 surface keeps the old signature,"
                    + " retrying at the next start" + (detail.isEmpty() ? "" : "; " + detail));
        return new Report(problems.isEmpty() ? Outcome.DONE : Outcome.PARTIAL, detail);
    }

    // ===================== the product name in the comments (2026-11-17) =====================

    /** The service files in which the panel wrote comments with the earlier name, one by one. */
    static final List<String> PRODUCT_FILES = List.of(
            "/usr/local/etc/dovecot/dovecot.conf", "/usr/local/etc/postfix/main.cf", "/etc/aliases",
            "/usr/local/etc/fail2ban/jail.local", "/usr/local/etc/redis.conf", "/usr/local/etc/clamd.conf",
            "/var/unbound/unbound.conf", "/var/unbound/forward.conf", "/etc/resolv.conf", "/usr/local/etc/php.ini",
            "/usr/local/etc/nginx/nginx.conf", "/usr/local/www/roundcube/config/config.inc.php",
            "/usr/local/etc/pkg/repos/zz-panel-branch.conf", DataFolderRename.NEW + "/locked-packages.txt",
            "/usr/local/etc/" + Product.SLUG + "/panel-secrets.properties",
            "/usr/local/etc/" + Product.SLUG + "/root-secrets.properties");

    /**
     * The folders whose files (not the subfolders) may have those comments. Not /etc/pf.conf: its first line is
     * the one PfPolicy recognises it by, and a pf.conf of the panel is rewritten in full by PfPolicy.
     */
    static final List<String> PRODUCT_FOLDERS = List.of(
            "/usr/local/etc/dovecot/conf.d", "/usr/local/etc/fail2ban/jail.d", "/usr/local/etc/fail2ban/filter.d",
            "/usr/local/etc/fail2ban/action.d", "/etc/pf.anchors", "/usr/local/etc/rspamd/local.d",
            "/usr/local/etc/rspamd/override.d", "/usr/local/etc/php-fpm.d", "/usr/local/etc/newsyslog.conf.d",
            "/usr/local/etc/nginx/conf.d", "install_scripts");

    /**
     * At startup (ProductRename): in the service files, the comment lines with the product's earlier name take the
     * current one (section "productComments"). Only the comments, and it is checked for each file before writing
     * (rewrite): the service reads the same file as before, so nothing needs to be reloaded.
     */
    public static void productCommentsAtBoot() {
        List<String> done = new ArrayList<>(), problems = new ArrayList<>();
        for (Path p : serviceFiles(List.of(), List.of())) {
            if (!stale(p, "productComments")) continue;
            rewrite(p, "productComments", done, problems);
        }
        if (!done.isEmpty()) LOGGER.info("[PanelMarker] DONE: the product name updated in the comments of " + String.join(", ", done));
        if (!problems.isEmpty()) LOGGER.warning("[PanelMarker] PARTIAL: " + String.join("; ", problems));
    }

    /**
     * The service files in which the panel writes comments: PRODUCT_FILES, the files (not the subfolders) of
     * PRODUCT_FOLDERS and of the folders nginx includes, and the extra ones requested by the caller. Only regular
     * files up to 4 MB, in the order in which they are listed.
     */
    static java.util.Set<Path> serviceFiles(java.util.Collection<String> moreFiles, java.util.Collection<String> moreFolders) {
        java.util.Set<Path> files = new LinkedHashSet<>();
        for (String f : PRODUCT_FILES) files.add(Path.of(f));
        for (String f : moreFiles) files.add(Path.of(f));
        java.util.Set<String> folders = new LinkedHashSet<>(PRODUCT_FOLDERS);
        folders.addAll(moreFolders);
        if (Shell.resolve("nginx") != null) {
            Shell.Result t = Shell.run(Duration.ofSeconds(20), "nginx", "-T");
            if (t.success()) folders.addAll(WebProtection.includedFolders(t.output()));
        }
        for (String d : folders) {
            Path dir = Path.of(d);
            if (!Files.isDirectory(dir)) continue;
            try (java.nio.file.DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
                for (Path c : ds) files.add(c);
            } catch (IOException e) {
                LOGGER.warning("[PanelMarker] " + d + " cannot be read: " + e.getMessage());
            }
        }
        files.removeIf(p -> {
            try {
                return !Files.isRegularFile(p) || Files.size(p) > 4L * 1024 * 1024;
            } catch (IOException e) {
                return true;
            }
        });
        return files;
    }

    /** The file exists and still has an earlier marker in a comment line. */
    static boolean stale(Path p, String section) {
        return stale(p, s -> current(s, section));
    }

    /** The file exists and the function would change its text (only comment lines, for whoever passes it). */
    static boolean stale(Path p, java.util.function.UnaryOperator<String> now) {
        try {
            if (!Files.isRegularFile(p)) return false;
            String s = Files.readString(p, StandardCharsets.UTF_8);
            return !now.apply(s).equals(s);
        } catch (IOException e) {
            return false;
        }
    }

    static boolean rewrite(Path p, String section, List<String> done, List<String> problems) {
        return rewrite(p, s -> current(s, section), done, problems);
    }

    /**
     * The file with the text the function gives, if only comment lines change: otherwise it is not touched and
     * this is said in problems. Atomic write, with the earlier permissions, owner and flags.
     */
    static boolean rewrite(Path p, java.util.function.UnaryOperator<String> now, List<String> done, List<String> problems) {
        try {
            // A link is followed: the panel's file is the one it points to.
            Path real = p.toRealPath();
            String before = Files.readString(real, StandardCharsets.UTF_8);
            String after = now.apply(before);
            if (after.equals(before)) return true;
            if (!withoutComments(after).equals(withoutComments(before))) {
                problems.add(p + ": more than comments would change, not touched");
                return false;
            }
            replaceKeeping(real, after);
            done.add(p.toString());
            return true;
        } catch (IOException | RuntimeException e) {
            problems.add(p + ": " + e.getMessage());
            return false;
        }
    }

    /** Writes alongside and replaces with a rename, with the earlier permissions, owner and group. */
    static void replaceKeeping(Path p, String content) throws IOException {
        // The temporary file starts with a dot and does not end in .conf: neither nginx nor fail2ban
        // would read it, if it stayed there.
        Path tmp = p.resolveSibling("." + p.getFileName() + ".daemoxcp-mail.tmp");
        Files.deleteIfExists(tmp);
        // An immutable file (chflags schg) cannot be replaced: the flag is removed, the file is written, and the
        // flag goes back on the new file. The panel itself puts it on /var/unbound/forward.conf, so that
        // local-unbound-setup does not rewrite it: on the production server, on 2026-11-17, the comment there
        // had not changed ("Operation not permitted").
        List<String> flags = immutableFlags(p);
        for (String f : flags) chflags("no" + f, p);
        try {
            Files.writeString(tmp, content, StandardCharsets.UTF_8);
            try {
                PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                Files.setPosixFilePermissions(tmp, a.permissions());
                try {
                    Files.setOwner(tmp, a.owner());
                    Files.setAttribute(tmp, "posix:group", a.group());
                } catch (IOException ignored) {
                    // Without permission to change the owner it stays the panel's, which is root.
                }
            } catch (UnsupportedOperationException ignored) {
                // File system without POSIX permissions: only in the tests.
            }
            Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tmp);
            if (!flags.isEmpty()) {
                for (String f : flags) chflags(f, p);
                if (!immutableFlags(p).containsAll(flags))
                    throw new IOException(p + " is no longer " + String.join(",", flags) + ": put it back with chflags");
            }
        }
    }

    /** The flags that make a file immutable even for root (with securelevel -1 root removes them and puts them back). */
    static final List<String> IMMUTABLE_FLAGS = List.of("schg", "uchg");

    /** The file's immutable flags, from stat -f %Sf (FreeBSD); none if stat does not answer. */
    static List<String> immutableFlags(Path p) {
        Shell.Result r = Shell.run(Duration.ofSeconds(5), "/usr/bin/stat", "-f", "%Sf", p.toString());
        List<String> out = new ArrayList<>();
        if (!r.success()) return out;
        for (String f : r.outputTrim().split(",")) if (IMMUTABLE_FLAGS.contains(f.trim())) out.add(f.trim());
        return out;
    }

    private static void chflags(String flag, Path p) throws IOException {
        Shell.Result r = Shell.run(Duration.ofSeconds(5), "/bin/chflags", flag, p.toString());
        if (!r.success()) throw new IOException("chflags " + flag + " " + p + ": " + r.outputTrim());
    }
}
