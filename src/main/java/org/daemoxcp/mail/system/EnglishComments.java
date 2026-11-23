package org.daemoxcp.mail.system;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * The comments that the panel used to write in Italian in the server's files, and their move to English
 * (2026-11-22).
 *
 * <p>Until today the comments of the configurations and scripts that the panel writes on the server (Dovecot,
 * Postfix, pf, rspamd, redis, clamd, nginx, php-fpm, fail2ban, the installation scripts) were in Italian: whoever
 * administers the server and does not read Italian could not understand why a line is there. The code now writes them
 * in English. The previous ones are in legacy-names.json, section "italianComments", line by line next to the
 * translation, and not in the code (the choice of 2026-10-30, LegacyNames).
 *
 * <p>At startup, in the panel's files, the Italian comment lines become the English ones: the same pass as for the
 * product name (PanelMarker.productCommentsAtBoot), with the same checks. ONLY the comment lines are changed, and
 * this is verified before writing; atomic write with the previous permissions, owner and flags; no reload, because
 * a comment does not change what the service does. Before the translation, the sections of even older comments are
 * applied (productComments: the product's previous name; damagedComments: the words damaged by text-based renames),
 * so that a line of those too reaches English in a single pass.
 *
 * <p>The code that recognises one of its blocks by the comment (RedisSocket, ClamdSocket, RspamdController,
 * LmtpSocket, DovecotQuota, PfPolicy) reads the file through {@link #english}: in this way it also recognises the
 * block written in Italian, if the pass at startup did not succeed, instead of adding a second one or believing it
 * belongs to someone else.
 *
 * <p>The spam Sieve script does not go through here: SpecialFolders rewrites and recompiles it by itself when it is
 * not the current one, and a source newer than its compiled version would make Dovecot recompile at every delivery.
 */
public final class EnglishComments {

    private static final Logger LOGGER = Logger.getLogger(EnglishComments.class.getName());

    static final String SECTION = "italianComments";

    /** The sections that apply, in order: the oldest forms first, the translation last. */
    static final List<String> CHAIN = List.of("productComments", "damagedComments", SECTION);

    /** The files with panel comments in addition to those of the name pass (PanelMarker.serviceFiles). */
    static final List<String> MORE_FILES = List.of(
            "/usr/local/etc/mysql/my.cnf", "/etc/sysctl.conf", "/etc/pf.conf",
            org.daemoxcp.mail.security.Fail2banManager.PERMABAN_FILE);

    /**
     * And the folders: those of the Postfix and Dovecot files, and the webmail site of the component-by-component
     * installation.
     */
    static final List<String> MORE_FOLDERS = List.of(
            "/usr/local/etc/postfix", "/usr/local/etc/dovecot", "/usr/local/etc/nginx/sites-enabled");

    private EnglishComments() {}

    /** The text with the previous comment lines in English; the other lines stay as they are. Pure. */
    public static String english(String content) {
        if (content == null) return null;
        String s = content;
        for (String section : CHAIN) s = PanelMarker.current(s, section);
        return s;
    }

    record Report(List<String> done, List<String> problems) {}

    /**
     * The copies of a file, made by the panel or by whoever administers it: ConfigBackups ("file.bak.MILLISECONDS"),
     * Fail2banManager (".bak.YYYYMMDD-HHMMSS"), BanActionRepair (".before-pf-"), the even older ones with the old
     * prefix in place of "before-" (section "bootEnvironmentPrefix" of legacy-names.json: old names are not written in
     * the code), and .pre-2.4, .orig, .old, .sample. A copy preserves the file as it was: it is not translated. Seen on
     * the production server on 2026-11-22, where jail.d and pf.anchors have about twenty of them.
     */
    static final java.util.regex.Pattern COPY = copyPattern();

    private static java.util.regex.Pattern copyPattern() {
        StringBuilder alternatives = new StringBuilder("\\.bak(\\..*)?|\\.before-.*|\\.pre-2\\.4|\\.orig|\\.old|\\.sample|~");
        for (String old : LegacyNames.oldNamesOf("bootEnvironmentPrefix", "before-"))
            alternatives.append("|\\.").append(java.util.regex.Pattern.quote(old)).append(".*");
        return java.util.regex.Pattern.compile(".*(" + alternatives + ")");
    }

    static boolean copy(Path p) {
        Path name = p.getFileName();
        return name != null && COPY.matcher(name.toString()).matches();
    }

    /**
     * The given files with the comment lines in English; those with nothing to change, and the copies, are not
     * touched.
     */
    static Report migrate(Collection<Path> files) {
        List<String> done = new ArrayList<>(), problems = new ArrayList<>();
        for (Path p : files) {
            if (copy(p) || !PanelMarker.stale(p, EnglishComments::english)) continue;
            PanelMarker.rewrite(p, EnglishComments::english, done, problems);
        }
        return new Report(done, problems);
    }

    /** At startup, as root (Main, after the product-name pass). A file that fails is retried at the next one. */
    public static void atBoot() {
        try {
            Set<Path> files = new LinkedHashSet<>(PanelMarker.serviceFiles(MORE_FILES, MORE_FOLDERS));
            files.addAll(CommentRepair.files());
            String jar = UpdateManager.jarPath();
            if (!jar.isEmpty()) {
                Path parent = Path.of(jar).toAbsolutePath().getParent();
                if (parent != null) files.add(parent.resolve("run.sh"));
            }
            Report r = migrate(files);
            if (!r.done().isEmpty())
                LOGGER.info("[EnglishComments] DONE: the comments in English in " + String.join(", ", r.done()));
            if (!r.problems().isEmpty())
                LOGGER.warning("[EnglishComments] PARTIAL, retrying at the next start: " + String.join("; ", r.problems()));
        } catch (Throwable t) {
            LOGGER.warning("[EnglishComments] failed: " + t);
        }
    }
}
