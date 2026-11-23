package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.Fail2banManager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * The comments that a text-based rename damaged in the files the panel writes on the
 * server, put right on servers already installed too (2026-10-30).
 *
 * <p>The rename of the JavaScript names of 2026-10-24 and that of the JSON keys of 2026-10-16
 * also changed Italian words inside the comments of the installation scripts: `che` (which)
 * became `whichLabel`, `riga` (line) `lineItem`, `gia'` (already) `already'`, `bloccati`
 * (locked) `lockedPackages`. They break nothing, but whoever opens php.ini, nginx.conf or the
 * permaban list on the server finds sentences that make no sense. Here the files written
 * earlier are fixed, with the correct Italian of the time; since 2026-11-22 the code writes
 * those comments in English, and EnglishComments, which at startup runs before this and also
 * knows the damaged lines, takes them straight to English: this repair remains for a file
 * that that pass could not rewrite.
 *
 * <p>The damaged lines and the correct ones are in the "damagedComments" section of
 * legacy-names.json, not in the code: they are old text, and a future text-based rename
 * would change them again. A line is replaced only if it is a comment (# or ;) equal, apart
 * from indentation, to a damaged line: the indentation stays, the other lines are not
 * touched, and a file that the administrator changed elsewhere keeps its changes. A comment
 * does not change what the service does, so no nginx -t nor reload. The write is the one of
 * PanelMarker: a temporary file next to it, same permissions and owner, rename. Repeating it
 * finds nothing.
 */
public final class CommentRepair {

    private static final Logger LOGGER = Logger.getLogger(CommentRepair.class.getName());

    static final String SECTION = "damagedComments";

    private CommentRepair() {}

    /**
     * The files written with those comments: php.ini, the rotation of its log and nginx.conf
     * from the full installation, Roundcube's nginx file from the installation of the
     * component alone, the permaban list, and the installation scripts that stay in the
     * panel's folder.
     */
    static List<Path> files() {
        return List.of(
                Path.of("/usr/local/etc/php.ini"),
                Path.of("/usr/local/etc/newsyslog.conf.d/php-errors.conf"),
                Path.of("/usr/local/etc/nginx/nginx.conf"),
                Path.of("/usr/local/etc/nginx/sites-enabled/roundcube.conf"),
                Path.of(Fail2banManager.PERMABAN_FILE),
                Path.of("install_scripts", "install_mail_server.sh"),
                Path.of("install_scripts", "install_roundcube.sh"));
    }

    public static void ensureAtBoot() {
        try {
            List<String> problems = new ArrayList<>();
            List<String> done = repair(files(), problems);
            if (!done.isEmpty()) LOGGER.info("[CommentRepair] comments repaired in " + String.join(", ", done));
            if (!problems.isEmpty()) LOGGER.warning("[CommentRepair] " + String.join("; ", problems));
        } catch (Throwable t) {
            LOGGER.warning("[CommentRepair] failed: " + t);
        }
    }

    /** The damaged line -> correct line pairs, without indentation; only those between two comments. */
    static Map<String, String> pairs() {
        Map<String, String> out = new LinkedHashMap<>();
        for (String[] p : LegacyNames.pairs(SECTION))
            if (comment(p[0]) && comment(p[1])) out.put(p[0].strip(), p[1].strip());
        return out;
    }

    static boolean comment(String line) {
        String s = line.stripLeading();
        return s.startsWith("#") || s.startsWith(";");
    }

    /**
     * The same text with the damaged lines put right, each with its own indentation. The whole
     * line is compared: a damaged line starts with # or ;, so only a comment changes, and the
     * same sentence inside another line (an echo that prints it) stays as it is.
     */
    static String repaired(String content, Map<String, String> pairs) {
        String[] lines = content.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String fixed = pairs.get(lines[i].strip());
            if (fixed == null) continue;
            String indent = lines[i].substring(0, lines[i].length() - lines[i].stripLeading().length());
            lines[i] = indent + fixed;
        }
        return String.join("\n", lines);
    }

    /** The files fixed; a file that is not there is skipped, an error goes into problems. */
    static List<String> repair(List<Path> files, List<String> problems) {
        Map<String, String> pairs = pairs();
        List<String> done = new ArrayList<>();
        if (pairs.isEmpty()) return done;
        for (Path p : files) {
            try {
                if (!Files.isRegularFile(p)) continue;
                // A link is followed: the file to fix is the one it points to.
                Path real = p.toRealPath();
                String before = Files.readString(real, StandardCharsets.UTF_8);
                String after = repaired(before, pairs);
                if (after.equals(before)) continue;
                PanelMarker.replaceKeeping(real, after);
                done.add(p.toString());
            } catch (IOException | RuntimeException e) {
                problems.add(p + ": " + e.getMessage());
            }
        }
        return done;
    }
}
