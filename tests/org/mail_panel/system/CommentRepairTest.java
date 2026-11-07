package org.mail_panel.system;

import org.mail_panel.scripts.FullMailServerScript;
import org.mail_panel.scripts.RoundcubeScript;
import org.mail_panel.security.Fail2banManager;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The comments damaged by the renames made on the text are put right at start
 * (CommentRepair.repair), in a temporary folder.
 *
 * The "old" files are built from those today's code writes, putting back the damaged lines taken
 * from the data file: the test writes no damaged line. After the repair every file must be
 * identical byte for byte to today's, with the same permissions; a second pass must find nothing;
 * the administrator's lines, a file that is not there and a damaged line that is not a comment stay
 * as they are. The effect on the real files is measured by the test on the VM (reperti).
 *
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.CommentRepairTest
 */
public class CommentRepairTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The body of a here-document of the script: what ends up in the file on the server. */
    static String heredoc(String script, String end) {
        int start = script.indexOf("<< '" + end + "'\n");
        if (start < 0) start = script.indexOf("<< " + end + "\n");
        start = script.indexOf('\n', start) + 1;
        int stop = script.indexOf("\n" + end + "\n", start);
        if (stop < 0) {
            // indented here-document (RoundcubeScript): the closing line has spaces in front
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("\n[ \t]*" + end + "\n").matcher(script);
            if (!m.find(start)) throw new IllegalStateException("here-document " + end + " not found");
            stop = m.start();
        }
        return script.substring(start, stop + 1);
    }

    /** The old text: every right line, with its indentation, goes back to the damaged one. */
    static String damaged(String today, Map<String, String> pairs) {
        Map<String, String> back = new LinkedHashMap<>();
        pairs.forEach((bad, good) -> back.put(good, bad));
        return CommentRepair.repaired(today, back);
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> pairs = CommentRepair.pairs();
        String full = new FullMailServerScript().getScriptContent();
        String roundcube = new RoundcubeScript().getScriptContent();

        System.out.println("\n== The data file ==");
        check("damagedComments: " + pairs.size() + " lines, all damaged comment -> different comment",
                pairs.size() == LegacyNames.pairs(CommentRepair.SECTION).size() && pairs.size() > 20
                        && pairs.entrySet().stream().allMatch(e -> !e.getKey().equals(e.getValue())));
        String today = full + roundcube + Fail2banManager.PERMABAN_HEADER;
        List<String> missing = new ArrayList<>(), stillThere = new ArrayList<>();
        pairs.forEach((bad, good) -> {
            if (!today.lines().map(String::strip).toList().contains(good)) missing.add(good);
            if (today.lines().map(String::strip).toList().contains(bad)) stillThere.add(bad);
        });
        missing.forEach(x -> System.out.println("        not written by the code: " + x));
        stillThere.forEach(x -> System.out.println("        still written by the code: " + x));
        check("every right line is the one today's code writes", missing.isEmpty());
        check("no damaged line is still written by the code", stillThere.isEmpty());

        // The files as today's code writes them, with the names they have on the server.
        Map<String, String> files = new LinkedHashMap<>();
        files.put("php.ini", heredoc(full, "PHPINIEOF"));
        files.put("php-errors.conf", heredoc(full, "PHPLOGEOF"));
        files.put("nginx.conf", heredoc(full, "NGINX_CONF"));
        files.put("roundcube.conf", heredoc(roundcube, "NGINXCONF"));
        files.put("permaban.list", Fail2banManager.PERMABAN_HEADER + "203.0.113.7\n");
        files.put("install_mail_server.sh", full);
        files.put("install_roundcube.sh", roundcube);

        System.out.println("\n== A server installed before ==");
        Path dir = Files.createTempDirectory("comment-repair");
        List<Path> paths = new ArrayList<>();
        int damagedFiles = 0;
        for (Map.Entry<String, String> e : files.entrySet()) {
            Path p = dir.resolve(e.getKey());
            String before = damaged(e.getValue(), pairs);
            if (!before.equals(e.getValue())) damagedFiles++;
            Files.writeString(p, before);
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-r-----"));
            paths.add(p);
        }
        check("the old files really have the damaged lines (" + damagedFiles + " of " + files.size() + ")",
                damagedFiles == files.size());

        // php.ini: the administrator added a line and a comment of their own; the file is a link.
        Path realIni = dir.resolve("php.ini.real");
        String adminIni = Files.readString(dir.resolve("php.ini")) + "; my comment\nmemory_limit = 512M\n";
        Files.writeString(realIni, adminIni);
        Files.setPosixFilePermissions(realIni, PosixFilePermissions.fromString("rw-r-----"));
        Files.delete(dir.resolve("php.ini"));
        Files.createSymbolicLink(dir.resolve("php.ini"), realIni.getFileName());

        // A damaged line that is not a comment: an echo that prints it.
        String bad = pairs.keySet().iterator().next();
        Path echo = dir.resolve("echo.sh");
        Files.writeString(echo, "echo \"" + bad + "\"\n");
        paths.add(echo);
        paths.add(dir.resolve("does-not-exist.conf"));

        List<String> problems = new ArrayList<>();
        List<String> done = CommentRepair.repair(paths, problems);
        problems.forEach(x -> System.out.println("        " + x));
        check("repaired " + done.size() + " files, without errors", done.size() == files.size() && problems.isEmpty());
        for (Map.Entry<String, String> e : files.entrySet()) {
            if (e.getKey().equals("php.ini")) continue;
            Path p = dir.resolve(e.getKey());
            check("  " + e.getKey() + " identical to today's, permissions rw-r-----",
                    Files.readString(p).equals(e.getValue())
                            && PosixFilePermissions.toString(Files.getPosixFilePermissions(p)).equals("rw-r-----"));
        }
        check("php.ini: the real file fixed, the administrator's lines stay, the link stays",
                Files.isSymbolicLink(dir.resolve("php.ini"))
                        && Files.readString(realIni).equals(files.get("php.ini") + "; my comment\nmemory_limit = 512M\n")
                        && PosixFilePermissions.toString(Files.getPosixFilePermissions(realIni)).equals("rw-r-----"));
        check("a damaged line outside a comment is not touched",
                Files.readString(echo).equals("echo \"" + bad + "\"\n"));
        try (var s = Files.list(dir)) {
            check("no temporary file left", s.noneMatch(p -> p.getFileName().toString().endsWith(".tmp")));
        }

        System.out.println("\n== At the second start ==");
        List<String> again = CommentRepair.repair(paths, problems);
        check("a second pass finds nothing", again.isEmpty() && problems.isEmpty());

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
