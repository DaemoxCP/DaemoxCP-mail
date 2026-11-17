package org.mail_panel.system;

import org.mail_panel.scripts.FullMailServerScript;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * The php.ini the installation writes, measured by having PHP read it.
 *
 * The php84 package installs no php.ini: in /usr/local/etc there are only the samples
 * php.ini-production and php.ini-development. Without that file PHP starts on the values compiled
 * in, and php-fpm does not complain. Measured on FreeBSD 15.1 with php84-8.4.26, without
 * php.ini: upload_max_filesize 2M, post_max_size 8M, display_errors ON, log_errors
 * OFF, expose_php on, session.save_path empty (that is /tmp).
 *
 * What must be tested here, and that reading the file would not tell:
 *  - that PHP accepts that file and the values really become those. PHP does not report a typo in
 *    a directive: it ignores it and keeps the default. So the text is not looked at, "php -c" is
 *    run and ini_get is read;
 *  - that the upload limit and Postfix's agree. They are two numbers in two places of the same
 *    script (r26): if PHP is lower, the attachment is refused before Postfix has its say, and the
 *    message the user reads talks about the wrong thing.
 *
 * It runs on the VM, where php is:
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PhpIniTest
 */
public class PhpIniTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        Path home = Files.createTempDirectory("php-ini");
        String script = new FullMailServerScript().getScriptContent();

        OUT.println("\n== The script writes a php.ini ==");
        String ini = between(script, "cat > /usr/local/etc/php.ini << 'PHPINIEOF'\n", "\nPHPINIEOF\n");
        check("there is a php.ini block in the script", ini != null && !ini.isBlank());
        if (ini == null) { OUT.println("\n" + (++failed) + " CHECKS FAILED"); System.exit(1); }
        check("and the script stops if it cannot write it",
                script.contains("if [ ! -f /usr/local/etc/php.ini ]"));
        // Roundcube's, no longer www's: the webmail has its own user (RoundcubeUser).
        check("it creates the sessions folder, 700 and roundcube's",
                script.contains("mkdir -p /var/db/mailpanel/php_sessions")
                        && script.contains(org.mail_panel.security.SafeOwnership.shell("/var/db/mailpanel/php_sessions", "roundcube", "roundcube")
                                + "chmod 700 /var/db/mailpanel/php_sessions; fi")
                        && !script.contains("chown -R roundcube:roundcube /var/db/mailpanel/php_sessions")
                        && !script.contains("chown www:www /var/db/mailpanel/php_sessions"));
        check("the error log exists and rotates",
                script.contains("touch /var/log/php_errors.log")
                        && script.contains("/usr/local/etc/newsyslog.conf.d/php-errors.conf"));

        OUT.println("\n== PHP reads it, and the values become those ==");
        if (!onPath("php")) {
            check("php is there (this test must be run on the VM, not on the Mac)", false);
            OUT.println("\n" + failed + " CHECKS FAILED");
            System.exit(1);
        }
        Path iniFile = home.resolve("php.ini");
        Files.writeString(iniFile, ini + "\n", StandardCharsets.UTF_8);
        Map<String, String> got = effective(iniFile);
        for (Map.Entry<String, String> e : got.entrySet())
            OUT.println(String.format("  %-26s [%s]", e.getKey(), e.getValue()));

        check("date.timezone is UTC (r13)", "UTC".equals(got.get("date.timezone")));
        check("expose_php off (r19: the PHP version is not announced)",
                "".equals(got.get("expose_php")) || "0".equals(got.get("expose_php")));
        check("display_errors off, log_errors on (r19: nothing to the user, everything in the log)",
                ("".equals(got.get("display_errors")) || "0".equals(got.get("display_errors")))
                        && "1".equals(got.get("log_errors")));
        check("the error log has a path, outside the document root",
                got.get("error_log") != null && got.get("error_log").startsWith("/var/log/"));
        check("allow_url_include off",
                "".equals(got.get("allow_url_include")) || "0".equals(got.get("allow_url_include")));
        // If the session extension is missing, ALL its directives come back empty and the two checks
        // below would fall saying the wrong thing: not "php.ini is badly written" but "php84-session
        // is missing". It really happens, because on FreeBSD session is a separate package -- this
        // same script installs it, but php84 alone does not.
        check("the session extension is there (without it, the checks below tell nothing apart:"
                + " pkg install -y php84-session)", !"".equals(got.get("session.save_path")));
        check("the sessions are NOT in /tmp",
                got.get("session.save_path") != null && !got.get("session.save_path").isEmpty()
                        && !got.get("session.save_path").startsWith("/tmp"));
        check("the session cookie is HttpOnly, Secure and strict mode",
                "1".equals(got.get("session.cookie_httponly"))
                        && "1".equals(got.get("session.cookie_secure"))
                        && "1".equals(got.get("session.use_strict_mode")));

        OUT.println("\n== PHP's limit and Postfix's agree ==");
        long upload = bytes(got.get("upload_max_filesize"));
        long post = bytes(got.get("post_max_size"));
        long memory = bytes(got.get("memory_limit"));
        long postfix = postfixMessageSizeLimit(script);
        OUT.println("  upload_max_filesize " + upload + "  post_max_size " + post
                + "  memory_limit " + memory + "  message_size_limit " + postfix);
        check("Postfix declares a limit in this same script", postfix > 0);
        check("PHP is not stricter than Postfix: " + upload + " >= " + postfix, upload >= postfix);
        check("post_max_size is above upload_max_filesize (the request also carries the rest)",
                post > upload);
        check("memory_limit is above post_max_size", memory > post);
        check("and it is no longer the 2M default one gets without php.ini", upload > 2L * 1024 * 1024);

        OUT.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }

    static final String[] WANTED = {
        "upload_max_filesize", "post_max_size", "memory_limit", "date.timezone",
        "session.save_path", "expose_php", "display_errors", "log_errors", "error_log",
        "allow_url_include", "session.cookie_httponly", "session.cookie_secure",
        "session.use_strict_mode",
    };

    /** The values PHP really has after reading that file. */
    static Map<String, String> effective(Path iniFile) throws Exception {
        StringBuilder php = new StringBuilder();
        for (String k : WANTED) php.append("echo \"").append(k).append("=\", ini_get(\"").append(k).append("\"), \"\\n\";");
        ProcessBuilder pb = new ProcessBuilder("php", "-c", iniFile.toAbsolutePath().toString(),
                "-r", php.toString());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        Map<String, String> got = new HashMap<>();
        for (String line : out.split("\n")) {
            int eq = line.indexOf('=');
            if (eq > 0) got.put(line.substring(0, eq), line.substring(eq + 1).trim());
        }
        if (got.size() < WANTED.length) {
            OUT.println(out);
            throw new IllegalStateException("php did not answer for all the directives");
        }
        return got;
    }

    /** The message_size_limit the script writes in Postfix's main.cf. */
    static long postfixMessageSizeLimit(String script) {
        for (String line : script.split("\n")) {
            String t = line.trim();
            if (!t.startsWith("message_size_limit")) continue;
            int eq = t.indexOf('=');
            if (eq < 0) continue;
            try { return Long.parseLong(t.substring(eq + 1).trim()); } catch (NumberFormatException ignored) {}
        }
        return -1;
    }

    /** "50M" -> 52428800, as PHP reads them. */
    static long bytes(String shorthand) {
        if (shorthand == null || shorthand.isEmpty()) return -1;
        String s = shorthand.trim();
        char last = s.charAt(s.length() - 1);
        long multiplier = switch (Character.toLowerCase(last)) {
            case 'k' -> 1024L;
            case 'm' -> 1024L * 1024;
            case 'g' -> 1024L * 1024 * 1024;
            default -> 1L;
        };
        if (multiplier != 1L) s = s.substring(0, s.length() - 1);
        try { return Long.parseLong(s.trim()) * multiplier; } catch (NumberFormatException e) { return -1; }
    }

    static String between(String text, String start, String end) {
        int a = text.indexOf(start);
        if (a < 0) return null;
        int b = text.indexOf(end, a + start.length());
        return b < 0 ? null : text.substring(a + start.length(), b);
    }

    static boolean onPath(String command) {
        String path = System.getenv("PATH");
        if (path == null) return false;
        for (String dir : path.split(":"))
            if (Files.isExecutable(Path.of(dir, command))) return true;
        return false;
    }
}
