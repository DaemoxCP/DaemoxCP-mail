package org.daemoxcp.mail.integration;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * The password plugin turned on by the panel's block in Roundcube's config.inc.php (WebmailPasswordConfig): the
 * config the panel writes, run by the real PHP, and the list of plugins Roundcube gets from it.
 *
 *  1. the full installation's list (archive, zipdownload, and the panel's SSO plugin): password added at the end, then
 *     the spam button (markasjunk, SpamLearning);
 *  2. a list that already has them, in either syntax: never twice;
 *  3. no list in this file: none created (Roundcube merges files by replacing the whole list, so a list made here
 *     would drop the plugins written elsewhere);
 *  4. the block applied twice: still one line, and PHP still parses the file;
 *  5. the current password is asked for (password_confirm_current): the panel checks it, and Roundcube's default
 *     without the plugin's own config file is off, so its form had no field for it (seen on the VM, 18/11/2026);
 *  6. the SSO plugin the panel writes sends the webmail's key under the panel's header name (since the rename of
 *     17/11/2026 it sent a header named after Java code, which Guzzle refuses), and PHP parses it.
 *
 * It needs the php command line (the test machine has it, with Roundcube): without, it says SKIPPED.
 *   java -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.integration.WebmailPasswordPluginTest
 */
public class WebmailPasswordPluginTest {

    static int failed = 0;
    static final String KEY = "abcdefghijklmnopqrstuvwxyz012345";

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        String php = Files.isExecutable(Path.of("/usr/local/bin/php")) ? "/usr/local/bin/php"
                : Files.isExecutable(Path.of("/usr/bin/php")) ? "/usr/bin/php" : null;
        if (php == null) {
            System.out.println("SKIPPED: it needs the php command line (the test machine has it).");
            return;
        }
        Path dir = Files.createTempDirectory("webmail-plugin-test");
        try {
            System.out.println("== The list Roundcube gets ==");
            String full = "<?php\n$config = [];\n$config['plugins'] = array('daemoxcp_mail_sso', 'archive', 'zipdownload');\n";
            check("the full installation's list: password and the spam button added (" + plugins(php, dir, apply(full)) + ")",
                    "daemoxcp_mail_sso,archive,zipdownload,password,markasjunk".equals(plugins(php, dir, apply(full))));
            String already = "<?php\n$config = [];\n$config['plugins'] = ['password', 'archive'];\n";
            check("a list that has password: password not added again (" + plugins(php, dir, apply(already)) + ")",
                    "password,archive,markasjunk".equals(plugins(php, dir, apply(already))));
            String both = "<?php\n$config = [];\n$config['plugins'] = ['markasjunk', 'password'];\n";
            check("a list that has both: unchanged (" + plugins(php, dir, apply(both)) + ")",
                    "markasjunk,password".equals(plugins(php, dir, apply(both))));
            String none = "<?php\n$config = [];\n$config['des_key'] = 'x';\n";
            check("no list in this file: none created (" + plugins(php, dir, apply(none)) + ")",
                    "(unset)".equals(plugins(php, dir, apply(none))));

            System.out.println("\n== Applied again ==");
            String twice = WebmailPasswordConfig.apply(apply(full), 2096, KEY);
            check("one line, not two", twice.split(java.util.regex.Pattern.quote(WebmailPasswordConfig.PLUGIN_LINE), -1).length == 2);
            check("still password and markasjunk once (" + plugins(php, dir, twice) + ")",
                    "daemoxcp_mail_sso,archive,zipdownload,password,markasjunk".equals(plugins(php, dir, twice)));
            Path f = dir.resolve("lint.php");
            Files.writeString(f, twice);
            check("php -l: no syntax errors", run(php, "-l", f.toString()).startsWith("No syntax errors"));

            System.out.println("\n== The current password ==");
            check("password_confirm_current is on (" + value(php, dir, apply(full), "password_confirm_current") + ")",
                    "true".equals(value(php, dir, apply(full), "password_confirm_current")));

            System.out.println("\n== The SSO plugin ==");
            String plugin = RoundcubeSsoManager.generatePluginPhp();
            check("the key goes under " + WebmailPasswordConfig.KEY_HEADER, plugin.contains("'" + WebmailPasswordConfig.KEY_HEADER + "' => $key"));
            check("no Java left in the PHP (no \" + ... + \")", !plugin.contains("\" + ") && !plugin.contains("@KEY_HEADER@"));
            Path p = dir.resolve("daemoxcp_mail_sso.php");
            Files.writeString(p, plugin);
            check("php -l: no syntax errors", run(php, "-l", p.toString()).startsWith("No syntax errors"));
        } finally {
            try (var s = Files.list(dir)) { for (Path p : s.toList()) Files.deleteIfExists(p); }
            Files.deleteIfExists(dir);
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    static String apply(String config) {
        return WebmailPasswordConfig.apply(config, 2096, KEY);
    }

    /** A setting after PHP has run the config, as var_export writes it. */
    static String value(String php, Path dir, String config, String key) throws Exception {
        Path f = dir.resolve("config.inc.php");
        Files.writeString(f, config);
        Path reader = dir.resolve("value.php");
        Files.writeString(reader, "<?php include '" + f + "'; var_export($config['" + key + "'] ?? null);");
        return run(php, reader.toString()).trim();
    }

    /** The list of plugins after PHP has run the config, comma-separated, or "(unset)". */
    static String plugins(String php, Path dir, String config) throws Exception {
        Path f = dir.resolve("config.inc.php");
        Files.writeString(f, config);
        Path reader = dir.resolve("read.php");
        Files.writeString(reader, "<?php include '" + f + "'; echo isset($config['plugins']) ? implode(',', $config['plugins']) : '(unset)';");
        return run(php, reader.toString()).trim();
    }

    static String run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        p.waitFor(30, TimeUnit.SECONDS);
        return out;
    }
}
