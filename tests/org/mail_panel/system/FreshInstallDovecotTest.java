package org.mail_panel.system;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.LinkedHashMap;
import java.util.Map;
import org.mail_panel.i18n.I18n;
import org.mail_panel.scripts.DovecotConfig;
import org.mail_panel.scripts.DovecotScript;
import org.mail_panel.scripts.FullMailServerScript;
import org.mail_panel.scripts.FullMailStackScript;

/**
 * An installation from scratch puts in Dovecot 2.4 where the catalog offers it (reperto 215).
 *
 * In the latest branch 2.4 is a separate port (dovecot24-mysql); every installer put in 2.3 all the same, and the
 * server then needed the guided move. Now the choice is one shell snippet (DovecotConfig.packagesShell) used by the
 * three installers, and the configuration that follows is written for the version installed (scriptFragment).
 *
 *  1. Every installer uses the snippet and installs $DOVECOT_PACKAGES, never the 2.3 names written out; the whole
 *     script still parses (sh -n), so the concatenation did not break a heredoc.
 *  2. The snippet with a fake pkg: 2.4 offered -> 2.4; not offered -> 2.3; 2.4 already installed and not offered
 *     (the branch changed back) -> 2.4, which 2.3 could not replace without losing the configuration. Always the MySQL
 *     flavor with its Pigeonhole.
 */
public class FreshInstallDovecotTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        I18n.setCurrent("en");
        Path work = Files.createTempDirectory("fresh-install-dovecot");
        try {
            System.out.println("== 1. The installers ==");
            Map<String, String> scripts = new LinkedHashMap<>();
            scripts.put("FullMailServerScript", new FullMailServerScript().getScriptContent());
            scripts.put("FullMailStackScript", new FullMailStackScript().getScriptContent());
            scripts.put("DovecotScript", new DovecotScript().getScriptContent());
            String choice = DovecotConfig.packagesShell().strip();
            for (Map.Entry<String, String> e : scripts.entrySet()) {
                String s = e.getValue();
                check(e.getKey() + ": the shared choice, then $DOVECOT_PACKAGES installed", s.contains(choice)
                        && (s.contains("install_packages $DOVECOT_PACKAGES\n") || s.contains("pkg install -y $DOVECOT_PACKAGES\n"))
                        && s.indexOf(choice) < s.indexOf("$DOVECOT_PACKAGES\n", s.indexOf(choice) + choice.length()));
                check("  never the 2.3 names written in an install command",
                        !s.matches("(?s).*(install_packages|pkg install -y) dovecot-mysql dovecot-pigeonhole-mysql.*"));
                Path f = work.resolve(e.getKey() + ".sh");
                Files.writeString(f, s, StandardCharsets.UTF_8);
                Process p = new ProcessBuilder("sh", "-n", f.toString()).redirectErrorStream(true).start();
                String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
                check("  the whole script parses (sh -n)" + (out.isEmpty() ? "" : ": " + out), p.waitFor() == 0);
            }

            System.out.println("\n== 2. The choice, with a fake pkg ==");
            Path bin = Files.createDirectories(work.resolve("bin"));
            Path pkg = bin.resolve("pkg");
            // pkg info -e NAME: installed if NAME is in $FAKE_INSTALLED; pkg rquery %v NAME: the version if in $FAKE_OFFERED.
            Files.writeString(pkg, """
                #!/bin/sh
                case "$1" in
                info) for n in $FAKE_INSTALLED; do [ "$n" = "$3" ] && exit 0; done; exit 1 ;;
                rquery) for n in $FAKE_OFFERED; do [ "$n" = "$3" ] && { echo 2.4.5_2; exit 0; }; done; exit 0 ;;
                esac
                exit 1
                """);
            Files.setPosixFilePermissions(pkg, PosixFilePermissions.fromString("rwxr-xr-x"));
            Path snippet = work.resolve("choice.sh");
            Files.writeString(snippet, choice + "\nprintf '%s' \"$DOVECOT_PACKAGES\" > \"$OUT\"\n");
            check("2.4 offered (latest): 2.4, MySQL flavor and its Pigeonhole",
                    run(work, snippet, "", "dovecot24-mysql dovecot24-pigeonhole-mysql").equals("dovecot24-mysql dovecot24-pigeonhole-mysql"));
            check("not offered (quarterly): 2.3, MySQL flavor and its Pigeonhole",
                    run(work, snippet, "", "").equals("dovecot-mysql dovecot-pigeonhole-mysql"));
            check("2.4 already installed, not offered any more: stays 2.4",
                    run(work, snippet, "dovecot24-mysql", "").equals("dovecot24-mysql dovecot24-pigeonhole-mysql"));
            check("  2.3 installed and 2.4 offered: 2.4 (a reinstall on latest)",
                    run(work, snippet, "dovecot-mysql", "dovecot24-mysql").equals("dovecot24-mysql dovecot24-pigeonhole-mysql"));
        } finally {
            new ProcessBuilder("rm", "-rf", work.toString()).start().waitFor();
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    /** The snippet under sh with the fake pkg first in PATH; what it chose. */
    static String run(Path work, Path snippet, String installed, String offered) throws Exception {
        Path out = work.resolve("out");
        Files.deleteIfExists(out);
        ProcessBuilder pb = new ProcessBuilder("sh", snippet.toString()).redirectErrorStream(true);
        pb.environment().put("PATH", work.resolve("bin") + ":/bin:/usr/bin");
        pb.environment().put("FAKE_INSTALLED", installed);
        pb.environment().put("FAKE_OFFERED", offered);
        pb.environment().put("OUT", out.toString());
        Process p = pb.start();
        p.getInputStream().readAllBytes();
        p.waitFor();
        return Files.exists(out) ? Files.readString(out) : "";
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
