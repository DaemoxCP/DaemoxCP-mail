package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.FullMailServerScript;
import org.daemoxcp.mail.scripts.FullMailStackScript;
import org.daemoxcp.mail.scripts.PostfixLevelScript;
import org.daemoxcp.mail.scripts.PostfixScript;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Postfix's compatibility level at installation (reperto 251): a server just installed by the panel must not start
 * with "Postfix: the level is behind" in Diagnostics, and raising the level must not change how mail behaves.
 *  1. each of the three scripts that write main.cf (FullMailServerScript, FullMailStackScript, PostfixScript) writes
 *     the 3.6 floor, and decides in main.cf every parameter that a reviewed level above it changes (or the change does
 *     not apply: TLS-RPT off);
 *  2. each runs the level piece after main.cf and before Postfix starts;
 *  3. with the real Postfix (on the VM): every default that `postconf -d` shows as depending on the level is listed in
 *     PostfixLevels at that level, and the gate of TLS-RPT is off by default;
 *  4. the piece itself, with a fake postfix and postconf: it raises to the level Postfix asks for only if reviewed and
 *     higher; a level not reviewed, no request, a lower level or a strange answer change nothing.
 * As root on the TEST VM (section 3 needs Postfix installed):
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PostfixLevelTest
 */
public class PostfixLevelTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final Pattern MAIN_CF = Pattern.compile("cat > /usr/local/etc/postfix/main\\.cf << '?([A-Z_]+)'?\\n(.*?)\\n\\1\\n",
            Pattern.DOTALL);
    static final Pattern SETTING = Pattern.compile("(?m)^([a-z0-9_]+)\\s*=\\s*(.*)$");
    static final Pattern POSTCONF_E = Pattern.compile("postconf -e \"?([a-z0-9_]+)=([^\"\\s]*)");

    static double level(String v) {
        Matcher m = Pattern.compile("^([0-9]+)(?:\\.([0-9]+))?").matcher(v.trim());
        if (!m.find()) return -1;
        return Double.parseDouble(m.group(1)) + (m.group(2) == null ? 0 : Double.parseDouble(m.group(2)) / 100.0);
    }

    /** What the script decides for Postfix: main.cf, plus any postconf -e. */
    static Map<String, String> decided(String script) {
        Map<String, String> out = new HashMap<>();
        Matcher m = MAIN_CF.matcher(script);
        if (m.find()) {
            Matcher s = SETTING.matcher(m.group(2));
            while (s.find()) out.put(s.group(1), s.group(2).trim());
        }
        Matcher e = POSTCONF_E.matcher(script);
        while (e.find()) out.putIfAbsent(e.group(1), e.group(2));
        return out;
    }

    static String run(String command, Map<String, String> env) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command).redirectErrorStream(true);
        pb.environment().putAll(env);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes());
        p.waitFor(60, TimeUnit.SECONDS);
        return out;
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> scripts = new LinkedHashMap<>();
        scripts.put("FullMailServerScript", new FullMailServerScript().getScriptContent());
        scripts.put("FullMailStackScript", new FullMailStackScript().getScriptContent());
        scripts.put("PostfixScript", new PostfixScript().getScriptContent());

        System.out.println("== 1. What each script decides in main.cf");
        for (Map.Entry<String, String> sc : scripts.entrySet()) {
            Map<String, String> d = decided(sc.getValue());
            String base = d.getOrDefault("compatibility_level", "");
            check(sc.getKey() + ": main.cf found, with the 3.6 floor (" + base + ")", MAIN_CF.matcher(sc.getValue()).find()
                    && base.equals("3.6"));
            for (String lv : PostfixLevels.reviewed()) {
                if (level(lv) <= level(base)) continue;
                for (String entry : PostfixLevels.parameters(lv)) {
                    String name = entry, gate = null, expected = null;
                    int at = entry.indexOf('@');
                    if (at > 0) {
                        name = entry.substring(0, at);
                        String[] g = entry.substring(at + 1).split("=", 2);
                        gate = g[0];
                        expected = g[1];
                    }
                    boolean set = d.containsKey(name);
                    // A gate left at its default: the default is checked against the real Postfix in section 3
                    boolean off = gate != null && !expected.equalsIgnoreCase(d.getOrDefault(gate, "no"));
                    check(sc.getKey() + ", level " + lv + ": " + name + (set ? " = " + d.get(name) + " in main.cf"
                            : off ? " does not apply (" + gate + " is not " + expected + ")" : " LEFT TO THE DEFAULT"), set || off);
                }
            }
        }

        System.out.println("\n== 2. The level piece, after main.cf and before Postfix starts");
        String marker = "# --- Il livello di compatibilita' di Postfix (PostfixLevelScript.java) ---";
        for (Map.Entry<String, String> sc : scripts.entrySet()) {
            String s = sc.getValue();
            Matcher m = MAIN_CF.matcher(s);
            int mainEnd = m.find() ? m.end() : -1;
            int piece = s.indexOf(marker);
            int start = s.indexOf("service postfix start", Math.max(piece, 0));
            check(sc.getKey() + ": once, after main.cf, before \"service postfix start\"", s.indexOf(marker) == s.lastIndexOf(marker)
                    && mainEnd > 0 && piece > mainEnd && start > piece);
        }

        System.out.println("\n== 3. PostfixLevels against the real Postfix");
        if (!Files.isExecutable(Path.of("/usr/local/sbin/postconf"))) {
            check("Postfix installed here (this section runs on the VM)", false);
        } else {
            String defaults = run("/usr/local/sbin/postconf -d", Map.of());
            Matcher dep = Pattern.compile("(?m)^([a-z0-9_]+) = .*\\$\\{\\{\\$compatibility_level\\} <level \\{([0-9.]+)\\}").matcher(defaults);
            int n = 0;
            while (dep.find()) {
                n++;
                String name = dep.group(1), lv = dep.group(2);
                check(name + " depends on level " + lv + ": listed there in PostfixLevels",
                        PostfixLevels.parameters(lv).stream().anyMatch(p -> p.equals(name) || p.startsWith(name + "@")));
            }
            check("Postfix shows level-dependent defaults (" + n + ")", n >= 10);
            check("smtp_tlsrpt_enable is off by default", run("/usr/local/sbin/postconf -dh smtp_tlsrpt_enable", Map.of()).trim().equals("no"));
            String version = run("/usr/local/sbin/postconf -h mail_version", Map.of()).trim();
            String asked = run("/usr/local/sbin/postfix check 2>&1 | sed -n 's/.*compatibility_level=\\([0-9][0-9.]*\\).*/\\1/p'", Map.of()).trim();
            String now = run("/usr/local/sbin/postconf -h compatibility_level", Map.of()).trim();
            System.out.println("    this Postfix: " + version + ", level " + now + (asked.isEmpty() ? ", asks for nothing more" : ", asks for " + asked));
            check("the level this Postfix asks for is reviewed", asked.isEmpty() || PostfixLevels.reviewed().contains(asked));
        }

        System.out.println("\n== 4. The piece, with a fake postfix and postconf");
        Path dir = Files.createTempDirectory("postfix-level-test");
        try {
            Path calls = dir.resolve("calls");
            Files.writeString(dir.resolve("postfix"), "#!/bin/sh\nprintf '%s\\n' \"$FAKE_CHECK\" >&2\n");
            Files.writeString(dir.resolve("postconf"), "#!/bin/sh\n"
                    + "if [ \"$1\" = -h ]; then echo \"$FAKE_NOW\"; exit 0; fi\n"
                    + "echo \"$*\" >> \"" + calls + "\"\n");
            for (String f : List.of("postfix", "postconf"))
                Files.setPosixFilePermissions(dir.resolve(f), PosixFilePermissions.fromString("rwx------"));
            String piece = PostfixLevelScript.shell();
            Object[][] cases = {
                {"asks for 3.11, written 3.6: raised", "postfix: To disable backwards compatibility use \"postconf compatibility_level=3.11\" and \"postfix reload\"", "3.6", "-e compatibility_level=3.11"},
                {"asks for a level not reviewed (3.12): unchanged, and said", "use \"postconf compatibility_level=3.12\"", "3.6", ""},
                {"asks for nothing: unchanged", "", "3.11", ""},
                {"asks for a lower level: unchanged", "use \"postconf compatibility_level=2\"", "3.6", ""},
                {"asks for the level already written: unchanged", "use \"postconf compatibility_level=3.6\"", "3.6", ""},
                {"a strange answer: nothing run, unchanged", "compatibility_level=$(touch " + dir.resolve("pwned") + ")", "3.6", ""},
            };
            for (Object[] c : cases) {
                Files.deleteIfExists(calls);
                String out = run(piece, Map.of("PF_SBIN", dir.toString(), "FAKE_CHECK", (String) c[1], "FAKE_NOW", (String) c[2]));
                String done = Files.exists(calls) ? Files.readString(calls).trim() : "";
                boolean said = ((String) c[3]).isEmpty() || out.contains("compatibility level: " + ((String) c[3]).replace("-e compatibility_level=", ""));
                check(c[0] + " [" + out.trim().replace('\n', ' ') + "]", done.equals(c[3]) && said
                        && !Files.exists(dir.resolve("pwned")));
            }
            Files.deleteIfExists(calls);
            String out = run(piece, Map.of("PF_SBIN", dir.toString(), "FAKE_CHECK", "use \"postconf compatibility_level=3.12\"", "FAKE_NOW", "3.6"));
            check("the level not reviewed is named in a WARNING", out.contains("WARNING") && out.contains("3.12"));
        } finally {
            try (var w = Files.walk(dir)) { w.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
        }

        System.out.println("\n" + (failed == 0 ? "ALL OK" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
