package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.scripts.InstallScripts;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;

/**
 * The panel card at the top of the dashboard: since when it has been running and on what (reperto 183).
 *
 *  1. Build.read: the entries Maven wrote; those the filter did not replace ("${...}") and a bad
 *     date count as not recorded, not as values.
 *  2. bootTime: the seconds of "sysctl -n kern.boottime", not the local date at the end of the line.
 *  3. build(): the real jar. Version and date are always there; build number and commit when it was
 *     built with tools/build-jar.sh (with -Dbuild.script=yes the test requires them).
 *  4. uptime: this JVM's start, the seconds until "now", never negative, and the permission.
 *  5. details: every entry, and on the FreeBSD VM the system ones read for real; the fingerprint is
 *     the jar's, computed again here on its own.
 *
 * Usage (on the VM, from the project root, after tools/build-jar.sh):
 *   javac --release 25 -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/system/PanelInfoTest.java
 *   java -Dbuild.script=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PanelInfoTest
 */
public class PanelInfoTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static PanelInfo.Build read(String text) throws Exception {
        try (InputStream in = new ByteArrayInputStream(text.getBytes(StandardCharsets.ISO_8859_1))) {
            return PanelInfo.Build.read(in);
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. Build.read ==");
        PanelInfo.Build b = read("version=1.0\nbuild=408\ncommit=ca5c22430963bcd278bfdcc80e2e973642c07eb5\nmodified=false\nbuiltAt=2026-11-07T14:50:43Z\n");
        check("the entries written by Maven", b.version().equals("1.0") && b.number().equals("408")
                && b.commit().equals("ca5c22430963bcd278bfdcc80e2e973642c07eb5") && !b.modified() && b.builtAt().equals("2026-11-07T14:50:43Z"));
        PanelInfo.Build raw = read("version=1.0\nbuild=${panel.build}\ncommit=${panel.commit}\nmodified=${panel.modified}\nbuiltAt=${maven.build.timestamp}\n");
        check("a ${...} the filter did not replace: not recorded, not a value", raw.version().equals("1.0")
                && raw.number().isEmpty() && raw.commit().isEmpty() && !raw.modified() && raw.builtAt().isEmpty());
        PanelInfo.Build empty = read("version=1.0\nbuild=\ncommit=\nmodified=\nbuiltAt=2026-11-07T14:50:43Z\n");
        check("empty (mvn package without the script): not recorded", empty.number().isEmpty() && empty.commit().isEmpty() && !empty.modified());
        check("modified=true", read("modified=true\n").modified());
        check("a date that is not ISO 8601 UTC: nothing, not the string as it is", read("builtAt=07/11/2026 15:50\n").builtAt().isEmpty());

        System.out.println("\n== 2. bootTime ==");
        check("the seconds of kern.boottime", Instant.ofEpochSecond(1794062163L)
                .equals(PanelInfo.bootTime("{ sec = 1794062163, usec = 48178 } Sat Nov  7 15:36:03 2026")));
        check("a line of another shape: null", PanelInfo.bootTime("sysctl: unknown oid 'kern.boottime'") == null
                && PanelInfo.bootTime("") == null && PanelInfo.bootTime(null) == null);

        System.out.println("\n== 3. build() from the jar ==");
        PanelInfo.Build jar = PanelInfo.build();
        check("version 1.0 (" + jar.version() + ")", jar.version().equals("1.0"));
        check("build date ISO 8601 UTC (" + jar.builtAt() + ")", !jar.builtAt().isEmpty() && jar.builtAt().endsWith("Z"));
        if ("yes".equals(System.getProperty("build.script"))) {
            check("build number (" + jar.number() + ")", jar.number().matches("[1-9][0-9]*"));
            check("full commit (" + jar.commit() + ")", jar.commit().matches("[0-9a-f]{40}"));
        }

        System.out.println("\n== 4. uptime ==");
        Instant start = Instant.ofEpochMilli(ManagementFactory.getRuntimeMXBean().getStartTime());
        Instant now = Instant.now();
        JSONObject up = PanelInfo.uptime(now, true);
        check("this JVM's start", up.getString("startedAt").equals(start.toString()) && PanelInfo.startedAt().equals(start));
        check("now, and the seconds in between", up.getString("now").equals(now.toString())
                && up.getLong("uptimeSeconds") == java.time.Duration.between(start, now).toSeconds());
        check("it says whether the details can be seen", up.getBoolean("details") && !PanelInfo.uptime(now, false).getBoolean("details"));
        check("a now before the start: 0, never negative", PanelInfo.uptime(start.minusSeconds(60), false).getLong("uptimeSeconds") == 0);

        System.out.println("\n== 5. details ==");
        JSONObject d = PanelInfo.details(2096);
        check("version, build, commit and date as build()", d.getString("version").equals(jar.version())
                && d.getString("build").equals(jar.number()) && d.getString("commit").equals(jar.commit()) && d.getString("builtAt").equals(jar.builtAt()));
        check("the process: PID, user, port", d.getLong("pid") == ProcessHandle.current().pid()
                && d.getString("user").equals(System.getProperty("user.name")) && d.getInt("port") == 2096);
        check("Java: this JVM's version", d.getJSONObject("java").getString("version").equals(Runtime.version().toString()));
        check("memory and processors", d.getLong("heapMax") > 0 && d.getLong("heapUsed") > 0 && d.getInt("processors") > 0);
        String path = d.getString("jarPath");
        if (path.isEmpty()) {
            System.out.println("  (not running from a jar: fingerprint and file not checked)");
        } else {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String sha = HexFormat.of().formatHex(md.digest(Files.readAllBytes(Path.of(path))));
            check("the jar and its fingerprint, computed again here (" + path + ")", d.getString("jarSha256").equals(sha)
                    && sha.equals(InstallScripts.jarSha256()));
        }
        if (Files.isExecutable(Path.of("/bin/freebsd-version"))) {
            JSONObject os = d.getJSONObject("os");
            check("FreeBSD: userland, kernel, architecture (" + os + ")", os.getString("userland").matches("[0-9]+\\.[0-9]+-[A-Z]+.*")
                    && !os.getString("kernel").isEmpty() && !os.getString("arch").isEmpty());
            check("the machine name (" + d.getString("hostname") + ")", !d.getString("hostname").isEmpty());
            check("the machine has been up since before the panel (" + d.getString("bootedAt") + ")", !d.getString("bootedAt").isEmpty()
                    && Instant.parse(d.getString("bootedAt")).isBefore(start));
        } else {
            System.out.println("  (not FreeBSD: the system entries are not checked)");
        }

        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
