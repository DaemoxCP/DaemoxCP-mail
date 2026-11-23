package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.scripts.InstallScripts;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The panel itself, for the card at the top of the dashboard (finding 183): since when it has been running,
 * and, behind the eye, what it runs with.
 *
 * <p>Two reads with two permissions (SSLMailServer, /api/panel_info):
 * <ul>
 *   <li>{@link #uptime}: when this process started. For anyone who sees the dashboard;</li>
 *   <li>{@link #details}: version, build number, commit, jar fingerprint, Java, system,
 *   machine, process and memory. With system.view, like the other system pages.</li>
 * </ul>
 *
 * <p>The instants come out in UTC, ISO 8601 (r13): the page converts them when it shows them.
 */
public final class PanelInfo {

    private static final Logger LOGGER = Logger.getLogger(PanelInfo.class.getName());

    private PanelInfo() {}

    /**
     * What Maven wrote in the jar (src/main/build-info/build-info.properties). An entry that
     * whoever built it did not pass is empty: version and builtAt are always there in a jar made
     * by Maven, build and commit only with tools/build-jar.sh.
     *
     * @param modified true if the sources had changes outside that commit
     */
    public record Build(String version, String number, String commit, boolean modified, String builtAt) {

        static final Build UNKNOWN = new Build("", "", "", false, "");

        static Build read(InputStream in) throws IOException {
            Properties p = new Properties();
            p.load(in);
            return new Build(value(p, "version"), value(p, "build"), value(p, "commit"),
                    "true".equals(value(p, "modified")), instant(value(p, "builtAt")));
        }

        /**
         * A value the filter did not replace stays "${...}" (a jar built without Maven, or the
         * test classes): it counts as not recorded, not as a build number.
         */
        private static String value(Properties p, String key) {
            String v = p.getProperty(key, "").trim();
            return v.contains("${") ? "" : v;
        }

        private static String instant(String v) {
            try {
                return v.isEmpty() ? "" : Instant.parse(v).toString();
            } catch (DateTimeParseException e) {
                return "";
            }
        }
    }

    private static volatile Build build;

    /** The running jar. It is read once: it is inside the jar, it does not change while the process lives. */
    public static Build build() {
        Build b = build;
        if (b != null) return b;
        try (InputStream in = PanelInfo.class.getResourceAsStream("/build-info.properties")) {
            b = in == null ? Build.UNKNOWN : Build.read(in);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Cannot read build-info.properties", e);
            b = Build.UNKNOWN;
        }
        build = b;
        return b;
    }

    /** When this process's JVM started. */
    public static Instant startedAt() {
        return Instant.ofEpochMilli(ManagementFactory.getRuntimeMXBean().getStartTime());
    }

    /**
     * Since when the panel has been running. The server's time goes with the answer: the page counts the
     * seconds from there, and a browser clock that is ahead or behind does not change the uptime.
     *
     * @param details true if the requester can also see the details (the page shows the eye)
     */
    public static JSONObject uptime(Instant now, boolean details) {
        Instant start = startedAt();
        return new JSONObject()
                .put("success", true)
                .put("startedAt", start.toString())
                .put("now", now.toString())
                .put("uptimeSeconds", Math.max(0, Duration.between(start, now).toSeconds()))
                .put("details", details);
    }

    /**
     * Everything else. Every entry that cannot be read stays empty (the page says "not
     * available"), never invented: a missing command does not stop the others.
     *
     * @param port the port the panel listens on
     */
    public static JSONObject details(int port) {
        Build b = build();
        JSONObject r = new JSONObject().put("success", true)
                .put("version", b.version())
                .put("build", b.number())
                .put("commit", b.commit())
                .put("modified", b.modified())
                .put("builtAt", b.builtAt());

        String jar = "";
        try {
            Path p = Path.of(PanelServiceRename.current(
                    Path.of(PanelInfo.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString()));
            if (p.getFileName() != null && p.getFileName().toString().endsWith(".jar")) jar = p.toString();
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "panel jar path", e);
        }
        // The fingerprint is the one InstallScripts took at startup: of the running jar, even if in
        // the meantime another one has arrived on disk.
        r.put("jarPath", jar).put("jarSha256", InstallScripts.jarSha256());

        Runtime.Version v = Runtime.version();
        r.put("java", new JSONObject()
                .put("version", v.toString())
                .put("vendor", System.getProperty("java.vendor", ""))
                .put("vm", System.getProperty("java.vm.name", ""))
                .put("home", System.getProperty("java.home", "")));

        r.put("os", new JSONObject()
                .put("userland", read("freebsd-version", "-u"))
                .put("kernel", read("uname", "-r"))
                .put("arch", read("uname", "-m")));
        r.put("hostname", read("hostname"));
        Instant boot = bootTime(read("sysctl", "-n", "kern.boottime"));
        r.put("bootedAt", boot == null ? "" : boot.toString());

        Runtime rt = Runtime.getRuntime();
        r.put("pid", ProcessHandle.current().pid())
         .put("user", System.getProperty("user.name", ""))
         .put("heapUsed", rt.totalMemory() - rt.freeMemory())
         .put("heapMax", rt.maxMemory())
         .put("processors", rt.availableProcessors())
         .put("port", port);
        return r;
    }

    /** A short command, its output on one line; "" if it is missing or does not answer. */
    private static String read(String... cmd) {
        Shell.Result res = Shell.run(Duration.ofSeconds(5), cmd);
        return res.success() ? res.outputTrim() : "";
    }

    private static final Pattern BOOT_SECONDS = Pattern.compile("\\{\\s*sec\\s*=\\s*(\\d{1,12})\\s*,");

    /**
     * The machine's boot time, from FreeBSD's "sysctl -n kern.boottime":
     * "{ sec = 1794062163, usec = 48178 } Sat Nov  7 15:36:03 2026". The seconds are taken, not the
     * date at the end, which is in the server's local time. Null if the line is not that one.
     */
    static Instant bootTime(String sysctl) {
        if (sysctl == null) return null;
        Matcher m = BOOT_SECONDS.matcher(sysctl);
        return m.find() ? Instant.ofEpochSecond(Long.parseLong(m.group(1))) : null;
    }
}
