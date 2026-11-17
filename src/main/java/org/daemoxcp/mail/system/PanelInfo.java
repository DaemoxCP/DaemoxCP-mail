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
 * Il pannello stesso, per la scheda in cima alla dashboard (reperto 183): da quando gira, e dietro
 * l'occhio con che cosa gira.
 *
 * <p>Due letture con due permessi (SSLMailServer, /api/panel_info):
 * <ul>
 *   <li>{@link #uptime}: quando e' partito questo processo. Per chiunque veda la dashboard;</li>
 *   <li>{@link #details}: versione, numero di build, commit, impronta del jar, Java, sistema,
 *   macchina, processo e memoria. Con system.view, come le altre pagine del sistema.</li>
 * </ul>
 *
 * <p>Gli istanti escono in UTC, ISO 8601 (r13): li converte la pagina, quando li mostra.
 */
public final class PanelInfo {

    private static final Logger LOGGER = Logger.getLogger(PanelInfo.class.getName());

    private PanelInfo() {}

    /**
     * Quello che Maven ha scritto nel jar (src/main/build-info/build-info.properties). Una voce che
     * chi ha costruito non ha passato e' vuota: version e builtAt ci sono sempre in un jar fatto da
     * Maven, build e commit solo con tools/build-jar.sh.
     *
     * @param modified vero se nei sorgenti c'erano modifiche fuori da quel commit
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
         * Un valore che il filtro non ha sostituito resta "${...}" (un jar costruito senza Maven, o
         * le classi delle prove): vale come non registrato, non come un numero di build.
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

    /** Il jar che gira. Si legge una volta: e' dentro il jar, non cambia finche' il processo vive. */
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

    /** Quando e' partita la JVM di questo processo. */
    public static Instant startedAt() {
        return Instant.ofEpochMilli(ManagementFactory.getRuntimeMXBean().getStartTime());
    }

    /**
     * Da quando gira il pannello. L'ora del server va con la risposta: la pagina conta i secondi da
     * li', e un orologio del browser avanti o indietro non cambia il tempo in funzione.
     *
     * @param details vero se chi chiede puo' vedere anche i dettagli (la pagina mostra l'occhio)
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
     * Tutto il resto. Ogni voce che non si riesce a leggere resta vuota (la pagina dice "non
     * disponibile"), mai inventata: un comando che manca non ferma le altre.
     *
     * @param port la porta su cui ascolta il pannello
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
        // L'impronta e' quella che InstallScripts ha preso all'avvio: del jar che gira, anche se nel
        // frattempo sul disco ne e' arrivato un altro.
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

    /** Un comando breve, la sua uscita su una riga; "" se non c'e' o non risponde. */
    private static String read(String... cmd) {
        Shell.Result res = Shell.run(Duration.ofSeconds(5), cmd);
        return res.success() ? res.outputTrim() : "";
    }

    private static final Pattern BOOT_SECONDS = Pattern.compile("\\{\\s*sec\\s*=\\s*(\\d{1,12})\\s*,");

    /**
     * L'accensione della macchina, da "sysctl -n kern.boottime" di FreeBSD:
     * "{ sec = 1794062163, usec = 48178 } Sat Nov  7 15:36:03 2026". Si prendono i secondi, non la
     * data in fondo, che e' nell'ora locale del server. Null se la riga non e' quella.
     */
    static Instant bootTime(String sysctl) {
        if (sysctl == null) return null;
        Matcher m = BOOT_SECONDS.matcher(sysctl);
        return m.find() ? Instant.ofEpochSecond(Long.parseLong(m.group(1))) : null;
    }
}
