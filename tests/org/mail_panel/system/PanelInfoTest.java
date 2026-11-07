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
 * La scheda del pannello in cima alla dashboard: da quando gira e con che cosa (reperto 183).
 *
 *  1. Build.read: le voci che Maven ha scritto; quelle che il filtro non ha sostituito ("${...}")
 *     e una data storta valgono come non registrate, non come valori.
 *  2. bootTime: i secondi di "sysctl -n kern.boottime", non la data locale in fondo alla riga.
 *  3. build(): il jar vero. Versione e data ci sono sempre; numero di build e commit se e' stato
 *     costruito con tools/build-jar.sh (con -Dbuild.script=yes la prova li pretende).
 *  4. uptime: l'avvio di questa JVM, i secondi fino a "adesso", mai negativi, e il permesso.
 *  5. details: ogni voce, e sulla VM FreeBSD quelle del sistema lette davvero; l'impronta e'
 *     quella del jar, ricalcolata qui a parte.
 *
 * Uso (sulla VM, dalla radice del progetto, dopo tools/build-jar.sh):
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
        check("le voci scritte da Maven", b.version().equals("1.0") && b.number().equals("408")
                && b.commit().equals("ca5c22430963bcd278bfdcc80e2e973642c07eb5") && !b.modified() && b.builtAt().equals("2026-11-07T14:50:43Z"));
        PanelInfo.Build raw = read("version=1.0\nbuild=${panel.build}\ncommit=${panel.commit}\nmodified=${panel.modified}\nbuiltAt=${maven.build.timestamp}\n");
        check("un ${...} che il filtro non ha sostituito: non registrato, non un valore", raw.version().equals("1.0")
                && raw.number().isEmpty() && raw.commit().isEmpty() && !raw.modified() && raw.builtAt().isEmpty());
        PanelInfo.Build empty = read("version=1.0\nbuild=\ncommit=\nmodified=\nbuiltAt=2026-11-07T14:50:43Z\n");
        check("vuote (mvn package senza lo script): non registrate", empty.number().isEmpty() && empty.commit().isEmpty() && !empty.modified());
        check("modified=true", read("modified=true\n").modified());
        check("una data che non e' ISO 8601 UTC: niente, non la stringa cosi' com'e'", read("builtAt=07/11/2026 15:50\n").builtAt().isEmpty());

        System.out.println("\n== 2. bootTime ==");
        check("i secondi di kern.boottime", Instant.ofEpochSecond(1794062163L)
                .equals(PanelInfo.bootTime("{ sec = 1794062163, usec = 48178 } Sat Nov  7 15:36:03 2026")));
        check("una riga che non e' quella: null", PanelInfo.bootTime("sysctl: unknown oid 'kern.boottime'") == null
                && PanelInfo.bootTime("") == null && PanelInfo.bootTime(null) == null);

        System.out.println("\n== 3. build() dal jar ==");
        PanelInfo.Build jar = PanelInfo.build();
        check("versione 1.0 (" + jar.version() + ")", jar.version().equals("1.0"));
        check("data di costruzione ISO 8601 UTC (" + jar.builtAt() + ")", !jar.builtAt().isEmpty() && jar.builtAt().endsWith("Z"));
        if ("yes".equals(System.getProperty("build.script"))) {
            check("numero di build (" + jar.number() + ")", jar.number().matches("[1-9][0-9]*"));
            check("commit intero (" + jar.commit() + ")", jar.commit().matches("[0-9a-f]{40}"));
        }

        System.out.println("\n== 4. uptime ==");
        Instant start = Instant.ofEpochMilli(ManagementFactory.getRuntimeMXBean().getStartTime());
        Instant now = Instant.now();
        JSONObject up = PanelInfo.uptime(now, true);
        check("l'avvio di questa JVM", up.getString("startedAt").equals(start.toString()) && PanelInfo.startedAt().equals(start));
        check("adesso, e i secondi fra i due", up.getString("now").equals(now.toString())
                && up.getLong("uptimeSeconds") == java.time.Duration.between(start, now).toSeconds());
        check("dice se si possono vedere i dettagli", up.getBoolean("details") && !PanelInfo.uptime(now, false).getBoolean("details"));
        check("un adesso prima dell'avvio: 0, mai negativo", PanelInfo.uptime(start.minusSeconds(60), false).getLong("uptimeSeconds") == 0);

        System.out.println("\n== 5. details ==");
        JSONObject d = PanelInfo.details(2096);
        check("versione, build, commit e data come build()", d.getString("version").equals(jar.version())
                && d.getString("build").equals(jar.number()) && d.getString("commit").equals(jar.commit()) && d.getString("builtAt").equals(jar.builtAt()));
        check("il processo: PID, utente, porta", d.getLong("pid") == ProcessHandle.current().pid()
                && d.getString("user").equals(System.getProperty("user.name")) && d.getInt("port") == 2096);
        check("Java: la versione di questa JVM", d.getJSONObject("java").getString("version").equals(Runtime.version().toString()));
        check("memoria e processori", d.getLong("heapMax") > 0 && d.getLong("heapUsed") > 0 && d.getInt("processors") > 0);
        String path = d.getString("jarPath");
        if (path.isEmpty()) {
            System.out.println("  (non gira da un jar: impronta e file non si provano)");
        } else {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String sha = HexFormat.of().formatHex(md.digest(Files.readAllBytes(Path.of(path))));
            check("il jar e la sua impronta, ricalcolata qui (" + path + ")", d.getString("jarSha256").equals(sha)
                    && sha.equals(InstallScripts.jarSha256()));
        }
        if (Files.isExecutable(Path.of("/bin/freebsd-version"))) {
            JSONObject os = d.getJSONObject("os");
            check("FreeBSD: userland, kernel, architettura (" + os + ")", os.getString("userland").matches("[0-9]+\\.[0-9]+-[A-Z]+.*")
                    && !os.getString("kernel").isEmpty() && !os.getString("arch").isEmpty());
            check("il nome della macchina (" + d.getString("hostname") + ")", !d.getString("hostname").isEmpty());
            check("la macchina e' accesa da prima del pannello (" + d.getString("bootedAt") + ")", !d.getString("bootedAt").isEmpty()
                    && Instant.parse(d.getString("bootedAt")).isBefore(start));
        } else {
            System.out.println("  (non e' FreeBSD: le voci del sistema non si provano)");
        }

        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
