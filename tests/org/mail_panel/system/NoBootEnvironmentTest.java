package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.i18n.I18n;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;

/**
 * Un sistema SENZA boot environment (UFS, o ZFS senza bectl): la reinstallazione e il ritorno non si
 * rompono e lo dicono (reperto 172). Lo si simula con un bectl finto davanti nel PATH che fallisce
 * sempre (Shell mette il PATH ereditato prima delle cartelle di sistema), in un processo figlio.
 *  - la via di ritorno della reinstallazione non si crea e lo si dice, senza fermare niente;
 *  - il controllo dello spazio non si fa (non c'e' niente da tenere occupato);
 *  - dopo l'installazione non si tocca niente;
 *  - il ritorno: nessuna via di ritorno, e un nome qualunque e' rifiutato;
 *  - la scheda dei boot environment dice che non ci sono.
 * Uso: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.NoBootEnvironmentTest
 */
public class NoBootEnvironmentTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0) { child(); return; }
        Path d = Files.createTempDirectory("no-bectl");
        try {
            Path fake = d.resolve("bectl");
            Files.writeString(fake, "#!/bin/sh\necho \"bectl: libbe_init(\\\"\\\") failed.\" >&2\nexit 1\n");
            Files.setPosixFilePermissions(fake, PosixFilePermissions.fromString("rwxr-xr-x"));
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            ProcessBuilder pb = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    NoBootEnvironmentTest.class.getName(), "child").inheritIO();
            pb.environment().put("PATH", d + ":" + System.getenv("PATH"));
            System.exit(pb.start().waitFor());
        } finally {
            Files.deleteIfExists(d.resolve("bectl"));
            Files.deleteIfExists(d);
        }
    }

    static void child() {
        I18n.setCurrent("en");
        List<String> log = new ArrayList<>();
        PackageWayBack.Prepared p = PackageWayBack.beforeInstallation(log::add);
        check("la via di ritorno non si crea, senza eccezioni", p.name().isEmpty());
        check("e lo dice", String.join("\n", log).contains("no ZFS boot environments"));
        log.clear();
        check("il controllo dello spazio non ferma niente", PackageWayBack.reinstallSpace(log::add) == null && log.isEmpty());
        PackageWayBack.afterInstallation(log::add, p, true);
        check("dopo l'installazione non si tocca niente", log.isEmpty());
        check("il ritorno: nessuna via di ritorno", ReinstallReturn.latest().isEmpty());
        JSONObject r = ReinstallReturn.goBack("reinstall-before-2026-11-06-120000", log::add);
        check("e un nome qualunque e' rifiutato", !r.optBoolean("success") && r.optString("error").contains("not there any more"));
        JSONObject be = UpdateManager.bootEnvironments();
        check("la scheda dice che non ci sono boot environment", !be.optBoolean("success") && !be.optString("error").isEmpty());
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
