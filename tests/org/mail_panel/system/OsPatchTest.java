package org.mail_panel.system;

import org.json.JSONObject;

import java.time.Instant;

/**
 * Le decisioni dell'installazione delle patch di FreeBSD dal pannello (reperto 185), senza un
 * sistema sotto: le uscite di freebsd-update sono quelle viste sulla VM e sul server vero.
 *
 *  1. target: la versione dal file tag ("...|15.1-RELEASE|6|..." -> 15.1-RELEASE-p6).
 *  2. Le uscite di freebsd-update: niente da scaricare, niente da installare, riavvia e reinstalla.
 *  3. rebootState: serve (kernel installato diverso da quello in uso), consigliato (patch
 *     installate dopo l'accensione), niente (e cosa e' stato fatto prima dell'ultima accensione).
 *  4. installConfig: la configurazione del sistema con CreateBootEnv no, una volta sola.
 *
 * Uso: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.OsPatchTest
 */
public class OsPatchTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) {
        System.out.println("== 1. target ==");
        check("p6 dal tag del server vero", OsPatch.target("freebsd-update|arm64|15.1-RELEASE|6|3b46c9fe530b8e80e7cc977d7619a523ace29a3ec12a38238635fb1d6fb1fa3c|1806537600")
                .equals("15.1-RELEASE-p6"));
        check("il livello 0 e' la release", OsPatch.target("freebsd-update|amd64|14.3-RELEASE|0|abc|1806537600").equals("14.3-RELEASE"));
        check("un tag che non e' quello: vuoto", OsPatch.target("qualcos'altro").isEmpty() && OsPatch.target(null).isEmpty()
                && OsPatch.target("freebsd-update|arm64|15.1-RELEASE|x|abc|1").isEmpty());

        System.out.println("\n== 2. Le uscite di freebsd-update ==");
        check("niente da scaricare", OsPatch.nothingToFetch("src component not installed, skipped\nNo updates needed to update system to 15.1-RELEASE-p6.")
                && !OsPatch.nothingToFetch("The following files will be updated as part of updating to\n15.1-RELEASE-p6:"));
        check("niente da installare", OsPatch.nothingToInstall("src component not installed, skipped\nNo updates are available to install.")
                && !OsPatch.nothingToInstall("There are updates available to install."));
        check("riavvia e reinstalla (passaggio di release)", OsPatch.asksRebootFirst(
                "Installing updates...\nKernel updates have been installed.  Please reboot and run\n'/usr/sbin/freebsd-update install' again to finish installing updates."));
        check("una patch normale non lo chiede", !OsPatch.asksRebootFirst("Creating snapshot of existing boot environment... done.\nInstalling updates... done."));

        System.out.println("\n== 3. rebootState ==");
        Instant boot = Instant.parse("2026-11-07T16:00:00Z");
        long before = boot.getEpochSecond() - 3600, after = boot.getEpochSecond() + 600;
        JSONObject k = OsPatch.rebootState("15.1-RELEASE-p6", "15.1-RELEASE", after, boot, "15.1-RELEASE-p6");
        check("kernel installato diverso da quello in uso: serve", k.getString("state").equals("needed"));
        check("  anche senza patch del pannello (un aggiornamento fatto a mano)", OsPatch.rebootState("15.1-RELEASE-p6", "15.1-RELEASE-p3", 0, boot, "")
                .getString("state").equals("needed"));
        check("patch installate dopo l'accensione, kernel giusto: consigliato",
                OsPatch.rebootState("15.1-RELEASE-p6", "15.1-RELEASE-p6", after, boot, "15.1-RELEASE-p6").getString("state").equals("advised"));
        JSONObject done = OsPatch.rebootState("15.1-RELEASE-p6", "15.1-RELEASE-p6", before, boot, "15.1-RELEASE-p6");
        check("patch installate prima dell'accensione: niente, e dice cosa e' stato fatto", done.getString("state").equals("none")
                && done.optString("done").equals("15.1-RELEASE-p6"));
        check("mai installato niente: niente", OsPatch.rebootState("15.1-RELEASE", "15.1-RELEASE", 0, boot, "").getString("state").equals("none")
                && !OsPatch.rebootState("15.1-RELEASE", "15.1-RELEASE", 0, boot, "").has("done"));
        check("versioni illeggibili: non si inventa un riavvio", OsPatch.rebootState("", "15.1-RELEASE", 0, null, "").getString("state").equals("none"));

        System.out.println("\n== 4. installConfig ==");
        String system = "KeyPrint 800651ef4b4c71c27e60786d7b487188970f4b4169cc055784e21eb71d410cc5\nServerName update.FreeBSD.org\n"
                + "Components src world kernel\n# CreateBootEnv yes\nCreateBootEnv yes\n";
        String conf = OsPatch.installConfig(system);
        check("tiene la chiave, il server e i componenti", conf.contains("KeyPrint 800651ef") && conf.contains("ServerName update.FreeBSD.org")
                && conf.contains("Components src world kernel"));
        check("CreateBootEnv no, una volta sola (freebsd-update rifiuta i doppioni)",
                conf.lines().filter(l -> l.trim().startsWith("CreateBootEnv")).toList().equals(java.util.List.of("CreateBootEnv no")));
        check("il commento di prima resta", conf.contains("# CreateBootEnv yes"));

        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
