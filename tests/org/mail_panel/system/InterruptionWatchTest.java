package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.i18n.I18n;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Il guardiano del servizio acceso (UpdateManager.watchOnce, reperto 166): quando NON deve toccare
 * l'elenco dei pacchetti sbloccati, e il testo dell'avviso di una reinstallazione interrotta.
 * Nessun pkg: ogni caso si ferma prima di riproteggere (il caso che riprotegge davvero e'
 * ReinstallJobTest J4, sul clone). Elenco, record del lavoro, turno e avviso in una cartella
 * temporanea.
 *
 * Uso: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InterruptionWatchTest
 */
public class InterruptionWatchTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static long deadPid() throws Exception {
        Process p = new ProcessBuilder("true").start();
        p.waitFor();
        return p.pid();
    }

    /** Ogni caso parte pulito: un elenco rimasto dal caso prima fa rifiutare il turno (take). */
    static void clearList() throws Exception {
        Files.deleteIfExists(PackageQueue.list);
        Files.deleteIfExists(PackageQueue.jobRecordPath());
    }

    static void writeList(long writerPid, boolean expectsRestart, String turnId) throws Exception {
        Files.writeString(PackageQueue.list, "dovecot\nnginx\n");
        Files.writeString(PackageQueue.jobRecordPath(), new JSONObject()
                .put("description", "prova").put("turnId", turnId).put("pid", writerPid)
                .put("expectsRestart", expectsRestart).put("startedUtc", "2026-11-06T00:00:00Z").toString());
    }

    public static void main(String[] args) throws Exception {
        I18n.setCurrent("en");
        Path d = Files.createTempDirectory("interruption-watch");
        PackageQueue.list = d.resolve("mail-panel-maintenance-locks");
        PackageQueue.turnLock = d.resolve("package-turn.lock");
        PackageRecovery.notice = d.resolve("package-job-interrupted.json");
        try {
            System.out.println("== Nessun elenco ==");
            check("niente da fare", UpdateManager.watchOnce().isEmpty());

            System.out.println("\n== L'elenco lasciato apposta dall'aggiornamento della JVM ==");
            clearList();
            writeList(deadPid(), true, "java-update");
            check("non lo tocca (lo chiude il riavvio che fa lui)", UpdateManager.watchOnce().isEmpty() && PackageQueue.statePresent());
            check("e non scrive nessun avviso", !Files.exists(PackageRecovery.notice));

            System.out.println("\n== Chi ha scritto l'elenco lavora ancora (un altro processo) ==");
            Process alive = new ProcessBuilder("sleep", "60").start();
            clearList();
            writeList(alive.pid(), false, InstallLocks.REINSTALL_TURN_PREFIX + "1");
            check("non lo tocca", UpdateManager.watchOnce().isEmpty() && PackageQueue.statePresent() && !Files.exists(PackageRecovery.notice));
            alive.destroyForcibly();
            alive.waitFor();

            System.out.println("\n== Lo ha scritto un lavoro di questo stesso processo, ancora sul turno ==");
            clearList();
            check("questo processo prende il turno", PackageQueue.take("prova-qui", "lavoro di prova") == null);
            writeList(ProcessHandle.current().pid(), false, "prova-qui");
            check("non lo tocca", UpdateManager.watchOnce().isEmpty() && PackageQueue.statePresent());
            PackageQueue.release("prova-qui");

            System.out.println("\n== Chi l'ha scritto e' morto, ma il turno lo tiene un altro processo ==");
            clearList();     // l'altro processo prende il turno prima, e poi c'e' l'elenco, come in un lavoro vero
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            Process holder = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    "org.mail_panel.system.TurnHolder", PackageQueue.list.toString(), "turno di prova")
                    .redirectErrorStream(true).start();
            BufferedReader out = new BufferedReader(new InputStreamReader(holder.getInputStream(), StandardCharsets.UTF_8));
            String line;
            boolean held = false;
            while ((line = out.readLine()) != null) { if (line.contains("HELD")) { held = true; break; } }
            check("l'altro processo tiene il turno", held);
            writeList(deadPid(), false, InstallLocks.REINSTALL_TURN_PREFIX + "2");
            String r = UpdateManager.watchOnce();
            check("il ripristino non tocca niente e dice perche'", r.contains("another panel process holds the package turn")
                    && PackageQueue.statePresent() && !Files.exists(PackageRecovery.notice));
            holder.getOutputStream().close();
            holder.waitFor();

            System.out.println("\n== L'avviso di una reinstallazione interrotta ==");
            PackageRecovery.recordInterruption(new JSONObject().put("description", "complete mail server installation")
                    .put("turnId", InstallLocks.REINSTALL_TURN_PREFIX + "3"), List.of("dovecot"), List.of("dovecot"), "");
            JSONObject n = PackageRecovery.notice();
            check("l'avviso sa che era la reinstallazione", n.optBoolean("reinstall"));
            String text = PackageRecovery.text(n.put("wayBack", "reinstall-before-2026-11-06-120000"));
            check("e dice come tornare con la sua via di ritorno", text.contains("bectl activate reinstall-before-2026-11-06-120000"));
            check("e che la posta puo' essere spenta", text.contains("mail services may be stopped"));
            check("non dice piu' «at startup»", !text.contains("at startup"));
            text = PackageRecovery.text(n.put("wayBack", ""));
            check("senza via di ritorno lo dice", text.contains("no way back"));
            Files.deleteIfExists(PackageRecovery.notice);
            PackageRecovery.recordInterruption(new JSONObject().put("description", "installing nginx")
                    .put("turnId", "install-4"), List.of("nginx"), List.of(), "");
            n = PackageRecovery.notice();
            check("l'installazione di un pacchetto dalla pagina non e' la reinstallazione", !n.optBoolean("reinstall")
                    && !PackageRecovery.text(n).contains("complete reinstallation"));
        } finally {
            try (var walk = Files.walk(d)) {
                for (Path q : walk.sorted((x, y) -> y.compareTo(x)).toList()) Files.deleteIfExists(q);
            }
        }
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
