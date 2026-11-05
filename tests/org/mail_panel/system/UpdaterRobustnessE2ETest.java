package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.util.Shell;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Dove l'aggiornamento dei pacchetti puo' rompersi: misure, non correzioni.
 *
 * Il committente vuole l'aggiornamento dei pacchetti «super solido». Il disegno del cuore (piano
 * firmato, -U, scaricamento e ricalcolo, inventario prima e dopo, riprotezione nel finally) e'
 * gia' provato dalle altre prove. Questa misura i bordi che quelle non toccano, con lavori veri su
 * pacchetti finti, e STAMPA cosa succede; i controlli dicono solo se la misura e' stata fatta,
 * non se il comportamento e' quello giusto (quello lo decide il committente):
 *
 *   M1  la via di ritorno: un aggiornamento guidato crea un boot environment? tiene una copia
 *       del pacchetto di prima?
 *   M2  il turno: due processi Java (il pannello web e un secondo, il menu o una prova) prendono
 *       il turno tutti e due?
 *   M2b un secondo avvio del jar mentre il pannello aggiorna: all'avvio riprotegge dall'elenco
 *   M3  un pkg esterno (da SSH) che tiene il lock del database mentre parte un lavoro del pannello
 *   M4  il pannello ucciso (kill -9, un riavvio, un crash) mentre pkg sta installando: che fine
 *       fa pkg, e cosa trova il pannello al riavvio
 *   M5  il timeout di runLogged: chi uccide, e in che stato lascia pkg
 *   M6  dopo un lavoro interrotto, il rapporto periodico lo dice?
 *   M7  la macchina che si spegne di colpo durante pkg upgrade (-Dmeasure=m7, poi il modo m7-after)
 *
 * Tocca il sistema: installa e toglie pacchetti finti, spegne i repository veri per la durata,
 * sblocca e riprotegge. Solo su una macchina di prova, da root, con -De2e.vm=yes:
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.UpdaterRobustnessE2ETest
 * Alla fine controlla che pacchetti, protezioni e repository siano quelli di prima.
 */
public class UpdaterRobustnessE2ETest {

    static final String PKG = "nginx-robust-probe";
    static final String OTHER = "robust-probe-other";
    static final String REPO_CONF = "/usr/local/etc/pkg/repos/zzz-robust-probe.conf";
    static final Path DIR = Path.of("/var/tmp/um-probe");
    static final Path SLEEP = DIR.resolve("sleep"), STARTED = DIR.resolve("started"), DONE = DIR.resolve("done");

    private static int failures = 0;
    private static Path work;
    private static boolean createdReposDir;

    public static void main(String[] args) throws Exception {
        if (args.length > 0) { child(args); return; }
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("Without -De2e.vm=yes this test does nothing: it changes packages.");
            return;
        }
        if (!sh("id -u").trim().equals("0")) { System.out.println("Root is needed."); System.exit(2); }
        if ("m7".equals(System.getProperty("measure"))) { m7Before(); return; }

        String packagesBefore = sh("pkg query %n-%v | sort | sha256");
        Set<String> lockedBefore = locked();
        String bootEnvironmentsBefore = sh("bectl list -H | cut -f1 | sort");
        cleanup();
        work = Files.createTempDirectory(Path.of("/var/tmp"), "robust-probe");
        Files.createDirectories(DIR);
        try {
            build(PKG, "1.0", false);
            build(PKG, "1.1", true);
            build(OTHER, "1.0", true);
            if (!Files.isDirectory(Path.of(REPO_CONF).getParent())) {
                Files.createDirectories(Path.of(REPO_CONF).getParent());
                createdReposDir = true;
            }
            Path repo = work.resolve("repo");
            sh("mkdir -p " + repo + " && cp " + work.resolve("pkgs/" + PKG + "-1.1.pkg") + " " + work.resolve("pkgs/" + OTHER + "-1.0.pkg")
                    + " " + repo + " && pkg repo " + repo + " >/dev/null 2>&1");
            Files.writeString(Path.of(REPO_CONF),
                    "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n"
                  + "robustprobe: { url: \"file://" + repo + "\", signature_type: \"none\", enabled: yes }\n");
            sh("pkg update -f -r robustprobe >/dev/null 2>&1");

            // -Dmeasure=m2b,m4: solo quelle; senza, tutte.
            Set<String> only = new TreeSet<>(List.of(System.getProperty("measure", "all").split(",")));
            java.util.function.Predicate<String> on = m -> only.contains("all") || only.contains(m);
            if (on.test("m1")) m1WayBack(bootEnvironmentsBefore);
            if (on.test("m2")) m2TurnAcrossProcesses();
            if (on.test("m2b")) m2bSecondStartDuringJob();
            if (on.test("m3")) m3ExternalPkgHoldsTheLock();
            if (on.test("m4")) m4PanelKilledDuringPkg();
            if (on.test("m5")) m5Timeout();
            if (on.test("m6")) m6ReportAfterInterruption();
        } finally {
            cleanup();
            sh("rm -f " + REPO_CONF + "; rm -rf /var/db/pkg/repos/robustprobe " + work + " " + DIR);
            if (createdReposDir) sh("rmdir " + Path.of(REPO_CONF).getParent());
            UpdateManager.refreshLockTrace();
            check("alla fine: gli stessi pacchetti di prima", sh("pkg query %n-%v | sort | sha256").equals(packagesBefore));
            check("alla fine: gli stessi pacchetti protetti", locked().equals(lockedBefore));
            check("alla fine: nessun elenco di un lavoro interrotto", !PackageQueue.statePresent());
            check("alla fine: FreeBSD-ports di nuovo acceso",
                    sh("pkg -vv 2>/dev/null | grep -A3 '^  FreeBSD-ports: {' | grep -c 'enabled *: yes'").trim().equals("1"));
            check("alla fine: gli stessi boot environment", sh("bectl list -H | cut -f1 | sort").equals(bootEnvironmentsBefore));
        }
        System.out.println(failures == 0 ? "\nMISURE FATTE" : "\n" + failures + " MISURE NON RIUSCITE");
        if (failures > 0) System.exit(1);
    }

    // ===================== M1 =====================

    static void m1WayBack(String bootEnvironmentsBefore) throws Exception {
        System.out.println("\n== M1. La via di ritorno di un aggiornamento guidato ==");
        fresh(0);
        JSONObject job = guided();
        if (job == null) return;
        String after = sh("bectl list -H | cut -f1 | sort");
        System.out.println("  esito del lavoro: " + job.optString("status") + " " + job.optString("errorMessage"));
        System.out.println("  versione dopo: " + sh("pkg query %v " + PKG).trim());
        System.out.println("  boot environment prima: " + bootEnvironmentsBefore.replace("\n", " "));
        System.out.println("  boot environment dopo:  " + after.replace("\n", " "));
        System.out.println("  il pacchetto 1.0 da qualche parte sulla macchina: "
                + (sh("find /var/cache/pkg /var/db/mailpanel /var/backups -name '" + PKG + "-1.0*' 2>/dev/null").trim().isEmpty() ? "NO" : "si'"));
        String log = job.optString("consoleLog");
        System.out.println("  il log parla di una via di ritorno (bectl / boot environment / pkg create): "
                + (log.matches("(?s).*(bectl|boot environment|ambiente di avvio|pkg create).*") ? "si'" : "NO"));
        check("M1 misurata: il lavoro e' finito", !job.optString("status").isEmpty());
    }

    // ===================== M2 =====================

    static void m2TurnAcrossProcesses() throws Exception {
        System.out.println("\n== M2. Il turno, con due processi ==");
        String mine = PackageQueue.take("measure-m2", "measurement M2");
        System.out.println("  questo processo prende il turno: " + (mine == null ? "si'" : "no: " + mine));
        String other = runChild(30, "take-turn").trim();
        System.out.println("  un secondo processo Java, nello stesso momento: " + other);
        PackageQueue.release("measure-m2");
        check("M2 misurata: il secondo processo ha risposto", !other.isEmpty());
    }

    // ===================== M2b =====================

    /**
     * Ogni avvio del jar, anche quello che poi si ferma perche' la porta e' occupata, chiama per
     * prima cosa restoreLocksAfterCrash (Main, prima del controllo della porta). Qui un lavoro
     * guidato e' in corso nel pannello (questo processo) e un secondo avvio del jar fa quel primo
     * passo, come farebbe chi apre il menu da console mentre il pannello web lavora.
     */
    static void m2bSecondStartDuringJob() throws Exception {
        System.out.println("\n== M2b. Un secondo avvio del jar mentre il pannello aggiorna ==");
        fresh(25);
        JSONObject pf = UpdateManager.packagePreflight(PKG);
        if (!pf.optBoolean("canProceed")) { check("M2b: il preflight lascia partire (" + firstProblem(pf) + ")", false); return; }
        JSONObject start = UpdateManager.startGuidedUpdate(PKG, pf.optString("signature"));
        String id = start.optString("jobId");
        if (id.isEmpty()) { check("M2b: il lavoro parte (" + start + ")", false); return; }
        if (!waitFor(STARTED, 240)) { check("M2b: il lavoro e' arrivato allo script di installazione", false); return; }
        System.out.println("  il lavoro e' dentro pkg upgrade; elenco su disco: "
                + (PackageQueue.statePresent() ? Files.readString(PackageQueue.list).trim().replace("\n", ",") : "NESSUNO"));
        String second = runChild(180, "restore").trim();
        System.out.println("  il secondo avvio (restoreLocksAfterCrash): " + (second.isEmpty() ? "(niente da fare)" : second.replace("\n", " | ")));
        System.out.println("  elenco su disco dopo il secondo avvio: " + (PackageQueue.statePresent() ? "c'e' ancora" : "CANCELLATO"));
        long deadline = System.currentTimeMillis() + 900_000;
        while (PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = UpdateManager.jobStatus(id).getJSONObject("job");
        System.out.println("  il lavoro del pannello: " + job.optString("status") + " " + job.optString("errorMessage"));
        System.out.println("  " + PKG + " alla fine: " + sh("pkg query '%v locked=%k' " + PKG).trim());

        // Stessa cosa, ma il secondo avvio arriva nella finestra fra lo sblocco e pkg upgrade:
        // si simula con un elenco scritto e il pacchetto sbloccato, come li lascia il lavoro un
        // attimo prima di lanciare pkg.
        fresh(0);
        PackageQueue.take("measure-m2b", "measurement M2b");
        PackageQueue.writeState(List.of(PKG));
        sh("pkg unlock -y " + PKG);
        String second2 = runChild(180, "restore").trim();
        System.out.println("  nella finestra fra sblocco e pkg upgrade, il secondo avvio: " + second2.replace("\n", " | "));
        System.out.println("  " + PKG + " adesso: " + sh("pkg query 'locked=%k' " + PKG).trim()
                + ", elenco su disco: " + (PackageQueue.statePresent() ? "c'e'" : "CANCELLATO"));
        String up = sh("pkg upgrade -y -U " + PKG + " 2>&1; echo rc=$?");
        System.out.println("  il pkg upgrade che il lavoro lancerebbe adesso: " + up.trim().replace("\n", " | "));
        PackageQueue.deleteState();
        PackageQueue.release("measure-m2b");
        check("M2b misurata", true);
        Files.writeString(SLEEP, "0");
    }

    // ===================== M3 =====================

    static void m3ExternalPkgHoldsTheLock() throws Exception {
        System.out.println("\n== M3. Un pkg esterno (da SSH) tiene il lock mentre parte un lavoro del pannello ==");
        fresh(0);
        Files.writeString(SLEEP, "45");
        Files.deleteIfExists(STARTED);
        Files.deleteIfExists(DONE);
        Process external = new ProcessBuilder("sh", "-c", "pkg install -y " + OTHER + " > " + DIR.resolve("external.log") + " 2>&1")
                .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
        if (!waitFor(STARTED, 60)) { check("M3: il pkg esterno e' arrivato al suo script", false); external.destroy(); return; }
        System.out.println("  pkg esterno nel suo script di installazione (tiene il lock del database)");
        long t0 = System.currentTimeMillis();
        JSONObject pf = UpdateManager.packagePreflight(PKG);
        System.out.println("  anteprima dell'aggiornamento guidato in " + (System.currentTimeMillis() - t0) / 1000 + " s: canProceed="
                + pf.optBoolean("canProceed") + " " + firstProblem(pf));
        if (!pf.optBoolean("canProceed")) {
            String all = pf.toString();
            System.out.println("  l'anteprima, per intero (prime righe): " + all.substring(0, Math.min(1500, all.length())));
        }
        JSONObject job = pf.optBoolean("canProceed") ? guidedWith(pf.optString("signature")) : null;
        if (job != null) {
            System.out.println("  il lavoro: " + job.optString("status") + " in " + job.optLong("elapsedSeconds") + " s");
            System.out.println("  errore: " + job.optString("errorMessage"));
            for (String l : job.optString("consoleLog").split("\n"))
                if (l.contains("lock") || l.contains("locked") || l.contains("pkg:")) System.out.println("    | " + l);
        }
        System.out.println("  il pkg esterno era ancora in corso alla fine del lavoro: " + (external.isAlive() ? "si'" : "no"));
        external.waitFor();
        System.out.println("  pkg esterno: uscita " + external.exitValue());
        System.out.println("  " + PKG + " dopo: " + sh("pkg query '%v locked=%k' " + PKG).trim()
                + ", elenco di un lavoro interrotto: " + (PackageQueue.statePresent() ? "SI'" : "no"));
        check("M3 misurata", true);
        Files.writeString(SLEEP, "0");
    }

    // ===================== M4 =====================

    static void m4PanelKilledDuringPkg() throws Exception {
        System.out.println("\n== M4. Il pannello ucciso mentre pkg installa ==");
        fresh(30);
        String cp = System.getProperty("java.class.path");
        Process child = new ProcessBuilder("java", "-De2e.vm=yes", "-cp", cp, UpdaterRobustnessE2ETest.class.getName(), "run-guided")
                .redirectErrorStream(true).redirectOutput(DIR.resolve("child.log").toFile())
                .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
        if (!waitFor(STARTED, 240)) {
            check("M4: il lavoro e' arrivato allo script di installazione", false);
            System.out.println(Files.readString(DIR.resolve("child.log")));
            child.destroyForcibly();
            return;
        }
        String pkgBefore = sh("pgrep -lf 'pkg upgrade' | grep -v pgrep").trim();
        System.out.println("  pkg in corso nel figlio: " + pkgBefore.replace("\n", " | "));
        sh("kill -9 " + child.pid());
        child.waitFor();
        Thread.sleep(2000);
        String pkgAfterKill = sh("pgrep -lf 'pkg upgrade' | grep -v pgrep").trim();
        System.out.println("  subito dopo kill -9 del processo Java: pkg " + (pkgAfterKill.isEmpty() ? "NON c'e' piu'" : "c'e' ancora: " + pkgAfterKill));
        System.out.println("  elenco del lavoro interrotto: " + (PackageQueue.statePresent() ? "c'e' (" + Files.readString(PackageQueue.list).trim().replace("\n", ",") + ")" : "NO"));
        System.out.println("  " + PKG + " protetto: " + (locked().contains(PKG) ? "si'" : "NO"));
        String restore1 = runChild(120, "restore").trim();
        System.out.println("  il riavvio del pannello (restoreLocksAfterCrash) adesso: " + restore1.replace("\n", " | "));
        boolean done = waitFor(DONE, 90);
        Thread.sleep(3000);
        System.out.println("  lo script di installazione e' arrivato in fondo: " + (done ? "si'" : "NO"));
        System.out.println("  pkg alla fine: " + (sh("pgrep -lf 'pkg upgrade' | grep -v pgrep").trim().isEmpty() ? "finito" : "ancora in corso"));
        System.out.println("  " + PKG + " alla fine: " + sh("pkg query '%v locked=%k' " + PKG).trim()
                + ", file installato: " + sh("cat /usr/local/share/robust-probe/version 2>&1").trim()
                + ", pkg check: " + sh("pkg check -s " + PKG + " 2>&1; echo rc=$?").trim().replace("\n", " "));
        System.out.println("  elenco del lavoro interrotto: " + (PackageQueue.statePresent() ? "c'e' ancora" : "tolto"));
        String restore2 = runChild(120, "restore").trim();
        System.out.println("  un secondo riavvio del pannello: " + restore2.replace("\n", " | "));
        System.out.println("  " + PKG + " dopo il secondo: " + sh("pkg query '%v locked=%k' " + PKG).trim());
        System.out.println("  il log del figlio (ultime righe):");
        List<String> lines = Files.readAllLines(DIR.resolve("child.log"));
        for (String l : lines.subList(Math.max(0, lines.size() - 12), lines.size())) System.out.println("    | " + l);
        check("M4 misurata", true);
        Files.writeString(SLEEP, "0");
    }

    // ===================== M5 =====================

    static void m5Timeout() throws Exception {
        System.out.println("\n== M5. Il timeout di runLogged durante un pkg ==");
        sh("pkg delete -y " + OTHER + " >/dev/null 2>&1");
        Files.writeString(SLEEP, "40");
        Files.deleteIfExists(STARTED);
        Files.deleteIfExists(DONE);
        UpdateManager.Job job = new UpdateManager.Job("measure-m5", "measure");
        long t0 = System.currentTimeMillis();
        String outcome;
        try {
            outcome = "codice " + UpdateManager.runLogged(job, "pkg install -y " + OTHER + " 2>&1", 10);
        } catch (Exception e) {
            // Misurato al primo giro: allo scadere non torna un codice, esce un'eccezione.
            outcome = "ECCEZIONE " + e;
        }
        long took = (System.currentTimeMillis() - t0) / 1000;
        String pkgNow = sh("pgrep -lf 'pkg install' | grep -v pgrep").trim();
        System.out.println("  runLogged con timeout 10 s e uno script da 40 s: tornato dopo " + took + " s, " + outcome);
        System.out.println("  pkg subito dopo: " + (pkgNow.isEmpty() ? "non c'e' piu'" : "c'e' ancora: " + pkgNow));
        boolean done = waitFor(DONE, 60);
        Thread.sleep(3000);
        System.out.println("  lo script di installazione e' arrivato in fondo: " + (done ? "si'" : "NO"));
        System.out.println("  " + OTHER + " registrato da pkg: " + sh("pkg query %v " + OTHER + " 2>&1").trim()
                + ", il suo file: " + sh("ls /usr/local/share/" + OTHER + "/ 2>&1").trim());
        System.out.println("  pkg check -s: " + sh("pkg check -s " + OTHER + " 2>&1; echo rc=$?").trim().replace("\n", " "));
        System.out.println("  il log del lavoro: " + job.toJson().optString("consoleLog").replace("\n", " | "));
        check("M5 misurata", true);
        Files.writeString(SLEEP, "0");
    }

    // ===================== M6 =====================

    /**
     * Dopo M4 un pacchetto dello stack puo' restare sbloccato fino al riavvio successivo, con
     * l'elenco del lavoro interrotto su disco. Il rapporto periodico e' l'unico canale che
     * raggiunge chi non apre il pannello: lo dice?
     */
    static void m6ReportAfterInterruption() throws Exception {
        System.out.println("\n== M6. Il rapporto dopo un lavoro interrotto ==");
        fresh(0);
        PackageQueue.writeState(List.of(PKG));
        sh("pkg unlock -y " + PKG);
        JSONObject d = UpdateManager.reportData(false);
        var toDo = d.optJSONArray("toDo");
        System.out.println("  " + PKG + " sbloccato, elenco del lavoro interrotto su disco; le cose da fare del rapporto:");
        boolean mentions = false;
        for (int i = 0; toDo != null && i < toDo.length(); i++) {
            String what = toDo.getJSONObject(i).optString("what");
            System.out.println("    - " + what);
            if (what.contains(PKG) || what.toLowerCase().contains("interrott") || what.toLowerCase().contains("interrupted")
                    || what.toLowerCase().contains("unlocked") || what.toLowerCase().contains("sbloccat")) mentions = true;
        }
        System.out.println("  il rapporto parla del pacchetto sbloccato o del lavoro interrotto: " + (mentions ? "si'" : "NO"));
        System.out.println("  conti del rapporto: protetti " + d.optInt("lockedPackageCount") + " su " + d.optInt("totalPackages"));
        PackageQueue.deleteState();
        sh("pkg lock -y " + PKG);
        check("M6 misurata", true);
    }

    // ===================== M7 =====================

    /** Dove M7 tiene cio' che serve dopo il riavvio: /var/tmp sta fuori dai boot environment. */
    static final Path M7 = Path.of("/var/tmp/um-probe-m7");

    /**
     * M7, prima parte: un aggiornamento guidato con lo script di installazione lungo, e la macchina
     * che si spegne di colpo mentre pkg installa (reboot -nq: niente script di spegnimento, niente
     * sync, come una mancanza di corrente). Chi la lancia aspetta "M7 IN PKG" e poi fa il riavvio.
     * La seconda parte (dopo il riavvio) e' il modo "m7-after".
     */
    static void m7Before() throws Exception {
        Files.createDirectories(M7);
        Files.writeString(M7.resolve("packages-before"), sh("pkg query %n-%v | sort | sha256"));
        Files.writeString(M7.resolve("locked-before"), String.join("\n", locked()));
        Files.writeString(M7.resolve("boot-environments-before"), sh("bectl list -H | cut -f1 | sort"));
        cleanup();
        work = Files.createDirectories(M7.resolve("work"));
        Files.createDirectories(DIR);
        build(PKG, "1.0", false);
        build(PKG, "1.1", true);
        Path repo = work.resolve("repo");
        sh("mkdir -p " + repo + " && cp " + work.resolve("pkgs/" + PKG + "-1.1.pkg") + " " + repo + " && pkg repo " + repo + " >/dev/null 2>&1");
        if (!Files.isDirectory(Path.of(REPO_CONF).getParent())) {
            Files.createDirectories(Path.of(REPO_CONF).getParent());
            Files.writeString(M7.resolve("created-repos-dir"), "yes");
        }
        Files.writeString(Path.of(REPO_CONF),
                "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n"
              + "robustprobe: { url: \"file://" + repo + "\", signature_type: \"none\", enabled: yes }\n");
        sh("pkg update -f -r robustprobe >/dev/null 2>&1");
        fresh(120);
        Thread t = new Thread(() -> {
            try { while (!Files.exists(STARTED)) Thread.sleep(200); System.out.println("M7 IN PKG"); System.out.flush(); }
            catch (InterruptedException ignored) { }
        });
        t.setDaemon(true);
        t.start();
        JSONObject job = guided();
        System.out.println("M7: the job ended before the reboot: " + job);
    }

    /** M7, seconda parte: cosa ha trovato il pannello all'avvio, com'e' pkg, e poi la pulizia. */
    static void m7After() throws Exception {
        System.out.println("== M7. Dopo un riavvio brusco durante pkg upgrade ==");
        System.out.println("  uptime: " + sh("uptime").trim());
        System.out.println("  il pannello all'avvio (panel.log): " + sh("grep -A3 'Interrupted maintenance detected' /var/db/mailpanel/panel.log | tail -4").trim().replace("\n", " | "));
        System.out.println("  elenco del lavoro interrotto: " + (PackageQueue.statePresent() ? "c'e' ancora" : "non c'e'"));
        System.out.println("  " + PKG + ": " + sh("pkg query '%v locked=%k' " + PKG + " 2>&1").trim()
                + ", file: " + sh("cat /usr/local/share/robust-probe/version 2>&1").trim());
        System.out.println("  pkg check -s " + PKG + ": " + sh("pkg check -s " + PKG + " 2>&1; echo rc=$?").trim().replace("\n", " "));
        System.out.println("  pkg check -d (dipendenze di tutto): " + sh("pkg check -d -a -n 2>&1 | tail -3; echo rc=$?").trim().replace("\n", " "));
        System.out.println("  lo script di installazione era arrivato in fondo: " + (Files.exists(DONE) ? "si'" : "NO"));
        System.out.println("  sqlite del database di pkg: " + sh("sqlite3 /var/db/pkg/local.sqlite 'pragma integrity_check' 2>&1").trim());
        // la pulizia
        cleanup();
        sh("rm -f " + REPO_CONF + "; rm -rf /var/db/pkg/repos/robustprobe " + DIR);
        if (Files.exists(M7.resolve("created-repos-dir"))) sh("rmdir " + Path.of(REPO_CONF).getParent());
        UpdateManager.refreshLockTrace();
        check("M7 alla fine: gli stessi pacchetti di prima",
                sh("pkg query %n-%v | sort | sha256").equals(Files.readString(M7.resolve("packages-before"))));
        check("M7 alla fine: gli stessi pacchetti protetti",
                String.join("\n", locked()).equals(Files.readString(M7.resolve("locked-before"))));
        check("M7 alla fine: FreeBSD-ports di nuovo acceso",
                sh("pkg -vv 2>/dev/null | grep -A3 '^  FreeBSD-ports: {' | grep -c 'enabled *: yes'").trim().equals("1"));
        sh("rm -rf " + M7);
    }

    // ===================== i figli =====================

    static void child(String[] args) throws Exception {
        switch (args[0]) {
            case "take-turn" -> {
                String r = PackageQueue.take("measure-m2-child", "measurement M2, second process");
                System.out.println(r == null ? "HA PRESO IL TURNO anche lui" : "turno rifiutato: " + r);
            }
            case "run-guided" -> {
                JSONObject job = guided();
                System.out.println("child finished: " + (job == null ? "null" : job.optString("status")));
            }
            case "restore" -> System.out.println(UpdateManager.restoreLocksAfterCrash());
            case "m7-after" -> m7After();
            default -> throw new IllegalArgumentException(args[0]);
        }
    }

    // ===================== attrezzi =====================

    /** nginx-robust-probe 1.0 installato e protetto, nel catalogo la 1.1, con lo script che dorme 'seconds'. */
    static void fresh(int seconds) throws Exception {
        sh("pkg unlock -y " + PKG + " >/dev/null 2>&1; pkg delete -y " + PKG + " >/dev/null 2>&1");
        sh("pkg add " + work.resolve("pkgs/" + PKG + "-1.0.pkg") + " >/dev/null 2>&1");
        sh("pkg lock -y " + PKG);
        Files.writeString(SLEEP, String.valueOf(seconds));
        Files.deleteIfExists(STARTED);
        Files.deleteIfExists(DONE);
    }

    static JSONObject guided() throws Exception {
        JSONObject pf = UpdateManager.packagePreflight(PKG);
        if (!pf.optBoolean("canProceed")) {
            check("il preflight lascia partire (" + firstProblem(pf) + ")", false);
            return null;
        }
        return guidedWith(pf.optString("signature"));
    }

    static JSONObject guidedWith(String signature) throws Exception {
        JSONObject start = UpdateManager.startGuidedUpdate(PKG, signature);
        String id = start.optString("jobId");
        if (id.isEmpty()) { System.out.println("  il lavoro non parte: " + start); return start; }
        System.out.println("  lavoro " + id + " partito");
        long deadline = System.currentTimeMillis() + 900_000;
        while (PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        return UpdateManager.jobStatus(id).getJSONObject("job");
    }

    static String firstProblem(JSONObject pf) {
        var checks = pf.optJSONArray("checks");
        for (int i = 0; checks != null && i < checks.length(); i++) {
            JSONObject c = checks.optJSONObject(i);
            if (c != null && !c.optBoolean("ok", true)) return c.toString();
        }
        return pf.optString("error", "");
    }

    /** Un pacchetto finto: un file con la versione, e uno script di installazione che puo' dormire. */
    static void build(String name, String version, boolean slow) throws Exception {
        String share = name.equals(PKG) ? "robust-probe" : OTHER;
        Path root = work.resolve("root-" + name + "-" + version);
        Path d = Files.createDirectories(root.resolve("usr/local/share/" + share));
        Files.writeString(d.resolve("version"), version + "\n");
        String post = slow
                ? "touch " + STARTED + "\necho \"post-install: sleeping $(cat " + SLEEP + " 2>/dev/null || echo 0) s\"\n"
                  + "sleep $(cat " + SLEEP + " 2>/dev/null || echo 0)\necho 'post-install: done'\ntouch " + DONE + "\nexit 0\n"
                : "exit 0\n";
        Path manifest = work.resolve("manifest-" + name + "-" + version);
        Files.writeString(manifest, "name: " + name + "\nversion: \"" + version + "\"\norigin: misc/" + name
                + "\ncomment: \"updater measurement\"\ndesc: \"updater measurement\"\nmaintainer: root@localhost\n"
                + "www: https://localhost/\nprefix: /usr/local\nscripts: {\n  post-install: <<EOD\n" + post + "EOD\n}\n");
        Path plist = work.resolve("plist-" + name + "-" + version);
        Files.writeString(plist, "/usr/local/share/" + share + "/version\n");
        Files.createDirectories(work.resolve("pkgs"));
        String out = sh("pkg create -M " + manifest + " -r " + root + " -p " + plist + " -o " + work.resolve("pkgs") + " 2>&1");
        if (!Files.exists(work.resolve("pkgs/" + name + "-" + version + ".pkg")))
            throw new IllegalStateException("pkg create " + name + " " + version + ": " + out);
    }

    static void cleanup() {
        sh("pkill -f 'pkg (install|upgrade).*robust-probe' ; sleep 1; "
         + "pkg unlock -y " + PKG + " >/dev/null 2>&1; pkg delete -y " + PKG + " " + OTHER + " >/dev/null 2>&1; "
         + "rm -rf /usr/local/share/robust-probe /usr/local/share/" + OTHER + "; true");
        PackageQueue.deleteState();
    }

    static String runChild(int seconds, String mode) throws Exception {
        String cp = System.getProperty("java.class.path");
        Process p = new ProcessBuilder("java", "-De2e.vm=yes", "-cp", cp, UpdaterRobustnessE2ETest.class.getName(), mode)
                .redirectErrorStream(true).redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
        StringBuilder out = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String l;
            while ((l = r.readLine()) != null) if (!l.startsWith("WARNING") && !l.contains("java.util.logging")) out.append(l).append('\n');
        }
        p.waitFor(seconds, java.util.concurrent.TimeUnit.SECONDS);
        return out.toString();
    }

    static boolean waitFor(Path f, int seconds) throws Exception {
        for (int i = 0; i < seconds * 2; i++) { if (Files.exists(f)) return true; Thread.sleep(500); }
        return false;
    }

    static Set<String> locked() {
        Set<String> r = new TreeSet<>();
        for (String l : sh("pkg lock -l 2>/dev/null").split("\n"))
            if (!l.trim().isEmpty() && !l.trim().endsWith(":")) r.add(l.trim().replaceAll("-[^-]+$", ""));
        return r;
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(600), cmd).output();
    }

    static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
