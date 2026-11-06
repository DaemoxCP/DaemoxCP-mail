package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
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
 * I bordi dell'aggiornamento dei pacchetti, con lavori veri su pacchetti finti.
 *
 * Il 06/11/2026 questa prova misurava soltanto (reperti 146-148): dove l'aggiornamento si rompe.
 * Il committente ha scelto di correggere i primi quattro punti, e adesso ogni misura controlla il
 * comportamento giusto, e continua a stampare cosa succede:
 *
 *   M1  la via di ritorno: un boot environment prima di ogni lavoro, tolto se non e' cambiato
 *       niente, i piu' vecchi potati, e l'avviso se posta e database ci stanno dentro
 *   M2  il turno vale fra processi: un secondo processo Java non lo prende
 *   M2b un secondo avvio del jar mentre il pannello aggiorna non tocca il lavoro in corso
 *   M3  un pkg esterno (da SSH) che tiene il lock: il lavoro del pannello si rifiuta
 *   M4  il pannello ucciso mentre pkg installa: al riavvio riprotegge appena pkg ha finito, senza
 *       aspettare il riavvio successivo, e lascia l'avviso
 *   M5  il timeout: un pkg non si uccide a meta' (si avvisa e si aspetta); un altro comando si
 *       ferma con tutti i suoi figli; mai un'eccezione al posto del codice d'uscita
 *   M6  il rapporto periodico dice i pacchetti senza protezione e il lavoro interrotto
 *   M7  la macchina che si spegne di colpo durante pkg upgrade (-Dmeasure=m7, poi il modo m7-after)
 *
 * Tocca il sistema: installa e toglie pacchetti finti, crea e toglie boot environment, spegne i
 * repository veri per la durata, sblocca e riprotegge. Solo su una macchina di prova, da root, con
 * -De2e.vm=yes:
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.UpdaterRobustnessE2ETest
 * Con -Dmeasure=m1,m4 solo quelle. Alla fine controlla che pacchetti, protezioni, repository e boot
 * environment siano quelli di prima.
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
    private static String noticeBefore;

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
        String bootEnvironmentsBefore = bootEnvironments();
        noticeBefore = Files.exists(PackageRecovery.notice) ? Files.readString(PackageRecovery.notice) : null;
        cleanup();
        work = Files.createTempDirectory(Path.of("/var/tmp"), "robust-probe");
        Files.createDirectories(DIR);
        try {
            setUp();
            Set<String> only = new TreeSet<>(List.of(System.getProperty("measure", "all").split(",")));
            java.util.function.Predicate<String> on = m -> only.contains("all") || only.contains(m);
            if (on.test("m1")) m1WayBack(bootEnvironmentsBefore);
            if (on.test("m2")) m2TurnAcrossProcesses();
            if (on.test("m2b")) m2bSecondStartDuringJob();
            if (on.test("m3")) m3ExternalPkgHoldsTheLock();
            if (on.test("m4")) m4PanelKilledDuringPkg();
            if (on.test("m5")) m5Timeout();
            if (on.test("m6")) m6Report();
        } finally {
            cleanup();
            sh("rm -f " + REPO_CONF + "; rm -rf /var/db/pkg/repos/robustprobe " + work + " " + DIR);
            if (createdReposDir) sh("rmdir " + Path.of(REPO_CONF).getParent());
            removeOwnBootEnvironments(bootEnvironmentsBefore);
            restoreNotice();
            UpdateManager.refreshLockTrace();
            check("alla fine: gli stessi pacchetti di prima", sh("pkg query %n-%v | sort | sha256").equals(packagesBefore));
            check("alla fine: gli stessi pacchetti protetti", locked().equals(lockedBefore));
            check("alla fine: nessun elenco di un lavoro interrotto", !PackageQueue.statePresent());
            check("alla fine: FreeBSD-ports di nuovo acceso",
                    sh("pkg -vv 2>/dev/null | grep -A3 '^  FreeBSD-ports: {' | grep -c 'enabled *: yes'").trim().equals("1"));
            check("alla fine: gli stessi boot environment", bootEnvironments().equals(bootEnvironmentsBefore));
        }
        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    static void setUp() throws Exception {
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
    }

    // ===================== M1 =====================

    static void m1WayBack(String bootEnvironmentsBefore) throws Exception {
        System.out.println("\n== M1. La via di ritorno ==");
        fresh(0);
        JSONObject job = guided();
        if (job == null) return;
        String log = job.optString("consoleLog");
        List<String> created = newOwn(bootEnvironmentsBefore);
        System.out.println("  esito: " + job.optString("status") + ", versione " + sh("pkg query %v " + PKG).trim());
        System.out.println("  boot environment nuovi: " + created);
        for (String l : log.split("\n")) if (l.contains("packages-before-") || l.contains("bectl")) System.out.println("    | " + l);
        check("M1 il lavoro riesce", "completed".equals(job.optString("status")));
        check("M1 un boot environment nuovo, del guidato", created.size() == 1 && created.get(0).endsWith("-guided-update"));
        check("M1 il log dice come tornare indietro", !created.isEmpty() && log.contains("bectl activate " + created.get(0)));
        List<String> inside = PackageWayBack.dataInside();
        System.out.println("  dati dentro il boot environment: " + inside);
        check("M1 il log avverte quando posta o database stanno dentro il boot environment",
                inside.isEmpty() || log.contains(String.join(", ", inside)));

        // Un lavoro che non cambia nessun pacchetto: il boot environment non serve e si toglie.
        String before = bootEnvironments();
        UpdateManager.Job j = new UpdateManager.Job("measure-m1-noop", "measure");
        UpdateManager.withWayBack(j, "noop-test", () -> j.write("nothing to do")).run();
        String noopLog = j.toJson().optString("consoleLog");
        System.out.println("  un lavoro senza cambiamenti: " + noopLog.replace("\n", " | "));
        check("M1 un lavoro senza cambiamenti non lascia il suo boot environment", bootEnvironments().equals(before)
                && noopLog.contains("packages-before-"));

        // La potatura: se ne tengono gli ultimi tre, mai uno in uso, e gli snapshot d'origine vanno via.
        String snapshotsBefore = sh("zfs list -H -t snapshot -o name | sort");
        List<String> old = new ArrayList<>();
        for (int i = 1; i <= 4; i++) {
            String n = "packages-before-2000-01-0" + i + "-000000-prune-test";
            sh("bectl create " + n);
            old.add(n);
        }
        StringBuilder pl = new StringBuilder();
        PackageWayBack.prune(l -> pl.append(l).append(" | "), PackageWayBack.KEEP);
        String now = bootEnvironments();
        System.out.println("  potatura: " + pl);
        // Con il boot environment di M1 (piu' recente) gli ultimi tre sono: M1, 04, 03.
        check("M1 la potatura toglie i piu' vecchi e tiene gli ultimi tre",
                !now.contains(old.get(0)) && !now.contains(old.get(1)) && now.contains(old.get(3)) && now.contains(old.get(2))
                && !created.isEmpty() && now.contains(created.get(0)));
        for (String n : old) if (now.contains(n)) PackageWayBack.destroy(n);
        check("M1 gli snapshot d'origine dei boot environment tolti vanno via", sh("zfs list -H -t snapshot -o name | sort")
                .lines().filter(x -> !snapshotsBefore.contains(x)).filter(x -> !created.isEmpty() && !x.isEmpty()).count() <= 1);
    }

    // ===================== M2 =====================

    static void m2TurnAcrossProcesses() throws Exception {
        System.out.println("\n== M2. Il turno, con due processi ==");
        String mine = PackageQueue.take("measure-m2", "measurement M2");
        String other = runChild(60, "take-turn").trim();
        PackageQueue.release("measure-m2");
        String afterRelease = runChild(60, "take-turn").trim();
        System.out.println("  questo processo: " + (mine == null ? "preso" : mine));
        System.out.println("  un secondo processo, nello stesso momento: " + other);
        System.out.println("  un secondo processo, dopo il rilascio: " + afterRelease);
        check("M2 il secondo processo NON prende il turno mentre lo tiene il primo", mine == null && other.startsWith("RIFIUTATO"));
        check("M2 e lo prende appena il primo lo rilascia", afterRelease.startsWith("PRESO"));
    }

    // ===================== M2b =====================

    static void m2bSecondStartDuringJob() throws Exception {
        System.out.println("\n== M2b. Un secondo avvio del jar mentre il pannello aggiorna ==");
        // Durante pkg upgrade.
        fresh(25);
        JSONObject pf = UpdateManager.packagePreflight(PKG);
        if (!pf.optBoolean("canProceed")) { check("M2b: il preflight lascia partire (" + firstProblem(pf) + ")", false); return; }
        JSONObject start = UpdateManager.startGuidedUpdate(PKG, pf.optString("signature"));
        String id = start.optString("jobId");
        if (id.isEmpty() || !waitFor(STARTED, 240)) { check("M2b: il lavoro arriva allo script di installazione (" + start + ")", false); return; }
        String second = runChild(180, "restore").trim();
        System.out.println("  il secondo avvio durante pkg upgrade: " + second.replace("\n", " | "));
        check("M2b durante pkg: il secondo avvio non tocca l'elenco", PackageQueue.statePresent() && second.contains("another panel process"));
        JSONObject job = waitJob(id);
        System.out.println("  il lavoro: " + job.optString("status") + " " + job.optString("errorMessage"));
        check("M2b durante pkg: il lavoro finisce bene e riprotegge", "completed".equals(job.optString("status"))
                && sh("pkg query 'locked=%k' " + PKG).trim().equals("locked=1"));

        // Nella finestra fra lo sblocco e pkg upgrade: questo processo tiene il turno, come il lavoro.
        fresh(0);
        PackageQueue.take("measure-m2b", "measurement M2b");
        PackageQueue.writeState(List.of(PKG));
        sh("pkg unlock -y " + PKG);
        String second2 = runChild(180, "restore").trim();
        System.out.println("  il secondo avvio nella finestra: " + second2.replace("\n", " | "));
        check("M2b nella finestra: il secondo avvio non riprotegge e non cancella l'elenco",
                PackageQueue.statePresent() && sh("pkg query 'locked=%k' " + PKG).trim().equals("locked=0"));
        String up = sh("pkg upgrade -y -U " + PKG + " 2>&1; echo rc=$?");
        System.out.println("  il pkg upgrade del lavoro, dopo: " + up.trim().replace("\n", " | "));
        check("M2b nella finestra: il pkg upgrade del lavoro funziona", up.contains("rc=0") && sh("pkg query %v " + PKG).trim().equals("1.1"));
        sh("pkg lock -y " + PKG);
        PackageQueue.deleteState();
        PackageQueue.release("measure-m2b");
        Files.writeString(SLEEP, "0");
        Files.deleteIfExists(PackageRecovery.notice);
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
        JSONObject pf = UpdateManager.packagePreflight(PKG);
        System.out.println("  anteprima del guidato col pkg esterno al lavoro: canProceed=" + pf.optBoolean("canProceed"));
        external.waitFor();
        check("M3 il lavoro del pannello non parte e non tocca niente", !pf.optBoolean("canProceed")
                && sh("pkg query '%v locked=%k' " + PKG).trim().equals("1.0 locked=1") && !PackageQueue.statePresent());
        Files.writeString(SLEEP, "0");
    }

    // ===================== M4 =====================

    static void m4PanelKilledDuringPkg() throws Exception {
        System.out.println("\n== M4. Il pannello ucciso mentre pkg installa ==");
        fresh(40);
        Files.deleteIfExists(PackageRecovery.notice);
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
        sh("kill -9 " + child.pid());
        child.waitFor();
        Thread.sleep(2000);
        System.out.println("  dopo kill -9 del pannello: pkg " + (sh("pgrep -lf 'pkg upgrade' | grep -v pgrep").trim().isEmpty() ? "finito" : "ancora al lavoro")
                + ", " + PKG + " protetto: " + (locked().contains(PKG) ? "si'" : "no"));
        // Il pannello riparte e resta acceso: il figlio fa il ripristino d'avvio e aspetta.
        String restart = runChild(200, "restore-and-stay", "150").trim();
        System.out.println("  il pannello riavviato (e rimasto acceso): " + restart.replace("\n", " | "));
        JSONObject n = PackageRecovery.notice();
        System.out.println("  " + PKG + " alla fine: " + sh("pkg query '%v locked=%k' " + PKG).trim()
                + ", elenco: " + (PackageQueue.statePresent() ? "c'e' ancora" : "tolto"));
        System.out.println("  l'avviso: " + n);
        check("M4 il riavvio dice che pkg sta ancora lavorando e che riprova", restart.contains("retrying every"));
        check("M4 riprotetto appena pkg ha finito, senza un altro riavvio",
                sh("pkg query '%v locked=%k' " + PKG).trim().equals("1.1 locked=1") && !PackageQueue.statePresent()
                && restart.contains("PROTECTED AGAIN IN THE BACKGROUND"));
        check("M4 l'avviso dice quale lavoro, che pkg lavorava, e quando e' stato riprotetto",
                n.optString("description").contains(PKG) && !n.optString("pkgWasRunning").isEmpty() && n.has("relockedUtc"));
        Files.writeString(SLEEP, "0");
        Files.deleteIfExists(PackageRecovery.notice);
    }

    // ===================== M5 =====================

    static void m5Timeout() throws Exception {
        System.out.println("\n== M5. Il timeout di runLogged ==");
        sh("pkg delete -y " + OTHER + " >/dev/null 2>&1");
        Files.writeString(SLEEP, "40");
        Files.deleteIfExists(STARTED);
        Files.deleteIfExists(DONE);
        UpdateManager.Job job = new UpdateManager.Job("measure-m5", "measure");
        long t0 = System.currentTimeMillis();
        String outcome;
        int code = Integer.MIN_VALUE;
        try { code = UpdateManager.runLogged(job, "pkg install -y " + OTHER + " 2>&1", 10); outcome = "codice " + code; }
        catch (Exception e) { outcome = "ECCEZIONE " + e; }
        long took = (System.currentTimeMillis() - t0) / 1000;
        String log = job.toJson().optString("consoleLog");
        System.out.println("  pkg install con timeout 10 s e uno script da 40 s: tornato dopo " + took + " s, " + outcome);
        for (String l : log.split("\n")) if (l.contains("pkg") && (l.contains("minut") || l.contains("TIMEOUT"))) System.out.println("    | " + l);
        check("M5 pkg: torna con il codice d'uscita di pkg, nessuna eccezione", code == 0);
        check("M5 pkg: non ucciso, arriva in fondo al suo script", Files.exists(DONE) && took >= 38
                && sh("pkg check -s " + OTHER + " >/dev/null 2>&1; echo $?").trim().equals("0"));
        check("M5 pkg: il log dice che aspetta, non che lo termina",
                log.contains(I18n.tr("server.um.runLogged.pkgStillRunning", java.util.Map.of("cmd", "pkg", "minutes", "1")).substring(0, 12))
                && !log.contains("TIMEOUT"));
        Files.writeString(SLEEP, "0");

        // Un comando che non e' pkg: allo scadere si ferma, con tutti i suoi figli.
        UpdateManager.Job j2 = new UpdateManager.Job("measure-m5b", "measure");
        t0 = System.currentTimeMillis();
        int c2 = Integer.MIN_VALUE;
        String o2;
        try { c2 = UpdateManager.runLogged(j2, "sleep 61 & sleep 62; wait", 3); o2 = "codice " + c2; }
        catch (Exception e) { o2 = "ECCEZIONE " + e; }
        long took2 = (System.currentTimeMillis() - t0) / 1000;
        String left = sh("pgrep -lf 'sleep 6[12]$'").trim();
        System.out.println("  sleep 61 & sleep 62 con timeout 3 s: tornato dopo " + took2 + " s, " + o2 + ", rimasti: " + (left.isEmpty() ? "nessuno" : left));
        check("M5 altro comando: fermato allo scadere con 124, senza eccezione", c2 == UpdateManager.TIMED_OUT && took2 < 20);
        check("M5 altro comando: nessun figlio rimasto in vita", left.isEmpty());
        sh("pkill -f 'sleep 6[12]$'");

        // Un processo lasciato andare dal comando, fuori dall'albero, che tiene aperta l'uscita:
        // il timeout vale lo stesso.
        UpdateManager.Job j3 = new UpdateManager.Job("measure-m5c", "measure");
        t0 = System.currentTimeMillis();
        int c3 = Integer.MIN_VALUE;
        String o3;
        try { c3 = UpdateManager.runLogged(j3, "(sleep 71 &) ; sleep 63", 3); o3 = "codice " + c3; }
        catch (Exception e) { o3 = "ECCEZIONE " + e; }
        long took3 = (System.currentTimeMillis() - t0) / 1000;
        System.out.println("  (sleep 71 &); sleep 63 con timeout 3 s: tornato dopo " + took3 + " s, " + o3);
        check("M5 un processo staccato che tiene l'uscita non scavalca il timeout", c3 == UpdateManager.TIMED_OUT && took3 < 30);
        // Un comando che FINISCE con un processo staccato ancora vivo non e' un problema: misurato
        // sulla VM, la JVM chiude da sola la pipe quando il processo esce, con la lettura nel
        // thread principale come in quello a parte. Il margine di OUTPUT_GRACE_SECONDS resta come
        // difesa, ma non ha un caso che lo faccia scattare, e qui non si conta.
        sh("pkill -f 'sleep 7[12]$'");

        // La tabella: cosa non si ferma mai.
        check("M5 la tabella dei comandi da non fermare", UpdateManager.mustNotBeKilled("pkg upgrade -y -U 2>&1")
                && UpdateManager.mustNotBeKilled("pkg install -f -y dovecot 2>&1")
                && UpdateManager.mustNotBeKilled("pkg autoremove -y 2>&1")
                && UpdateManager.mustNotBeKilled("freebsd-update install 2>&1")
                && !UpdateManager.mustNotBeKilled("pkg upgrade -F -y -U 2>&1")
                && !UpdateManager.mustNotBeKilled("pkg upgrade -n 2>&1")
                && !UpdateManager.mustNotBeKilled("freebsd-update --not-running-from-cron fetch 2>&1")
                && !UpdateManager.mustNotBeKilled("cp -Rp /var/db/mysql /x"));
    }

    // ===================== M6 =====================

    static void m6Report() throws Exception {
        System.out.println("\n== M6. Il rapporto ==");
        fresh(0);
        // Un lavoro interrotto con il pacchetto ancora sbloccato, e l'avviso.
        PackageQueue.take("measure-m6", "Guided update of " + PKG);
        PackageQueue.writeState(List.of(PKG));
        PackageQueue.release("measure-m6");
        sh("pkg unlock -y " + PKG);
        PackageRecovery.recordInterruption(PackageQueue.jobRecord(), List.of(PKG), List.of(PKG), "");
        JSONArray toDo = UpdateManager.reportData(false).optJSONArray("toDo");
        List<String> whats = new ArrayList<>();
        for (int i = 0; toDo != null && i < toDo.length(); i++) whats.add(toDo.getJSONObject(i).optInt("urgency") + " " + toDo.getJSONObject(i).optString("what"));
        whats.forEach(w -> System.out.println("    - " + w));
        check("M6 il rapporto dice, con urgenza 0, i pacchetti ancora senza protezione",
                whats.stream().anyMatch(w -> w.startsWith("0 ") && w.contains(PKG) && w.contains("pkg lock -y")));
        check("M6 il rapporto dice quale lavoro si e' interrotto e cosa controllare",
                whats.stream().anyMatch(w -> w.startsWith("1 ") && w.contains("Guided update of " + PKG) && w.contains("pkg check -s")));
        JSONObject st = PackageRecovery.status();
        check("M6 la pagina riceve l'avviso e i pacchetti senza protezione",
                st.optJSONObject("notice") != null && st.optJSONArray("stillUnprotected") != null
                && st.getJSONArray("stillUnprotected").toList().contains(PKG));
        check("M6 l'avviso non si chiude finche' i pacchetti sono senza protezione", !PackageRecovery.dismiss().optBoolean("success"));
        PackageQueue.deleteState();
        // Senza elenco, ma con un pacchetto dello stack sbloccato fuori dal pannello.
        toDo = UpdateManager.reportData(false).optJSONArray("toDo");
        boolean loose = false;
        for (int i = 0; toDo != null && i < toDo.length(); i++) if (toDo.getJSONObject(i).optString("what").contains(PKG)) loose = true;
        check("M6 un pacchetto dello stack sbloccato fuori dal pannello e' nel rapporto", loose);
        check("M6 l'avviso si chiude dopo aver controllato", PackageRecovery.dismiss().optBoolean("success") && PackageRecovery.notice().isEmpty());
        sh("pkg lock -y " + PKG);
    }

    // ===================== M7 =====================

    /** Dove M7 tiene cio' che serve dopo il riavvio: /var/tmp sta fuori dai boot environment. */
    static final Path M7 = Path.of("/var/tmp/um-probe-m7");

    /**
     * M7, prima parte: un aggiornamento guidato con lo script di installazione lungo, e la macchina
     * che si spegne di colpo mentre pkg installa (reboot -nq: niente script di spegnimento, niente
     * sync, come una mancanza di corrente). Chi la lancia aspetta "M7 IN PKG" e poi fa il riavvio.
     * La seconda parte (dopo il riavvio, e dopo che il pannello e' ripartito) e' il modo "m7-after".
     */
    static void m7Before() throws Exception {
        Files.createDirectories(M7);
        Files.writeString(M7.resolve("packages-before"), sh("pkg query %n-%v | sort | sha256"));
        Files.writeString(M7.resolve("locked-before"), String.join("\n", locked()));
        Files.writeString(M7.resolve("boot-environments-before"), bootEnvironments());
        cleanup();
        Files.deleteIfExists(PackageRecovery.notice);
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

    /** M7, seconda parte: cosa ha trovato il pannello all'avvio, cosa dicono pagina e rapporto, e la pulizia. */
    static void m7After() throws Exception {
        System.out.println("== M7. Dopo un riavvio brusco durante pkg upgrade ==");
        JSONObject n = PackageRecovery.notice();
        System.out.println("  l'avviso lasciato dal pannello all'avvio: " + n);
        System.out.println("  " + PKG + ": " + sh("pkg query '%v locked=%k' " + PKG + " 2>&1").trim()
                + ", script di installazione arrivato in fondo: " + (Files.exists(DONE) ? "si'" : "NO"));
        check("M7 riprotetto all'avvio, elenco chiuso", sh("pkg query 'locked=%k' " + PKG).trim().equals("locked=1") && !PackageQueue.statePresent());
        check("M7 l'avviso dice quale lavoro si e' interrotto, ed e' riprotetto", n.optString("description").contains(PKG) && n.has("relockedUtc"));
        JSONArray toDo = UpdateManager.reportData(false).optJSONArray("toDo");
        boolean inReport = false;
        for (int i = 0; toDo != null && i < toDo.length(); i++)
            if (toDo.getJSONObject(i).optString("what").contains(PKG) && toDo.getJSONObject(i).optString("what").contains("pkg install -f")) inReport = true;
        check("M7 il rapporto lo dice, con cosa fare", inReport);
        check("M7 l'avviso si chiude dopo aver controllato", PackageRecovery.dismiss().optBoolean("success"));
        // la pulizia
        cleanup();
        sh("rm -f " + REPO_CONF + "; rm -rf /var/db/pkg/repos/robustprobe " + DIR);
        if (Files.exists(M7.resolve("created-repos-dir"))) sh("rmdir " + Path.of(REPO_CONF).getParent());
        removeOwnBootEnvironments(Files.readString(M7.resolve("boot-environments-before")));
        UpdateManager.refreshLockTrace();
        check("M7 alla fine: gli stessi pacchetti di prima",
                sh("pkg query %n-%v | sort | sha256").equals(Files.readString(M7.resolve("packages-before"))));
        check("M7 alla fine: gli stessi pacchetti protetti",
                String.join("\n", locked()).equals(Files.readString(M7.resolve("locked-before"))));
        check("M7 alla fine: gli stessi boot environment", bootEnvironments().equals(Files.readString(M7.resolve("boot-environments-before"))));
        sh("rm -rf " + M7);
        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    // ===================== i figli =====================

    static void child(String[] args) throws Exception {
        switch (args[0]) {
            case "take-turn" -> {
                String r = PackageQueue.take("measure-m2-child", "measurement M2, second process");
                System.out.println(r == null ? "PRESO" : "RIFIUTATO: " + r);
                if (r == null) PackageQueue.release("measure-m2-child");
            }
            case "run-guided" -> {
                JSONObject job = guided();
                System.out.println("child finished: " + (job == null ? "null" : job.optString("status")));
            }
            case "restore" -> System.out.println(UpdateManager.restoreLocksAfterCrash());
            case "restore-and-stay" -> {
                System.out.println(UpdateManager.restoreLocksAfterCrash());
                long until = System.currentTimeMillis() + Long.parseLong(args[1]) * 1000;
                while (PackageQueue.statePresent() && System.currentTimeMillis() < until) Thread.sleep(1000);
                if (!PackageQueue.statePresent()) System.out.println("PROTECTED AGAIN IN THE BACKGROUND");
            }
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
        JSONObject start = UpdateManager.startGuidedUpdate(PKG, pf.optString("signature"));
        String id = start.optString("jobId");
        if (id.isEmpty()) { System.out.println("  il lavoro non parte: " + start); return start; }
        System.out.println("  lavoro " + id + " partito");
        return waitJob(id);
    }

    static JSONObject waitJob(String id) throws Exception {
        long deadline = System.currentTimeMillis() + 900_000;
        while (PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        return UpdateManager.jobStatus(id).getJSONObject("job");
    }

    static String firstProblem(JSONObject pf) {
        String all = pf.toString();
        return all.substring(0, Math.min(400, all.length()));
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

    /** L'avviso di un lavoro interrotto com'era prima della prova (di solito: non c'era). */
    static void restoreNotice() throws Exception {
        if (noticeBefore == null) Files.deleteIfExists(PackageRecovery.notice);
        else Files.writeString(PackageRecovery.notice, noticeBefore);
    }

    static String bootEnvironments() {
        return sh("bectl list -H | cut -f1 | sort");
    }

    /** I boot environment dei pacchetti comparsi durante la prova. */
    static List<String> newOwn(String before) {
        List<String> r = new ArrayList<>();
        for (String n : bootEnvironments().split("\n"))
            if (n.startsWith(PackageWayBack.PREFIX) && !before.contains(n)) r.add(n.trim());
        return r;
    }

    static void removeOwnBootEnvironments(String before) {
        for (String n : newOwn(before)) PackageWayBack.destroy(n);
    }

    static String runChild(int seconds, String... mode) throws Exception {
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of("java", "-De2e.vm=yes", "-cp", cp, UpdaterRobustnessE2ETest.class.getName()));
        cmd.addAll(List.of(mode));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true)
                .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
        StringBuilder out = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String l;
            while ((l = r.readLine()) != null)
                if (!l.startsWith("WARNING") && !l.startsWith("INFO:") && !l.matches("^[A-Z][a-z]{2} \\d{2}, \\d{4} .*")) out.append(l).append('\n');
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
