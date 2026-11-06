package org.mail_panel.system;

import org.mail_panel.Main;
import org.mail_panel.sqli.dataBaseManager;
import org.mail_panel.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * La reinstallazione completa staccata dal menu (ReinstallJob, reperto 163): il menu muore e lei
 * va avanti fino in fondo.
 *
 *  J1. il menu ucciso con kill -9 a meta';
 *  J2. il terminale del menu che si chiude: SIGHUP a tutto il suo gruppo di processi (il menu
 *      parte sotto daemon(8), cosi' ha un gruppo suo come davanti a un terminale vero);
 *  J3. un menu ucciso a meta' e un secondo menu aperto mentre lei lavora: il secondo segue quella
 *      in corso, non ne fa partire un'altra;
 *  J4. la reinstallazione stessa uccisa con kill -9: il menu lo dice e non la da' per riuscita, e
 *      un «servizio» acceso col guardiano (UpdateManager.startInterruptionWatch, reperto 166)
 *      riprotegge i pacchetti da solo e scrive l'avviso con la via di ritorno. Lo stesso servizio
 *      resta acceso durante J1-J3, e li' non deve toccare niente.
 * Dopo ognuna: l'esito, la fine dello script, i pacchetti riprotetti, il turno libero.
 *
 * Lo script e' piantato con una classe ombra di FullMailServerScript (tests/planted, davanti al jar
 * nel classpath: la reinstallazione lo riscrive sempre dal suo jar), e su disco all'inizio c'e' uno
 * script VECCHIO che non deve mai girare. Lo script piantato: fase 1, dodici passi da un secondo, poi
 * un segno. Il resto e' vero: la
 * JVM staccata (Main --reinstall), il turno, lo sblocco e la riprotezione dei pacchetti protetti
 * (pkg vero), la via di ritorno (bectl vero). Il pannello di prova sta in una cartella sua, con
 * SQLite, segreti e registri suoi; MySQL non serve (porta 1). SOLO su un clone di prova: si accende
 * con -De2e.vm=yes, da root, e si rifiuta di partire se ci sono gia' vie di ritorno vere (la
 * potatura ne toglierebbe) o pacchetti sbloccati da un lavoro interrotto.
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ReinstallJobTest
 */
public class ReinstallJobTest {

    static final String HOST = "mail.e2e.test";
    static int failed = 0;
    static Path base, panel, logs;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(300), cmd).outputTrim();
    }

    static int locked() {
        return (int) sh("pkg query -e '%k = 1' '%n' 2>/dev/null").lines().filter(l -> !l.isBlank()).count();
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("child")) { child(args); return; }
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("SALTATA: serve -De2e.vm=yes (un clone di prova sulla VM FreeBSD, da root).");
            System.exit(0);
        }
        for (String n : sh("bectl list -H 2>/dev/null | cut -f1").split("\n"))
            if (PackageWayBack.REINSTALL_OWN.matcher(n.trim()).matches()) {
                System.out.println("FERMATA: c'e' gia' la via di ritorno di una reinstallazione (" + n.trim() + "): la potatura la toglierebbe.");
                System.exit(2);
            }
        if (PackageQueue.statePresent()) {
            System.out.println("FERMATA: c'e' l'elenco di un lavoro sui pacchetti interrotto: prima lo si chiude.");
            System.exit(2);
        }
        int lockedBefore = locked();
        String beBefore = sh("bectl list -H | cut -f1 | sort");
        base = Files.createTempDirectory("reinstall-job");
        panel = base.resolve("panel");
        logs = base.resolve("logs");
        Files.createDirectories(panel);
        System.out.println("pacchetti protetti prima: " + lockedBefore);
        // Senza la classe ombra davanti al jar la reinstallazione scriverebbe ed eseguirebbe lo script VERO.
        if (!new org.mail_panel.scripts.FullMailServerScript().getScriptContent().contains("classe ombra")) {
            System.out.println("FERMATA: manca la classe ombra di tests/planted davanti al jar: questa prova eseguirebbe lo script vero.");
            System.exit(2);
        }
        Path notice = base.resolve("package-job-interrupted.json");
        Path serviceOut = base.resolve("service.out");
        Process service = null;
        try {
            check("pannello di prova pronto", run(panel, "setup").contains("SETUP OK"));
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            service = new ProcessBuilder(java, "-cp", absolute(System.getProperty("java.class.path")),
                    ReinstallJobTest.class.getName(), "child", "service-watch", notice.toString())
                    .directory(base.toFile()).redirectErrorStream(true).redirectOutput(serviceOut.toFile()).start();
            for (int i = 0; i < 40 && !(Files.exists(serviceOut) && Files.readString(serviceOut).contains("WATCHING")); i++) Thread.sleep(250);
            check("il servizio col guardiano e' acceso", Files.readString(serviceOut).contains("WATCHING"));

            System.out.println("\n== J1. Il menu ucciso con kill -9 a meta' ==");
            Process menu = startMenu("j1");
            long job = waitJobStep(3);
            check("la reinstallazione staccata e' partita ed e' al passo 3", job > 0);
            check("in un'altra sessione del menu (" + sess(job) + " e " + sess(menu.pid()) + ")",
                    sess(job).matches("[0-9]+") && sess(menu.pid()).matches("[0-9]+") && !sess(job).equals(sess(menu.pid())));
            menu.destroyForcibly();
            menu.waitFor();
            afterJob("J1", job, lockedBefore);

            System.out.println("\n== J2. Il terminale del menu si chiude: SIGHUP al suo gruppo di processi ==");
            Path menuPid = base.resolve("menu-j2.pid");
            sh("cd " + panel + " && /usr/sbin/daemon -o " + base.resolve("menu-j2.out") + " -p " + menuPid + " " + String.join(" ", menuCommand()));
            job = waitJobStep(3);
            long menuJ2 = Long.parseLong(Files.readString(menuPid).trim());
            String pgid = sh("ps -o pgid= -p " + menuJ2).trim();
            check("il menu ha un gruppo suo (" + pgid + ") e la reinstallazione e' fuori", job > 0 && !pgid.isEmpty()
                    && !pgid.equals(sh("ps -o pgid= -p " + job).trim()));
            sh("kill -HUP -" + pgid);
            check("il menu e' morto col suo terminale", waitGone(menuJ2));
            afterJob("J2", job, lockedBefore);

            System.out.println("\n== J3. Un menu ucciso, un secondo menu aperto mentre la reinstallazione lavora ==");
            menu = startMenu("j3a");
            job = waitJobStep(3);
            menu.destroyForcibly();
            menu.waitFor();
            Process second = startMenu("j3b");
            String out = new String(second.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int code = second.waitFor();
            echo(out);
            check("il secondo menu segue quella in corso", out.contains("already running") && out.contains("pid " + job));
            check("e non ne fa partire un'altra", count(out, "runs by itself") == 0 && jobLogs() == 3);
            check("la segue fino in fondo e la da' per riuscita", code == 0 && out.contains("step 12") && out.contains("MENU RESULT true"));
            afterJob("J3", job, lockedBefore);

            System.out.println("\n== J4. La reinstallazione stessa uccisa con kill -9 ==");
            menu = startMenu("j4");
            job = waitJobStep(3);
            check("durante J1-J3 il guardiano non ha toccato niente", !Files.exists(notice)
                    && !Files.readString(serviceOut).contains("Interrupted package job detected"));
            sh("kill -9 " + job);
            out = new String(menu.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            code = menu.waitFor();
            echo(out);
            check("il menu dice che si e' fermata senza finire", out.contains("stopped without finishing"));
            check("e non la da' per riuscita", code != 0 && out.contains("MENU RESULT false"));
            boolean relocked = false;
            for (int i = 0; i < 60 && !relocked; i++) {
                Thread.sleep(1000);
                relocked = !PackageQueue.statePresent() && locked() == lockedBefore;
            }
            check("il servizio acceso se ne accorge e riprotegge i pacchetti da solo", relocked);
            org.json.JSONObject n = Files.exists(notice) ? new org.json.JSONObject(Files.readString(notice)) : new org.json.JSONObject();
            check("e scrive l'avviso: era la reinstallazione, con la sua via di ritorno (" + n.optString("wayBack") + ")",
                    n.optBoolean("reinstall") && PackageWayBack.REINSTALL_OWN.matcher(n.optString("wayBack")).matches());
            echo(Files.readString(serviceOut));
        } finally {
            if (service != null) { service.getOutputStream().close(); service.waitFor(); }
            // Le vie di ritorno fatte dalle reinstallazioni di prova.
            for (String n : sh("bectl list -H | cut -f1").split("\n"))
                if (PackageWayBack.REINSTALL_OWN.matcher(n.trim()).matches()) PackageWayBack.destroy(n.trim());
            if (PackageQueue.statePresent()) UpdateManager.restoreLocksAfterCrash();
            removeTree(base);
        }
        check("alla fine: gli stessi boot environment e gli stessi pacchetti protetti",
                sh("bectl list -H | cut -f1 | sort").equals(beBefore) && locked() == lockedBefore);
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** Dopo una reinstallazione lasciata sola: esito, script finito, pacchetti riprotetti, turno libero. */
    static void afterJob(String name, long job, int lockedBefore) throws Exception {
        Path exit = latestExit(120);
        check(name + ": la reinstallazione arriva in fondo da sola, esito 0", exit != null && Files.readString(exit).trim().equals("0"));
        check(name + ": lo script e' finito (il segno c'e')", Files.exists(panel.resolve("script-done")));
        if (exit == null) {
            // Nessun esito: la prova va avanti con le altre, senza leggere un registro che non sa trovare.
            check(name + ": il registro della reinstallazione si trova", false);
            waitGone(job);
            if (PackageQueue.statePresent()) UpdateManager.restoreLocksAfterCrash();
            Files.deleteIfExists(panel.resolve("script-done"));
            return;
        }
        String log = Files.readString(Path.of(exit.toString().replace(".exit", ".log")));
        check(name + ": il registro ha tutto, fino alla riprotezione", log.contains("step 12") && log.contains("packages locked again"));
        check(name + ": lo script vecchio non e' girato", !log.contains("stale script ran"));
        check(name + ": i pacchetti di nuovo protetti, nessun elenco", locked() == lockedBefore && !PackageQueue.statePresent());
        check(name + ": la reinstallazione non c'e' piu' e il turno e' libero", waitGone(job) && takeAndRelease());
        Files.deleteIfExists(panel.resolve("script-done"));
    }

    static boolean takeAndRelease() {
        String r = PackageQueue.take("check", "controllo");
        PackageQueue.release("check");
        return r == null;
    }

    static boolean waitGone(long pid) throws Exception {
        for (int i = 0; i < 60 && pid > 0; i++) {
            if (ProcessHandle.of(pid).map(h -> !h.isAlive()).orElse(true)) return true;
            Thread.sleep(500);
        }
        return pid <= 0 || ProcessHandle.of(pid).map(h -> !h.isAlive()).orElse(true);
    }

    static String sess(long pid) {
        return sh("ps -o sid= -p " + pid).trim();     // su FreeBSD "sess" non c'e': ps esce con un errore e niente
    }

    static int count(String s, String w) {
        int n = 0, i = 0;
        while ((i = s.indexOf(w, i)) >= 0) { n++; i += w.length(); }
        return n;
    }

    static long jobLogs() throws Exception {
        if (!Files.isDirectory(logs)) return 0;
        try (var f = Files.list(logs)) { return f.filter(p -> p.toString().endsWith(".log")).count(); }
    }

    /** Aspetta che la reinstallazione piu' recente sia al passo n dello script; il suo pid, o 0. */
    static long waitJobStep(int n) throws Exception {
        for (int i = 0; i < 240; i++) {
            Thread.sleep(500);
            if (!Files.isDirectory(logs)) continue;
            Path log;
            try (var f = Files.list(logs)) {
                log = f.filter(p -> p.getFileName().toString().matches("reinstall-[0-9-]+\\.log")).sorted().reduce((a, b) -> b).orElse(null);
            }
            if (log == null || !Files.readString(log).contains("step " + n)) continue;
            Path pid = Path.of(log.toString().replace(".log", ".pid"));
            String s = Files.exists(pid) ? Files.readString(pid).trim() : "";
            return s.matches("[0-9]+") ? Long.parseLong(s) : 0;
        }
        return 0;
    }

    static Path latestExit(int seconds) throws Exception {
        for (int i = 0; i < seconds * 2; i++) {
            try (var f = Files.list(logs)) {
                Path log = f.filter(p -> p.getFileName().toString().matches("reinstall-[0-9-]+\\.log")).sorted().reduce((a, b) -> b).orElse(null);
                if (log != null) {
                    Path exit = Path.of(log.toString().replace(".log", ".exit"));
                    if (Files.exists(exit)) return exit;
                }
            }
            Thread.sleep(500);
        }
        return null;
    }

    static List<String> menuCommand() {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        return List.of(java, "-Dmailpanel.secrets.dir=" + base.resolve("secrets"), "-Dmailpanel.reinstall.dir=" + logs,
                "-cp", absolute(System.getProperty("java.class.path")),
                ReinstallJobTest.class.getName(), "child", "menu", HOST);
    }

    static Process startMenu(String name) throws Exception {
        return new ProcessBuilder(menuCommand()).directory(panel.toFile()).redirectErrorStream(true)
                .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
    }

    static String run(Path dir, String... step) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>(List.of(java, "-Dmailpanel.secrets.dir=" + base.resolve("secrets"),
                "-cp", absolute(System.getProperty("java.class.path")), ReinstallJobTest.class.getName(), "child"));
        cmd.addAll(List.of(step));
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        echo(out);
        return out;
    }

    static void echo(String out) {
        for (String l : out.split("\n")) if (!l.isBlank()) System.out.println("      | " + l.replaceAll("\u001b\\[[0-9;]*m", ""));
    }

    static void child(String[] a) throws Exception {
        switch (a[1]) {
            case "setup" -> {
                Main.dbManager = new dataBaseManager();
                Main.dbManager.ensureMailHostnameColumn();
                Main.dbManager.ensureSslChainColumn();
                Main.dbManager.ensureRoundcubeColumns();
                Main.dbManager.ensurePostfixColumn();
                if (Main.dbManager.check_tables() < 1) { Main.dbManager.create_tables(); Main.dbManager.insert_data_default(); }
                Main.dbManager.update_mysql_config("127.0.0.1", "1", "e2e_nobody", "E2eNessuna1", "e2e_nobody");
                // Uno script VECCHIO su disco: la reinstallazione deve riscriverlo dal suo jar (qui la
                // classe ombra di tests/planted) e non eseguire questo (InstallScripts, reperto 169).
                Files.createDirectories(Path.of("install_scripts"));
                Files.writeString(Path.of("install_scripts/install_mail_server.sh"),
                        "#!/bin/sh\n# uno script di una versione di prima\necho \"stale script ran\"\nexit 42\n");
                System.out.println("SETUP OK");
                System.exit(0);
            }
            case "service-watch" -> {
                // Il guardiano del servizio --web, con un giro di 3 secondi invece di 60.
                UpdateManager.watchSeconds = 3;
                PackageRecovery.notice = Path.of(a[2]);
                UpdateManager.startInterruptionWatch();
                System.out.println("WATCHING");
                System.out.flush();
                System.in.read();
                System.exit(0);
            }
            case "menu" -> {
                boolean ok = ReinstallJob.runFromMenu(a[2], System.out);
                System.out.println("MENU RESULT " + ok);
                System.exit(ok ? 0 : 1);
            }
            default -> throw new IllegalArgumentException(a[1]);
        }
    }

    static String absolute(String cp) {
        StringBuilder b = new StringBuilder();
        for (String part : cp.split(java.io.File.pathSeparator)) {
            if (b.length() > 0) b.append(java.io.File.pathSeparator);
            b.append(Path.of(part).toAbsolutePath());
        }
        return b.toString();
    }

    static void removeTree(Path p) throws Exception {
        if (!Files.exists(p)) return;
        try (var walk = Files.walk(p)) {
            for (Path q : walk.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(q);
        }
    }
}
