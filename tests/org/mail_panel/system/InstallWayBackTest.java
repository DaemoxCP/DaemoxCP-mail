package org.mail_panel.system;

import org.mail_panel.Main;
import org.mail_panel.sqli.dataBaseManager;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * La via di ritorno della reinstallazione completa dal menu, nelle due parti che non chiedono
 * bectl (quella con bectl vero e' ReinstallWayBackE2ETest, sul clone):
 *
 *  1. Il passo in mezzo di InstallLocks.prepare (dove la reinstallazione crea il boot environment)
 *     gira col turno gia' preso e PRIMA di ogni sblocco: il boot environment ha i pacchetti protetti
 *     com'erano e nessun elenco aperto. Se il passo rifiuta (il boot environment non si crea) o
 *     esplode, non si sblocca niente, l'elenco non si scrive e il turno si libera.
 *  2. Main.installOnTurn dice se lo script e' arrivato alla fase 1 (ha cominciato a cambiare il
 *     sistema): uno script piantato che si ferma prima (come per Roundcube non configurato) no, uno
 *     che stampa la fase 1 e poi fallisce o riesce si'. E' cio' che decide se il boot environment
 *     resta. Il corpo vero, in un processo figlio con cartella, SQLite e segreti suoi; MySQL non
 *     serve (porta 1: la password resta in attesa, PendingDbPassword).
 *
 * Uso: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallWayBackTest
 */
public class InstallWayBackTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0) { child(args); return; }
        Path d = Files.createTempDirectory("install-way-back");
        PackageQueue.list = d.resolve("mail-panel-maintenance-locks");
        PackageQueue.turnLock = d.resolve("package-turn.lock");
        try {
            System.out.println("== Il passo della via di ritorno: col turno, prima dello sblocco ==");
            InstallLocksTest.FakePkg p = new InstallLocksTest.FakePkg().with("mysql84-server", "nginx", "dovecot");
            boolean[] turnHeld = {false};
            long[] lockedThen = {-1};
            boolean[] listThen = {true};
            InstallLocksTest.FakePkg pkg = p;
            InstallLocks.Start s = InstallLocks.prepare("prova", p, () -> {
                turnHeld[0] = PackageQueue.holder() != null;
                lockedThen[0] = pkg.lockedCount();
                listThen[0] = PackageQueue.statePresent();
                return null;
            });
            check("il passo trova il turno gia' preso", turnHeld[0]);
            check("e i tre pacchetti ancora protetti", lockedThen[0] == 3);
            check("e nessun elenco di sblocchi su disco", !listThen[0]);
            check("poi l'installazione parte e sblocca", s.refusal() == null && s.held() != null && p.lockedCount() == 0);
            InstallLocks.finish(s.held(), p, false);
            check("alla fine riprotetti e turno libero", p.lockedCount() == 3 && PackageQueue.holder() == null);

            System.out.println("\n== Il passo rifiuta (il boot environment non si crea) ==");
            p = new InstallLocksTest.FakePkg().with("mysql84-server", "nginx");
            s = InstallLocks.prepare("prova", p, () -> "prova: il boot environment non si crea");
            check("l'installazione non parte, col motivo del passo", s.held() == null && "prova: il boot environment non si crea".equals(s.refusal()));
            check("niente sbloccato", p.unlockCalls() == 0 && p.lockedCount() == 2);
            check("nessun elenco su disco", !Files.exists(PackageQueue.list));
            check("il turno e' libero", PackageQueue.holder() == null && takeAndRelease());

            System.out.println("\n== Il passo esplode ==");
            p = new InstallLocksTest.FakePkg().with("mysql84-server");
            s = InstallLocks.prepare("prova", p, () -> { throw new IllegalStateException("prova: bectl esplode"); });
            check("l'installazione non parte", s.held() == null && s.refusal() != null && s.refusal().contains("bectl esplode"));
            check("niente sbloccato, nessun elenco, turno libero", p.unlockCalls() == 0 && !Files.exists(PackageQueue.list) && takeAndRelease());

            System.out.println("\n== Lo script si ferma prima della fase 1 ==");
            String out = run(d.resolve("early"), "early");
            check("non ha cambiato niente", out.contains("TOUCHED false") && out.contains("RESULT false"));

            System.out.println("\n== Lo script arriva alla fase 1 e fallisce ==");
            out = run(d.resolve("phase1-fail"), "phase1-fail");
            check("ha cominciato a cambiare il sistema", out.contains("TOUCHED true") && out.contains("RESULT false"));

            System.out.println("\n== Lo script arriva in fondo ==");
            out = run(d.resolve("phase1-ok"), "phase1-ok");
            check("ha cambiato il sistema", out.contains("TOUCHED true") && out.contains("RESULT true"));

            System.out.println("\n== Lo script nomina le fasi solo nei controlli, senza la riga della fase 1 ==");
            out = run(d.resolve("other-phase"), "other-phase");
            check("non conta come cambiamento", out.contains("TOUCHED false"));
        } finally {
            removeTree(d);
        }
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static boolean takeAndRelease() {
        String r = PackageQueue.take("check", "controllo");
        PackageQueue.release("check");
        return r == null;
    }

    static String plantedScript(String kind) {
        String body = switch (kind) {
            case "early" -> "echo \"$(printf '\\033[0;31m')  ERROR: Roundcube domain not configured!$(printf '\\033[0m')\"\nexit 1\n";
            case "phase1-fail" -> "echo \"$(printf '\\033[1;33m')[PHASE 1/10] Cleaning up existing installation...$(printf '\\033[0m')\"\necho \"planted: failing in phase 2\"\nexit 1\n";
            case "phase1-ok" -> "echo \"$(printf '\\033[1;33m')[PHASE 1/10] Cleaning up existing installation...$(printf '\\033[0m')\"\nexit 0\n";
            case "other-phase" -> "echo \"Checking: PHASE 1 comes after the checks\"\nexit 1\n";
            default -> throw new IllegalArgumentException(kind);
        };
        return "#!/bin/sh\n# prova: piantato al posto di install_mail_server.sh\n" + body;
    }

    static String run(Path dir, String kind) throws Exception {
        Files.createDirectories(dir);
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>(List.of(java, "-Dmailpanel.secrets.dir=" + dir.resolve("secrets"),
                "-cp", absolute(System.getProperty("java.class.path")), InstallWayBackTest.class.getName(), "child", kind));
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true)
                .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        for (String l : out.split("\n")) if (!l.isBlank()) System.out.println("      | " + l);
        return out;
    }

    static void child(String[] a) throws Exception {
        Path cwd = Path.of("").toAbsolutePath();
        PackageQueue.list = cwd.resolve("maintenance-locks");
        PackageQueue.turnLock = cwd.resolve("package-turn.lock");
        PendingDbPassword.postfixMap = cwd.resolve("mysql-virtual-domains.cf");
        Main.dbManager = new dataBaseManager();
        Main.dbManager.ensureMailHostnameColumn();
        Main.dbManager.ensureSslChainColumn();
        Main.dbManager.ensureRoundcubeColumns();
        Main.dbManager.ensurePostfixColumn();
        if (Main.dbManager.check_tables() < 1) { Main.dbManager.create_tables(); Main.dbManager.insert_data_default(); }
        Main.dbManager.update_mysql_config("127.0.0.1", "1", "e2e_nobody", "E2eNessuna1", "e2e_nobody");
        Files.createDirectories(cwd.resolve("install_scripts"));
        Files.writeString(cwd.resolve("install_scripts/install_mail_server.sh"), plantedScript(a[1]));
        if (PackageQueue.take("reinstall", "installazione di prova") != null) { System.out.println("TURN?"); System.exit(1); }
        AtomicBoolean touched = new AtomicBoolean(false);
        boolean ok;
        try {
            Method m = Main.class.getDeclaredMethod("installOnTurn", String.class, AtomicBoolean.class);
            m.setAccessible(true);
            ok = (Boolean) m.invoke(null, "mail.e2e.test", touched);
        } finally {
            PackageQueue.release("reinstall");
        }
        System.out.println("TOUCHED " + touched.get() + " RESULT " + ok);
        System.exit(0);
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
