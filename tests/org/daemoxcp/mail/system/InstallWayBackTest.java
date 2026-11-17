package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.sqli.dataBaseManager;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The way back of the full reinstallation from the menu, in the two parts that do not ask for
 * bectl (the one with real bectl is ReinstallWayBackE2ETest, on the clone):
 *
 *  1. The middle step of InstallLocks.prepare (where the reinstallation creates the boot
 *     environment) runs with the turn already taken and BEFORE any unlock: the boot environment has
 *     the protected packages as they were and no open list. If the step refuses (the boot
 *     environment is not created) or blows up, nothing is unlocked, the list is not written and the
 *     turn is freed.
 *  2. Main.installOnTurn says whether the script reached phase 1 (it started changing the system):
 *     a planted script that stops before (as for an unconfigured Roundcube) did not, one that prints
 *     phase 1 and then fails or succeeds did. It is what decides whether the boot environment stays.
 *     The real body, in a child process with its own folder, SQLite and secrets; MySQL is not needed
 *     (port 1: the password stays pending, PendingDbPassword).
 *
 * Usage: java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.InstallWayBackTest
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
        PackageQueue.list = d.resolve("daemoxcp-mail-maintenance-locks");
        PackageQueue.turnLock = d.resolve("package-turn.lock");
        try {
            System.out.println("== The way-back step: with the turn, before the unlock ==");
            InstallLocksTest.FakePkg p = new InstallLocksTest.FakePkg().with("mysql84-server", "nginx", "dovecot");
            boolean[] turnHeld = {false};
            long[] lockedThen = {-1};
            boolean[] listThen = {true};
            InstallLocksTest.FakePkg pkg = p;
            InstallLocks.Start s = InstallLocks.prepare("test", p, () -> {
                turnHeld[0] = PackageQueue.holder() != null;
                lockedThen[0] = pkg.lockedCount();
                listThen[0] = PackageQueue.statePresent();
                return null;
            });
            check("the step finds the turn already taken", turnHeld[0]);
            check("and the three packages still protected", lockedThen[0] == 3);
            check("and no list of unlocks on disk", !listThen[0]);
            check("then the installation starts and unlocks", s.refusal() == null && s.held() != null && p.lockedCount() == 0);
            InstallLocks.finish(s.held(), p, false);
            check("at the end locked again and the turn free", p.lockedCount() == 3 && PackageQueue.holder() == null);

            System.out.println("\n== The step refuses (the boot environment is not created) ==");
            p = new InstallLocksTest.FakePkg().with("mysql84-server", "nginx");
            s = InstallLocks.prepare("test", p, () -> "test: the boot environment is not created");
            check("the installation does not start, with the step's reason", s.held() == null && "test: the boot environment is not created".equals(s.refusal()));
            check("nothing unlocked", p.unlockCalls() == 0 && p.lockedCount() == 2);
            check("no list on disk", !Files.exists(PackageQueue.list));
            check("the turn is free", PackageQueue.holder() == null && takeAndRelease());

            System.out.println("\n== The step blows up ==");
            p = new InstallLocksTest.FakePkg().with("mysql84-server");
            s = InstallLocks.prepare("test", p, () -> { throw new IllegalStateException("test: bectl blows up"); });
            check("the installation does not start", s.held() == null && s.refusal() != null && s.refusal().contains("bectl blows up"));
            check("nothing unlocked, no list, the turn free", p.unlockCalls() == 0 && !Files.exists(PackageQueue.list) && takeAndRelease());

            System.out.println("\n== The script stops before phase 1 ==");
            String out = run(d.resolve("early"), "early");
            check("it changed nothing", out.contains("TOUCHED false") && out.contains("RESULT false"));

            System.out.println("\n== The script reaches phase 1 and fails ==");
            out = run(d.resolve("phase1-fail"), "phase1-fail");
            check("it started changing the system", out.contains("TOUCHED true") && out.contains("RESULT false"));

            System.out.println("\n== The script reaches the end ==");
            out = run(d.resolve("phase1-ok"), "phase1-ok");
            check("it changed the system", out.contains("TOUCHED true") && out.contains("RESULT true"));

            System.out.println("\n== The script names the phases only in the checks, without the phase 1 line ==");
            out = run(d.resolve("other-phase"), "other-phase");
            check("it does not count as a change", out.contains("TOUCHED false"));
        } finally {
            removeTree(d);
        }
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static boolean takeAndRelease() {
        String r = PackageQueue.take("check", "check");
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
        return "#!/bin/sh\n# test: planted in place of install_mail_server.sh\n" + body;
    }

    static String run(Path dir, String kind) throws Exception {
        Files.createDirectories(dir);
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>(List.of(java, "-Ddaemoxcp.mail.secrets.dir=" + dir.resolve("secrets"),
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
        Main.dbManager.update_mysql_config("127.0.0.1", "1", "e2e_nobody", "E2eNobody1", "e2e_nobody");
        Files.createDirectories(cwd.resolve("install_scripts"));
        Files.writeString(cwd.resolve("install_scripts/install_mail_server.sh"), plantedScript(a[1]));
        if (PackageQueue.take("reinstall", "test installation") != null) { System.out.println("TURN?"); System.exit(1); }
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
