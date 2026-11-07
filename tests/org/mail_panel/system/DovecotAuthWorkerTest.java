package org.mail_panel.system;

import org.mail_panel.scripts.DovecotConfig;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Dovecot's auth-worker no longer as root (DovecotAuthWorker).
 *
 * Measured on 07/11/2026 on the real server and on the VM (Dovecot 2.3.21): `dovecot/auth -w` ran as
 * root, and it only looks passwords up in MySQL. Here:
 *  1. pure: the drivers read from `doveconf -n`, the decision (already moved, a driver that needs
 *     root, an internal user that is missing), the file, and that the installer writes the same file
 *     in both Dovecot syntaxes;
 *  2. with -De2e.vm=yes, as root, on the FreeBSD VM: the real Dovecot. The repair moves auth-worker to
 *     dovecot and a real login still works (-Dtest.mailbox and -Dtest.passfile, a test mailbox of the
 *     VM), a wrong password is still refused; the second time it does nothing and logs nothing; a
 *     setting doveconf refuses is rolled back; the check after the reload sees a worker still root.
 *     At the end Dovecot is put back as the test found it.
 *
 * Usage (on the VM):
 *   java -De2e.vm=yes -Dtest.mailbox=alice@rehearsal.test -Dtest.passfile=/root/upgrade/alice.pass \
 *        -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.DovecotAuthWorkerTest
 */
public class DovecotAuthWorkerTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** `doveconf -n` of the VM, 07/11/2026, the auth part. */
    static final String CONF = """
            passdb {
              args = /usr/local/etc/dovecot/master-users
              driver = passwd-file
              master = yes
              result_success = continue
            }
            passdb {
              args = /usr/local/etc/dovecot/dovecot-sql.conf
              driver = sql
            }
            userdb {
              args = uid=vmail gid=vmail home=/var/vmail/%d/%n
              driver = static
            }
            """;

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. The decision and the file ==");
        check("drivers from doveconf -n", DovecotAuthWorker.drivers(CONF).equals(Set.of("passwd-file", "sql", "static")));
        check("auth-worker as root (empty user): APPLY",
                DovecotAuthWorker.decide("", CONF, "dovecot", true).action() == DovecotAuthWorker.Action.APPLY);
        check("auth-worker as root (written out): APPLY",
                DovecotAuthWorker.decide("root", CONF, "dovecot", true).action() == DovecotAuthWorker.Action.APPLY);
        check("already as dovecot: NOTHING",
                DovecotAuthWorker.decide("dovecot", CONF, "dovecot", true).action() == DovecotAuthWorker.Action.NOTHING);
        DovecotAuthWorker.Decision pam = DovecotAuthWorker.decide("", CONF.replace("driver = sql", "driver = pam"), "dovecot", true);
        check("a pam passdb: stays root, and says why (" + pam.reason() + ")",
                pam.action() == DovecotAuthWorker.Action.STAYS_ROOT && pam.reason().contains("pam"));
        check("the internal user missing on the system: stays root",
                DovecotAuthWorker.decide("", CONF, "dovecot", false).action() == DovecotAuthWorker.Action.STAYS_ROOT);
        check("an internal user that is not a user name: stays root",
                DovecotAuthWorker.decide("", CONF, "dove cot;", true).action() == DovecotAuthWorker.Action.STAYS_ROOT);

        String file = DovecotAuthWorker.fileContent("dovecot");
        boolean onlyTheBlock = true;
        for (String l : file.split("\n"))
            onlyTheBlock &= l.startsWith("#") || l.equals("service auth-worker {") || l.equals("  user = dovecot") || l.equals("}");
        check("the file: comments and the auth-worker block, nothing else", onlyTheBlock && file.contains("  user = dovecot\n"));
        String fragment = DovecotConfig.fromPanelConfig().scriptFragment();
        check("the installer (2.3) writes the same file",
                fragment.contains("cat > \"$DOVECOT_ETC/conf.d/10-auth-worker.conf\" <<'DOVECOT_AUTH_WORKER'\n" + file + "DOVECOT_AUTH_WORKER\n"));
        check("  and so does the 2.4 one", DovecotConfig.file24().stream().anyMatch(f ->
                f.path().equals("conf.d/10-auth-worker.conf") && f.content().equals(file) && !f.expand()));

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 2 skipped: it changes Dovecot, turned on with -De2e.vm=yes on the VM)");
            finish();
            return;
        }
        endToEnd();
        finish();
    }

    static void finish() {
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static final Path FILE = Path.of(DovecotAuthWorker.CONF_D, DovecotAuthWorker.FILE_NAME);

    static void endToEnd() throws Exception {
        System.out.println("\n== 2. The real Dovecot ==");
        String found = Files.exists(FILE) ? Files.readString(FILE) : null;
        List<String> logged = new ArrayList<>();
        Logger log = Logger.getLogger(DovecotAuthWorker.class.getName());
        Handler h = new Handler() {
            @Override public void publish(LogRecord r) { logged.add(r.getLevel() + ": " + r.getMessage()); }
            @Override public void flush() {}
            @Override public void close() {}
        };
        log.addHandler(h);
        try {
            if (found != null) { Files.delete(FILE); DovecotAuthWorker.reload(); }
            check("at the start auth-worker runs as root (doveconf says '')", workerSetting().isEmpty());
            login("before the repair");

            DovecotAuthWorker.ensureAtBoot();
            System.out.println("    log: " + logged);
            check("the repair says DONE", logged.size() == 1 && logged.get(0).startsWith("INFO: [DovecotAuthWorker] DONE: "));
            check("doveconf: auth-worker as dovecot", workerSetting().equals("dovecot"));
            DovecotAuthWorker.lookup();
            List<String> users = DovecotAuthWorker.workerUsers();
            check("the running auth-worker processes are dovecot's (" + users + ")", !users.isEmpty() && users.stream().allMatch("dovecot"::equals));
            login("after the repair");

            logged.clear();
            String content = Files.readString(FILE);
            DovecotAuthWorker.ensureAtBoot();
            check("the second time: nothing logged, file unchanged", logged.isEmpty() && Files.readString(FILE).equals(content));

            System.out.println("\n== 3. Planted faults ==");
            Files.delete(FILE);
            DovecotAuthWorker.reload();
            logged.clear();
            boolean applied = DovecotAuthWorker.apply("nosuchuser-mp");
            check("a user Dovecot refuses: not applied, rolled back (" + logged + ")", !applied
                    && logged.stream().anyMatch(l -> l.startsWith("WARNING: [DovecotAuthWorker] ROLLED_BACK: ")));
            check("  the file is gone and auth-worker is root as before", !Files.exists(FILE) && workerSetting().isEmpty());
            check("  and authentication works", DovecotAuthWorker.LOOKUP_OK.contains(DovecotAuthWorker.lookup()));
            DovecotAuthWorker.lookup();
            String problem = DovecotAuthWorker.verify("dovecot");
            check("the check after the reload sees a worker still root (" + problem + ")", problem != null && problem.contains("root"));
        } finally {
            log.removeHandler(h);
            if (found != null) Files.writeString(FILE, found); else Files.deleteIfExists(FILE);
            DovecotAuthWorker.reload();
            System.out.println("\n  Dovecot put back as found: auth-worker '" + workerSetting() + "'");
        }
    }

    static String workerSetting() {
        return Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-h", "service/auth-worker/user").outputTrim();
    }

    /** A real login on the VM's test mailbox, and a wrong password refused. */
    static void login(String when) throws Exception {
        String box = System.getProperty("test.mailbox", "");
        String passFile = System.getProperty("test.passfile", "");
        if (box.isEmpty() || passFile.isEmpty()) {
            System.out.println("    (no -Dtest.mailbox/-Dtest.passfile: real login not tried " + when + ")");
            return;
        }
        String pass = Files.readString(Path.of(passFile)).trim();
        Shell.Result ok = Shell.run(Duration.ofSeconds(20), DovecotAuthWorker.DOVEADM, "auth", "test", box, pass);
        Shell.Result bad = Shell.run(Duration.ofSeconds(20), DovecotAuthWorker.DOVEADM, "auth", "test", box, pass + "-wrong");
        check("a real login " + when + ": succeeds", ok.success() && ok.outputTrim().contains("auth succeeded"));
        check("  a wrong password " + when + ": refused", !bad.success() && bad.outputTrim().contains("auth failed"));
    }
}
