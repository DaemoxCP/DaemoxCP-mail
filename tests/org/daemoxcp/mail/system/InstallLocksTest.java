package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The full reinstallation with the protected packages (InstallLocks), with a fake pkg.
 *
 * The real pkg cannot give the faults that matter here: an unlock that says yes and does not
 * unlock, a read of the locks that does not answer, a relock that fails. With the fake one they are
 * all tested, and for each the same thing that matters on the machine is looked at: whether the
 * script can start, what stays protected, whether the list on disk closes or stays, whether the turn
 * is freed. The list, the job record and the turn's lock live in a test folder, not in /var/db.
 *
 * The real case (the panel running, 39 protected, the reinstallation from the menu) is tested by
 * MenuReinstall on the VM; this test runs anywhere, but it must be run on the VM like the others.
 */
public class InstallLocksTest {

    private static int failed = 0;

    /** Fake pkg: who is protected, who is installed, and the faults to plant. */
    static final class FakePkg implements InstallLocks.Pkg {
        final Map<String, Boolean> locked = new LinkedHashMap<>();   // name -> protected
        final Set<String> installed = new TreeSet<>();
        final List<String> calls = new ArrayList<>();
        Set<String> unlockLies = Set.of();      // pkg unlock says yes, but it stays protected
        Set<String> lockFails = Set.of();       // pkg lock fails
        int lockListNullFrom = Integer.MAX_VALUE; // from the n-th read, pkg does not answer
        Runnable onFirstRead = null;            // something that happens during the first read
        String explodeAt = null;                // pkg blows up unlocking this package
        boolean stateExistedAtFirstUnlock = false;
        int reads = 0;

        FakePkg with(String... names) {
            for (String n : names) { locked.put(n, true); installed.add(n); }
            return this;
        }

        public String lockList() {
            reads++;
            calls.add("list");
            if (reads == 1 && onFirstRead != null) onFirstRead.run();
            if (reads >= lockListNullFrom) return null;
            StringBuilder sb = new StringBuilder();
            for (var e : locked.entrySet()) if (e.getValue()) sb.append(e.getKey()).append("-1.0_1\n");
            return sb.toString().trim();
        }
        public boolean unlock(String n) {
            calls.add("unlock " + n);
            if (!calls.contains("unlocked-once")) {
                calls.add("unlocked-once");
                stateExistedAtFirstUnlock = PackageQueue.statePresent();
            }
            if (n.equals(explodeAt)) throw new IllegalStateException("test: pkg blows up on " + n);
            if (unlockLies.contains(n)) return true;
            if (!locked.containsKey(n)) return false;
            locked.put(n, false);
            return true;
        }
        public boolean lock(String n) {
            calls.add("lock " + n);
            if (lockFails.contains(n) || !installed.contains(n)) return false;
            locked.put(n, true);
            return true;
        }
        public boolean installed(String n) { return installed.contains(n); }

        int unlockCalls() { return (int) calls.stream().filter(c -> c.startsWith("unlock ")).count(); }
        long lockedCount() { return locked.values().stream().filter(b -> b).count(); }
    }

    public static void main(String[] args) throws Exception {
        Path d = Files.createTempDirectory("install-locks");
        PackageQueue.list = d.resolve("daemoxcp-mail-maintenance-locks");
        PackageQueue.turnLock = d.resolve("package-turn.lock");
        Path list = PackageQueue.list;

        System.out.println("== No protected package ==");
        FakePkg p = new FakePkg();
        InstallLocks.Start s = InstallLocks.prepare("test", p);
        check("it starts", s.refusal() == null && s.held() != null);
        check("it unlocks nothing and does not write the list", p.unlockCalls() == 0 && !Files.exists(list));
        check("it holds the turn", PackageQueue.holder() != null);
        InstallLocks.finish(s.held(), p, false);
        check("at the end the turn is free", PackageQueue.holder() == null);

        System.out.println("\n== Three protected, all well ==");
        p = new FakePkg().with("mysql84-server", "dovecot-mysql", "nginx");
        s = InstallLocks.prepare("test", p);
        check("it starts", s.refusal() == null && s.held() != null);
        check("the list was on disk BEFORE the first unlock", p.stateExistedAtFirstUnlock);
        check("the list names the three packages, without version",
                Files.readString(list).equals("dovecot-mysql\nmysql84-server\nnginx\n"));
        check("all three unlocked", p.lockedCount() == 0);
        // Next to the list, whoever wrote it: if this process dies, the start notice
        // (PackageRecovery) says the reinstallation was interrupted, not "a job".
        check("the job record says which job and from which process",
                "test".equals(PackageQueue.jobRecord().optString("description"))
                && PackageQueue.jobRecord().optLong("pid") == ProcessHandle.current().pid()
                && !PackageQueue.jobRecord().optBoolean("expectsRestart"));
        check("the report says how many and where the list is",
                s.report().contains("3") && s.report().contains(list.toString()));
        check("another job does not take the turn", PackageQueue.take("other", "other") != null);
        // The script reinstalled the packages: all must be locked again, the list closes.
        String back = InstallLocks.finish(s.held(), p, false);
        check("all three locked again", p.lockedCount() == 3);
        check("the list is closed", !Files.exists(list));
        check("and the job record with it", !Files.exists(PackageQueue.jobRecordPath()));
        check("the turn is free", PackageQueue.holder() == null);
        check("the report says 3 protected again", back.contains("3"));
        check("a second close does nothing", InstallLocks.finish(s.held(), p, false).isEmpty());

        System.out.println("\n== The script removed a package ==");
        p = new FakePkg().with("mysql84-server", "dovecot");
        s = InstallLocks.prepare("test", p);
        p.installed.remove("dovecot");
        p.locked.remove("dovecot");
        back = InstallLocks.finish(s.held(), p, false);
        check("the other one is protected again", p.locked.get("mysql84-server"));
        check("the list closes all the same (like the restore at start)", !Files.exists(list));
        check("and the report names the one that vanished", back.contains("dovecot"));

        System.out.println("\n== A relock fails ==");
        p = new FakePkg().with("mysql84-server", "nginx");
        s = InstallLocks.prepare("test", p);
        p.lockFails = Set.of("nginx");
        back = InstallLocks.finish(s.held(), p, false);
        check("the list STAYS, so the next start tries again", Files.exists(list));
        check("the report names nginx as not protected", back.contains("nginx") && back.contains(list.toString()));
        check("the turn is freed anyway", PackageQueue.holder() == null);
        Files.delete(list);

        System.out.println("\n== After the script pkg does not answer ==");
        p = new FakePkg().with("mysql84-server");
        s = InstallLocks.prepare("test", p);
        p.lockListNullFrom = p.reads + 1;
        back = InstallLocks.finish(s.held(), p, false);
        check("it is not known whether it is protected: the list stays", Files.exists(list));
        check("and the report says so", back.contains(list.toString()));
        check("the turn is freed", PackageQueue.holder() == null);
        Files.delete(list);

        System.out.println("\n== An unlock says yes and does not unlock ==");
        p = new FakePkg().with("mysql84-server", "nginx", "redis");
        p.unlockLies = Set.of("mysql84-server");
        s = InstallLocks.prepare("test", p);
        check("it does NOT start", s.refusal() != null && s.held() == null);
        check("the refusal names the package left protected", s.refusal().contains("mysql84-server"));
        check("the others are protected again: as before", p.lockedCount() == 3);
        check("the list is closed", !Files.exists(list));
        check("the turn is free", PackageQueue.holder() == null);

        System.out.println("\n== pkg does not say who is protected ==");
        p = new FakePkg().with("mysql84-server");
        p.lockListNullFrom = 1;
        s = InstallLocks.prepare("test", p);
        check("it does NOT start", s.refusal() != null && s.held() == null);
        check("it unlocked nothing and did not write the list", p.unlockCalls() == 0 && !Files.exists(list));
        check("the turn is free", PackageQueue.holder() == null);

        System.out.println("\n== After the unlock pkg does not answer ==");
        p = new FakePkg().with("mysql84-server", "nginx");
        p.lockListNullFrom = 2;
        s = InstallLocks.prepare("test", p);
        check("it does NOT start: it is not known whether the unlock succeeded", s.refusal() != null && s.held() == null);
        check("it tried to lock both again", p.calls.contains("lock mysql84-server") && p.calls.contains("lock nginx"));
        check("and, without being able to check it, the list stays for the next start", Files.exists(list));
        check("the turn is free", PackageQueue.holder() == null);
        Files.delete(list);

        System.out.println("\n== The list cannot be written ==");
        // Another job's list appears while the locks are read: writeState refuses it (CREATE_NEW),
        // and then nothing must be unlocked.
        p = new FakePkg().with("mysql84-server", "nginx");
        p.onFirstRead = () -> {
            try { Files.writeString(list, "kafka\n"); } catch (Exception e) { throw new RuntimeException(e); }
        };
        s = InstallLocks.prepare("test", p);
        check("it does NOT start", s.refusal() != null && s.held() == null);
        check("it unlocked nothing", p.unlockCalls() == 0 && p.lockedCount() == 2);
        check("the other one's list is untouched", Files.readString(list).equals("kafka\n"));
        check("the turn is free", PackageQueue.holder() == null);
        Files.delete(list);

        System.out.println("\n== pkg blows up halfway through the unlock ==");
        p = new FakePkg().with("mysql84-server", "nginx");
        p.explodeAt = "nginx";   // the second in order: mysql84-server is already unlocked
        s = InstallLocks.prepare("test", p);
        check("it does NOT start", s.refusal() != null && s.held() == null);
        check("the first one had really been unlocked", p.calls.contains("unlock mysql84-server"));
        check("it locked again what was there", p.lockedCount() == 2);
        check("the list is closed", !Files.exists(list));
        check("the turn is free", PackageQueue.holder() == null);

        System.out.println("\n== The turn is already taken ==");
        check("another job takes the turn", PackageQueue.take("maint", "maintenance") == null);
        p = new FakePkg().with("mysql84-server");
        s = InstallLocks.prepare("test", p);
        check("it does NOT start, and it says who holds it", s.refusal() != null && s.refusal().contains("maintenance"));
        check("and it asked pkg nothing", p.calls.isEmpty());
        PackageQueue.release("maint");

        System.out.println("\n== There is the list of an interrupted job ==");
        Files.writeString(list, "kafka\n");
        p = new FakePkg().with("mysql84-server");
        s = InstallLocks.prepare("test", p);
        check("it does NOT start", s.refusal() != null && s.held() == null);
        check("and it asked pkg nothing", p.calls.isEmpty());
        Files.delete(list);

        Files.deleteIfExists(PackageQueue.turnLock);
        Files.deleteIfExists(PackageQueue.jobRecordPath());
        Files.delete(d);
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failed++;
    }
}
