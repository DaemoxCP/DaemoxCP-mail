package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * One package job at a time, and the list to lock them again really written.
 *
 * A review of the updates PR: two updates approved from two cards started together and
 * overwrote each other's list on disk; and if the list could not be written (full disk, /var/db
 * not writable) the job unlocked all the same. Here it is tested that only one takes the turn
 * even with many trying at the same instant, that it is freed even if the job fails, and that the
 * list does not overwrite an interrupted job's and, if it cannot be written, says so.
 *
 * The panel's messages are read in English (I18n.setCurrent): outside a request it writes Italian.
 */
public class PackageQueueTest {

    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        org.daemoxcp.mail.i18n.I18n.setCurrent("en");
        // The list in a test folder, not in /var/db.
        Path d = Files.createTempDirectory("turn-test");
        Path f = d.resolve("daemoxcp-mail-maintenance-locks");
        PackageQueue.list = f;
        // And the turn's lock between processes: without it, the test would take the real one, and
        // on a machine with the panel running it would find it taken (or hold it from its jobs).
        PackageQueue.turnLock = d.resolve("package-turn.lock");

        // --- The turn ---
        real("free at the start", PackageQueue.holder() == null);
        real("the first one takes it", PackageQueue.take("a", "maintenance") == null);
        String no = PackageQueue.take("b", "kafka update");
        real("the second one does not, and the message says who holds it", no != null && no.contains("(maintenance"));
        real("not even for the locks, while a job runs",
            PackageQueue.takeForLocks("c", "package protection") != null);
        PackageQueue.release("b");
        real("whoever does not hold it cannot free it", PackageQueue.holder() != null);
        PackageQueue.release("a");
        real("whoever holds it frees it", PackageQueue.holder() == null);

        // Many at the same instant: only one takes it.
        int n = 64;
        CountDownLatch via = new CountDownLatch(1), finished = new CountDownLatch(n);
        AtomicInteger taken = new AtomicInteger();
        for (int i = 0; i < n; i++) {
            final String id = "t" + i;
            Thread.ofPlatform().start(() -> {
                try {
                    via.await();
                    if (PackageQueue.take(id, "job " + id) == null) taken.incrementAndGet();
                } catch (InterruptedException ignored) {
                } finally { finished.countDown(); }
            });
        }
        via.countDown();
        finished.await(10, TimeUnit.SECONDS);
        real(n + " together: only one takes the turn", taken.get() == 1);
        String keeps = PackageQueue.holder();
        PackageQueue.release(keeps.substring("job ".length(), keeps.indexOf(',')));
        real("and then frees it", PackageQueue.holder() == null);

        // start: the turn is freed when the job ends, even if it fails.
        CountDownLatch inside = new CountDownLatch(1), leave = new CountDownLatch(1);
        real("long job: takes the turn", PackageQueue.take("long", "long job") == null);
        PackageQueue.start("long", "test-long", () -> {
            inside.countDown();
            try { leave.await(); } catch (InterruptedException ignored) { }
        });
        inside.await(5, TimeUnit.SECONDS);
        real("while it runs, the turn stays its own", PackageQueue.take("other", "other") != null);
        leave.countDown();
        real("once the job is over, the turn is freed", waitUntilFree());

        Thread.setDefaultUncaughtExceptionHandler((t, x) -> { });   // the wanted exception does not dirty the output
        real("job that fails: takes the turn", PackageQueue.take("broken", "broken job") == null);
        PackageQueue.start("broken", "test-broken", () -> { throw new IllegalStateException("test"); });
        real("even if it fails, the turn is freed", waitUntilFree());

        // --- The list on disk ---
        real("new list: written", PackageQueue.writeState(List.of("kafka", "librdkafka")) == null);
        real("new list: right content", "kafka\nlibrdkafka\n".equals(Files.readString(f)));
        String e = PackageQueue.writeState(f, List.of("nginx"));
        real("list already there: refused", e != null && e.contains("already exists"));
        real("list already there: NOT overwritten", "kafka\nlibrdkafka\n".equals(Files.readString(f)));
        Path withoutFolder = d.resolve("does-not-exist").resolve("daemoxcp-mail-maintenance-locks");
        e = PackageQueue.writeState(withoutFolder, List.of("nginx"));
        real("folder that is not there: refused, and it says why", e != null && e.startsWith("I cannot write"));
        real("folder that is not there: no file left", !Files.exists(withoutFolder));

        // With the list of an unfinished job on disk, those packages might still be unlocked: no job
        // that installs or upgrades starts. Putting the protections back does, because that is the
        // very remedy.
        String e2 = PackageQueue.take("upd", "update of the unprotected packages");
        real("open list: an update does not start", e2 != null && e2.contains("did not finish"));
        real("open list: and the turn does not stay taken", PackageQueue.holder() == null);
        real("open list: the protections can be put back",
            PackageQueue.takeForLocks("lock", "package protection") == null);
        PackageQueue.release("lock");
        PackageQueue.deleteState();
        real("list closed: the update starts", PackageQueue.take("upd", "update") == null);
        PackageQueue.release("upd");

        // The update of the panel's Java (finding 210): its list is there by design while its script works outside the
        // panel. On the real server a job asked meanwhile said "a job that did not finish ... restart the panel".
        real("the Java's list is written", PackageQueue.writeStateForRestart(List.of("openjdk25")) == null);
        String e3 = PackageQueue.take("all", "update of everything");
        real("while the Java's script works: another job does not start, and it says to wait for the Java ("
                + e3 + ")", e3 != null && e3.contains("Java is being updated") && !e3.contains("did not finish") && !e3.contains("restart the panel"));
        real("  and the turn does not stay taken", PackageQueue.holder() == null);
        PackageQueue.deleteState();
        Files.deleteIfExists(PackageQueue.running());

        // The file of the lock between processes stays (the lock is what counts, not the file): it is
        // the test folder's, not the one in /var/db/daemoxcp-mail.
        real("the turn's lock is the test folder's, not the one in /var/db",
            Files.exists(PackageQueue.turnLock) && PackageQueue.turnLock.getParent().equals(d));
        Files.deleteIfExists(PackageQueue.turnLock);
        Files.delete(d);
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    private static boolean waitUntilFree() throws InterruptedException {
        for (int i = 0; i < 100 && PackageQueue.holder() != null; i++) Thread.sleep(50);
        return PackageQueue.holder() == null;
    }

    private static void real(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failed++;
    }
}
