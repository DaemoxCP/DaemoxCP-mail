package org.daemoxcp.mail.system;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

/**
 * One panel at a time (PanelInstanceLock): a second panel waits a little, then gives up and names the pid of the one
 * running; a panel killed with SIGKILL leaves no orphan lock. The other process is a real one (this class with --hold),
 * because a lock held by the same JVM is not the case that matters.
 *
 * It runs anywhere, in a temporary folder:
 *   java -cp "tests:daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.PanelInstanceLockTest
 */
public class PanelInstanceLockTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 2 && "--hold".equals(args[0])) {
            String r = PanelInstanceLock.acquire(Path.of(args[1]), Duration.ofSeconds(1));
            System.out.println(r == null ? "HOLDING " + ProcessHandle.current().pid() : "BUSY " + r);
            System.out.flush();
            Thread.sleep(120_000);
            return;
        }
        Path dir = Files.createTempDirectory("panel-lock-test");
        Path file = dir.resolve("panel-root.lock");
        String me = String.valueOf(ProcessHandle.current().pid());

        System.out.println("== Nobody holds it ==");
        check("taken at once", PanelInstanceLock.acquire(file, Duration.ofSeconds(1)) == null);
        check("the file says who holds it (this process)", Files.readString(file).trim().equals(me));
        check("asked again by the same process: still its own", PanelInstanceLock.acquire(file, Duration.ofSeconds(1)) == null);
        PanelInstanceLock.release();

        System.out.println("\n== Another panel holds it ==");
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process other = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                PanelInstanceLockTest.class.getName(), "--hold", file.toString()).redirectErrorStream(true).start();
        String line;
        try (BufferedReader out = new BufferedReader(new InputStreamReader(other.getInputStream()))) {
            do { line = out.readLine(); } while (line != null && !line.startsWith("HOLDING") && !line.startsWith("BUSY"));
            check("the other process holds it (" + line + ")", line != null && line.startsWith("HOLDING "));
            String otherPid = line == null ? "" : line.substring("HOLDING ".length()).trim();
            long start = System.nanoTime();
            String who = PanelInstanceLock.acquire(file, Duration.ofSeconds(2));
            long waited = (System.nanoTime() - start) / 1_000_000;
            check("this one gives up and names it (" + who + "), after waiting about 2 s (" + waited + " ms)",
                    otherPid.equals(who) && waited >= 1800 && waited < 10_000);

            System.out.println("\n== The other panel is killed (SIGKILL) ==");
            other.destroyForcibly();
            other.waitFor();
            check("no orphan lock: taken at once", PanelInstanceLock.acquire(file, Duration.ofSeconds(3)) == null);
            check("and the file now names this process", Files.readString(file).trim().equals(me));
        } finally {
            other.destroyForcibly();
            PanelInstanceLock.release();
            Files.deleteIfExists(file);
            Files.deleteIfExists(dir);
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
