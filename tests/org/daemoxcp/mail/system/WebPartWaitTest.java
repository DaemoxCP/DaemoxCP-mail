package org.daemoxcp.mail.system;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * The root part waits for the web part (PanelSeparation.waitForWeb). Measured on the VM on 20/11/2026: once over many
 * starts the root part checked daemon(8)'s pidfile right after daemon returned, before the new supervisor had written
 * it, read an empty or stale pid, said «the web part stopped right away» and served everything as root.
 *  1. a pause before every check, the first one included;
 *  2. the supervisor not there yet at the first check, then there and answering: the web part is up;
 *  3. missing for GONE_CHECKS checks in a row: stopped; missing now and then, never that many in a row: still waited for;
 *  4. there but never answering: silent at the deadline.
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.WebPartWaitTest
 */
public class WebPartWaitTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** A web part that follows a script: the supervisor's pid at each check (0 = missing), answering from a check on. */
    static PanelSeparation.Probe script(int[] supervisor, int answersFrom, AtomicInteger checks) {
        return new PanelSeparation.Probe() {
            @Override public int supervisor() {
                int i = checks.getAndIncrement();
                return supervisor[Math.min(i, supervisor.length - 1)];
            }
            @Override public boolean answering() { return checks.get() - 1 >= answersFrom; }
        };
    }

    public static void main(String[] a) {
        System.out.println("== 1. A pause before every check");
        AtomicInteger pauses = new AtomicInteger(), checks = new AtomicInteger();
        String r = PanelSeparation.waitForWeb(script(new int[]{1234}, 0, checks), 90, pauses::incrementAndGet);
        check("up at the first check, after one pause (" + pauses.get() + ")", r == null && pauses.get() == 1 && checks.get() == 1);

        System.out.println("\n== 2. The pidfile not written yet at the first check");
        checks.set(0);
        r = PanelSeparation.waitForWeb(script(new int[]{-1, 1234}, 1, checks), 90, () -> { });
        check("missing once, then there and answering: up (was «stopped right away»)", r == null && checks.get() == 2);
        checks.set(0);
        r = PanelSeparation.waitForWeb(script(new int[]{-1, -1, 1234}, 2, checks), 90, () -> { });
        check("missing twice, then there: up", r == null);

        System.out.println("\n== 3. Stopped for real");
        checks.set(0);
        r = PanelSeparation.waitForWeb(script(new int[]{-1}, 0, checks), 90, () -> { });
        check("missing " + PanelSeparation.GONE_CHECKS + " checks in a row: stopped, at once", PanelSeparation.GONE.equals(r)
                && checks.get() == PanelSeparation.GONE_CHECKS);
        checks.set(0);
        r = PanelSeparation.waitForWeb(script(new int[]{-1, -1, 1234, -1, -1, 1234, 1234}, 6, checks), 90, () -> { });
        check("missing now and then, never three in a row: waited for, then up", r == null && checks.get() == 7);
        check("three checks in a row", PanelSeparation.GONE_CHECKS == 3);

        System.out.println("\n== 4. Never answering");
        checks.set(0);
        r = PanelSeparation.waitForWeb(script(new int[]{1234}, Integer.MAX_VALUE, checks), 5, () -> { });
        check("there but silent: SILENT after the seconds given (" + checks.get() + " checks)", PanelSeparation.SILENT.equals(r) && checks.get() == 5);

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
