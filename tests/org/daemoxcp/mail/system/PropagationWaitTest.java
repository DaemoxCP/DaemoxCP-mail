package org.daemoxcp.mail.system;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** Waiting for propagation, with a fake clock: six real minutes are not waited for. */
public class PropagationWaitTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** Fake clock: it does not sleep, it moves on. */
    static class FakeClock implements MtaStsSetup.Clock {
        long t = 0; final AtomicInteger slept = new AtomicInteger();
        public long now() { return t; }
        public void sleep(long ms) throws InterruptedException { slept.incrementAndGet(); t += ms; }
    }

    public static void main(String[] a) {
        final long MAX = 6 * 60 * 1000L, INT = 30 * 1000L;

        System.out.println("\n== they already answer: not an instant is waited ==");
        FakeClock o = new FakeClock();
        List<String> remain = MtaStsSetup.waitForPropagation(
                List.of("a.it", "b.it"), d -> true, o, MAX, INT, r -> {});
        require("none is left behind", remain.isEmpty());
        require("it did not sleep even once", o.slept.get() == 0);

        System.out.println("\n== it answers at the third try: it stops right after ==");
        o = new FakeClock();
        AtomicInteger attempts = new AtomicInteger();
        remain = MtaStsSetup.waitForPropagation(
                List.of("domain-d.test"), d -> attempts.incrementAndGet() >= 3, o, MAX, INT, r -> {});
        require("in the end it answers", remain.isEmpty());
        require("it slept 2 times, no more", o.slept.get() == 2);
        require("the clock moved 60 s, not 6 minutes", o.t == 60_000L);

        System.out.println("\n== it never answers: it leaves at the deadline, it does not loop forever ==");
        o = new FakeClock();
        remain = MtaStsSetup.waitForPropagation(
                List.of("never.it"), d -> false, o, MAX, INT, r -> {});
        require("the domain is returned as not resolved", remain.equals(List.of("never.it")));
        require("the loop ended (no hang)", true);
        require("it slept 12 times: 6 minutes / 30 s", o.slept.get() == 12);
        require("it did not pass the deadline", o.t <= MAX);

        System.out.println("\n== empty list: it must not even enter the loop ==");
        o = new FakeClock();
        remain = MtaStsSetup.waitForPropagation(
                new ArrayList<>(), d -> false, o, MAX, INT, r -> {});
        require("it comes back empty", remain.isEmpty());
        require("it did not sleep", o.slept.get() == 0);

        System.out.println("\n== one answers and one does not: only the missing one is returned ==");
        o = new FakeClock();
        remain = MtaStsSetup.waitForPropagation(
                List.of("ok.it", "no.it"), d -> d.equals("ok.it"), o, MAX, INT, r -> {});
        require("only no.it is left", remain.equals(List.of("no.it")));

        System.out.println("\n== the interruption makes it leave at once ==");
        o = new FakeClock() { public void sleep(long ms) throws InterruptedException {
            slept.incrementAndGet(); throw new InterruptedException(); } };
        remain = MtaStsSetup.waitForPropagation(
                List.of("x.it"), d -> false, o, MAX, INT, r -> {});
        require("it leaves after one wait", o.slept.get() == 1);
        require("it reports the domain as not resolved", remain.equals(List.of("x.it")));
        require("the thread's interrupt flag stays raised", Thread.interrupted());

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }
}
