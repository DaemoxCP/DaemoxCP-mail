package org.mail_panel.system;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** L'attesa della propagazione, con un orologio finto: sei minuti veri non si aspettano. */
public class PropagationWaitTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    /** Orologio finto: non dorme, avanza. */
    static class FakeClock implements MtaStsSetup.Clock {
        long t = 0; final AtomicInteger slept = new AtomicInteger();
        public long now() { return t; }
        public void sleep(long ms) throws InterruptedException { slept.incrementAndGet(); t += ms; }
    }

    public static void main(String[] a) {
        final long MAX = 6 * 60 * 1000L, INT = 30 * 1000L;

        System.out.println("\n== rispondono gia': non si aspetta un istante ==");
        FakeClock o = new FakeClock();
        List<String> remain = MtaStsSetup.waitForPropagation(
                List.of("a.it", "b.it"), d -> true, o, MAX, INT, r -> {});
        require("nessuno resta indietro", remain.isEmpty());
        require("non ha dormito nemmeno una volta", o.slept.get() == 0);

        System.out.println("\n== risponde al terzo tentativo: si smette subito dopo ==");
        o = new FakeClock();
        AtomicInteger attempts = new AtomicInteger();
        remain = MtaStsSetup.waitForPropagation(
                List.of("domain-d.test"), d -> attempts.incrementAndGet() >= 3, o, MAX, INT, r -> {});
        require("alla fine risponde", remain.isEmpty());
        require("ha dormito 2 volte, non di piu'", o.slept.get() == 2);
        require("l'orologio e' avanzato di 60s, non di 6 minuti", o.t == 60_000L);

        System.out.println("\n== non risponde mai: si esce alla scadenza, non si gira per sempre ==");
        o = new FakeClock();
        remain = MtaStsSetup.waitForPropagation(
                List.of("mai.it"), d -> false, o, MAX, INT, r -> {});
        require("il dominio viene restituito come non risolto", remain.equals(List.of("mai.it")));
        require("il ciclo e' finito (nessun blocco)", true);
        require("ha dormito 12 volte: 6 minuti / 30s", o.slept.get() == 12);
        require("non ha superato la scadenza", o.t <= MAX);

        System.out.println("\n== elenco vuoto: non deve nemmeno entrare nel ciclo ==");
        o = new FakeClock();
        remain = MtaStsSetup.waitForPropagation(
                new ArrayList<>(), d -> false, o, MAX, INT, r -> {});
        require("torna vuoto", remain.isEmpty());
        require("non ha dormito", o.slept.get() == 0);

        System.out.println("\n== uno risponde e uno no: si restituisce solo quello che manca ==");
        o = new FakeClock();
        remain = MtaStsSetup.waitForPropagation(
                List.of("ok.it", "no.it"), d -> d.equals("ok.it"), o, MAX, INT, r -> {});
        require("resta solo no.it", remain.equals(List.of("no.it")));

        System.out.println("\n== l'interruzione fa uscire subito ==");
        o = new FakeClock() { public void sleep(long ms) throws InterruptedException {
            slept.incrementAndGet(); throw new InterruptedException(); } };
        remain = MtaStsSetup.waitForPropagation(
                List.of("x.it"), d -> false, o, MAX, INT, r -> {});
        require("esce dopo una sola attesa", o.slept.get() == 1);
        require("segnala il dominio come non risolto", remain.equals(List.of("x.it")));
        require("il flag di interruzione del thread resta alzato", Thread.interrupted());

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }
}
