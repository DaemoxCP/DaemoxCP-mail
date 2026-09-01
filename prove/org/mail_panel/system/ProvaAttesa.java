package org.mail_panel.system;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** L'attesa della propagazione, con un orologio finto: sei minuti veri non si aspettano. */
public class ProvaAttesa {

    static int falliti = 0;
    static void esigi(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }

    /** Orologio finto: non dorme, avanza. */
    static class Finto implements AttivaMtaSts.Orologio {
        long t = 0; final AtomicInteger dormite = new AtomicInteger();
        public long adesso() { return t; }
        public void dormi(long ms) throws InterruptedException { dormite.incrementAndGet(); t += ms; }
    }

    public static void main(String[] a) {
        final long MAX = 6 * 60 * 1000L, INT = 30 * 1000L;

        System.out.println("\n== rispondono gia': non si aspetta un istante ==");
        Finto o = new Finto();
        List<String> restano = AttivaMtaSts.attendiPropagazione(
                List.of("a.it", "b.it"), d -> true, o, MAX, INT, r -> {});
        esigi("nessuno resta indietro", restano.isEmpty());
        esigi("non ha dormito nemmeno una volta", o.dormite.get() == 0);

        System.out.println("\n== risponde al terzo tentativo: si smette subito dopo ==");
        o = new Finto();
        AtomicInteger tentativi = new AtomicInteger();
        restano = AttivaMtaSts.attendiPropagazione(
                List.of("domain-d.test"), d -> tentativi.incrementAndGet() >= 3, o, MAX, INT, r -> {});
        esigi("alla fine risponde", restano.isEmpty());
        esigi("ha dormito 2 volte, non di piu'", o.dormite.get() == 2);
        esigi("l'orologio e' avanzato di 60s, non di 6 minuti", o.t == 60_000L);

        System.out.println("\n== non risponde mai: si esce alla scadenza, non si gira per sempre ==");
        o = new Finto();
        restano = AttivaMtaSts.attendiPropagazione(
                List.of("mai.it"), d -> false, o, MAX, INT, r -> {});
        esigi("il dominio viene restituito come non risolto", restano.equals(List.of("mai.it")));
        esigi("il ciclo e' finito (nessun blocco)", true);
        esigi("ha dormito 12 volte: 6 minuti / 30s", o.dormite.get() == 12);
        esigi("non ha superato la scadenza", o.t <= MAX);

        System.out.println("\n== elenco vuoto: non deve nemmeno entrare nel ciclo ==");
        o = new Finto();
        restano = AttivaMtaSts.attendiPropagazione(
                new ArrayList<>(), d -> false, o, MAX, INT, r -> {});
        esigi("torna vuoto", restano.isEmpty());
        esigi("non ha dormito", o.dormite.get() == 0);

        System.out.println("\n== uno risponde e uno no: si restituisce solo quello che manca ==");
        o = new Finto();
        restano = AttivaMtaSts.attendiPropagazione(
                List.of("ok.it", "no.it"), d -> d.equals("ok.it"), o, MAX, INT, r -> {});
        esigi("resta solo no.it", restano.equals(List.of("no.it")));

        System.out.println("\n== l'interruzione fa uscire subito ==");
        o = new Finto() { public void dormi(long ms) throws InterruptedException {
            dormite.incrementAndGet(); throw new InterruptedException(); } };
        restano = AttivaMtaSts.attendiPropagazione(
                List.of("x.it"), d -> false, o, MAX, INT, r -> {});
        esigi("esce dopo una sola attesa", o.dormite.get() == 1);
        esigi("segnala il dominio come non risolto", restano.equals(List.of("x.it")));
        esigi("il flag di interruzione del thread resta alzato", Thread.interrupted());

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }
}
