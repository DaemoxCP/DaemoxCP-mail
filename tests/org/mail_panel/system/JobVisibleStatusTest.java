package org.mail_panel.system;

import org.json.JSONObject;

/**
 * Un lavoro e' finito quando ha finito, non quando ha un esito.
 *
 * La manutenzione completa scriveva "completed" appena pkg upgrade usciva con 0, e DOPO
 * confrontava con il piano e con l'inventario, riproteggeva i pacchetti, controllava
 * protezioni e servizi: cinque passi che possono cambiare l'esito in "error". La pagina
 * (updPoll) smette di chiedere al primo esito che vede. Misurato sulla VM FreeBSD 15.1 il
 * 23/10/2026: una sonda fermata al primo "completed" ha trovato 14 pacchetti su 39 ancora da
 * riproteggere, e il log senza la verifica finale.
 *
 * Le prove sono scritte per FALLIRE senza la correzione: la 3 e la 7 riproducono il lavoro
 * che dice "completed" e poi continua, e guardano quello che la pagina avrebbe visto.
 */
public class JobVisibleStatusTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {

        // --- 1. Gli stati di prima di un esito restano come sono ---
        UpdateManager.Job j = new UpdateManager.Job("prova-1", "prova");
        check("un lavoro appena creato e' \"pending\"", "pending".equals(seenStatus(j)));
        j.status = "running";
        check("un lavoro in corso e' \"running\"", "running".equals(seenStatus(j)));

        // --- 2. "completed" senza la fine scritta: il lavoro non ha finito ---
        j.status = "completed";
        check("\"completed\" con il lavoro ancora aperto si vede \"running\"", "running".equals(seenStatus(j)));
        j.finishedAt = System.currentTimeMillis();
        check("  e si vede \"completed\" appena la fine e' scritta", "completed".equals(seenStatus(j)));

        // --- 3. Lo stesso per "error" ---
        UpdateManager.Job e = new UpdateManager.Job("prova-3", "prova");
        e.status = "error";
        e.errorMessage = "qualcosa";
        check("\"error\" con il lavoro ancora aperto si vede \"running\"", "running".equals(seenStatus(e)));
        e.finishedAt = System.currentTimeMillis();
        check("  e si vede \"error\" appena la fine e' scritta", "error".equals(seenStatus(e)));
        check("  con il suo messaggio", "qualcosa".equals(e.toJson().optString("errorMessage")));

        // --- 4. La fine scritta dal pavimento, quando il lavoro se la dimentica ---
        UpdateManager.Job d = new UpdateManager.Job("prova-4", "prova");
        UpdateManager.withEndMarked(d, () -> d.status = "completed").run();
        check("un lavoro che da' l'esito senza scrivere la fine non resta \"running\" per sempre",
             "completed".equals(seenStatus(d)) && d.finishedAt > 0);

        // --- 5. ... anche quando esce con un'eccezione ---
        UpdateManager.Job x = new UpdateManager.Job("prova-5", "prova");
        boolean propagated = false;
        try {
            UpdateManager.withEndMarked(x, () -> { x.status = "error"; throw new IllegalStateException("guasto"); }).run();
        } catch (IllegalStateException ex) { propagated = true; }
        check("un lavoro che esce con un'eccezione ha la fine scritta", x.finishedAt > 0 && "error".equals(seenStatus(x)));
        check("  e l'eccezione non viene inghiottita", propagated);

        // --- 6. Il pavimento non sposta la fine di chi l'ha scritta ---
        UpdateManager.Job f = new UpdateManager.Job("prova-6", "prova");
        UpdateManager.withEndMarked(f, () -> { f.status = "completed"; f.finishedAt = 12345L; }).run();
        check("la fine scritta dal lavoro resta quella", f.finishedAt == 12345L);

        // --- 7. La forma vera della manutenzione, guardata come la guarda la pagina ---
        // Il lavoro dice "completed", poi riprotegge e verifica, poi scrive la fine. Chi chiede
        // lo stato mentre il lavoro gira non deve mai vedere un esito senza la verifica finale.
        UpdateManager.Job m = new UpdateManager.Job("prova-7", "prova");
        Thread work = new Thread(UpdateManager.withEndMarked(m, () -> {
            m.status = "running";
            m.write("pkg upgrade terminato con codice 0");
            m.status = "completed";
            try {
                for (int i = 1; i <= 5; i++) { Thread.sleep(60); m.write("  riprotetto " + i + "/5"); }
                Thread.sleep(60);
                m.write("Verifica superata");
            } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            finally { m.finishedAt = System.currentTimeMillis(); }
        }));
        work.setDaemon(true);
        work.start();
        String firstOutcome = null, logAtFirstOutcome = null;
        long t0 = System.currentTimeMillis();
        while (System.currentTimeMillis() - t0 < 10_000) {
            JSONObject s = m.toJson();
            String st = s.optString("status");
            if ("completed".equals(st) || "error".equals(st)) {
                firstOutcome = st;
                logAtFirstOutcome = s.optString("consoleLog");
                break;
            }
            Thread.sleep(10);
        }
        check("la pagina vede un esito (" + firstOutcome + ")", "completed".equals(firstOutcome));
        check("  e quando lo vede la riprotezione e' finita",
             logAtFirstOutcome != null && logAtFirstOutcome.contains("riprotetto 5/5"));
        check("  e c'e' la verifica finale", logAtFirstOutcome != null && logAtFirstOutcome.contains("Verifica superata"));

        // --- 8. L'esito cambiato nel finally arriva alla pagina ---
        // E' il caso che faceva danno: "completed" nel corpo, poi la riprotezione fallisce e il
        // finally lo cambia in "error". La pagina, fermata al primo "completed", non lo sapeva.
        UpdateManager.Job g = new UpdateManager.Job("prova-8", "prova");
        Thread failing = new Thread(UpdateManager.withEndMarked(g, () -> {
            g.status = "completed";
            try { Thread.sleep(200); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            g.status = "error";
            g.errorMessage = "protezione persa";
            g.finishedAt = System.currentTimeMillis();
        }));
        failing.setDaemon(true);
        failing.start();
        firstOutcome = null;
        t0 = System.currentTimeMillis();
        while (System.currentTimeMillis() - t0 < 10_000) {
            String st = g.toJson().optString("status");
            if ("completed".equals(st) || "error".equals(st)) { firstOutcome = st; break; }
            Thread.sleep(10);
        }
        check("un esito cambiato in \"error\" dopo il \"completed\" arriva come \"error\" (" + firstOutcome + ")",
             "error".equals(firstOutcome));

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    /** Lo stato come lo riceve la pagina: e' l'unico che conta. */
    private static String seenStatus(UpdateManager.Job j) {
        return j.toJson().optString("status");
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
