package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.logging.Logger;

/**
 * Un lavoro sui pacchetti morto a meta' si completa da solo: il pannello in servizio controlla quello che il lavoro
 * ha cambiato, rimette in servizio i servizi e verifica.
 *
 * <p>Prima (reperto 152) il pannello riproteggeva i pacchetti e lasciava un avviso: «il lavoro non ha fatto i suoi
 * controlli finali, falli a mano: pkg check -s, riavvia i servizi, reinstalla un pacchetto il cui script potrebbe
 * non essere finito». Il committente (08/11/2026): li deve fare il pannello. Adesso, quando trova la traccia di un
 * lavoro (PackageQueue.runningRecord) il cui processo non c'e' piu':
 * <ol>
 *   <li>aspetta che pkg abbia finito e che i pacchetti siano di nuovo protetti, e prende il turno: nessun altro
 *       lavoro sui pacchetti nel frattempo;</li>
 *   <li>confronta i pacchetti di adesso con quelli che la traccia aveva all'inizio: quello che e' cambiato e' quello
 *       che il lavoro ha fatto prima di morire;</li>
 *   <li>controlla i file dei pacchetti cambiati (pkg check -s) e reinstalla quelli che non tornano;</li>
 *   <li>per ogni servizio di quei pacchetti: se gira ancora coi file di prima (partito prima dell'ultimo pacchetto
 *       che lo riguarda) lo riavvia, dopo avergli fatto provare la configurazione, e controlla che il pid sia
 *       cambiato; se era acceso all'inizio e adesso e' spento lo riaccende; poi i suoi dati (redis);</li>
 *   <li>verifica: i servizi accesi all'inizio sono accesi, e le ricerche della posta rispondono (Postfix e
 *       Dovecot);</li>
 *   <li>scrive nell'avviso che cosa ha fatto. Se tutto torna, l'avviso resta da leggere ma non e' piu' una cosa
 *       da fare; se qualcosa non torna, dice che cosa e come rimediare.</li>
 * </ol>
 * Non lo fa per la reinstallazione completa interrotta (la posta puo' essere spenta con le configurazioni
 * cancellate: li' serve la via di ritorno, e l'avviso la dice), ne' per un riavvio voluto (l'aggiornamento della
 * JVM). Un servizio la cui configurazione non passa la prova non si riavvia: riavviarlo lo spegnerebbe.
 */
public final class InterruptedJobRecovery {

    private static final Logger LOGGER = Logger.getLogger(InterruptedJobRecovery.class.getName());

    private InterruptedJobRecovery() {}

    /** Quello che serve dal sistema, separato per provare le decisioni senza pkg ne' servizi veri. */
    interface Machine {
        long now();
        /** pkg sta lavorando adesso? */
        boolean pkgRunning();
        /** I pacchetti installati adesso, nome -> versione. */
        Map<String, String> inventory();
        /** Quando e' stato installato ciascuno (secondi dall'epoca), per i nomi dati. */
        Map<String, Long> installTimes(Collection<String> names);
        /** I nomi veri (rc.d) dei servizi che un pacchetto riguarda, lui o chi dipende da lui. */
        List<String> servicesOf(String pkg);
        /** Quali servizi sono accesi adesso (solo quelli presenti sul sistema). */
        Map<String, Boolean> servicesState();
        String pid(String service);
        /** Quando e' partito quel processo (secondi dall'epoca), -1 se non si sa. */
        long processStart(String pid);
        /** La prova della configurazione del servizio, o null se non ne ha una. */
        Shell.Result configTest(String service);
        boolean restart(String service);
        boolean start(String service);
        boolean running(String service);
        /** Dopo il riavvio: il servizio ha ritrovato i suoi dati? null se non c'e' una prova, altrimenti il perche' no ("" = si'). */
        String dataCheck(String service);
        /** I pacchetti fra quelli dati i cui file non tornano (pkg check -s). */
        List<String> checksumFailures(Collection<String> pkgs);
        /** Reinstalla quei pacchetti dallo stesso catalogo, togliendo e rimettendo le protezioni: null se riesce. */
        String reinstall(List<String> pkgs);
        /** Le ricerche della posta (Postfix e Dovecot): null se rispondono, altrimenti il perche'. */
        String mailLookups();
    }

    /** Un servizio da rimettere in servizio, e perche'. */
    enum Action { RESTART, START, CHECK }

    /** Che cosa e' cambiato fra l'inizio del lavoro e adesso: nome -> {prima, adesso} ("" = non c'era / non c'e' piu'). */
    static Map<String, String[]> changes(Map<String, String> before, Map<String, String> now) {
        Map<String, String[]> out = new TreeMap<>();
        Set<String> names = new LinkedHashSet<>(before.keySet());
        names.addAll(now.keySet());
        for (String n : names) {
            String b = before.getOrDefault(n, ""), a = now.getOrDefault(n, "");
            if (!b.equals(a)) out.put(n, new String[]{b, a});
        }
        return out;
    }

    /**
     * Che cosa fare di un servizio. RESTART se e' acceso ma col processo partito prima dell'ultimo pacchetto che lo
     * riguarda (gira ancora coi file di prima); START se era acceso all'inizio del lavoro e adesso e' spento; CHECK se
     * e' acceso e gia' partito dopo (per esempio dopo un riavvio della macchina); null se era spento e lo e' ancora.
     */
    static Action decide(boolean wasRunning, boolean running, long processStart, long newestChange) {
        if (running) return processStart >= 0 && processStart > newestChange ? Action.CHECK : Action.RESTART;
        return wasRunning ? Action.START : null;
    }

    /**
     * All'avvio del giro del guardiano (UpdateManager.watchOnce), solo nel pannello in servizio. "" se non c'era
     * niente da fare o se e' presto (pkg lavora ancora, l'elenco c'e' ancora, il turno lo tiene un altro).
     */
    static String completeIfInterrupted(Machine m) {
        JSONObject rec = PackageQueue.runningRecord();
        if (rec.isEmpty()) return "";
        long pid = rec.optLong("pid", 0), self = ProcessHandle.current().pid();
        if (pid == self && PackageQueue.holder() != null) return "";           // un lavoro di questo processo
        if (pid > 0 && pid != self && ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)) return "";
        if (rec.optBoolean("expectsRestart")) {
            PackageQueue.deleteRunning();
            return "";
        }
        // Prima le protezioni (lo fa il ripristino) e pkg fermo: completare mentre pkg scrive vorrebbe dire
        // riavviare servizi a meta' di un aggiornamento.
        if (PackageQueue.statePresent() || m.pkgRunning()) return "";
        String refusal = PackageQueue.takeForLocks("interrupted-recovery", I18n.tr("server.recovery.turnComplete"));
        if (refusal != null) return "";
        try {
            // Riletta col turno: un altro processo puo' averla gia' chiusa.
            rec = PackageQueue.runningRecord();
            if (rec.isEmpty()) return "";
            JSONObject outcome = complete(m, rec);
            PackageQueue.deleteRunning();
            return outcome == null ? "" : outcome.optString("summary");
        } finally {
            PackageQueue.release("interrupted-recovery");
        }
    }

    /** Il lavoro interrotto, completato e verificato. null se non aveva cambiato niente. */
    static JSONObject complete(Machine m, JSONObject rec) {
        String description = rec.optString("description", "");
        boolean reinstallJob = rec.optString("id", "").startsWith(InstallLocks.REINSTALL_TURN_PREFIX);
        JSONObject inv = rec.optJSONObject("inventory");
        JSONObject svc = rec.optJSONObject("services");
        Map<String, String> before = new LinkedHashMap<>();
        if (inv != null) for (String k : inv.keySet()) before.put(k, inv.optString(k));
        Map<String, Boolean> servicesBefore = new LinkedHashMap<>();
        if (svc != null) for (String k : svc.keySet()) servicesBefore.put(k, svc.optBoolean(k));

        Map<String, String> now = m.inventory();
        Map<String, String[]> changed = inv == null ? Map.of() : changes(before, now);
        Map<String, Boolean> servicesNow = m.servicesState();
        boolean fell = false;
        for (Map.Entry<String, Boolean> e : servicesBefore.entrySet())
            if (e.getValue() && !Boolean.TRUE.equals(servicesNow.get(e.getKey()))) fell = true;
        if (changed.isEmpty() && !fell) {
            LOGGER.info("[InterruptedJobRecovery] " + description + " stopped before changing anything: nothing to complete");
            return null;
        }

        JSONObject r = new JSONObject().put("startedUtc", iso(m.now()));
        JSONArray changedJson = new JSONArray();
        for (Map.Entry<String, String[]> e : changed.entrySet())
            changedJson.put(new JSONObject().put("name", e.getKey()).put("from", e.getValue()[0]).put("to", e.getValue()[1]));
        r.put("changed", changedJson);
        List<String> problems = new ArrayList<>();

        if (reinstallJob) {
            // La reinstallazione completa: niente riavvii automatici, la via di ritorno la dice gia' l'avviso.
            r.put("skipped", "reinstall");
            r.put("ok", false).put("problems", new JSONArray().put(I18n.tr("server.recovery.complete.reinstall")));
            PackageRecovery.recordRecovery(rec, r);
            return r.put("summary", "the interrupted job was the complete reinstallation: nothing restarted automatically");
        }

        // 1. I file dei pacchetti cambiati e ancora installati; quelli che non tornano si reinstallano.
        List<String> installedChanged = new ArrayList<>();
        for (Map.Entry<String, String[]> e : changed.entrySet()) if (!e.getValue()[1].isEmpty()) installedChanged.add(e.getKey());
        List<String> broken = installedChanged.isEmpty() ? List.of() : m.checksumFailures(installedChanged);
        r.put("checked", new JSONArray(installedChanged));
        if (!broken.isEmpty()) {
            String err = m.reinstall(broken);
            r.put("reinstalled", new JSONArray(broken));
            if (err != null) {
                problems.add(I18n.tr("server.recovery.complete.reinstallFailed", Map.of("list", String.join(" ", broken), "err", err)));
            } else {
                List<String> still = m.checksumFailures(broken);
                if (!still.isEmpty())
                    problems.add(I18n.tr("server.recovery.complete.stillBroken", Map.of("list", String.join(" ", still))));
            }
        }

        // 2. I servizi: quelli dei pacchetti cambiati, e quelli accesi all'inizio e spenti adesso.
        Map<String, Long> times = m.installTimes(installedChanged);
        Map<String, Long> newestFor = new LinkedHashMap<>();
        for (String p : installedChanged)
            for (String s : m.servicesOf(p))
                newestFor.merge(s, times.getOrDefault(p, m.now()), Math::max);
        for (Map.Entry<String, Boolean> e : servicesBefore.entrySet())
            if (e.getValue() && !Boolean.TRUE.equals(servicesNow.get(e.getKey()))) newestFor.putIfAbsent(e.getKey(), 0L);
        JSONArray services = new JSONArray();
        for (Map.Entry<String, Long> e : newestFor.entrySet()) {
            String s = e.getKey();
            boolean running = m.running(s);
            String pidBefore = running ? m.pid(s) : "";
            Action a = decide(Boolean.TRUE.equals(servicesBefore.get(s)), running,
                    pidBefore.isEmpty() ? -1 : m.processStart(pidBefore), e.getValue());
            if (a == null) continue;
            JSONObject o = new JSONObject().put("name", s).put("action", a.name().toLowerCase());
            if (a != Action.CHECK) {
                Shell.Result test = m.configTest(s);
                if (test != null && !test.success()) {
                    o.put("ok", false).put("why", I18n.tr("server.recovery.complete.configRefused", Map.of("s", s)));
                    problems.add(o.getString("why"));
                    services.put(o);
                    continue;
                }
                boolean done = a == Action.RESTART ? m.restart(s) : m.start(s);
                String pidAfter = m.running(s) ? m.pid(s) : "";
                o.put("pidBefore", pidBefore).put("pidAfter", pidAfter);
                if (!done || pidAfter.isEmpty()) {
                    o.put("ok", false).put("why", I18n.tr("server.recovery.complete.notRunning", Map.of("s", s)));
                    problems.add(o.getString("why"));
                    services.put(o);
                    continue;
                }
                if (a == Action.RESTART && !pidBefore.isEmpty() && pidBefore.equals(pidAfter)) {
                    o.put("ok", false).put("why", I18n.tr("server.recovery.complete.samePid", Map.of("s", s, "pid", pidAfter)));
                    problems.add(o.getString("why"));
                    services.put(o);
                    continue;
                }
            }
            String data = m.dataCheck(s);
            if (data != null && !data.isEmpty()) {
                o.put("ok", false).put("why", data);
                problems.add(data);
            } else {
                o.put("ok", true);
            }
            services.put(o);
        }
        r.put("services", services);

        // 3. La verifica: accesi quelli accesi all'inizio, e la posta che trova le caselle.
        Map<String, Boolean> after = m.servicesState();
        for (Map.Entry<String, Boolean> e : servicesBefore.entrySet())
            if (e.getValue() && !Boolean.TRUE.equals(after.get(e.getKey())))
                problems.add(I18n.tr("server.recovery.complete.notRunning", Map.of("s", e.getKey())));
        String lookups = m.mailLookups();
        if (lookups != null) problems.add(I18n.tr("server.recovery.complete.lookups", Map.of("why", lookups)));

        LinkedHashSet<String> unique = new LinkedHashSet<>(problems);
        r.put("problems", new JSONArray(new ArrayList<>(unique))).put("ok", unique.isEmpty()).put("finishedUtc", iso(m.now()));
        PackageRecovery.recordRecovery(rec, r);
        String summary = description + ": " + changed.size() + " packages changed, " + services.length()
                + " services handled, " + (unique.isEmpty() ? "all verified" : "problems: " + String.join("; ", unique));
        if (unique.isEmpty()) LOGGER.info("[InterruptedJobRecovery] DONE: " + summary);
        else LOGGER.warning("[InterruptedJobRecovery] " + summary);
        return r.put("summary", summary);
    }

    private static String iso(long epochSeconds) {
        return Instant.ofEpochSecond(epochSeconds).truncatedTo(ChronoUnit.SECONDS).toString();
    }
}
