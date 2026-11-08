package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Dopo un lavoro sui pacchetti che non e' arrivato in fondo: riproteggere anche quando pkg sta
 * ancora lavorando, e DIRLO.
 *
 * Misurato sulla VM il 06/11/2026 (reperto 147):
 *  - il pannello ucciso a meta' di un aggiornamento: pkg continua e finisce da solo; il pannello
 *    riavviato mentre pkg lavora non riesce a riproteggere («PROTECTING AGAIN FAILED») e il
 *    pacchetto restava sbloccato fino al riavvio SUCCESSIVO, cioe' anche per settimane;
 *  - la corrente che manca durante pkg: all'avvio il pacchetto si riprotegge, ma risulta
 *    installato con lo script di installazione mai finito;
 *  - in tutti e due i casi l'unica traccia era una riga WARNING nel log: niente in pagina, niente
 *    nel rapporto periodico.
 *
 * Qui stanno le due risposte: il ripristino che riprova da solo ogni RETRY_SECONDS finche' pkg
 * non ha finito, e l'avviso su disco (NOTICE_PATH) che la pagina Aggiornamenti e il rapporto
 * mostrano finche' un amministratore non dice di aver controllato.
 */
public final class PackageRecovery {

    private PackageRecovery() {}

    private static final Logger LOGGER = Logger.getLogger(PackageRecovery.class.getName());

    /** L'avviso di un lavoro interrotto: resta finche' un amministratore non lo chiude. */
    public static final String NOTICE_PATH = "/var/db/mailpanel/package-job-interrupted.json";

    /** Dove sta l'avviso. E' una variabile solo perche' le prove non scrivano in /var/db. */
    static Path notice = Path.of(NOTICE_PATH);

    /** Ogni quanto si riprova a riproteggere mentre pkg lavora. */
    static int retrySeconds = 30;

    private static Thread retry;

    /** Il pkg che sta lavorando adesso ("pid nome argomenti"), o "" se nessuno. */
    static String pkgRunning() {
        return Shell.runShell(Duration.ofSeconds(15), "pgrep -lfx 'pkg(-static)? .*' 2>/dev/null").outputTrim();
    }

    private static String now() {
        return Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
    }

    /**
     * Annota che un lavoro si e' interrotto: quale (dal record che il lavoro ha scritto accanto al
     * suo elenco), con quali pacchetti, quali erano ancora sbloccati all'avvio, e se pkg stava
     * ancora lavorando. Un avviso gia' presente non si sovrascrive: ci si aggiunge.
     */
    static void recordInterruption(JSONObject job, List<String> packages, List<String> unlockedAtStart, String pkgNow) {
        JSONObject n = new JSONObject()
                .put("description", job.optString("description", ""))
                .put("startedUtc", job.optString("startedUtc", ""))
                .put("detectedUtc", now())
                .put("packages", new JSONArray(packages))
                .put("unlockedAtStart", new JSONArray(unlockedAtStart))
                .put("pkgWasRunning", pkgNow);
        // La reinstallazione completa interrotta lascia la posta spenta e le configurazioni
        // cancellate, non solo dei pacchetti da riproteggere: l'avviso lo dice, con la sua via di
        // ritorno (reperto 166).
        if (job.optString("turnId", "").startsWith(InstallLocks.REINSTALL_TURN_PREFIX))
            n.put("reinstall", true).put("wayBack", PackageWayBack.newestReinstallWayBack());
        JSONObject old = notice();
        if (!old.isEmpty()) n.put("earlier", old);
        write(n);
        LOGGER.warning("Interrupted package job recorded in " + notice + ": " + n.optString("description"));
    }

    /**
     * Il lavoro interrotto e' stato completato dal pannello (InterruptedJobRecovery): l'avviso dice che cosa ha
     * fatto e se tutto torna. Se l'avviso non c'era (un lavoro che non aveva sbloccato niente, e quindi non lasciava
     * l'elenco), lo crea dalla traccia del lavoro.
     */
    static void recordRecovery(JSONObject running, JSONObject recovery) {
        JSONObject n = notice();
        if (n.isEmpty()) {
            List<String> names = new java.util.ArrayList<>();
            JSONArray ch = recovery.optJSONArray("changed");
            for (int i = 0; ch != null && i < ch.length(); i++) names.add(ch.getJSONObject(i).optString("name"));
            n.put("description", running.optString("description", ""))
             .put("startedUtc", running.optString("startedUtc", ""))
             .put("detectedUtc", now())
             .put("packages", new JSONArray(names))
             .put("unlockedAtStart", new JSONArray())
             .put("pkgWasRunning", "");
            if (running.optString("id", "").startsWith(InstallLocks.REINSTALL_TURN_PREFIX))
                n.put("reinstall", true).put("wayBack", PackageWayBack.newestReinstallWayBack());
        }
        write(n.put("recovery", recovery));
    }

    /** L'avviso dice un lavoro completato e verificato: da leggere, non una cosa da fare. */
    static boolean completed(JSONObject n) {
        JSONObject r = n.optJSONObject("recovery");
        return r != null && r.optBoolean("ok");
    }

    /** I pacchetti sono di nuovo protetti: l'avviso lo dice, ma resta finche' qualcuno non controlla. */
    static void markRelocked() {
        JSONObject n = notice();
        if (n.isEmpty() || n.has("relockedUtc")) return;
        write(n.put("relockedUtc", now()));
    }

    private static void write(JSONObject n) {
        try {
            Files.createDirectories(notice.getParent());
            Path tmp = notice.resolveSibling(notice.getFileName() + ".tmp");
            Files.writeString(tmp, n.toString(2) + "\n", StandardCharsets.UTF_8);
            Files.move(tmp, notice, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot write " + notice, e);
        }
    }

    /**
     * Per il rapporto periodico (UpdateManager.reportData): l'avviso come una cosa da fare, o null se
     * non c'e'. La reinstallazione interrotta e' la cosa piu' urgente (la posta puo' essere spenta) e
     * ha il suo titolo; prima usciva con l'urgenza e il titolo di un lavoro qualunque (reperto 172).
     */
    public static JSONObject reportItem() {
        JSONObject n = notice();
        // Completato e verificato dal pannello: non c'e' niente da fare (la pagina lo mostra comunque).
        if (n.isEmpty() || completed(n)) return null;
        boolean reinstall = n.optBoolean("reinstall");
        return new JSONObject().put("urgency", reinstall ? 0 : 1)
                .put("title", I18n.tr(reinstall ? "mail.report.title.reinstallInterrupted" : "server.recovery.title"))
                .put("what", text(n))
                .put("where", I18n.tr(reinstall ? "mail.report.where.interrupted" : "server.um.x.updatesPage"));
    }

    /** L'avviso, o un oggetto vuoto se non c'e'. */
    public static JSONObject notice() {
        try { return new JSONObject(Files.readString(notice)); }
        catch (Exception e) { return new JSONObject(); }
    }

    /** Per la pagina: l'avviso e, se l'elenco e' ancora su disco, i pacchetti ancora sbloccati. */
    public static JSONObject status() {
        JSONObject r = new JSONObject().put("success", true);
        JSONObject n = notice();
        r.put("notice", n.isEmpty() ? JSONObject.NULL : n.put("text", text(n)).put("completed", completed(n)));
        if (PackageQueue.statePresent()) {
            r.put("stillUnprotected", new JSONArray(statePackages()));
            r.put("retrying", retry != null && retry.isAlive());
        }
        return r;
    }

    /** I nomi scritti nell'elenco del lavoro interrotto (righe valide, senza commenti). */
    static List<String> statePackages() {
        try {
            return Files.readAllLines(PackageQueue.list).stream().map(String::trim)
                    .filter(l -> !l.isEmpty() && UpdateManager.isValidName(l)).toList();
        } catch (Exception e) { return List.of(); }
    }

    /**
     * L'amministratore ha controllato: l'avviso si chiude. Non si chiude finche' i pacchetti sono
     * ancora sbloccati: quello non e' un avviso da archiviare, e' un lavoro da finire.
     */
    public static JSONObject dismiss() {
        if (PackageQueue.statePresent())
            return new JSONObject().put("success", false).put("error", I18n.tr("server.recovery.cannotDismiss"));
        try {
            Files.deleteIfExists(notice);
            return new JSONObject().put("success", true).put("note", I18n.tr("server.recovery.dismissed"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", String.valueOf(e.getMessage()));
        }
    }

    /**
     * Riprova a riproteggere ogni retrySeconds, in un thread a parte, finche' il tentativo non
     * dice di aver finito. Un solo thread per volta: un secondo avvio della stessa richiesta non
     * ne crea un altro.
     */
    static synchronized void retryInBackground(BooleanSupplier attempt) {
        if (retry != null && retry.isAlive()) return;
        retry = new Thread(() -> {
            try {
                while (true) {
                    Thread.sleep(retrySeconds * 1000L);
                    if (attempt.getAsBoolean()) return;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "package-relock-retry");
        retry.setDaemon(true);
        retry.start();
    }

    /** Che cosa ha fatto il pannello completando il lavoro, in una frase: pacchetti, reinstallazioni, servizi. */
    static String actions(JSONObject r) {
        List<String> parts = new java.util.ArrayList<>();
        JSONArray ch = r.optJSONArray("changed");
        if (ch != null && ch.length() > 0) {
            List<String> list = new java.util.ArrayList<>();
            for (int i = 0; i < ch.length(); i++) {
                JSONObject c = ch.getJSONObject(i);
                list.add(c.optString("name") + " " + (c.optString("from").isEmpty() ? "-" : c.optString("from")) + " -> "
                        + (c.optString("to").isEmpty() ? "-" : c.optString("to")));
            }
            parts.add(I18n.tr("server.recovery.actions.changed", Map.of("list", String.join(", ", list))));
        }
        JSONArray re = r.optJSONArray("reinstalled");
        if (re != null && re.length() > 0)
            parts.add(I18n.tr("server.recovery.actions.reinstalled", Map.of("list",
                    String.join(" ", re.toList().stream().map(String::valueOf).toList()))));
        JSONArray sv = r.optJSONArray("services");
        List<String> handled = new java.util.ArrayList<>();
        for (int i = 0; sv != null && i < sv.length(); i++) {
            JSONObject o = sv.getJSONObject(i);
            String key = "server.recovery.actions." + o.optString("action");
            handled.add(I18n.tr(key, Map.of("s", o.optString("name"), "before", o.optString("pidBefore", "?"),
                    "after", o.optString("pidAfter", "?"))));
        }
        parts.add(handled.isEmpty() ? I18n.tr("server.recovery.actions.noServices")
                : I18n.tr("server.recovery.actions.services", Map.of("list", String.join(", ", handled))));
        return String.join(" ", parts);
    }

    /** Il testo dell'avviso nella lingua della richiesta, per la pagina e per il rapporto. */
    static String text(JSONObject n) {
        String what = n.optString("description", "");
        String list = String.join(" ", n.optJSONArray("packages") == null ? List.of()
                : n.getJSONArray("packages").toList().stream().map(String::valueOf).toList());
        String state = !n.optString("relockedUtc").isEmpty()
                ? I18n.tr("server.recovery.relocked", java.util.Map.of("when", n.optString("relockedUtc")))
                : I18n.tr("server.recovery.notYetRelocked");
        String pkg = n.optString("pkgWasRunning", "").isEmpty() ? "" : " " + I18n.tr("server.recovery.pkgWasRunning");
        String reinstall = !n.optBoolean("reinstall") ? ""
                : " " + (n.optString("wayBack", "").isEmpty() ? I18n.tr("server.recovery.reinstallNoWayBack")
                        : I18n.tr("server.recovery.reinstallHint", java.util.Map.of("name", n.optString("wayBack"))));
        JSONObject r = n.optJSONObject("recovery");
        if (r != null && !n.optBoolean("reinstall")) {
            // Il pannello l'ha completato: si dice che cosa ha fatto, e solo se qualcosa non torna che cosa resta.
            Map<String, String> v = new java.util.HashMap<>();
            v.put("what", what.isEmpty() ? I18n.tr("server.recovery.unknownJob") : what);
            v.put("started", n.optString("startedUtc", "?"));
            v.put("detected", n.optString("detectedUtc", "?"));
            v.put("done", r.optString("finishedUtc", "?"));
            v.put("actions", actions(r));
            v.put("problems", String.join(" ", r.optJSONArray("problems") == null ? List.of()
                    : r.getJSONArray("problems").toList().stream().map(String::valueOf).toList()));
            return I18n.tr(r.optBoolean("ok") ? "server.recovery.completedText" : "server.recovery.completedProblemsText", v);
        }
        return I18n.tr("server.recovery.text", java.util.Map.of(
                "what", what.isEmpty() ? I18n.tr("server.recovery.unknownJob") : what,
                "started", n.optString("startedUtc", "?"),
                "detected", n.optString("detectedUtc", "?"),
                "state", state + pkg,
                "list", list.isEmpty() ? "?" : list)) + reinstall;
    }
}
