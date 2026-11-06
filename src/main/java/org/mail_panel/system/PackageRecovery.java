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
        JSONObject old = notice();
        if (!old.isEmpty()) n.put("earlier", old);
        write(n);
        LOGGER.warning("Interrupted package job recorded in " + notice + ": " + n.optString("description"));
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

    /** L'avviso, o un oggetto vuoto se non c'e'. */
    public static JSONObject notice() {
        try { return new JSONObject(Files.readString(notice)); }
        catch (Exception e) { return new JSONObject(); }
    }

    /** Per la pagina: l'avviso e, se l'elenco e' ancora su disco, i pacchetti ancora sbloccati. */
    public static JSONObject status() {
        JSONObject r = new JSONObject().put("success", true);
        JSONObject n = notice();
        r.put("notice", n.isEmpty() ? JSONObject.NULL : n.put("text", text(n)));
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

    /** Il testo dell'avviso nella lingua della richiesta, per la pagina e per il rapporto. */
    static String text(JSONObject n) {
        String what = n.optString("description", "");
        String list = String.join(" ", n.optJSONArray("packages") == null ? List.of()
                : n.getJSONArray("packages").toList().stream().map(String::valueOf).toList());
        String state = !n.optString("relockedUtc").isEmpty()
                ? I18n.tr("server.recovery.relocked", java.util.Map.of("when", n.optString("relockedUtc")))
                : I18n.tr("server.recovery.notYetRelocked");
        String pkg = n.optString("pkgWasRunning", "").isEmpty() ? "" : " " + I18n.tr("server.recovery.pkgWasRunning");
        return I18n.tr("server.recovery.text", java.util.Map.of(
                "what", what.isEmpty() ? I18n.tr("server.recovery.unknownJob") : what,
                "started", n.optString("startedUtc", "?"),
                "detected", n.optString("detectedUtc", "?"),
                "state", state + pkg,
                "list", list.isEmpty() ? "?" : list));
    }
}
