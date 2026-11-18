package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Una versione nuova del pannello: la si cerca fra le release di GitHub una volta al giorno, e la si dice, con il
 * link alla pagina della release. Niente si scarica e niente si installa: l'aggiornamento resta quello di
 * tools/upgrade/upgrade-panel.sh, con le sue verifiche.
 *
 * <p>Cosa esce dal server, e nient'altro: una richiesta HTTPS a api.github.com per l'elenco delle release di
 * {@link #REPOSITORY}, con User-Agent {@link Product#SLUG} (GitHub lo vuole) e senza la versione. GitHub vede
 * l'indirizzo del server, come per ogni richiesta; chi non lo vuole spegne il controllo dalla pagina Aggiornamenti.
 *
 * <p>Della risposta si usano solo il tag (che deve essere una versione, {@link #TAG}), la data, e i segni di bozza
 * e di pre-release. Il nome e il testo della release non arrivano mai nella pagina, e il link si costruisce qui dal
 * tag gia' controllato: nessun indirizzo preso dalla risposta.
 *
 * <p>Le pre-release le vede solo un pannello che e' a sua volta una pre-release: una versione 0.x o con un suffisso
 * (0.9.0, 1.1.0-beta.1). Chi gira su una 1.0.0 non viene invitato a una beta.
 *
 * <p>L'ultimo esito sta in panel_settings ({@link #STATE}): un riavvio non rifa' la richiesta, e la pagina lo legge
 * senza toccare la rete. Gli istanti sono UTC, ISO 8601 (r13).
 */
public final class ReleaseCheck {

    private static final Logger LOGGER = Logger.getLogger(ReleaseCheck.class.getName());

    /** Il repository pubblico del pannello. */
    public static final String REPOSITORY = "DaemoxCP/mail";
    static final URI API = URI.create("https://api.github.com/repos/" + REPOSITORY + "/releases?per_page=30");
    static final String RELEASE_PAGE = "https://github.com/" + REPOSITORY + "/releases/tag/";

    /** Acceso ("1", come senza scelta) o spento ("0"). */
    static final String ENABLED = "release_check_enabled";
    /** L'ultimo controllo, in JSON: checkedAt, ok, error, newest. */
    static final String STATE = "release_check_state";

    static final Duration EVERY = Duration.ofHours(24);
    /** Fra due «Controlla adesso»: GitHub concede 60 richieste l'ora per indirizzo senza credenziali. */
    static final Duration MANUAL_GAP = Duration.ofSeconds(60);
    static final int MAX_BODY = 2 * 1024 * 1024;

    /** Una versione: tre numeri, con o senza v davanti, e un eventuale suffisso di pre-release. */
    static final Pattern TAG = Pattern.compile("v?(\\d{1,5})\\.(\\d{1,5})\\.(\\d{1,5})(?:-([0-9A-Za-z]{1,18}(?:\\.[0-9A-Za-z]{1,18}){0,4}))?");

    private static volatile ScheduledExecutorService scheduler;
    private static final Object LOCK = new Object();

    private ReleaseCheck() {}

    /* ===================================================================
     * Le versioni: si provano senza rete
     * =================================================================== */

    /** Una versione semantica. {@code pre} e' null per una versione stabile. */
    record Version(int major, int minor, int patch, String pre) implements Comparable<Version> {

        static Version parse(String s) {
            if (s == null) return null;
            Matcher m = TAG.matcher(s.trim());
            if (!m.matches()) return null;
            try {
                return new Version(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)), m.group(4));
            } catch (NumberFormatException e) {
                return null;
            }
        }

        /** Una pre-release: un suffisso, o una 0.x (che e' una beta per definizione). */
        boolean isPreRelease() {
            return pre != null || major == 0;
        }

        /** Come la regola 11 di semver.org: una pre-release viene prima della stessa versione stabile. */
        @Override
        public int compareTo(Version o) {
            int c = Integer.compare(major, o.major);
            if (c == 0) c = Integer.compare(minor, o.minor);
            if (c == 0) c = Integer.compare(patch, o.patch);
            if (c != 0) return c;
            if (pre == null || o.pre == null) return pre == null ? (o.pre == null ? 0 : 1) : -1;
            String[] a = pre.split("\\."), b = o.pre.split("\\.");
            for (int i = 0; i < Math.min(a.length, b.length); i++) {
                boolean na = a[i].chars().allMatch(Character::isDigit), nb = b[i].chars().allMatch(Character::isDigit);
                if (na && nb) c = Long.compare(Long.parseLong(a[i]), Long.parseLong(b[i]));
                else if (na || nb) c = na ? -1 : 1;
                else c = a[i].compareTo(b[i]);
                if (c != 0) return c;
            }
            return Integer.compare(a.length, b.length);
        }

        @Override
        public String toString() {
            return major + "." + minor + "." + patch + (pre == null ? "" : "-" + pre);
        }
    }

    /**
     * La release piu' nuova di quella che gira, fra quelle che GitHub ha dato, o null se non ce n'e'. Le bozze no; le
     * pre-release solo se gira una pre-release; un tag che non e' una versione si salta.
     *
     * @return version, tag, url, publishedAt (ISO 8601 UTC o vuoto), preRelease
     */
    static JSONObject newest(JSONArray releases, Version current) {
        if (releases == null || current == null) return null;
        Version best = null;
        JSONObject found = null;
        for (int i = 0; i < releases.length(); i++) {
            JSONObject r = releases.optJSONObject(i);
            if (r == null || r.optBoolean("draft", false)) continue;
            String tag = r.optString("tag_name", "");
            Version v = Version.parse(tag);
            if (v == null) continue;
            boolean pre = r.optBoolean("prerelease", false) || v.pre() != null;
            if (pre && !current.isPreRelease()) continue;
            if (v.compareTo(current) <= 0 || (best != null && v.compareTo(best) <= 0)) continue;
            best = v;
            found = new JSONObject()
                    .put("version", v.toString())
                    .put("tag", tag)
                    .put("url", RELEASE_PAGE + tag)
                    .put("publishedAt", instant(r.optString("published_at", "")))
                    .put("preRelease", pre);
        }
        return found;
    }

    private static String instant(String v) {
        try {
            return v.isEmpty() ? "" : Instant.parse(v).toString();
        } catch (DateTimeParseException e) {
            return "";
        }
    }

    /* ===================================================================
     * La richiesta
     * =================================================================== */

    /**
     * Un controllo: la richiesta a GitHub e la scelta della release. Non salva niente.
     *
     * @param api     l'indirizzo dell'elenco ({@link #API}; un altro solo nelle prove)
     * @param current la versione che gira
     * @return checkedAt, ok, error (un codice: network, not_found, rate_limited, http_NNN, invalid, too_large) e
     *         newest (la release piu' nuova, o assente)
     */
    static JSONObject check(URI api, Version current, Instant now) {
        JSONObject r = new JSONObject().put("checkedAt", now.toString()).put("ok", false);
        try {
            HttpClient http = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();
            HttpRequest req = HttpRequest.newBuilder(api)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .header("User-Agent", Product.SLUG)
                    .timeout(Duration.ofSeconds(20))
                    .GET().build();
            HttpResponse<InputStream> res = http.send(req, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = res.body()) {
                int status = res.statusCode();
                if (status != 200) {
                    String remaining = res.headers().firstValue("x-ratelimit-remaining").orElse("");
                    return r.put("error", status == 404 ? "not_found"
                            : (status == 429 || (status == 403 && "0".equals(remaining))) ? "rate_limited" : "http_" + status);
                }
                byte[] body = in.readNBytes(MAX_BODY + 1);
                if (body.length > MAX_BODY) return r.put("error", "too_large");
                JSONArray releases = new JSONArray(new String(body, StandardCharsets.UTF_8));
                JSONObject n = newest(releases, current);
                if (n != null) r.put("newest", n);
                return r.put("ok", true);
            }
        } catch (JSONException e) {
            return r.put("error", "invalid");
        } catch (IOException e) {
            return r.put("error", "network");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return r.put("error", "network");
        }
    }

    /* ===================================================================
     * Il pannello: l'ultimo esito, il controllo di ogni giorno, «Controlla adesso»
     * =================================================================== */

    /** La versione che gira, o null se il jar non la dice (costruito senza Maven). */
    static Version running() {
        return Version.parse(PanelInfo.build().version());
    }

    public static boolean enabled() {
        return !"0".equals(setting(ENABLED, "1"));
    }

    /**
     * Quello che sa la pagina, senza toccare la rete: la versione che gira, se il controllo e' acceso, l'ultimo
     * controllo e la release nuova, se c'e' ed e' ancora piu' nuova di quella che gira (dopo un aggiornamento
     * l'esito salvato parla di una versione che ormai gira).
     */
    public static JSONObject status() {
        return status(running(), PanelInfo.build().version(), enabled(), savedState());
    }

    /** {@link #status()} senza database: si prova da sola. */
    static JSONObject status(Version current, String rawVersion, boolean enabled, JSONObject state) {
        JSONObject r = new JSONObject().put("success", true)
                .put("current", current == null ? (rawVersion == null ? "" : rawVersion) : current.toString())
                .put("enabled", enabled)
                .put("repository", REPOSITORY);
        if (state == null) return r;
        r.put("checkedAt", state.optString("checkedAt", "")).put("ok", state.optBoolean("ok", false));
        if (!state.optBoolean("ok", false)) r.put("error", state.optString("error", "network"));
        JSONObject n = state.optJSONObject("newest");
        Version v = n == null ? null : Version.parse(n.optString("version", ""));
        if (v != null && current != null && v.compareTo(current) > 0) r.put("newest", n);
        return r;
    }

    /** La release nuova da dire, con la versione che gira (current), o null: per la dashboard e il rapporto periodico. */
    public static JSONObject available() {
        JSONObject s = status();
        JSONObject n = s.optJSONObject("newest");
        return n == null ? null : new JSONObject(n.toString()).put("current", s.optString("current", ""));
    }

    /**
     * «Controlla adesso». Un minuto almeno fra due controlli, chiunque li abbia chiesti: piu' spesso non cambia
     * niente, e GitHub conta le richieste.
     */
    public static JSONObject checkNow() {
        Version current = running();
        if (current == null) return status().put("success", false).put("error", "unknown_version");
        synchronized (LOCK) {
            JSONObject state = savedState();
            Instant now = Instant.now();
            if (!due(state, now, MANUAL_GAP)) return status().put("justChecked", true);
            save(check(API, current, now));
        }
        return status();
    }

    /** Acceso o spento dalla pagina Aggiornamenti. */
    public static JSONObject setEnabled(boolean on) {
        storeSetting(ENABLED, on ? "1" : "0");
        return status();
    }

    /** Il controllo di ogni giorno: si guarda ogni ora se sono passate 24 ore dall'ultimo. Dieci minuti dopo l'avvio. */
    public static void start() {
        synchronized (LOCK) {
            if (scheduler != null) return;
            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "release-check");
                t.setDaemon(true);
                return t;
            });
            scheduler.scheduleWithFixedDelay(ReleaseCheck::tick, 600, 3600, TimeUnit.SECONDS);
        }
    }

    static void tick() {
        try {
            if (!enabled()) return;
            Version current = running();
            if (current == null) return;
            synchronized (LOCK) {
                Instant now = Instant.now();
                if (!due(savedState(), now, EVERY)) return;
                JSONObject r = check(API, current, now);
                save(r);
                JSONObject n = r.optJSONObject("newest");
                if (n != null) LOGGER.info("[ReleaseCheck] A newer version is published on GitHub: " + n.optString("version"));
            }
        } catch (RuntimeException e) {
            LOGGER.warning("[ReleaseCheck] Check failed: " + e.getClass().getSimpleName());
        }
    }

    /**
     * Se e' ora di un controllo: nessun controllo prima, o l'ultimo e' di almeno {@code gap} fa. Un istante nel futuro
     * (un orologio tornato indietro) vale come nessun controllo: non ferma i controlli per giorni.
     */
    static boolean due(JSONObject state, Instant now, Duration gap) {
        Instant last = state == null ? null : parseInstant(state.optString("checkedAt", ""));
        return last == null || last.isAfter(now) || Duration.between(last, now).compareTo(gap) >= 0;
    }

    private static JSONObject savedState() {
        String s = setting(STATE, "");
        if (s.isEmpty()) return null;
        try {
            return new JSONObject(s);
        } catch (JSONException e) {
            return null;
        }
    }

    private static void save(JSONObject state) {
        storeSetting(STATE, state.toString());
    }

    private static Instant parseInstant(String v) {
        try {
            return v.isEmpty() ? null : Instant.parse(v);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static String setting(String key, String defaultValue) {
        try {
            String v = Main.mailDatabase == null ? null : Main.mailDatabase.getSetting(key, defaultValue);
            return v == null ? defaultValue : v;
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private static void storeSetting(String key, String value) {
        try {
            if (Main.mailDatabase != null) Main.mailDatabase.setSetting(key, value);
        } catch (Exception ignored) { }
    }
}
