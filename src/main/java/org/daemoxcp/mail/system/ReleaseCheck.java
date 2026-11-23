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
 * A new version of the panel: it is looked for among the GitHub releases once a day, and reported, with the
 * link to the release page. Nothing is downloaded and nothing is installed: the upgrade remains the one of
 * tools/upgrade/upgrade-panel.sh, with its checks.
 *
 * <p>What leaves the server, and nothing else: one HTTPS request to api.github.com for the list of releases of
 * {@link #REPOSITORY}, with User-Agent {@link Product#SLUG} (GitHub requires one) and without the version. GitHub
 * sees the server's address, as for every request; whoever does not want that turns the check off from the
 * Updates page.
 *
 * <p>Of the response only the tag (which must be a version, {@link #TAG}), the date, and the draft and
 * pre-release flags are used. The name and the text of the release never reach the page, and the link is built
 * here from the tag already checked: no address taken from the response.
 *
 * <p>Pre-releases are seen only by a panel that is itself a pre-release: a 0.x version or one with a suffix
 * (0.9.0, 1.1.0-beta.1). Whoever runs a 1.0.0 is not invited to a beta.
 *
 * <p>The last result is kept in panel_settings ({@link #STATE}): a restart does not repeat the request, and the
 * page reads it without touching the network. Instants are UTC, ISO 8601 (r13).
 */
public final class ReleaseCheck {

    private static final Logger LOGGER = Logger.getLogger(ReleaseCheck.class.getName());

    /** The panel's public repository. */
    public static final String REPOSITORY = "DaemoxCP/DaemoxCP-mail";
    static final URI API = URI.create("https://api.github.com/repos/" + REPOSITORY + "/releases?per_page=30");
    static final String RELEASE_PAGE = "https://github.com/" + REPOSITORY + "/releases/tag/";

    /** On ("1", as with no choice) or off ("0"). */
    static final String ENABLED = "release_check_enabled";
    /** The last check, in JSON: checkedAt, ok, error, newest. */
    static final String STATE = "release_check_state";

    static final Duration EVERY = Duration.ofHours(24);
    /** Between two "Check now": GitHub allows 60 requests an hour per address without credentials. */
    static final Duration MANUAL_GAP = Duration.ofSeconds(60);
    static final int MAX_BODY = 2 * 1024 * 1024;

    /** A version: three numbers, with or without a leading v, and an optional pre-release suffix. */
    static final Pattern TAG = Pattern.compile("v?(\\d{1,5})\\.(\\d{1,5})\\.(\\d{1,5})(?:-([0-9A-Za-z]{1,18}(?:\\.[0-9A-Za-z]{1,18}){0,4}))?");

    private static volatile ScheduledExecutorService scheduler;
    private static final Object LOCK = new Object();

    private ReleaseCheck() {}

    /*
     * ===================================================================
     * Versions: tested without the network
     * ===================================================================
     */

    /** A semantic version. {@code pre} is null for a stable version. */
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

        /** A pre-release: a suffix, or a 0.x (which is a beta by definition). */
        boolean isPreRelease() {
            return pre != null || major == 0;
        }

        /** Like rule 11 of semver.org: a pre-release comes before the same stable version. */
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
     * The release newer than the running one, among those GitHub returned, or null if there is none. No drafts;
     * pre-releases only if a pre-release is running; a tag that is not a version is skipped.
     *
     * @return version, tag, url, publishedAt (ISO 8601 UTC or empty), preRelease
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

    /*
     * ===================================================================
     * The request
     * ===================================================================
     */

    /**
     * One check: the request to GitHub and the choice of the release. It saves nothing.
     *
     * @param api     the address of the list ({@link #API}; another one only in tests)
     * @param current the running version
     * @return checkedAt, ok, error (a code: network, no_ipv4, not_found, rate_limited, http_NNN, invalid, too_large)
     *         and newest (the newest release, or absent)
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
            // GitHub has no IPv6 (api.github.com has no AAAA, 2026-11-18): a server without IPv4 cannot reach it.
            return r.put("error", ServerAddresses.read().v4().present() ? "network" : "no_ipv4");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return r.put("error", "network");
        }
    }

    /*
     * ===================================================================
     * The panel: the last result, the daily check, "Check now"
     * ===================================================================
     */

    /** The running version, or null if the jar does not say it (built without Maven). */
    static Version running() {
        return Version.parse(PanelInfo.build().version());
    }

    public static boolean enabled() {
        return !"0".equals(setting(ENABLED, "1"));
    }

    /**
     * What the page knows, without touching the network: the running version, whether the check is on, the last
     * check and the new release, if there is one and it is still newer than the running one (after an upgrade
     * the saved result talks about a version that is now running).
     */
    public static JSONObject status() {
        return status(running(), PanelInfo.build().version(), enabled(), savedState());
    }

    /** {@link #status()} without a database: it can be tested on its own. */
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

    /**
     * The new release to report, with the running version (current), or null: for the dashboard and the
     * periodic report.
     */
    public static JSONObject available() {
        JSONObject s = status();
        JSONObject n = s.optJSONObject("newest");
        return n == null ? null : new JSONObject(n.toString()).put("current", s.optString("current", ""));
    }

    /**
     * "Check now". At least one minute between two checks, whoever asked for them: more often changes
     * nothing, and GitHub counts the requests.
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

    /** Turned on or off from the "Updates" page. */
    public static JSONObject setEnabled(boolean on) {
        storeSetting(ENABLED, on ? "1" : "0");
        return status();
    }

    /**
     * The daily check: every hour it looks whether 24 hours have passed since the last one. Ten minutes after
     * startup.
     */
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
     * Whether a check is due: no check before, or the last one is at least {@code gap} old. An instant in the
     * future (a clock that went backwards) counts as no check: it does not stop the checks for days.
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
