package org.daemoxcp.mail.system;

import com.sun.net.httpserver.HttpServer;
import org.json.JSONArray;
import org.json.JSONObject;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The new-version notice (ReleaseCheck): which GitHub release is "newer" than the running panel, and what the check
 * does with each answer GitHub can give. GitHub is a local HTTP server here, so the test needs no network and never
 * reaches api.github.com.
 *
 * It runs anywhere:
 *   java -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.system.ReleaseCheckTest
 */
public class ReleaseCheckTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static ReleaseCheck.Version v(String s) {
        return ReleaseCheck.Version.parse(s);
    }

    static JSONObject release(String tag, boolean draft, boolean pre, String publishedAt, String htmlUrl) {
        return new JSONObject().put("tag_name", tag).put("draft", draft).put("prerelease", pre)
                .put("published_at", publishedAt).put("html_url", htmlUrl)
                .put("name", "<script>alert(1)</script>").put("body", "release notes");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== Versions ==");
        check("v0.9.0, 0.9.0 and 1.0.0-beta.1 are versions",
                "0.9.0".equals(String.valueOf(v("v0.9.0"))) && "0.9.0".equals(String.valueOf(v("0.9.0")))
                        && "1.0.0-beta.1".equals(String.valueOf(v("1.0.0-beta.1"))));
        boolean refused = true;
        for (String bad : new String[]{"latest", "v1.0", "1.0.0.0", "v1.0.0-", "1.0.0-beta..1", "1.0.0<script>", "1.0.0-be ta",
                "1.0.0/../../x", "123456.0.0", "", "1.0.0-1234567890123456789"})
            if (v(bad) != null) { refused = false; System.out.println("    accepted: " + bad); }
        check("a tag that is not a version is refused (latest, v1.0, 1.0.0.0, markup, paths, spaces, overlong)", refused && v(null) == null);

        String[] order = {"0.9.0", "0.9.1", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
                "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0", "2.0.0"};
        boolean sorted = true;
        for (int i = 0; i + 1 < order.length; i++)
            for (int j = i + 1; j < order.length; j++)
                if (v(order[i]).compareTo(v(order[j])) >= 0 || v(order[j]).compareTo(v(order[i])) <= 0) {
                    sorted = false;
                    System.out.println("    not in order: " + order[i] + " < " + order[j]);
                }
        check("the order of semver.org: pre-releases before the release, numbers as numbers (beta.2 < beta.11, 1.9 < 1.10)", sorted);
        check("v1.0.0 and 1.0.0 are the same version", v("v1.0.0").compareTo(v("1.0.0")) == 0);
        check("a 0.x and a suffixed version are pre-releases, 1.0.0 is not",
                v("0.9.0").isPreRelease() && v("1.1.0-beta.1").isPreRelease() && !v("1.0.0").isPreRelease());

        System.out.println("\n== Which release is the one to tell ==");
        JSONArray list = new JSONArray()
                .put(release("v0.8.0", false, false, "2026-10-01T10:00:00Z", ""))
                .put(release("v0.9.0", false, true, "2026-11-18T10:00:00Z", ""))
                .put(release("v1.0.0", false, false, "2026-12-01T10:00:00Z", "https://github.com/DaemoxCP/mail/releases/tag/v1.0.0"))
                .put(release("v1.0.1", false, false, "2026-12-05T10:00:00Z", "https://attacker.example/releases/tag/v1.0.1"))
                .put(release("v1.1.0", true, false, "2026-12-10T10:00:00Z", ""))
                .put(release("v1.2.0", false, true, "2026-12-11T10:00:00Z", ""))
                .put(release("v2.0.0-beta.1", false, false, "2026-12-12T10:00:00Z", ""))
                .put(release("nightly", false, false, "2026-12-13T10:00:00Z", ""))
                .put("not an object");

        JSONObject forBeta = ReleaseCheck.newest(list, v("0.9.0"));
        check("a 0.9.0 panel (a beta) is told the newest one, a pre-release too: 2.0.0-beta.1 ("
                + (forBeta == null ? null : forBeta.optString("version")) + ")",
                forBeta != null && "2.0.0-beta.1".equals(forBeta.optString("version")) && forBeta.optBoolean("preRelease"));

        JSONObject forStable = ReleaseCheck.newest(list, v("1.0.0"));
        check("a 1.0.0 panel is told 1.0.1: not the draft 1.1.0, not the pre-releases 1.2.0 and 2.0.0-beta.1 ("
                + (forStable == null ? null : forStable.optString("version")) + ")",
                forStable != null && "1.0.1".equals(forStable.optString("version")) && !forStable.optBoolean("preRelease"));
        check("its link is built from the tag, never taken from the answer (" + (forStable == null ? null : forStable.optString("url")) + ")",
                forStable != null && "https://github.com/DaemoxCP/mail/releases/tag/v1.0.1".equals(forStable.optString("url")));
        check("its date is ISO 8601 UTC (" + (forStable == null ? null : forStable.optString("publishedAt")) + ")",
                forStable != null && "2026-12-05T10:00:00Z".equals(forStable.optString("publishedAt")));
        check("the release's name and text are not carried", forStable != null && !forStable.has("name") && !forStable.has("body"));
        check("nothing newer: nothing to tell", ReleaseCheck.newest(list, v("9.9.9")) == null);
        check("the release that runs is not newer than itself", ReleaseCheck.newest(new JSONArray().put(release("v1.0.0", false, false, "", "")), v("1.0.0")) == null);
        check("no list, or no running version: nothing", ReleaseCheck.newest(null, v("1.0.0")) == null && ReleaseCheck.newest(list, null) == null);

        System.out.println("\n== What the pages read (status) ==");
        JSONObject saved = new JSONObject().put("checkedAt", "2026-12-06T08:00:00Z").put("ok", true)
                .put("newest", new JSONObject(forStable.toString()));
        JSONObject s = ReleaseCheck.status(v("1.0.0"), "1.0.0", true, saved);
        check("a newer release saved: it is told", s.optJSONObject("newest") != null && "1.0.1".equals(s.getJSONObject("newest").optString("version")));
        s = ReleaseCheck.status(v("1.0.1"), "1.0.1", true, saved);
        check("after updating to it, the saved result does not tell it any more", !s.has("newest") && s.optBoolean("ok"));
        s = ReleaseCheck.status(v("1.0.0"), "1.0.0", false, null);
        check("never checked: no date, no result, and the switch says off", !s.has("checkedAt") && !s.has("newest") && !s.optBoolean("enabled", true));
        s = ReleaseCheck.status(v("1.0.0"), "1.0.0", true,
                new JSONObject().put("checkedAt", "2026-12-06T08:00:00Z").put("ok", false).put("error", "not_found"));
        check("a failed check: its reason (" + s.optString("error") + ")", "not_found".equals(s.optString("error")) && !s.optBoolean("ok", true));
        s = ReleaseCheck.status(null, "", true, saved);
        check("a jar that does not say its version: nothing told", !s.has("newest") && "".equals(s.optString("current", "x")));

        System.out.println("\n== When to ask GitHub ==");
        Instant now = Instant.parse("2026-12-06T12:00:00Z");
        JSONObject at = new JSONObject().put("checkedAt", "2026-12-06T08:00:00Z");
        check("never asked: now", ReleaseCheck.due(null, now, ReleaseCheck.EVERY));
        check("four hours ago: not for the daily check", !ReleaseCheck.due(at, now, ReleaseCheck.EVERY));
        check("four hours ago: yes for \"Check now\"", ReleaseCheck.due(at, now, ReleaseCheck.MANUAL_GAP));
        check("30 seconds ago: not even for \"Check now\"",
                !ReleaseCheck.due(new JSONObject().put("checkedAt", now.minusSeconds(30).toString()), now, ReleaseCheck.MANUAL_GAP));
        check("25 hours ago: the daily check asks", ReleaseCheck.due(new JSONObject().put("checkedAt", now.minus(Duration.ofHours(25)).toString()), now, ReleaseCheck.EVERY));
        check("a date in the future (the clock went back): asks, it does not wait for days",
                ReleaseCheck.due(new JSONObject().put("checkedAt", "2027-06-01T00:00:00Z"), now, ReleaseCheck.EVERY));

        System.out.println("\n== GitHub's answers, from a local server ==");
        Map<String, String> seen = new ConcurrentHashMap<>();
        HttpServer github = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        github.createContext("/", ex -> {
            seen.put("User-Agent", String.valueOf(ex.getRequestHeaders().getFirst("User-Agent")));
            seen.put("Accept", String.valueOf(ex.getRequestHeaders().getFirst("Accept")));
            seen.put("method", ex.getRequestMethod());
            String path = ex.getRequestURI().getPath();
            byte[] body;
            int status = 200;
            switch (path) {
                case "/ok" -> body = list.toString().getBytes(StandardCharsets.UTF_8);
                case "/empty" -> body = "[]".getBytes(StandardCharsets.UTF_8);
                case "/missing" -> { status = 404; body = "{\"message\":\"Not Found\"}".getBytes(StandardCharsets.UTF_8); }
                case "/limited" -> {
                    status = 403;
                    ex.getResponseHeaders().add("x-ratelimit-remaining", "0");
                    body = "{\"message\":\"API rate limit exceeded\"}".getBytes(StandardCharsets.UTF_8);
                }
                case "/broken" -> { status = 500; body = new byte[0]; }
                case "/html" -> body = "<html>not json</html>".getBytes(StandardCharsets.UTF_8);
                case "/object" -> body = "{\"message\":\"Moved\"}".getBytes(StandardCharsets.UTF_8);
                case "/huge" -> body = ("[" + "\"x\",".repeat(ReleaseCheck.MAX_BODY / 4 + 10) + "\"x\"]").getBytes(StandardCharsets.UTF_8);
                default -> { status = 404; body = new byte[0]; }
            }
            ex.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
            if (body.length > 0) ex.getResponseBody().write(body);
            ex.close();
        });
        github.start();
        String base = "http://127.0.0.1:" + github.getAddress().getPort();
        Instant t = Instant.parse("2026-12-06T12:00:00Z");
        try {
            JSONObject r = ReleaseCheck.check(URI.create(base + "/ok"), v("1.0.0"), t);
            check("a list: ok, 1.0.1 found, the time of the check saved (" + r + ")",
                    r.optBoolean("ok") && "1.0.1".equals(r.getJSONObject("newest").optString("version"))
                            && "2026-12-06T12:00:00Z".equals(r.optString("checkedAt")));
            check("asked with GET, User-Agent daemoxcp-mail without the version (" + seen.get("User-Agent") + ")",
                    "GET".equals(seen.get("method")) && "daemoxcp-mail".equals(seen.get("User-Agent")));
            check("and GitHub's JSON type (" + seen.get("Accept") + ")", "application/vnd.github+json".equals(seen.get("Accept")));

            r = ReleaseCheck.check(URI.create(base + "/empty"), v("1.0.0"), t);
            check("no releases yet: ok, nothing to tell", r.optBoolean("ok") && !r.has("newest"));
            for (Object[] c : List.of(
                    new Object[]{"/missing", "not_found", "404: the repository is not public"},
                    new Object[]{"/limited", "rate_limited", "403 with no requests left"},
                    new Object[]{"/broken", "http_500", "500"},
                    new Object[]{"/html", "invalid", "a page instead of JSON"},
                    new Object[]{"/object", "invalid", "JSON that is not a list"},
                    new Object[]{"/huge", "too_large", "more than " + ReleaseCheck.MAX_BODY + " bytes"})) {
                r = ReleaseCheck.check(URI.create(base + c[0]), v("1.0.0"), t);
                check(c[2] + ": " + c[1] + " (" + r.optString("error") + ")", !r.optBoolean("ok", true) && c[1].equals(r.optString("error")) && !r.has("newest"));
            }
        } finally {
            github.stop(0);
        }
        int closed;
        try (java.net.ServerSocket ss = new java.net.ServerSocket(0, 1, InetAddress.getLoopbackAddress())) { closed = ss.getLocalPort(); }
        JSONObject r = ReleaseCheck.check(URI.create("http://127.0.0.1:" + closed + "/ok"), v("1.0.0"), t);
        check("nobody answers: network (" + r.optString("error") + ")", !r.optBoolean("ok", true) && "network".equals(r.optString("error")));

        System.out.println("\n== The address the panel asks ==");
        check("api.github.com over HTTPS, the panel's repository (" + ReleaseCheck.API + ")",
                "https".equals(ReleaseCheck.API.getScheme()) && "api.github.com".equals(ReleaseCheck.API.getHost())
                        && ReleaseCheck.API.getPath().equals("/repos/DaemoxCP/mail/releases"));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
