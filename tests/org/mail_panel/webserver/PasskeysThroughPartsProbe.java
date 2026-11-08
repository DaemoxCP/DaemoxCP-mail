package org.mail_panel.webserver;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.security.SoftAuthenticator;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * Passkeys through the two parts of a running separated panel: the
 * browser talks to the web part, the root part keeps the challenges and decides. With a software
 * authenticator (real P-256 key, real ES256 signatures):
 *
 *  1. sign in with a one-time console code, through the web part;
 *  2. register a passkey from the account API (it goes to the root part, with the Host for the rpId);
 *  3. sign out, then sign in with that passkey: options and verification both through the web part;
 *  4. the session works, the account lists the passkey; an assertion for another challenge is refused;
 *  5. the passkey is removed again and the session closed.
 *
 * It connects to 127.0.0.1 with the panel's name as Host (the panel answers only to its names, and a
 * passkey needs a DNS name). Run on the VM, with the Host header allowed to the HTTP client:
 *   java -Djdk.httpclient.allowRestrictedHeaders=host -cp "tests:freebsd-mail-panel-1.0.jar" \
 *        org.mail_panel.webserver.PasskeysThroughPartsProbe <panel name> <port> "<console code>"
 */
public class PasskeysThroughPartsProbe {

    static int failed = 0;
    static HttpClient http;
    static String host, base;
    static final String UA = "passkeys-through-parts-probe";
    static final Map<String, String> cookies = new HashMap<>();

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static HttpResponse<String> send(String method, String path, String body, String csrf) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).header("Host", host).header("User-Agent", UA)
                .header("Accept-Language", "en");
        if (!cookies.isEmpty()) {
            StringBuilder c = new StringBuilder();
            cookies.forEach((k, v) -> c.append(c.length() == 0 ? "" : "; ").append(k).append('=').append(v));
            b.header("Cookie", c.toString());
        }
        if (csrf != null) b.header("X-CSRF-Token", csrf);
        if (body != null) b.header("Content-Type", "application/json");
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        for (String sc : r.headers().allValues("Set-Cookie")) {
            String pair = sc.split(";", 2)[0];
            int eq = pair.indexOf('=');
            String name = pair.substring(0, eq), value = pair.substring(eq + 1);
            if (value.isEmpty() || sc.contains("Max-Age=0")) cookies.remove(name);
            else cookies.put(name, value);
        }
        return r;
    }

    /** The sign-in page: its pre-login cookie and token. */
    static String pageToken() throws Exception {
        String html = send("GET", "/index", null, null).body();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("id=\"csrf_token\" value=\"([^\"]*)\"").matcher(html);
        return m.find() ? m.group(1) : "";
    }

    public static void main(String[] a) throws Exception {
        // The panel's certificate is not for this name: trust it here, the probe is about the passkeys.
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        host = a[0] + ":" + a[1];
        base = "https://127.0.0.1:" + a[1];
        String origin = "https://" + host;
        SSLContext trustAll = SSLContext.getInstance("TLS");
        trustAll.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] x, String t) { }
            public void checkServerTrusted(X509Certificate[] x, String t) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        http = HttpClient.newBuilder().sslContext(trustAll).build();

        System.out.println("== 1. Sign in with a console code ==");
        String token = pageToken();
        HttpResponse<String> r = send("POST", "/api/login", new JSONObject().put("action", "console_verify").put("code", a[2])
                .put("csrf_token", token).toString(), null);
        String csrf = r.statusCode() == 200 ? new JSONObject(r.body()).optString("csrf_token", "") : "";
        check("signed in (" + r.statusCode() + ")", r.statusCode() == 200 && !csrf.isEmpty());

        System.out.println("\n== 2. Register a passkey (the root part keeps the challenge) ==");
        SoftAuthenticator key = new SoftAuthenticator();
        r = send("POST", "/api/account", "{\"action\":\"passkey_register_options\"}", csrf);
        JSONObject opts = r.statusCode() == 200 ? new JSONObject(r.body()) : new JSONObject();
        check("registration options (" + r.statusCode() + ")", opts.optBoolean("success") && opts.has("options"));
        String rpId = opts.has("options") ? opts.getJSONObject("options").getJSONObject("publicKey").getJSONObject("rp").optString("id") : "";
        check("  for the panel's name as rpId (" + rpId + ")", rpId.equals(a[0]));
        String credential = key.register(opts.getJSONObject("options").toString(), origin);
        r = send("POST", "/api/account", new JSONObject().put("action", "passkey_register").put("request", opts.optString("request"))
                .put("name", "Probe passkey").put("credential", new JSONObject(credential)).toString(), csrf);
        check("registered (" + r.statusCode() + " " + r.body() + ")", r.statusCode() == 200);

        System.out.println("\n== 3. Sign out, then in with the passkey ==");
        r = send("POST", "/api/logout", "{}", csrf);
        check("signed out (" + r.statusCode() + ")", r.statusCode() == 200 && !cookies.containsKey(WebSessions.COOKIE));
        token = pageToken();
        r = send("POST", "/api/login", new JSONObject().put("action", "passkey_options").put("csrf_token", token).toString(), null);
        JSONObject login = r.statusCode() == 200 ? new JSONObject(r.body()) : new JSONObject();
        check("sign-in options (" + r.statusCode() + ")", login.optBoolean("success") && login.has("options"));
        String assertion = key.assertion(login.getJSONObject("options").toString(), origin);
        r = send("POST", "/api/login", new JSONObject().put("action", "passkey_verify").put("request", login.optString("request"))
                .put("credential", new JSONObject(assertion)).put("csrf_token", token).toString(), null);
        csrf = r.statusCode() == 200 ? new JSONObject(r.body()).optString("csrf_token", "") : "";
        check("signed in with the passkey (" + r.statusCode() + " " + r.body() + ")", r.statusCode() == 200 && cookies.containsKey(WebSessions.COOKIE));

        System.out.println("\n== 4. The session, and a replay ==");
        r = send("GET", "/api/account", null, null);
        JSONArray keys = r.statusCode() == 200 ? new JSONObject(r.body()).optJSONArray("passkeys") : null;
        long probeId = -1;
        if (keys != null) for (int i = 0; i < keys.length(); i++)
            if ("Probe passkey".equals(keys.getJSONObject(i).optString("name"))) probeId = keys.getJSONObject(i).getLong("id");
        check("the session works and the account lists the passkey (" + r.statusCode() + ")", probeId > 0);
        // As a browser that is not signed in: signed in, the sign-in page has no token to give.
        String session = cookies.remove(WebSessions.COOKIE);
        String replayToken = pageToken();
        r = send("POST", "/api/login", new JSONObject().put("action", "passkey_options").put("csrf_token", replayToken).toString(), null);
        String otherRequest = r.statusCode() == 200 ? new JSONObject(r.body()).optString("request") : "";
        r = send("POST", "/api/login", new JSONObject().put("action", "passkey_verify").put("request", otherRequest)
                .put("credential", new JSONObject(assertion)).put("csrf_token", replayToken).toString(), null);
        check("the same assertion for another challenge: refused by the root part (" + r.statusCode() + ")",
                !otherRequest.isEmpty() && r.statusCode() == 401);
        cookies.put(WebSessions.COOKIE, session);

        System.out.println("\n== 5. Clean up ==");
        r = send("POST", "/api/account", new JSONObject().put("action", "passkey_delete").put("id", probeId).toString(), csrf);
        check("the probe's passkey removed (" + r.statusCode() + " " + r.body() + ")", r.statusCode() == 200);
        r = send("POST", "/api/logout", "{}", csrf);
        check("signed out (" + r.statusCode() + ")", r.statusCode() == 200);

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

}
