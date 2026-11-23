package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * MTA-STS: the declaration that this domain's servers always speak TLS.
 *
 * What it is for. Between two mail servers TLS is opportunistic: the sender asks for
 * STARTTLS and, if the recipient does not offer it, delivers IN CLEAR TEXT. An attacker in the
 * middle can delete that offer as it passes, and the sender has no way to notice: it only sees
 * a server that says it does not speak TLS. MTA-STS closes that door by saying in advance
 * "my servers always have TLS: if you cannot get it, do NOT deliver".
 *
 * Why a DNS record is not enough, which is the point this work was stuck on for a long time.
 * RFC 8461 splits the thing in two:
 *
 *   Section 3.1  the TXT on _mta-sts.<domain> contains only "v=STSv1; id=...": the id lets
 *                senders notice that the policy has changed. It does NOT contain the policy.
 *   Section 3.2  the real policy is at https://mta-sts.<domain>/.well-known/mta-sts.txt,
 *                served with a certificate valid FOR THAT NAME. It is that certificate that
 *                proves the policy comes from the domain owner: MTA-STS does not use DNSSEC.
 *
 * Hence the rule that governs this class: **the TXT record is not published until the
 * policy really answers.** Publishing it before means publicly declaring a protection that
 * is not there, and the senders who go and read it find a 404. The panel therefore goes and
 * ASKS for the file before allowing publication, instead of trusting that it has written the
 * right configuration.
 */
public class MtaSts {

    /** The fixed path required by RFC 8461 Section 3.2. */
    public static final String PATH = "/.well-known/mta-sts.txt";

    private MtaSts() {}

    /*
     * ===================================================================
     * The file, as a pure function
     * ===================================================================
     */

    /**
     * The policy. Fields and values allowed by Section 3.2: version, mode, mx (repeatable), max_age.
     *
     * The ABNF allows both LF and CRLF as line terminator (sts-policy-term = LF / CRLF):
     * LF is used, which is what the rest of the panel writes.
     */
    public static String policy(String mailHost, String mode, int maxAge) {
        return "version: STSv1\n"
             + "mode: " + mode + "\n"
             + "mx: " + mailHost + "\n"
             + "max_age: " + maxAge + "\n";
    }

    /** The modes defined by the specification. */
    public static boolean validMode(String m) {
        return m != null && List.of("testing", "enforce", "none").contains(m.trim().toLowerCase(Locale.ROOT));
    }

    /**
     * How long senders keep the policy in memory.
     *
     * In "testing" it stays low: if something is wrong, the error expires in a day instead of
     * a week. In "enforce" it stays high, because a policy that expires and is not downloaded
     * again loses the protection exactly when it is needed.
     */
    public static int recommendedMaxAge(String mode) {
        return "enforce".equalsIgnoreCase(mode) ? 604800 : 86400;
    }

    /**
     * The id to put in the TXT record. Section 3.1 wants it 1..32 alphanumeric characters.
     *
     * It is derived from the CONTENT of the policy, not from the clock: so it changes if and only if
     * the policy has really changed. An id that changes at every read would make every sender in
     * the world download the policy again all the time; one that never changes would prevent them
     * from noticing a modification.
     */
    public static String id(String policy) {
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(policy.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 10; i++) sb.append(String.format("%02x", h[i]));
            return sb.toString();
        } catch (Exception e) {
            return "0000000000000000";
        }
    }

    /** The content of the TXT record on _mta-sts.<domain>. Section 3.1 */
    public static String recordTxt(String policy) {
        return "v=STSv1; id=" + id(policy);
    }

    /** Is the domain hosted by this panel? Whitelist, as for autoconfig. */
    public static String managedDomain(String required) {
        if (required == null) return null;
        String r = required.trim().toLowerCase(Locale.ROOT);
        if (r.startsWith("mta-sts.")) r = r.substring("mta-sts.".length());
        int p = r.indexOf(':');
        if (p > 0) r = r.substring(0, p);
        if (r.isEmpty()) return null;
        // Same reason as for autoconfig: public route, no query per request.
        return DomainCache.managed(r);
    }

    public static String mailHost() {
        try {
            return Main.mailDatabase.getSetting("mail_hostname", "");
        } catch (Exception e) {
            return "";
        }
    }

    /** The chosen mode, kept among the settings. It starts from "testing". */
    public static String currentMode() {
        try {
            String m = Main.mailDatabase.getSetting("mta_sts_mode", "testing");
            return validMode(m) ? m.toLowerCase(Locale.ROOT) : "testing";
        } catch (Exception e) {
            return "testing";
        }
    }

    public static JSONObject setMode(String mode) {
        if (!validMode(mode))
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.mtasts.badMode"));
        try {
            Main.mailDatabase.setSetting("mta_sts_mode", mode.toLowerCase(Locale.ROOT));
            return new JSONObject().put("success", true).put("mode", mode.toLowerCase(Locale.ROOT))
                    .put("note", "enforce".equalsIgnoreCase(mode)
                        ? I18n.tr("server.mtasts.modeEnforce")
                        : "none".equalsIgnoreCase(mode)
                        ? I18n.tr("server.mtasts.modeNone")
                        : I18n.tr("server.mtasts.modeTesting"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.mtasts.saveFailed", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("MtaSts", e))));
        }
    }

    /*
     * ===================================================================
     * The real state, domain by domain
     * ===================================================================
     */

    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);
        String host = mailHost();
        String mode = currentMode();
        r.put("mailHost", host).put("mode", mode).put("path", PATH);
        if (host == null || host.isBlank())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.mtasts.noHostname"));

        String pol = policy(host, mode, recommendedMaxAge(mode));
        r.put("policy", pol).put("id", id(pol)).put("recordTxt", recordTxt(pol));

        JSONArray domains = new JSONArray();
        try {
            for (var d : Main.mailDatabase.getDomains()) {
                JSONObject j = new JSONObject().put("domain", d.domain)
                        .put("webName", "mta-sts." + d.domain)
                        .put("txtName", "_mta-sts." + d.domain);
                j.put("policyReachable", testPolicy("mta-sts." + d.domain, host, mode));
                domains.put(j);
            }
        } catch (Exception ignore) {}
        r.put("domains", domains);
        return r;
    }

    /**
     * Asks for the policy as a sending server would, and looks at what comes back.
     *
     * It is the only check that counts: reading the nginx configuration says what SHOULD
     * happen, this says what happens. The outcomes stay distinct because "the certificate
     * does not cover that name" and "the file is not there" have two opposite remedies.
     */
    /** Like testPolicy, but for any domain: the DNS check uses it. */
    /**
     * The TXT record that matches the policy served NOW.
     *
     * The only place where that value is computed. There were two: here the policy, and in
     * DnsRecordsGenerator a "v=STSv1; id=" + System.currentTimeMillis() that offered whoever
     * reads the instructions an id taken from the clock: different at every page load, and
     * forever disconnected from the content of the policy. The id is not decorative: it is the
     * signal by which senders notice that the policy has changed, and a stuck one leaves them
     * on the old copy until it expires.
     */
    public static String currentTxtRecord() {
        try {
            String mode = currentMode();
            return recordTxt(policy(mailHost(), mode, recommendedMaxAge(mode))).trim();
        } catch (Exception e) {
            // Better nothing than an invented value: an empty string makes no record pass
            // as correct, and suggests to nobody that they publish nonsense.
            return "";
        }
    }

    public static JSONObject publicTest(String domain) {
        return testPolicy("mta-sts." + domain, mailHost(), currentMode());
    }

    /**
     * Codes 520-527 do not exist in HTTP: Cloudflare returns them, and nginx never
     * emits them. If one arrives, the request went through the proxy instead of going
     * straight to the server: that is, the name still has the orange cloud.
     * Meanings from the Cloudflare documentation (Troubleshooting Cloudflare 5xx errors).
     */
    static String explainCode(int code) {
        String what;
        switch (code) {
            case 520: what = I18n.tr("server.mtasts.cf520"); break;
            case 521: what = I18n.tr("server.mtasts.cf521"); break;
            case 522: what = I18n.tr("server.mtasts.cf522"); break;
            case 523: what = I18n.tr("server.mtasts.cf523"); break;
            case 525: what = I18n.tr("server.mtasts.cf525"); break;
            case 526: what = I18n.tr("server.mtasts.cf526"); break;
            default: return "";
        }
        return " " + I18n.tr("server.mtasts.cfCode", java.util.Map.of("c", String.valueOf(code), "what", String.valueOf(what)));
    }

    private static JSONObject testPolicy(String webName, String mailHost, String mode) {
        JSONObject r = new JSONObject();
        String url = "https://" + webName + PATH;
        r.put("url", url);
        try {
            var http = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(6))
                    .followRedirects(java.net.http.HttpClient.Redirect.NEVER).build();
            var req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(url))
                    .timeout(java.time.Duration.ofSeconds(8)).GET().build();
            var resp = http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            r.put("code", resp.statusCode());
            String body = resp.body() == null ? "" : resp.body();
            boolean ok = resp.statusCode() == 200
                    && body.contains("version: STSv1")
                    && body.contains("mx: " + mailHost);
            r.put("ok", ok);
            if (!ok) {
                if (resp.statusCode() != 200)
                    r.put("error", I18n.tr("server.mtasts.status", java.util.Map.of("c", String.valueOf(resp.statusCode()))) + explainCode(resp.statusCode()));
                else if (!body.contains("version: STSv1"))
                    r.put("error", I18n.tr("server.mtasts.notPolicy"));
                else
                    r.put("error", I18n.tr("server.mtasts.noMx", java.util.Map.of("host", String.valueOf(mailHost))));
            }
            return r;
        } catch (javax.net.ssl.SSLException e) {
            return r.put("ok", false).put("tls", true)
                    .put("error", I18n.tr("server.mtasts.certInvalid", java.util.Map.of("name", String.valueOf(webName))));
        } catch (java.net.UnknownHostException e) {
            return r.put("ok", false).put("dns", true)
                    .put("error", I18n.tr("server.mtasts.noCname", java.util.Map.of("name", String.valueOf(webName))));
        } catch (Exception e) {
            return r.put("ok", false)
                    .put("error", I18n.tr("server.mtasts.unreachable", java.util.Map.of("err", String.valueOf(e.getClass().getSimpleName()))));
        }
    }

    /**
     * Can the TXT record be published for this domain?
     *
     * Only if the policy already answers. It is the rule that keeps the whole mechanism honest:
     * the TXT is a public promise, and one does not make a promise before being able to keep it.
     */
    public static JSONObject publishable(String domain) {
        String host = mailHost();
        String mode = currentMode();
        JSONObject test = testPolicy("mta-sts." + domain, host, mode);
        JSONObject r = new JSONObject().put("domain", domain).put("test", test);
        if (test.optBoolean("ok", false))
            return r.put("publishable", true)
                    .put("value", recordTxt(policy(host, mode, recommendedMaxAge(mode))));
        return r.put("publishable", false)
                .put("reason", I18n.tr("server.mtasts.notYet", java.util.Map.of("url", String.valueOf("https://mta-sts." + domain + PATH), "err", String.valueOf(test.optString("error", I18n.tr("server.mtasts.unknownReason"))))));
    }

    /** The managed domains, for the interface. */
    public static List<String> domains() {
        List<String> l = new ArrayList<>();
        try { for (var d : Main.mailDatabase.getDomains()) l.add(d.domain); } catch (Exception ignore) {}
        return l;
    }
}
