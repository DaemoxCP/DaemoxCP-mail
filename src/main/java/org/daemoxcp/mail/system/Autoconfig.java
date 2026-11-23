package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The configuration file that Thunderbird looks for by itself when you add a mailbox.
 *
 * Why this class exists, given that we already have the SRV records: **Thunderbird does not
 * use them.** Bugzilla requests 342242 and 675476 have been asking for RFC 6186 for years and have
 * not been implemented; the Mozilla documentation lists as the only mechanisms the XML file,
 * Mozilla's central database and finally guessing. So without this file, whoever adds a
 * mailbox in Thunderbird still has to remember server, ports and encryption, exactly as
 * before.
 *
 * The file is generated for EACH domain, not a single one for all of them. The official
 * documentation does not say whether Thunderbird requires the &lt;domain&gt; element to match the
 * domain of the address: when the source does not cover the case, we choose the alternative that
 * is right either way, and one file per domain is right in both scenarios.
 *
 * The values are NOT hand-written here: ports and encryption are the ones the panel really
 * configures (Dovecot listening on 993 with direct TLS, Postfix submission on 587 with
 * smtpd_tls_security_level=encrypt), and the username is the full address because that is how
 * Dovecot queries the database (WHERE email='%s').
 */
public class Autoconfig {

    /** IMAP port over direct TLS: imaps inet_listener in DovecotConfig. */
    public static final int IMAP_PORT = 993;
    /** Submission: "submission inet" in master.cf, with mandatory TLS. */
    public static final int SMTP_PORT = 587;

    private Autoconfig() {}

    /*
     * ===================================================================
     * The file
     * ===================================================================
     */

    /**
     * The XML for one domain. A pure function: same inputs, same file, and it can be tested
     * without a server.
     */
    public static String xml(String domain, String mailHost) {
        String d = escape(domain);
        String h = escape(mailHost);
        return """
            <?xml version="1.0" encoding="UTF-8"?>
            <clientConfig version="1.1">
              <emailProvider id="%s">
                <domain>%s</domain>
                <displayName>%s</displayName>
                <displayShortName>%s</displayShortName>

                <incomingServer type="imap">
                  <hostname>%s</hostname>
                  <port>%d</port>
                  <socketType>SSL</socketType>
                  <username>%%EMAILADDRESS%%</username>
                  <authentication>password-cleartext</authentication>
                </incomingServer>

                <outgoingServer type="smtp">
                  <hostname>%s</hostname>
                  <port>%d</port>
                  <socketType>STARTTLS</socketType>
                  <username>%%EMAILADDRESS%%</username>
                  <authentication>password-cleartext</authentication>
                </outgoingServer>
              </emailProvider>
            </clientConfig>
            """.formatted(d, d, d, d, h, IMAP_PORT, h, SMTP_PORT);
    }

    /**
     * XML escaping. With a whitelist upstream, domain names would never contain these
     * characters, but the file is built by concatenation: if one day someone puts into it
     * a value that comes from outside, this still holds up.
     */
    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    /** A domain is served only if the panel really manages it. A whitelist, not a filter. */
    public static String managedDomain(String required) {
        if (required == null) return null;
        String r = required.trim().toLowerCase(Locale.ROOT);
        if (r.startsWith("autoconfig.")) r = r.substring("autoconfig.".length());
        int p = r.indexOf(':');
        if (p > 0) r = r.substring(0, p);
        if (r.isEmpty()) return null;
        // The database is not queried on every request: this route is public and anyone
        // can call it over and over. See DomainCache.
        return DomainCache.managed(r);
    }

    /** The domain of the mailbox given in the emailaddress parameter, if there is one. */
    public static String domainFromAddress(String address) {
        if (address == null) return null;
        int a = address.lastIndexOf('@');
        return a < 0 ? null : address.substring(a + 1);
    }

    public static String mailHost() {
        try {
            return Main.mailDatabase.getSetting("mail_hostname", "");
        } catch (Exception e) {
            return "";
        }
    }

    /*
     * ===================================================================
     * The real state of the server
     * ===================================================================
     */

    private static final String[] CONF_CANDIDATES = {
        "/usr/local/etc/nginx/sites-enabled/roundcube.conf",
        "/usr/local/etc/nginx/nginx.conf",
    };

    /** The nginx configuration file that contains the site listening on 443. */
    public static String confNginx() {
        for (String c : CONF_CANDIDATES) {
            try {
                Path p = Path.of(c);
                if (!Files.isReadable(p)) continue;
                String t = Files.readString(p);
                // We do NOT look for "listen 443": this server listens on 8443, and "listen 8443"
                // does not contain "listen 443". The check written that way declared as not found
                // a configuration that was there, on a port chosen on purpose.
                if (t.contains("listen ") && t.contains("ssl") && t.contains("server_name")) return c;
            } catch (Exception ignore) {}
        }
        return null;
    }

    static final String MARKER = "# --- autoconfig Thunderbird (" + Product.NAME + ") ---";

    /**
     * The panel's block is already there, with the current marker or with the previous one
     * (legacy-names.json). The file belongs to nginx, not to the panel: the previous marker stays
     * where it is, and without recognising it a second block would be added, which nginx -t rejects.
     */
    static boolean hasBlock(String text) {
        for (String m : PanelMarker.forms("autoconfigMarker", MARKER)) if (text.contains(m)) return true;
        return false;
    }

    /**
     * What is missing for Thunderbird to find the file. It READS, it touches nothing.
     */
    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);
        String host = mailHost();
        r.put("mailHost", host);
        if (host == null || host.isBlank())
            return r.put("ready", false)
                    .put("error", I18n.tr("server.autoconf.noHostnameFile"));

        String conf = confNginx();
        r.put("conf", conf == null ? JSONObject.NULL : conf);
        if (conf == null)
            return r.put("ready", false)
                    .put("error", I18n.tr("server.autoconf.noNginx443"));

        String text = "";
        try { text = Files.readString(Path.of(conf)); } catch (Exception ignore) {}
        boolean coveredName = text.contains("autoconfig.") && text.contains("mta-sts.");
        boolean brokenPresent = hasBlock(text);
        r.put("coveredName", coveredName).put("brokenPresent", brokenPresent);
        r.put("serverName", firstLineWith(text, "server_name"));
        // If the public surface on 443 is installed, those names are its own and this
        // tab must not even offer to touch nginx: a button that, when pressed,
        // refuses, is a button that should not have been shown.
        r.put("surface443", WebProtection.state().optBoolean("installed", false));

        // The certificate: if it does not cover autoconfig.<domain>, Thunderbird runs into a TLS
        // error before it even reads the file.
        JSONArray domains = new JSONArray();
        List<String> troubles = new ArrayList<>();
        int reviewed = 0, working = 0;
        boolean readList = false;
        try {
            var allItems = Main.mailDatabase.getDomains();
            readList = true;
            for (var d : allItems) {
                String name = "autoconfig." + d.domain;
                JSONObject j = new JSONObject().put("domain", d.domain).put("name", name);
                j.put("dns", resolves(name));
                j.put("certificate", certificateCovers(name));
                // The test that counts: we ASK for the file the way Thunderbird would ask for it.
                // Reading the nginx configuration says what should happen; this test
                // says what does happen. They are not the same thing, and when they diverge it is
                // always the second one that is right.
                JSONObject test = testDownload(name, d.domain);
                j.put("test", test);
                reviewed++;
                if (test.optBoolean("ok", false)) working++;
                else troubles.add(d.domain + " (" + test.optString("error", I18n.tr("server.autoconf.failed")) + ")");
                domains.put(j);
            }
        } catch (Exception e) {
            troubles.add(I18n.tr("server.autoconf.domainsUnreadable", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("Autoconfig", e))));
        }
        r.put("domains", domains).put("reviewed", reviewed).put("working", working);

        // The verdict comes from the TEST, not from the text of the configuration.
        //
        // It used to be "nomeCoperto && rottaPresente", that is the result of a search inside
        // nginx.conf for the marker that this very class writes. But the route can live
        // elsewhere -- and it does live elsewhere: the 443 tab installs it in
        // conf.d/daemoxcp-mail-public.conf, which serves exactly these two files, the MTA-STS
        // policy and this XML. Result: the panel really downloaded the file, got it,
        // and a moment later declared that nginx does not serve it and that clients have to
        // be configured by hand. The comment above already said which of the two measurements is
        // right; the verdict used the other one.
        boolean ready = ready(readList, reviewed, working);
        r.put("ready", ready);
        r.put("why", ready
                ? I18n.tr("server.autoconf.arrivesAll", java.util.Map.of("n", String.valueOf(reviewed))) + " " + (brokenPresent
                        ? I18n.tr("server.autoconf.routeIn", java.util.Map.of("conf", String.valueOf(conf)))
                        : I18n.tr("server.autoconf.routeElsewhere", java.util.Map.of("conf", String.valueOf(conf))))
                : reviewed == 0
                  ? I18n.tr("server.autoconf.noneTried")
                  : I18n.tr("server.autoconf.notArriving", java.util.Map.of("n", String.valueOf(troubles.size()), "tot", String.valueOf(reviewed), "list", String.valueOf(String.join("; ", troubles)))));
        return r;
    }

    /**
     * Asks for the file exactly as Thunderbird would and looks at what comes back.
     *
     * The outcomes are kept separate on purpose: "the certificate is not valid for that name"
     * and "the file is not there" are two different faults with two opposite remedies, and
     * confusing them would send someone off to redo the wrong thing.
     */
    /**
     * The verdict, split out of state() so that a test can reach it.
     *
     * This is the line that was wrong: it used to say "ready" based on a text search inside
     * nginx.conf, and so it declared that nginx was not serving a file it was serving. Now
     * it depends only on the tests, and it has three conditions, all of them necessary:
     *
     *  - the list of domains could be read: if it was not read, nothing was tested;
     *  - at least one domain was tested: zero tests, all successful, make "0 == 0", that is
     *    green. On zero domains a count always says yes, and it is the quietest way to
     *    declare working something that nobody has looked at;
     *  - all the tests succeeded: a single failing one is enough, because it is a domain whose
     *    clients still have to be configured by hand.
     */
    static boolean ready(boolean readList, int reviewed, int working) {
        return readList && reviewed > 0 && working == reviewed;
    }

    private static JSONObject testDownload(String name, String domain) {
        JSONObject r = new JSONObject();
        String url = "https://" + name + "/mail/config-v1.1.xml?emailaddress=test@" + domain;
        r.put("url", url);
        try {
            java.net.http.HttpClient http = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(6))
                    .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
                    .build();
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(url))
                    .timeout(java.time.Duration.ofSeconds(8))
                    .GET().build();
            java.net.http.HttpResponse<String> resp =
                    http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            r.put("code", resp.statusCode());
            String body = resp.body() == null ? "" : resp.body();
            boolean right = resp.statusCode() == 200 && body.contains("<clientConfig")
                    && body.contains("<domain>" + domain + "</domain>");
            r.put("ok", right);
            if (!right) {
                if (resp.statusCode() != 200)
                    r.put("error", I18n.tr("server.autoconf.status", java.util.Map.of("c", String.valueOf(resp.statusCode()))));
                else if (!body.contains("<clientConfig"))
                    r.put("error", I18n.tr("server.autoconf.notConfigFile"));
                else
                    r.put("error", I18n.tr("server.autoconf.otherDomain", java.util.Map.of("d", String.valueOf(domain))));
            }
            return r;
        } catch (javax.net.ssl.SSLException e) {
            return r.put("ok", false).put("tls", true)
                    .put("error", I18n.tr("server.autoconf.certInvalid", java.util.Map.of("name", String.valueOf(name))));
        } catch (java.net.UnknownHostException e) {
            return r.put("ok", false)
                    .put("error", I18n.tr("server.autoconf.noCname", java.util.Map.of("name", String.valueOf(name))));
        } catch (Exception e) {
            return r.put("ok", false)
                    .put("error", I18n.tr("server.autoconf.unreachable", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("Autoconfig", e))));
        }
    }

    private static String firstLineWith(String text, String ago) {
        for (String r : text.split("\n")) if (r.contains(ago)) return r.trim();
        return "";
    }

    /** The name resolves in DNS (the autoconfig.* CNAME created by the DNS page). */
    private static boolean resolves(String name) {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", name);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return !out.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    /** The certificate in use contains that name among its SANs. */
    private static boolean certificateCovers(String name) {
        try {
            Path cert = Path.of("/usr/local/etc/ssl/mail/fullchain.pem");
            if (!Files.isReadable(cert)) return false;
            ProcessBuilder pb = new ProcessBuilder("openssl", "x509", "-in", cert.toString(),
                    "-noout", "-text");
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            for (String r : out.split("\n")) {
                if (!r.contains("DNS:")) continue;
                for (String piece : r.split(",")) {
                    String s = piece.trim();
                    if (s.startsWith("DNS:") && s.substring(4).trim().equalsIgnoreCase(name)) return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /*
     * ===================================================================
     * The installation
     * ===================================================================
     */

    /**
     * Adds to nginx the autoconfig name and the route that forwards the request to the
     * panel, which generates the right XML for the requested domain.
     *
     * It follows the same discipline used to raise Postfix's level: a backup
     * copy, the change, VALIDATION with nginx -t, and if the validation fails the copy
     * is restored and nothing is reloaded. A webmail taken down to add a
     * configuration file would be a terrible trade.
     */
    public static JSONObject install() {
        JSONObject r = new JSONObject();
        try {
            JSONObject st = state();
            if (!st.optBoolean("success", false) || st.has("error"))
                return r.put("success", false).put("error", st.optString("error", I18n.tr("server.autoconf.stateUnreadable")));
            if (st.optBoolean("ready", false))
                return r.put("success", true).put("alreadyDone", true)
                        .put("note", I18n.tr("server.autoconf.alreadyAll") + " " + st.optString("why", ""));

            // The guard that counts, and it applies even when the file does NOT arrive.
            //
            // If the public surface on 443 is installed, autoconfig.<domain> and
            // mta-sts.<domain> are already served by it, and it is a block written precisely for this:
            // only two exact locations, 404 on everything else, rate limits, only GET and
            // HEAD, and a log of its own that the fail2ban jail watches.
            //
            // That block is declared "server_name _", that is, it wins as default_server only
            // as long as nobody else claims those names. Adding "autoconfig.* mta-sts.*" to the
            // webmail's server_name would take them away from it -- in nginx a wildcard name
            // beats the default_server -- and with them the protection and the jail's log, which
            // would stay "active" on a file that nobody writes any more.
            //
            // "nginx -t" would not notice: it is a break in meaning, not in
            // syntax. So the decision has to be made here, before writing.
            if (WebProtection.state().optBoolean("installed", false))
                return r.put("success", false).put("alreadyElsewhere", true)
                        .put("error", I18n.tr("server.autoconf.publicSurface", java.util.Map.of("file", WebProtection.FILE_NAME)) + " " + st.optString("why", ""));

            // Which MTA-STS policies answer BEFORE anything is touched. Without this
            // snapshot, afterwards there is no way to know whether I broke one.
            List<String> policiesBefore = answeringPolicies();
            r.put("policiesBefore", new JSONArray(policiesBefore));

            String conf = st.getString("conf");
            Path p = Path.of(conf);
            String text = Files.readString(p);
            r.put("conf", conf);

            Path copy = Path.of("/var/db/daemoxcp-mail/nginx-before-autoconfig.conf");
            Files.createDirectories(copy.getParent());
            Files.writeString(copy, text);
            r.put("copy", copy.toString());

            String fresh = text;

            // 1. the names: without them, nginx does not answer for autoconfig.<domain>
            if (!fresh.contains("autoconfig.") || !fresh.contains("mta-sts.")) {
                int i = fresh.indexOf("server_name");
                if (i < 0) return r.put("success", false)
                        .put("error", I18n.tr("server.autoconf.noServerName"));
                int end = fresh.indexOf(';', i);
                if (end < 0) return r.put("success", false)
                        .put("error", I18n.tr("server.autoconf.serverNameNoSemicolon"));
                fresh = fresh.substring(0, end) + " autoconfig.* mta-sts.*" + fresh.substring(end);
            }

            // 2. the route: the request goes to the panel, which knows which domains exist and
            //    builds the XML for the right one. A static file could not.
            if (!hasBlock(fresh)) {
                int i = fresh.indexOf("location /");
                if (i < 0) return r.put("success", false)
                        .put("error", I18n.tr("server.autoconf.noLocation"));
                // Two routes, a single marker: both forward the request to the panel, which
                // knows which domains exist and generates the content for the requested one. A
                // static file could not, because the content depends on the domain.
                String broken = MARKER + "\n"
                        + "    location = /mail/config-v1.1.xml {\n"
                        + "        proxy_pass https://127.0.0.1:2096/autoconfig/mail/config-v1.1.xml;\n"
                        + "        proxy_set_header Host $host;\n"
                        + "    }\n"
                        + "    location = /.well-known/mta-sts.txt {\n"
                        + "        proxy_pass https://127.0.0.1:2096/mta-sts/policy;\n"
                        + "        proxy_set_header Host $host;\n"
                        + "    }\n\n    ";
                fresh = fresh.substring(0, i) + broken + fresh.substring(i);
            }

            Files.writeString(p, fresh);

            // 3. the validation. This is where we decide whether to go ahead or go back.
            Outcome test = run("nginx", "-t");
            if (test.code != 0) {
                Files.writeString(p, text);
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.autoconf.nginxRejected", java.util.Map.of("out", String.valueOf(test.output.trim()))));
            }

            Outcome reloadOutcome = run("service", "nginx", "reload");
            if (reloadOutcome.code != 0) {
                Files.writeString(p, text);
                run("service", "nginx", "reload");
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.autoconf.reloadFailed", java.util.Map.of("out", String.valueOf(reloadOutcome.output.trim()))));
            }

            // A check cannot look only at what I wanted to achieve: it must also look at
            // what I might have broken. Moving names between two server_name directives moves the
            // requests from one block to the other, and the block that loses them is the one that
            // serves the MTA-STS policy. With the TXT records already published, making it disappear
            // means leaving the world the declaration of a protection that no longer answers.
            List<String> policiesAfter = answeringPolicies();
            List<String> lost = new ArrayList<>(policiesBefore);
            lost.removeAll(policiesAfter);
            if (!lost.isEmpty()) {
                Files.writeString(p, text);
                run("service", "nginx", "reload");
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.autoconf.stsLost", java.util.Map.of("list", String.valueOf(String.join(", ", lost)))));
            }

            JSONObject after = state();
            r.put("stateAfter", after);
            if (!after.optBoolean("ready", false)) {
                Files.writeString(p, text);
                run("service", "nginx", "reload");
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.autoconf.stillNotArriving", java.util.Map.of("why", String.valueOf(after.optString("why", "")), "copy", String.valueOf(copy))));
            }

            return r.put("success", true)
                    .put("note", I18n.tr("server.autoconf.done", java.util.Map.of("copy", String.valueOf(copy))));
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.autoconf.installError", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("Autoconfig", e))));
        }
    }

    /**
     * The domains whose MTA-STS policy answers right now.
     *
     * It is used to take a before/after around an nginx change: it is the only way to
     * notice having broken something one was not trying to touch. A domain that already
     * was not answering before does not count as damage -- it was not broken here -- and
     * including it would make a successful installation fail.
     */
    private static List<String> answeringPolicies() {
        List<String> liveOnes = new ArrayList<>();
        try {
            for (var d : Main.mailDatabase.getDomains())
                if (MtaSts.publicTest(d.domain).optBoolean("ok", false)) liveOnes.add(d.domain);
        } catch (Exception ignore) {}
        return liveOnes;
    }

    private record Outcome(int code, String output) {}

    private static Outcome run(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return new Outcome(p.waitFor(), out);
        } catch (Exception e) {
            return new Outcome(-1, String.valueOf(e.getMessage()));
        }
    }

    /** The preview of the file, to look at it before installing anything. */
    public static JSONObject preview() {
        JSONObject r = new JSONObject().put("success", true);
        String host = mailHost();
        if (host == null || host.isBlank())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.autoconf.noHostname"));
        List<String> names = new ArrayList<>();
        try { for (var d : Main.mailDatabase.getDomains()) names.add(d.domain); } catch (Exception ignore) {}
        if (names.isEmpty())
            return new JSONObject().put("success", false).put("error", I18n.tr("server.autoconf.noDomains"));
        return r.put("domain", names.get(0)).put("mailHost", host)
                .put("xml", xml(names.get(0), host)).put("domainCount", names.size());
    }
}
