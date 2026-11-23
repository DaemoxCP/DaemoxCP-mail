package org.daemoxcp.mail.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.integration.SieveGenerator;
import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.system.AddressTransform;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

/**
 * The page is told when the panel's Sieve rules were NOT written (finding 223).
 *
 * <p>{@code SieveGenerator.saveSieveScript} returns false when it does not write a mailbox's rules: a bad address, and
 * since finding 221 also while any folder from / to /var/mail/sieve can be changed by others (for example /var/mail
 * without its sticky bit). Its callers dropped that result, so the page said the change was done while Dovecot kept
 * running the earlier rules.
 *
 * <p>On the REAL server (SSLMailServer), over HTTPS, with the test MySQL and a SieveGenerator that refuses or accepts on
 * request (the real one writes under /var/mail as root; its refusals are SieveGroupMailTest's). For /api/forwarding
 * (create, update, delete), /api/sieve (create, update, delete), /api/autoresponder (save) and /api/aliases
 * (transform_to_mailbox of an address that left filters behind):
 * <ul>
 *   <li>refused: success false, saved true, the message of the language files (English, and Italian once), and the
 *       change still in the database: nothing undone in silence;</li>
 *   <li>accepted: success true, no error and no saved;</li>
 *   <li>each time the generator got the mailbox's address and the rules generated from the database as it is now.</li>
 * </ul>
 *
 * <p>The alias part makes the server run its mail configuration script (folders in /var/vmail, Postfix and Dovecot
 * reloaded). As an unprivileged user the script cannot even be written next to the jar, and nothing happens; as root it
 * would change the machine, so as root that part is skipped, saying so. Run it as an unprivileged user, with the jar and
 * the tests in a folder that user can read but not write.
 *
 * <p>Usage (with the test MySQL of README.md):
 * <pre>
 *   su -m nobody -c 'java -Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test \
 *        -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.SieveRulesNotWrittenTest'
 * </pre>
 */
public class SieveRulesNotWrittenTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** A generator that writes nothing: it keeps what it was given and answers as told. */
    static final class FakeGenerator extends SieveGenerator {
        volatile boolean accept;
        final List<String[]> calls = new CopyOnWriteArrayList<>();

        @Override
        public boolean saveSieveScript(String email, String script) {
            calls.add(new String[]{email, script});
            return accept;
        }

        String[] last() {
            return calls.isEmpty() ? null : calls.get(calls.size() - 1);
        }
    }

    static HttpClient http;
    static String base;
    static String csrf;
    static final String UA = "SieveRulesNotWrittenTest/1.0";
    static final String DOMAIN = "rules-not-written.example";

    static JSONObject post(String path, JSONObject body, String cookies) throws Exception {
        body.put("csrf_token", csrf);
        HttpRequest r = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA).header("Cookie", cookies)
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body.toString())).build();
        HttpResponse<String> answer = http.send(r, HttpResponse.BodyHandlers.ofString());
        return new JSONObject(answer.body());
    }

    /** The answer when the rules were not written: not success, saved, and exactly that message. */
    static boolean refused(JSONObject o, String message) {
        return !o.optBoolean("success", true) && o.optBoolean("saved") && o.optString("error").equals(message);
    }

    /** The answer when they were: success, nothing else to say. */
    static boolean accepted(JSONObject o) {
        return o.optBoolean("success") && !o.has("saved") && !o.has("error");
    }

    /** The generator was called for that address, with rules that contain the text. */
    static boolean wrote(FakeGenerator g, int before, String address, String text) {
        String[] last = g.last();
        return g.calls.size() == before + 1 && last != null && last[0].equals(address) && last[1].contains(text);
    }

    static boolean isRoot() {
        try {
            return new com.sun.security.auth.module.UnixSystem().getUid() == 0;
        } catch (Throwable t) {
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): this test needs the test MySQL, skipped.");
            return;
        }
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        I18n.setCurrent("en");
        String notWrittenEn = I18n.t("en", "server.sieve.notWritten");
        String notWrittenIt = I18n.t("it", "server.sieve.notWritten");
        check("the two messages are in the language files", !notWrittenEn.equals("server.sieve.notWritten")
                && !notWrittenIt.equals("server.sieve.notWritten") && !notWrittenEn.equals(notWrittenIt)
                && !I18n.t("en", "server.convert.oldFiltersKept").equals("server.convert.oldFiltersKept"));

        Path dir = Files.createTempDirectory("sieve-not-written");
        // The panel's keys in a test folder, before anything reads them.
        if (System.getProperty("daemoxcp.mail.secrets.dir") == null)
            System.setProperty("daemoxcp.mail.secrets.dir", Files.createDirectories(dir.resolve("secrets")).toString());
        if (!isRoot() && PanelSecrets.text(PanelSecrets.VAULT_PUBLIC_KEY).isEmpty()) {
            // Mailbox passwords are encrypted with the vault's public key, which root writes at start (as root the
            // vault makes its pair by itself). As the web part would have it: a test pair, the public half only.
            KeyPairGenerator pair = KeyPairGenerator.getInstance("RSA");
            pair.initialize(3072);
            PanelSecrets.setText(PanelSecrets.VAULT_PUBLIC_KEY,
                    Base64.getEncoder().encodeToString(pair.generateKeyPair().getPublic().getEncoded()));
        }
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "daemoxcp_mail"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "daemoxcp_mail_test"));
        check("connected to MySQL", db.connect());
        TestSessions.auditLogTo(db, dir.resolve("audit.log"));
        db.ensureMailboxPasswordVaultColumns();
        MailDatabase.Domain dom = db.getDomainByName(DOMAIN);
        int domainId = dom != null ? dom.id : db.addDomain(DOMAIN, "test");
        String boxAddress = "box@" + DOMAIN;
        MailDatabase.Mailbox old = db.getMailboxByEmail(boxAddress);
        int box = old != null ? old.id : db.addMailbox(domainId, boxAddress, "A-long-test-password-42", "Box", 100);
        for (MailDatabase.ForwardingRule r : db.getForwardingRules(box)) db.deleteForwardingRule(r.id);
        for (MailDatabase.SieveFilter f : db.getSieveFilters(box)) db.deleteSieveFilter(f.id);

        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        String[] login = TestSessions.open(db, "sieve-not-written-test", UA);
        csrf = login[1];
        String en = "__Host-DaemoxCPMail=" + login[0] + "; __Host-lang=en";
        String it = "__Host-DaemoxCPMail=" + login[0] + "; __Host-lang=it";

        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        check("test certificate", cert.waitFor() == 0);
        SSLMailServer srv = new SSLMailServer(0, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
        // The generator the server would make at start (initializeManagers, not run here): this one writes nothing.
        FakeGenerator gen = new FakeGenerator();
        Field g = SSLMailServer.class.getDeclaredField("sieveGenerator");
        g.setAccessible(true);
        g.set(srv, gen);
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();
        base = "https://127.0.0.1:" + https.getAddress().getPort();

        SSLContext trustAll = SSLContext.getInstance("TLS");
        trustAll.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] x, String a) { }
            public void checkServerTrusted(X509Certificate[] x, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        http = HttpClient.newBuilder().sslContext(trustAll).build();

        try {
            System.out.println("\n== Forwarding ==");
            gen.accept = false;
            int n = gen.calls.size();
            JSONObject c1 = post("/api/forwarding", new JSONObject().put("action", "create").put("mailbox_id", box)
                    .put("destination", "far@elsewhere.example").put("keep_copy", true), en);
            check("create, rules refused: " + c1, refused(c1, notWrittenEn));
            check("the generator got the mailbox and rules with the new forward", wrote(gen, n, boxAddress, "far@elsewhere.example"));
            List<MailDatabase.ForwardingRule> rules = db.getForwardingRules(box);
            check("the rule is in the database all the same", rules.size() == 1 && rules.get(0).destination.equals("far@elsewhere.example"));
            int ruleId = rules.isEmpty() ? 0 : rules.get(0).id;

            JSONObject c1it = post("/api/forwarding", new JSONObject().put("action", "update").put("mailbox_id", box)
                    .put("rule_id", ruleId).put("destination", "near@elsewhere.example").put("keep_copy", false).put("enabled", true), it);
            check("update in Italian, rules refused: the Italian message", refused(c1it, notWrittenIt));
            rules = db.getForwardingRules(box);
            check("the update is in the database", rules.size() == 1 && rules.get(0).destination.equals("near@elsewhere.example")
                    && !rules.get(0).keepCopy);

            gen.accept = true;
            n = gen.calls.size();
            JSONObject c2 = post("/api/forwarding", new JSONObject().put("action", "update").put("mailbox_id", box)
                    .put("rule_id", ruleId).put("destination", "far@elsewhere.example").put("keep_copy", true).put("enabled", true), en);
            check("update, rules written: " + c2, accepted(c2));
            check("the generator got the rules with the forward", wrote(gen, n, boxAddress, "far@elsewhere.example"));

            gen.accept = false;
            n = gen.calls.size();
            JSONObject c3 = post("/api/forwarding", new JSONObject().put("action", "delete").put("mailbox_id", box)
                    .put("rule_id", ruleId), en);
            check("delete, rules refused: " + c3, refused(c3, notWrittenEn));
            check("the generator got rules without the forward", gen.calls.size() == n + 1
                    && !gen.last()[1].contains("far@elsewhere.example"));
            check("the rule is gone from the database", db.getForwardingRules(box).isEmpty());

            System.out.println("\n== Filters ==");
            JSONArray conditions = new JSONArray().put(new JSONObject().put("field", "subject").put("operator", "contains")
                    .put("value", "invoice-223"));
            JSONArray actions = new JSONArray().put(new JSONObject().put("type", "move").put("value", "INBOX.Invoices"));
            n = gen.calls.size();
            JSONObject s1 = post("/api/sieve", new JSONObject().put("action", "create").put("mailbox_id", box)
                    .put("name", "Invoices").put("priority", 1).put("conditions", conditions).put("actions", actions), en);
            check("create, rules refused: " + s1, refused(s1, notWrittenEn));
            check("the generator got rules with the filter", wrote(gen, n, boxAddress, "invoice-223"));
            List<MailDatabase.SieveFilter> filters = db.getSieveFilters(box);
            check("the filter is in the database all the same", filters.size() == 1 && filters.get(0).name.equals("Invoices"));
            int filterId = filters.isEmpty() ? 0 : filters.get(0).id;

            gen.accept = true;
            n = gen.calls.size();
            JSONObject s2 = post("/api/sieve", new JSONObject().put("action", "update").put("mailbox_id", box)
                    .put("filter_id", filterId).put("name", "Bills").put("priority", 1).put("enabled", true)
                    .put("conditions", conditions).put("actions", actions), en);
            check("update, rules written: " + s2, accepted(s2));
            check("the generator got the rules", wrote(gen, n, boxAddress, "invoice-223"));
            check("the update is in the database", db.getSieveFilters(box).get(0).name.equals("Bills"));

            gen.accept = false;
            JSONObject s3 = post("/api/sieve", new JSONObject().put("action", "update").put("mailbox_id", box)
                    .put("filter_id", filterId).put("name", "Bills").put("priority", 1).put("enabled", false)
                    .put("conditions", conditions).put("actions", actions), en);
            check("update, rules refused: " + s3, refused(s3, notWrittenEn));
            n = gen.calls.size();
            JSONObject s4 = post("/api/sieve", new JSONObject().put("action", "delete").put("mailbox_id", box)
                    .put("filter_id", filterId), en);
            check("delete, rules refused: " + s4, refused(s4, notWrittenEn));
            check("the generator was called", gen.calls.size() == n + 1);
            check("the filter is gone from the database", db.getSieveFilters(box).isEmpty());

            System.out.println("\n== Auto-reply ==");
            n = gen.calls.size();
            JSONObject a1 = post("/api/autoresponder", new JSONObject().put("mailbox_id", box).put("enabled", true)
                    .put("subject", "Away-223").put("body", "Back on Monday.").put("interval_hours", 24), en);
            check("save, rules refused: " + a1, refused(a1, notWrittenEn));
            check("the generator got rules with the auto-reply", wrote(gen, n, boxAddress, "Away-223"));
            MailDatabase.AutoResponder ar = db.getAutoResponder(box);
            check("the auto-reply is in the database all the same", ar != null && ar.enabled && "Away-223".equals(ar.subject));
            gen.accept = true;
            JSONObject a2 = post("/api/autoresponder", new JSONObject().put("mailbox_id", box).put("enabled", false)
                    .put("subject", "Away-223").put("body", "Back on Monday.").put("interval_hours", 24), en);
            check("save, rules written: " + a2, accepted(a2));

            System.out.println("\n== No such mailbox ==");
            n = gen.calls.size();
            JSONObject none = post("/api/autoresponder", new JSONObject().put("mailbox_id", 987654321).put("enabled", true)
                    .put("subject", "x").put("body", "y").put("interval_hours", 24), en);
            check("not a success: " + none, !none.optBoolean("success"));
            check("the generator was not called", gen.calls.size() == n);

            System.out.println("\n== Alias to mailbox ==");
            if (isRoot()) {
                System.out.println("  SKIPPED as root: the conversion runs the mail configuration script, which would"
                        + " create folders in /var/vmail and reload Postfix and Dovecot. Run the test as an unprivileged user.");
            } else {
                aliasToMailbox(db, domainId, gen, dir, en);
            }
        } finally {
            https.stop(0);
            for (MailDatabase.ForwardingRule r : db.getForwardingRules(box)) db.deleteForwardingRule(r.id);
            for (MailDatabase.SieveFilter sf : db.getSieveFilters(box)) db.deleteSieveFilter(sf.id);
            db.close();
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    /**
     * An alias that was a mailbox and left its filters on the disk becomes a mailbox again: the panel rewrites those
     * filters empty. When it cannot, the mailbox is there but the page must say the old filters still apply.
     */
    static void aliasToMailbox(MailDatabase db, int domainId, FakeGenerator gen, Path dir, String en) throws Exception {
        // AddressTransform reads the mail and the filters on the disk: here, from a test folder.
        Field vmail = AddressTransform.class.getDeclaredField("vmail");
        Field sieve = AddressTransform.class.getDeclaredField("sieve");
        vmail.setAccessible(true);
        sieve.setAccessible(true);
        Object vmailBefore = vmail.get(null), sieveBefore = sieve.get(null);
        vmail.set(null, Files.createDirectories(dir.resolve("vmail")));
        sieve.set(null, Files.createDirectories(dir.resolve("sieve")));
        String refusedAddress = "kept-filters@" + DOMAIN, acceptedAddress = "cleared-filters@" + DOMAIN, plainAddress = "plain@" + DOMAIN;
        try {
            for (String a : new String[]{refusedAddress, acceptedAddress, plainAddress}) {
                MailDatabase.Mailbox m = db.getMailboxByEmail(a);
                if (m != null) db.deleteMailbox(m.id);
                if (db.getAliases(domainId).stream().noneMatch(x -> x.source.equals(a))) db.addAlias(domainId, a, "box@" + DOMAIN);
            }
            for (String a : new String[]{refusedAddress, acceptedAddress}) {
                Path rules = Files.createDirectories(dir.resolve("sieve").resolve(DOMAIN).resolve(a.substring(0, a.indexOf('@'))));
                Files.writeString(rules.resolve(".dovecot.sieve"), "require \"fileinto\";\nfileinto \"INBOX.Old\";\n");
            }

            gen.accept = false;
            int n = gen.calls.size();
            JSONObject r1 = convert(refusedAddress, db, en);
            String expected = I18n.t("en", "server.convert.nowMailbox", Map.of("address", refusedAddress)) + " "
                    + I18n.t("en", "server.convert.oldFiltersKept");
            check("old filters not rewritten: not a success, saved, says so: " + r1, !r1.optBoolean("success", true)
                    && r1.optBoolean("saved") && r1.optString("error").equals(expected) && r1.optInt("id") > 0);
            check("the generator got the new mailbox, with rules without the old ones", wrote(gen, n, refusedAddress, "require")
                    && !gen.last()[1].contains("INBOX.Old"));
            check("the mailbox is in the database all the same", db.getMailboxByEmail(refusedAddress) != null);

            gen.accept = true;
            n = gen.calls.size();
            JSONObject r2 = convert(acceptedAddress, db, en);
            check("old filters rewritten: success, the usual message: " + r2, r2.optBoolean("success") && !r2.has("saved")
                    && r2.optString("message").equals(I18n.t("en", "server.convert.nowMailbox", Map.of("address", acceptedAddress))));
            check("the generator got it", wrote(gen, n, acceptedAddress, "require"));

            gen.accept = false;
            n = gen.calls.size();
            JSONObject r3 = convert(plainAddress, db, en);
            check("no old filters: success, nothing to rewrite: " + r3, r3.optBoolean("success") && !r3.has("saved"));
            check("the generator was not called", gen.calls.size() == n);
        } finally {
            for (String a : new String[]{refusedAddress, acceptedAddress, plainAddress}) {
                MailDatabase.Mailbox m = db.getMailboxByEmail(a);
                if (m != null) db.deleteMailbox(m.id);
            }
            vmail.set(null, vmailBefore);
            sieve.set(null, sieveBefore);
        }
    }

    /** The conversion as the page asks for it, with the fingerprint its preview would have given. */
    static JSONObject convert(String address, MailDatabase db, String cookies) throws Exception {
        String fingerprint = AddressTransform.fingerprint(AddressTransform.state(db, address));
        return post("/api/aliases", new JSONObject().put("action", "transform_to_mailbox").put("source", address)
                .put("password", "A-long-test-password-42").put("name", "Converted").put("quota_mb", 100)
                .put("keep_forwards", false).put("old_mail", "").put("fingerprint", fingerprint), cookies);
    }
}
