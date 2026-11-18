package org.daemoxcp.mail.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.integration.SieveGenerator;
import org.daemoxcp.mail.security.PanelSecrets;

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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

/**
 * The Sieve dialogs of the Mailboxes page and the routes they call speak the same language (reperto 224).
 *
 * <p>Before: the Filters dialog sent conditions and actions as JSON text, which /api/sieve reads with optJSONArray (null
 * for a text), so creating a filter ended in a NullPointerException whose English message reached the page; editing
 * asked GET /api/sieve?id=, which the route did not know, and sent id where it reads filter_id; deleting a forward sent
 * id where /api/forwarding reads rule_id, and no mailbox_id, so the rules of mailbox 0 were "rewritten". And the routes
 * rewrote the rules of the mailbox named by the REQUEST: a wrong number rewrote another mailbox, while the one that
 * owns the changed row kept its old rules.
 *
 * <p>On the REAL server (SSLMailServer), over HTTPS, with the test MySQL and a SieveGenerator that writes nothing and
 * remembers which mailbox it was asked to write, the requests exactly as the fixed page sends them:
 * <ul>
 *   <li>a filter is created (enabled or not, as the dialog says), read back by its number with conditions and actions
 *       as arrays, changed and deleted; each time the rules written are those of the filter's own mailbox;</li>
 *   <li>a forward is deleted by rule_id alone, and its mailbox gets its rules rewritten;</li>
 *   <li>a wrong mailbox_id in a change does not move the rewrite to another mailbox;</li>
 *   <li>conditions or actions as text, or empty, are refused with the message of the language files and change
 *       nothing; a number that is not a row gives "not found"; no exception text reaches the page;</li>
 *   <li>when the rules are not written, reperto 223 still holds: success false, saved true, server.sieve.notWritten.</li>
 * </ul>
 *
 * <p>Usage (with the test MySQL of README.md):
 * <pre>
 *   su -m nobody -c 'java -Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test \
 *        -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.SieveDialogFieldsTest'
 * </pre>
 */
public class SieveDialogFieldsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** A generator that writes nothing: it keeps the address it was asked to write and answers as told. */
    static final class FakeGenerator extends SieveGenerator {
        volatile boolean accept = true;
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
    static final String UA = "SieveDialogFieldsTest/1.0";
    static final String DOMAIN = "sieve-dialog-fields.example";

    static JSONObject post(String path, JSONObject body, String cookies) throws Exception {
        body.put("csrf_token", csrf);
        HttpRequest r = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA).header("Cookie", cookies)
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body.toString())).build();
        return new JSONObject(http.send(r, HttpResponse.BodyHandlers.ofString()).body());
    }

    static JSONObject get(String path, String cookies) throws Exception {
        HttpRequest r = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA).header("Cookie", cookies)
                .GET().build();
        return new JSONObject(http.send(r, HttpResponse.BodyHandlers.ofString()).body());
    }

    /** Written: success, nothing else to say. */
    static boolean accepted(JSONObject o) {
        return o.optBoolean("success") && !o.has("saved") && !o.has("error");
    }

    /** Refused with exactly that message, and nothing saved. */
    static boolean refusedWith(JSONObject o, String message) {
        return !o.optBoolean("success", true) && !o.has("saved") && o.optString("error").equals(message);
    }

    /** The generator was called once more, for that address. */
    static boolean wroteFor(FakeGenerator g, int before, String address) {
        String[] last = g.last();
        return g.calls.size() == before + 1 && last != null && last[0].equals(address);
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
        String badRules = I18n.t("en", "server.filter.badRules");
        String badRulesIt = I18n.t("it", "server.filter.badRules");
        String filterNotFound = I18n.t("en", "server.filter.notFound");
        String forwardNotFound = I18n.t("en", "server.forward.notFound");
        String notWritten = I18n.t("en", "server.sieve.notWritten");
        check("the messages are in the language files, English and Italian",
                !badRules.equals("server.filter.badRules") && !badRulesIt.equals("server.filter.badRules") && !badRules.equals(badRulesIt)
                        && !filterNotFound.equals("server.filter.notFound") && !forwardNotFound.equals("server.forward.notFound")
                        && !I18n.t("it", "server.filter.notFound").equals(filterNotFound)
                        && !I18n.t("it", "server.forward.notFound").equals(forwardNotFound));

        Path dir = Files.createTempDirectory("sieve-dialog-fields");
        if (System.getProperty("daemoxcp.mail.secrets.dir") == null)
            System.setProperty("daemoxcp.mail.secrets.dir", Files.createDirectories(dir.resolve("secrets")).toString());
        if (!isRoot() && PanelSecrets.text(PanelSecrets.VAULT_PUBLIC_KEY).isEmpty()) {
            // Mailbox passwords are encrypted with the vault's public key, which root writes at start.
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
        String boxAddress = "box@" + DOMAIN, otherAddress = "other@" + DOMAIN;
        int box = mailbox(db, domainId, boxAddress), other = mailbox(db, domainId, otherAddress);
        clear(db, box);
        clear(db, other);

        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        String[] login = TestSessions.open(db, "sieve-dialog-fields-test", UA);
        csrf = login[1];
        String en = "__Host-DaemoxCPMail=" + login[0] + "; __Host-lang=en";
        String it = "__Host-DaemoxCPMail=" + login[0] + "; __Host-lang=it";

        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        check("test certificate", cert.waitFor() == 0);
        SSLMailServer srv = new SSLMailServer(0, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
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
            JSONArray conditions = new JSONArray().put(new JSONObject().put("field", "subject").put("operator", "contains")
                    .put("value", "invoice-224"));
            JSONArray actions = new JSONArray().put(new JSONObject().put("type", "move").put("value", "INBOX.Invoices"));

            System.out.println("\n== Filters, as the dialog sends them ==");
            int n = gen.calls.size();
            JSONObject c1 = post("/api/sieve", new JSONObject().put("action", "create").put("mailbox_id", box)
                    .put("name", "Invoices").put("enabled", true).put("conditions", conditions).put("actions", actions), en);
            check("create: written " + c1, accepted(c1));
            check("the rules written are the mailbox's, with the filter", wroteFor(gen, n, boxAddress)
                    && gen.last()[1].contains("invoice-224") && gen.last()[1].contains("INBOX.Invoices"));
            List<MailDatabase.SieveFilter> filters = db.getSieveFilters(box);
            check("the filter is in the database, enabled", filters.size() == 1 && filters.get(0).name.equals("Invoices")
                    && filters.get(0).enabled);
            int filterId = filters.isEmpty() ? 0 : filters.get(0).id;

            JSONObject c2 = post("/api/sieve", new JSONObject().put("action", "create").put("mailbox_id", box)
                    .put("name", "Paused").put("enabled", false).put("conditions", conditions).put("actions", actions), en);
            check("create a disabled one: written " + c2, accepted(c2));
            MailDatabase.SieveFilter paused = db.getSieveFilters(box).stream().filter(x -> x.name.equals("Paused")).findFirst().orElse(null);
            check("it is in the database DISABLED, as the dialog said", paused != null && !paused.enabled);

            JSONObject one = get("/api/sieve?id=" + filterId, en);
            JSONObject read = one.optJSONObject("filter");
            check("GET ?id= gives that filter: " + one, one.optBoolean("success") && read != null && read.optInt("id") == filterId
                    && read.optString("name").equals("Invoices") && read.optBoolean("enabled"));
            check("with conditions and actions as arrays, as they were sent", read != null
                    && read.optJSONArray("conditions") != null && read.optJSONArray("conditions").similar(conditions)
                    && read.optJSONArray("actions") != null && read.optJSONArray("actions").similar(actions));
            JSONObject missing = get("/api/sieve?id=987654321", en);
            check("GET ?id= of no filter: not found " + missing, refusedWith(missing, filterNotFound));
            JSONObject list = get("/api/sieve?mailbox_id=" + box, en);
            JSONArray listed = list.optJSONArray("filters");
            check("the list of the mailbox still answers, with arrays: " + list, list.optBoolean("success") && listed != null
                    && listed.length() == 2 && listed.getJSONObject(0).optJSONArray("conditions") != null);

            JSONArray changed = new JSONArray().put(new JSONObject().put("field", "from").put("operator", "is")
                    .put("value", "bills@elsewhere.example"));
            n = gen.calls.size();
            JSONObject u1 = post("/api/sieve", new JSONObject().put("action", "update").put("filter_id", filterId)
                    .put("name", "Bills").put("enabled", true).put("conditions", changed).put("actions", actions), en);
            check("update by filter_id, no mailbox_id: written " + u1, accepted(u1));
            check("the rules written are the filter's mailbox's, with the change", wroteFor(gen, n, boxAddress)
                    && gen.last()[1].contains("bills@elsewhere.example"));
            MailDatabase.SieveFilter after = filter(db, box, filterId);
            check("the change is in the database", after != null && after.name.equals("Bills")
                    && new JSONArray(after.conditions).similar(changed));

            n = gen.calls.size();
            JSONObject u2 = post("/api/sieve", new JSONObject().put("action", "update").put("filter_id", filterId)
                    .put("mailbox_id", other).put("name", "Bills").put("enabled", true).put("conditions", changed)
                    .put("actions", actions), en);
            check("update naming another mailbox: written " + u2, accepted(u2));
            check("the rewrite follows the filter's row, not the mailbox_id of the request", wroteFor(gen, n, boxAddress));

            System.out.println("\n== Filters, what is refused ==");
            int rows = db.getSieveFilters(box).size();
            n = gen.calls.size();
            JSONObject t1 = post("/api/sieve", new JSONObject().put("action", "create").put("mailbox_id", box)
                    .put("name", "As text").put("enabled", true).put("conditions", conditions.toString())
                    .put("actions", actions.toString()), en);
            check("conditions and actions as JSON text (the page before): refused with the message " + t1, refusedWith(t1, badRules));
            JSONObject t2 = post("/api/sieve", new JSONObject().put("action", "create").put("mailbox_id", box)
                    .put("name", "Empty").put("enabled", true).put("conditions", new JSONArray()).put("actions", actions), it);
            check("no conditions: refused, in Italian " + t2, refusedWith(t2, badRulesIt));
            JSONObject t3 = post("/api/sieve", new JSONObject().put("action", "create").put("mailbox_id", box)
                    .put("name", "Not objects").put("enabled", true).put("conditions", new JSONArray().put("subject"))
                    .put("actions", actions), en);
            check("conditions that are not objects: refused " + t3, refusedWith(t3, badRules));
            JSONObject t4 = post("/api/sieve", new JSONObject().put("action", "update").put("filter_id", filterId)
                    .put("name", "Bills").put("enabled", true).put("conditions", changed.toString()).put("actions", actions), en);
            check("an update with conditions as text: refused " + t4, refusedWith(t4, badRules));
            JSONObject t5 = post("/api/sieve", new JSONObject().put("action", "update").put("filter_id", 987654321)
                    .put("name", "Ghost").put("enabled", true).put("conditions", changed).put("actions", actions), en);
            check("update of no filter: not found " + t5, refusedWith(t5, filterNotFound));
            JSONObject t6 = post("/api/sieve", new JSONObject().put("action", "delete").put("filter_id", 987654321), en);
            check("delete of no filter: not found " + t6, refusedWith(t6, filterNotFound));
            JSONObject t7 = post("/api/sieve", new JSONObject().put("action", "delete").put("id", filterId), en);
            check("delete with id instead of filter_id (no such field): not found, nothing deleted " + t7,
                    refusedWith(t7, filterNotFound) && filter(db, box, filterId) != null);
            check("nothing written to the database, nothing to the mail server", db.getSieveFilters(box).size() == rows
                    && filter(db, box, filterId).name.equals("Bills") && gen.calls.size() == n);
            JSONObject t8 = get("/api/sieve?mailbox_id=abc", en);
            check("a mailbox number that is not a number: no exception text " + t8,
                    !t8.toString().contains("For input string") && !t8.toString().contains("Exception"));

            System.out.println("\n== Filters, rules not written (reperto 223 still holds) ==");
            gen.accept = false;
            n = gen.calls.size();
            JSONObject r1 = post("/api/sieve", new JSONObject().put("action", "update").put("filter_id", filterId)
                    .put("name", "Bills").put("enabled", false).put("conditions", changed).put("actions", actions), en);
            check("update, rules refused: success false, saved, the message " + r1, !r1.optBoolean("success", true)
                    && r1.optBoolean("saved") && r1.optString("error").equals(notWritten));
            check("the generator was asked for the filter's mailbox", wroteFor(gen, n, boxAddress));
            check("the change is in the database all the same", !filter(db, box, filterId).enabled);
            gen.accept = true;

            n = gen.calls.size();
            JSONObject d1 = post("/api/sieve", new JSONObject().put("action", "delete").put("filter_id", filterId), en);
            check("delete by filter_id, as the dialog sends it: written " + d1, accepted(d1));
            check("the rules written are the mailbox's, without the filter", wroteFor(gen, n, boxAddress)
                    && !gen.last()[1].contains("bills@elsewhere.example"));
            check("the filter is gone from the database", filter(db, box, filterId) == null);

            System.out.println("\n== Forwarding ==");
            JSONObject fw = post("/api/forwarding", new JSONObject().put("action", "create").put("mailbox_id", box)
                    .put("destination", "far@elsewhere.example").put("keep_copy", true), en);
            check("create: written " + fw, accepted(fw));
            List<MailDatabase.ForwardingRule> rules = db.getForwardingRules(box);
            int ruleId = rules.isEmpty() ? 0 : rules.get(0).id;
            check("the forward is in the database", rules.size() == 1);

            n = gen.calls.size();
            JSONObject f1 = post("/api/forwarding", new JSONObject().put("action", "update").put("rule_id", ruleId)
                    .put("mailbox_id", other).put("destination", "near@elsewhere.example").put("keep_copy", false).put("enabled", true), en);
            check("update naming another mailbox: written " + f1, accepted(f1));
            check("the rewrite follows the forward's row, not the mailbox_id of the request", wroteFor(gen, n, boxAddress)
                    && gen.last()[1].contains("near@elsewhere.example"));

            n = gen.calls.size();
            JSONObject f2 = post("/api/forwarding", new JSONObject().put("action", "delete").put("id", ruleId), en);
            check("delete with id (the page before): not found, the forward stays " + f2,
                    refusedWith(f2, forwardNotFound) && forward(db, box, ruleId) != null && gen.calls.size() == n);

            gen.accept = false;
            JSONObject f3 = post("/api/forwarding", new JSONObject().put("action", "delete").put("rule_id", ruleId), en);
            check("delete by rule_id, rules refused: success false, saved, the message " + f3, !f3.optBoolean("success", true)
                    && f3.optBoolean("saved") && f3.optString("error").equals(notWritten));
            check("the generator was asked for the forward's mailbox, rules without it", wroteFor(gen, n, boxAddress)
                    && !gen.last()[1].contains("near@elsewhere.example"));
            check("the forward is gone from the database", forward(db, box, ruleId) == null);
            gen.accept = true;

            JSONObject f4 = post("/api/forwarding", new JSONObject().put("action", "delete").put("rule_id", ruleId), en);
            check("delete it again: not found " + f4, refusedWith(f4, forwardNotFound));
            JSONObject f5 = get("/api/forwarding?mailbox_id=abc", en);
            check("a mailbox number that is not a number: no exception text " + f5,
                    !f5.toString().contains("For input string") && !f5.toString().contains("Exception"));
            check("the other mailbox was never written", gen.calls.stream().noneMatch(c -> c[0].equals(otherAddress)));
        } finally {
            https.stop(0);
            clear(db, box);
            clear(db, other);
            for (String a : new String[]{boxAddress, otherAddress}) {
                MailDatabase.Mailbox m = db.getMailboxByEmail(a);
                if (m != null) db.deleteMailbox(m.id);
            }
            MailDatabase.Domain d = db.getDomainByName(DOMAIN);
            if (d != null) db.deleteDomain(d.id);
            db.close();
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static int mailbox(MailDatabase db, int domainId, String address) throws Exception {
        MailDatabase.Mailbox m = db.getMailboxByEmail(address);
        return m != null ? m.id : db.addMailbox(domainId, address, "A-long-test-password-42", "Test", 100);
    }

    // Read through the lists, which the server had before reperto 224 too: the test runs against the jar of before.
    static MailDatabase.SieveFilter filter(MailDatabase db, int mailboxId, int id) {
        return db.getSieveFilters(mailboxId).stream().filter(x -> x.id == id).findFirst().orElse(null);
    }

    static MailDatabase.ForwardingRule forward(MailDatabase db, int mailboxId, int id) {
        return db.getForwardingRules(mailboxId).stream().filter(x -> x.id == id).findFirst().orElse(null);
    }

    static void clear(MailDatabase db, int mailboxId) throws Exception {
        for (MailDatabase.ForwardingRule r : db.getForwardingRules(mailboxId)) db.deleteForwardingRule(r.id);
        for (MailDatabase.SieveFilter sf : db.getSieveFilters(mailboxId)) db.deleteSieveFilter(sf.id);
    }
}
