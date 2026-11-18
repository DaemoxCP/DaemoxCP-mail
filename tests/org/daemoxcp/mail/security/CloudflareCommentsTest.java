package org.daemoxcp.mail.security;

import com.sun.net.httpserver.HttpServer;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * The comments of the DNS records the panel writes on Cloudflare, always in English (reperto 211). The owner, on
 * 09/11/2026: "when it adds a record, do not use Italian in the comments like «Creato dal pannello di posta» but always
 * English". Against a fake Cloudflare API on this machine (nothing real is touched):
 *  - the records the panel creates (CNAME, SRV, TXT) carry an English comment, and no payload has Italian in it;
 *  - the records with the Italian comment of before get the English one: only those, with exactly that text, and with
 *    a PATCH that names only the comment (name, content, TTL and proxy stay); a user's own comment stays;
 *  - the second time there is nothing to do and nothing is written; a Cloudflare that refuses gives -1;
 *  - if Cloudflare ignored the filter and answered every record, still only the exact ones are touched.
 *
 * Usage (from the project root, after mvn package):
 *   javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/security/CloudflareCommentsTest.java
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.CloudflareCommentsTest
 */
public class CloudflareCommentsTest {

    private static int failed = 0;

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String ITALIAN = "Creato dal pannello di posta";
    /** The comments of before the product name (DaemoxCP Mail, 17/11/2026), and today's DKIM one. */
    static final String OLD_ENGLISH = "Created by the mail panel";
    static final String OLD_DKIM = "DKIM rotation - auto-managed by FreeBSD Mail Panel";
    static final String DKIM = "DKIM rotation - auto-managed by DaemoxCP Mail";
    static final String ZONE = "0123456789abcdef0123456789abcdef";

    /** The fake zone: id -> record. */
    static final List<JSONObject> records = new ArrayList<>();
    static final List<String> writes = new ArrayList<>();
    static boolean ignoreFilter = false, refusePatch = false;

    static JSONObject record(int n, String type, String name, String comment) {
        JSONObject r = new JSONObject().put("id", String.format("%032x", n)).put("type", type).put("name", name)
                .put("content", "target-" + n).put("ttl", 300).put("proxied", false);
        if (comment != null) r.put("comment", comment);
        return r;
    }

    public static void main(String[] args) throws Exception {
        org.daemoxcp.mail.i18n.I18n.setCurrent("en");
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            String method = ex.getRequestMethod(), path = ex.getRequestURI().getPath(), query = ex.getRequestURI().getRawQuery();
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            boolean bearer = ("Bearer test-token").equals(ex.getRequestHeaders().getFirst("Authorization"));
            JSONObject out = new JSONObject().put("success", bearer).put("errors", new JSONArray()).put("messages", new JSONArray());
            if (bearer && method.equals("GET") && path.equals("/zones/" + ZONE + "/dns_records")) {
                String exact = null;
                for (String kv : query == null ? new String[0] : query.split("&"))
                    if (kv.startsWith("comment.exact=")) exact = URLDecoder.decode(kv.substring(14), StandardCharsets.UTF_8);
                JSONArray result = new JSONArray();
                for (JSONObject r : records) if (ignoreFilter || exact == null || exact.equals(r.optString("comment", null))) result.put(r);
                out.put("result", result).put("result_info", new JSONObject().put("page", 1).put("total_pages", 1));
            } else if (bearer && (method.equals("PATCH") || method.equals("POST"))) {
                writes.add(method + " " + path + " " + body);
                if (method.equals("PATCH") && refusePatch) {
                    out.put("success", false).put("errors", new JSONArray().put(new JSONObject().put("code", 1000).put("message", "refused (test)")));
                } else if (method.equals("PATCH")) {
                    String id = path.substring(path.lastIndexOf('/') + 1);
                    JSONObject patch = new JSONObject(body);
                    for (JSONObject r : records) if (r.getString("id").equals(id)) for (String k : patch.keySet()) r.put(k, patch.get(k));
                    out.put("result", new JSONObject().put("id", id));
                } else {
                    out.put("result", new JSONObject().put("id", String.format("%032x", 999)));
                }
            }
            byte[] b = out.toString().getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(b); }
        });
        server.start();
        try {
            CloudflareManager cf = new CloudflareManager(null, "http://127.0.0.1:" + server.getAddress().getPort());

            System.out.println("== The records the panel creates ==");
            cf.createCnameRecord("test-token", ZONE, "autoconfig.example.org", "mail.example.org", 300);
            cf.createSrvRecord("test-token", ZONE, "_imaps._tcp.example.org", "mail.example.org", 0, 1, 993, 300);
            cf.createTxtRecord("test-token", ZONE, "mail._domainkey.example.org", "v=DKIM1; k=rsa; p=AAAA", 300);
            check("three records created: " + writes.size(), writes.size() == 3);
            check("each with an English comment", writes.stream().allMatch(w -> {
                String c = new JSONObject(w.substring(w.indexOf('{'))).optString("comment");
                return c.equals(CloudflareManager.RECORD_COMMENT) || c.equals(DKIM);
            }));
            check("  and no Italian in what is sent", writes.stream().noneMatch(w -> w.contains("Creato") || w.contains("pannello") || w.contains("posta")));

            System.out.println("\n== The records with the Italian comment of before ==");
            writes.clear();
            records.add(record(1, "CNAME", "autoconfig.example.org", ITALIAN));
            records.add(record(2, "SRV", "_imaps._tcp.example.org", ITALIAN));
            records.add(record(3, "CNAME", "mta-sts.example.org", ITALIAN));
            records.add(record(4, "TXT", "mail._domainkey.example.org", OLD_DKIM));
            records.add(record(5, "A", "www.example.org", "mine, written by hand"));
            records.add(record(6, "A", "shop.example.org", null));
            records.add(record(7, "CNAME", "old.example.org", ITALIAN + " (copy)"));
            records.add(record(8, "CNAME", "done.example.org", CloudflareManager.RECORD_COMMENT));
            records.add(record(11, "CNAME", "renamed.example.org", OLD_ENGLISH));
            int n = cf.renameLegacyComments("test-token", ZONE);
            check("5 renamed: the three Italian ones, the English one and the DKIM one with the name of before (" + n + ")", n == 5);
            check("  only those five, with a PATCH that names only the comment, with today's text", writes.size() == 5 && writes.stream().allMatch(w ->
                    w.startsWith("PATCH /zones/" + ZONE + "/dns_records/") && new JSONObject(w.substring(w.indexOf('{'))).keySet().equals(java.util.Set.of("comment"))
                    && java.util.Set.of(CloudflareManager.RECORD_COMMENT, DKIM).contains(new JSONObject(w.substring(w.indexOf('{'))).getString("comment"))));
            check("  the DKIM one with today's DKIM text", records.get(3).getString("comment").equals(DKIM));
            check("  the English one of before with today's", records.get(8).getString("comment").equals(CloudflareManager.RECORD_COMMENT));
            check("  name, content, TTL and proxy as they were", records.get(0).getString("name").equals("autoconfig.example.org")
                    && records.get(0).getString("content").equals("target-1") && records.get(0).getInt("ttl") == 300 && !records.get(0).getBoolean("proxied"));
            check("  a comment written by hand, none, and one that only starts like it: untouched",
                    records.get(4).getString("comment").equals("mine, written by hand") && !records.get(5).has("comment")
                    && records.get(6).getString("comment").equals(ITALIAN + " (copy)")
                    && records.get(3).getString("comment").startsWith("DKIM rotation"));
            check("  no Italian comment left", records.stream().noneMatch(r -> ITALIAN.equals(r.optString("comment", null))));

            writes.clear();
            check("the second time: nothing to do, nothing written", cf.renameLegacyComments("test-token", ZONE) == 0 && writes.isEmpty());

            System.out.println("\n== Cloudflare that answers otherwise ==");
            records.add(record(9, "CNAME", "late.example.org", ITALIAN));
            ignoreFilter = true;
            writes.clear();
            check("it ignores the filter and answers every record: still only the exact one is touched",
                    cf.renameLegacyComments("test-token", ZONE) == 1 && writes.size() == 1 && writes.get(0).contains(String.format("%032x", 9)));
            ignoreFilter = false;
            records.add(record(10, "CNAME", "refused.example.org", ITALIAN));
            refusePatch = true;
            check("it refuses the change: -1 (tried again at the next start), the comment stays",
                    cf.renameLegacyComments("test-token", ZONE) == -1 && ITALIAN.equals(records.get(records.size() - 1).getString("comment")));
            refusePatch = false;
            check("a wrong token: -1, nothing written", cf.renameLegacyComments("another-token", ZONE) == -1);
        } finally {
            server.stop(0);
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
