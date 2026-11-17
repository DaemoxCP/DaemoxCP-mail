package org.daemoxcp.mail.security;

import com.sun.net.httpserver.HttpServer;
import org.json.JSONArray;
import org.json.JSONObject;

import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * What "Set up everything" must never do to a domain's DNS, against a fake Cloudflare API on this machine (nothing real
 * is touched). Found by the solidity review of 17/11/2026:
 *  1. a zone that cannot be read is not an empty zone: the two reads throw ZoneReadException when Cloudflare refuses,
 *     does not answer JSON, or the zone has more records than are read. Before, they returned an empty list, and a
 *     second SPF, DMARC or DKIM record could be created next to the first one;
 *  2. the server's IP: only a public IPv4 counts (no private, provider NAT, loopback, link-local or documentation
 *     address), and an unknown one is "", never the text "YOUR_SERVER_IP";
 *  3. the TXT records carry the comment of what they are: "DKIM rotation" only on DKIM records;
 *  4. DKIM: the key is installed (database, file, rspamd signing) only after its record has been seen in the zone; a
 *     name that already holds a record is left alone and no key is made; a key already installed whose record holds
 *     another key is said, not overwritten; a zone that cannot be read writes nothing.
 *
 * Usage (from the project root, after mvn package):
 *   java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.security.DnsSafetyTest
 */
public class DnsSafetyTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String ZONE = "0123456789abcdef0123456789abcdef";
    static final List<JSONObject> records = new ArrayList<>();
    static final List<String> writes = new ArrayList<>();
    /** "ok", "refuse" (success false), "garbage" (not JSON), "big" (11 pages), "refuseCreate", "hideCreated". */
    static String mode = "ok";
    static int nextId = 1;

    public static void main(String[] args) throws Exception {
        org.daemoxcp.mail.i18n.I18n.setCurrent("en");
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            String method = ex.getRequestMethod(), path = ex.getRequestURI().getPath(), query = ex.getRequestURI().getRawQuery();
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String answer;
            if (method.equals("GET") && path.equals("/zones/" + ZONE + "/dns_records")) {
                if (mode.equals("garbage")) {
                    answer = "<html>502 Bad Gateway</html>";
                } else if (mode.equals("refuse")) {
                    answer = new JSONObject().put("success", false).put("errors", new JSONArray()
                            .put(new JSONObject().put("code", 10000).put("message", "Authentication error (test)"))).toString();
                } else {
                    String type = null;
                    for (String kv : query == null ? new String[0] : query.split("&"))
                        if (kv.startsWith("type=")) type = URLDecoder.decode(kv.substring(5), StandardCharsets.UTF_8);
                    JSONArray result = new JSONArray();
                    for (JSONObject r : records) {
                        if (type != null && !type.equals(r.getString("type"))) continue;
                        if (mode.equals("hideCreated") && r.optBoolean("created")) continue;
                        result.put(r);
                    }
                    answer = new JSONObject().put("success", true).put("result", result)
                            .put("result_info", new JSONObject().put("page", 1).put("total_pages", mode.equals("big") ? 11 : 1)).toString();
                }
            } else if (method.equals("POST") && path.equals("/zones/" + ZONE + "/dns_records")) {
                writes.add(body);
                if (mode.equals("refuseCreate")) {
                    answer = new JSONObject().put("success", false).put("errors", new JSONArray()
                            .put(new JSONObject().put("code", 81057).put("message", "Record already exists (test)"))).toString();
                } else {
                    JSONObject in = new JSONObject(body);
                    String id = String.format("%032x", nextId++);
                    records.add(new JSONObject().put("id", id).put("type", in.getString("type")).put("name", in.getString("name"))
                            .put("content", in.optString("content")).put("comment", in.optString("comment")).put("created", true));
                    answer = new JSONObject().put("success", true).put("result", new JSONObject().put("id", id)).toString();
                }
            } else {
                answer = new JSONObject().put("success", false).toString();
            }
            byte[] b = answer.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.start();
        CloudflareManager cf = new CloudflareManager(null, "http://127.0.0.1:" + server.getAddress().getPort());
        try {
            reads(cf);
            serverIp();
            comments(cf);
            dkim(cf);
        } finally {
            server.stop(0);
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    static String thrown(Runnable r) {
        try {
            r.run();
            return null;
        } catch (CloudflareManager.ZoneReadException e) {
            return e.getMessage();
        }
    }

    static void reads(CloudflareManager cf) {
        System.out.println("== 1. A zone that cannot be read is not an empty zone ==");
        records.clear();
        records.add(new JSONObject().put("id", "a".repeat(32)).put("type", "TXT").put("name", "example.test").put("content", "\"v=spf1 mx -all\""));
        mode = "ok";
        check("a zone that answers: its TXT and all its records are read",
                cf.listTxtRecordsContaining("t", ZONE, null).size() == 1 && cf.listRecords("t", ZONE).size() == 1);
        for (String m : new String[] {"refuse", "garbage"}) {
            mode = m;
            String txt = thrown(() -> cf.listTxtRecordsContaining("t", ZONE, null));
            String all = thrown(() -> cf.listRecords("t", ZONE));
            check("Cloudflare " + (m.equals("refuse") ? "refuses" : "answers something that is not JSON")
                            + ": both reads throw, saying nothing was written (" + txt + ")",
                    txt != null && all != null && txt.contains("I wrote nothing") && all.contains("I wrote nothing"));
        }
        mode = "refuse";
        String why = thrown(() -> cf.listRecords("t", ZONE));
        check("  and the reason from Cloudflare is in the message", why != null && why.contains("Authentication error (test)"));
        mode = "big";
        String big = thrown(() -> cf.listTxtRecordsContaining("t", ZONE, null));
        check("a zone with more pages than are read: it throws instead of answering a part (" + big + ")",
                big != null && big.contains("more than 1000") && thrown(() -> cf.listRecords("t", ZONE)) != null);
        mode = "ok";
    }

    static void serverIp() {
        System.out.println("\n== 2. Only a public IPv4 is the server's address ==");
        String[] yes = {"8.8.8.8", "95.217.1.2", "172.15.0.1", "172.32.0.1", "100.63.255.255", "100.128.0.1", "198.20.0.1", "223.255.255.254"};
        String[] no = {"10.1.2.3", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.1.1", "172.16.0.1", "172.31.255.255",
                "192.168.1.20", "192.0.2.10", "198.51.100.7", "203.0.113.10", "198.18.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
                "YOUR_SERVER_IP", "", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", " 8.8.8.8"};
        List<String> wrongYes = new ArrayList<>(), wrongNo = new ArrayList<>();
        for (String ip : yes) if (!DnsRecordsGenerator.isPublicIpv4(ip)) wrongYes.add(ip);
        for (String ip : no) if (DnsRecordsGenerator.isPublicIpv4(ip)) wrongNo.add(ip);
        check("public addresses accepted " + (wrongYes.isEmpty() ? "" : wrongYes), wrongYes.isEmpty());
        check("private, provider NAT, loopback, link-local, documentation, multicast and malformed refused "
                + (wrongNo.isEmpty() ? "" : wrongNo), wrongNo.isEmpty());
    }

    static void comments(CloudflareManager cf) {
        System.out.println("\n== 3. Each TXT record says what it is ==");
        writes.clear();
        cf.createTxtRecord("t", ZONE, "example.test", "v=spf1 mx -all", 3600);
        cf.createTxtRecord("t", ZONE, "_dmarc.example.test", "v=DMARC1; p=none", 3600);
        cf.createTxtRecord("t", ZONE, "mail._domainkey.example.test", "v=DKIM1; k=rsa; p=AAAA", 3600);
        check("SPF and DMARC: the panel's comment, not \"DKIM rotation\"",
                new JSONObject(writes.get(0)).getString("comment").equals(CloudflareManager.RECORD_COMMENT)
                        && new JSONObject(writes.get(1)).getString("comment").equals(CloudflareManager.RECORD_COMMENT));
        check("DKIM: the rotation comment, which DkimManager reads back",
                new JSONObject(writes.get(2)).getString("comment").equals(CloudflareManager.DKIM_COMMENT));
    }

    static void dkim(CloudflareManager cf) throws Exception {
        System.out.println("\n== 4. DKIM: sign only with a key whose record is in the zone ==");
        String name = "mail._domainkey.example.test";
        DkimManager.NewKey key = new DkimManager.NewKey("mail", "PRIVATE", "NEWKEYABC", "v=DKIM1; k=rsa; p=NEWKEYABC");
        List<String> installed = new ArrayList<>();

        records.clear(); writes.clear(); installed.clear(); mode = "ok";
        DkimManager.RecordStep st = DkimManager.ensurePublished(cf, "t", ZONE, "example.test", null, null,
                s -> key, k -> installed.add(k.selector()));
        check("no key, free name: record created, then the key installed (" + st.message() + ")",
                st.ok() && writes.size() == 1 && installed.equals(List.of("mail")));

        records.clear(); writes.clear(); installed.clear(); mode = "hideCreated";
        st = DkimManager.ensurePublished(cf, "t", ZONE, "example.test", null, null, s -> key, k -> installed.add(k.selector()));
        check("Cloudflare says yes but the record is not in the zone: the key is NOT installed (" + st.message() + ")",
                !st.ok() && installed.isEmpty());

        records.clear(); writes.clear(); installed.clear(); mode = "refuseCreate";
        st = DkimManager.ensurePublished(cf, "t", ZONE, "example.test", null, null, s -> key, k -> installed.add(k.selector()));
        check("Cloudflare refuses the record: the key is NOT installed", !st.ok() && installed.isEmpty());

        records.clear(); writes.clear(); installed.clear(); mode = "ok";
        records.add(new JSONObject().put("id", "b".repeat(32)).put("type", "TXT").put("name", name).put("content", "\"v=DKIM1; k=rsa; p=SOMEONEELSE\""));
        boolean[] made = {false};
        st = DkimManager.ensurePublished(cf, "t", ZONE, "example.test", null, null, s -> { made[0] = true; return key; },
                k -> installed.add(k.selector()));
        check("the name already holds a record: nothing written, no key made, nothing installed (" + st.message() + ")",
                !st.ok() && writes.isEmpty() && !made[0] && installed.isEmpty());

        st = DkimManager.ensurePublished(cf, "t", ZONE, "example.test", "mail", "MYKEY", s -> key, k -> installed.add(k.selector()));
        check("a key already installed, but the record holds another one: said, not overwritten (" + st.message() + ")",
                !st.ok() && writes.isEmpty() && st.message().contains("another key"));

        records.clear(); writes.clear();
        records.add(new JSONObject().put("id", "c".repeat(32)).put("type", "TXT").put("name", name).put("content", "\"v=DKIM1; k=rsa; p=MYKEY\""));
        st = DkimManager.ensurePublished(cf, "t", ZONE, "example.test", "mail", "MYKEY", s -> key, k -> installed.add(k.selector()));
        check("a key already installed with its record published: present, nothing written", st.ok() && writes.isEmpty());

        records.clear(); writes.clear(); installed.clear();
        st = DkimManager.ensurePublished(cf, "t", ZONE, "example.test", "mail", "MYKEY", s -> key, k -> installed.add(k.selector()));
        check("a key already installed whose record is missing: its own record is published, no new key",
                st.ok() && writes.size() == 1 && writes.get(0).contains("p=MYKEY") && installed.isEmpty());

        records.clear(); writes.clear(); installed.clear(); mode = "refuse";
        boolean threw = false;
        try {
            DkimManager.ensurePublished(cf, "t", ZONE, "example.test", null, null, s -> key, k -> installed.add(k.selector()));
        } catch (CloudflareManager.ZoneReadException e) {
            threw = true;
        }
        check("a zone that cannot be read: it stops, nothing written, nothing installed", threw && writes.isEmpty() && installed.isEmpty());
        mode = "ok";
    }
}
