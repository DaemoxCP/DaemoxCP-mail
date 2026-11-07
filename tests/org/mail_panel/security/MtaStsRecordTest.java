package org.mail_panel.security;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tests the writing of the _mta-sts record on Cloudflare, AutoDns.alignMtaStsTxt(), with a fake
 * Cloudflare: the zone lives in memory, and every operation can be made to refuse.
 *
 * What must be shown: at the end ONE MTA-STS record stays on that name, with the right id. With two
 * v=STSv1 records senders act as if MTA-STS were not there (RFC 8461 §3.1), and before, the writing
 * looked at the first record: if it was already right it answered "unchanged" and left the other.
 * At the end the test puts that logic back in front of the same case, to show that the checks see
 * it.
 *
 * The panel's messages are read in English (I18n.setCurrent): outside a request it writes Italian.
 */
public class MtaStsRecordTest {

    static int failed = 0;

    static void require(String what, boolean condition) {
        System.out.println((condition ? "  OK   " : "  FAILED ") + what);
        if (!condition) failed++;
    }

    static final String NAME_PATTERN = "_mta-sts.domain-d.test";
    static final String RIGHT = "v=STSv1; id=0fec393151a7c577266a";
    static final String OLD = "v=STSv1; id=1700000000000";

    /** A Cloudflare zone in memory. It returns the TXT records as the API does: with the quotes. */
    static class FakeCloudflare extends CloudflareManager {
        final Map<String, TxtRecordInfo> zone = new LinkedHashMap<>();
        final List<String> operations = new ArrayList<>();
        String refuseDeletionOf = null;
        boolean refuseUpdate = false;
        boolean firstReadingEmpty = false;   // the listing that fails and comes back empty without saying so
        int readings = 0, next = 1;

        FakeCloudflare() { super(null); }

        FakeCloudflare put(String name, String rawContent) {
            TxtRecordInfo t = new TxtRecordInfo();
            t.id = "r" + (next++); t.name = name; t.content = rawContent; t.ttl = 3600;
            zone.put(t.id, t);
            return this;
        }

        @Override
        public List<TxtRecordInfo> listTxtRecordsContaining(String token, String zoneId, String part) {
            readings++;
            List<TxtRecordInfo> outside = new ArrayList<>();
            if (firstReadingEmpty && readings == 1) return outside;
            for (TxtRecordInfo t : zone.values()) {
                if (part != null && !t.name.contains(part)) continue;
                TxtRecordInfo c = new TxtRecordInfo();
                c.id = t.id; c.name = t.name; c.content = t.content; c.ttl = t.ttl;
                outside.add(c);
            }
            return outside;
        }

        @Override
        public RecordOp deleteRecord(String token, String zoneId, String id) {
            operations.add("remove " + id);
            if (id.equals(refuseDeletionOf)) return new RecordOp(false, null, "permission denied (fake)");
            if (zone.remove(id) == null) return new RecordOp(false, null, "no such record");
            return new RecordOp(true, id, null);
        }

        @Override
        public RecordOp updateTxtRecord(String token, String zoneId, String id, String name, String value, int ttl) {
            operations.add("update " + id);
            if (refuseUpdate) return new RecordOp(false, null, "permission denied (fake)");
            TxtRecordInfo t = zone.get(id);
            if (t == null) return new RecordOp(false, null, "no such record");
            t.content = formatTxtRecordContent(value);
            return new RecordOp(true, id, null);
        }

        @Override
        public RecordOp createTxtRecord(String token, String zoneId, String name, String value, int ttl) {
            operations.add("create");
            put(name, formatTxtRecordContent(value));
            return new RecordOp(true, "r" + (next - 1), null);
        }

        /** The MTA-STS contents left on that name, already cleaned of the quotes. */
        List<String> mtaSts() {
            List<String> c = new ArrayList<>();
            for (TxtRecordInfo t : zone.values())
                if (t.name.equals(NAME_PATTERN)) c.add(DnsRules.cloudflareContent(t.content));
            return DnsRules.onlyMtaSts(c);
        }

        long otherTxt() {
            return zone.values().stream()
                    .filter(t -> !(t.name.equals(NAME_PATTERN) && DnsRules.eMtaSts(DnsRules.cloudflareContent(t.content))))
                    .count();
        }
    }

    static JSONObject write(FakeCloudflare cf) {
        return new AutoDns(null, cf).alignMtaStsTxt("token", "zone", NAME_PATTERN, RIGHT, new JSONObject());
    }

    static String removed(JSONObject r) {
        JSONArray a = r.optJSONArray("removed");
        return a == null ? "[]" : a.toString();
    }

    public static void main(String[] a) {

        org.mail_panel.i18n.I18n.setCurrent("en");
        System.out.println("\n== the rule: what counts as an MTA-STS record ==");
        require("\"v=STSv1; id=1\" counts", DnsRules.eMtaSts("v=STSv1; id=1"));
        require("\"V=STSV1; id=1\" counts (mailauth ignores case)", DnsRules.eMtaSts("V=STSV1; id=1"));
        require("\" v=STSv1; id=1\" counts (mailauth trims the spaces at the edges)", DnsRules.eMtaSts(" v=STSv1; id=1"));
        require("an SPF does not count", !DnsRules.eMtaSts("v=spf1 -all"));
        require("a Google verification does not count", !DnsRules.eMtaSts("google-site-verification=abc"));
        require("null does not count", !DnsRules.eMtaSts(null));

        System.out.println("\n== no record: it is created ==");
        FakeCloudflare cf = new FakeCloudflare();
        JSONObject r = write(cf);
        require("succeeded: " + r.optString("note", r.optString("error")), r.optBoolean("success"));
        require("the name has one record, the right one: " + cf.mtaSts(), cf.mtaSts().equals(List.of(RIGHT)));

        System.out.println("\n== a right record: nothing is touched ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + RIGHT + "\"");
        r = write(cf);
        require("unchanged", r.optBoolean("success") && r.optBoolean("unchanged"));
        require("no operation on Cloudflare: " + cf.operations, cf.operations.isEmpty());

        System.out.println("\n== a record with the old id: it is updated ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, OLD);   // without quotes, as Cloudflare sometimes gives it
        r = write(cf);
        require("succeeded and updated", r.optBoolean("success") && r.optBoolean("updated"));
        require("one record stays, the right one: " + cf.mtaSts(), cf.mtaSts().equals(List.of(RIGHT)));

        System.out.println("\n== two records, the first already right (the case that used to say \"unchanged\") ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + RIGHT + "\"").put(NAME_PATTERN, "\"" + OLD + "\"");
        r = write(cf);
        require("succeeded: " + r.optString("note", r.optString("error")), r.optBoolean("success"));
        require("it does NOT say unchanged", !r.optBoolean("unchanged"));
        require("only one record stays, the right one: " + cf.mtaSts(), cf.mtaSts().equals(List.of(RIGHT)));
        require("it removes only the old one, without updating anything: " + cf.operations,
                cf.operations.equals(List.of("remove r2")));
        require("and it says so in the answer: " + removed(r), removed(r).contains(OLD));

        System.out.println("\n== two records, the right one is the second ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + OLD + "\"").put(NAME_PATTERN, "\"" + RIGHT + "\"");
        r = write(cf);
        require("it keeps the right one and removes the other: " + cf.operations,
                r.optBoolean("success") && cf.operations.equals(List.of("remove r1")));
        require("only one record stays: " + cf.mtaSts(), cf.mtaSts().equals(List.of(RIGHT)));

        System.out.println("\n== two records, none right ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + OLD + "\"").put(NAME_PATTERN, "\"v=STSv1; id=2\"");
        r = write(cf);
        require("first it removes the other, then it updates the one left: " + cf.operations,
                cf.operations.equals(List.of("remove r2", "update r1")));
        require("succeeded, with a single right record: " + cf.mtaSts(),
                r.optBoolean("success") && cf.mtaSts().equals(List.of(RIGHT)));

        System.out.println("\n== three records, one written in upper case, and TXT records that have nothing to do with it ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + OLD + "\"").put(NAME_PATTERN, "\"V=STSV1; id=9\"")
                .put(NAME_PATTERN, "\"google-site-verification=abc\"").put(NAME_PATTERN, "\"" + RIGHT + "\"")
                .put("domain-d.test", "\"v=spf1 mx -all\"").put("_mta-sts.other.it", "\"" + OLD + "\"");
        r = write(cf);
        require("succeeded, with a single right record: " + cf.mtaSts(),
                r.optBoolean("success") && cf.mtaSts().equals(List.of(RIGHT)));
        require("it also removes the upper-case one, which counts for mailauth: " + removed(r),
                removed(r).contains("V=STSV1; id=9"));
        require("it does not touch the Google verification, the SPF and the other domain (" + cf.otherTxt() + " stay)",
                cf.otherTxt() == 3);

        System.out.println("\n== Cloudflare refuses to remove the extra record ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + RIGHT + "\"").put(NAME_PATTERN, "\"" + OLD + "\"");
        cf.refuseDeletionOf = "r2";
        r = write(cf);
        require("NOT succeeded", !r.optBoolean("success"));
        require("the error says which record and why it matters: " + r.optString("error"),
                r.optString("error").contains(OLD) && r.optString("error").contains("RFC 8461"));

        System.out.println("\n== Cloudflare refuses the update, after removing the other ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + OLD + "\"").put(NAME_PATTERN, "\"v=STSv1; id=2\"");
        cf.refuseUpdate = true;
        r = write(cf);
        require("NOT succeeded", !r.optBoolean("success"));
        require("and it says so, together with what it removed: " + r.optString("error"),
                r.optString("error").contains("refused the update") && r.optString("error").contains("id=2"));
        require("only one record stays (with the old id, but senders read it): " + cf.mtaSts(),
                cf.mtaSts().equals(List.of(OLD)));

        System.out.println("\n== the first read comes back empty because of an error, and there was already a record ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + OLD + "\"");
        cf.firstReadingEmpty = true;
        r = write(cf);
        require("it notices that now there are two records: " + r.optString("error"),
                !r.optBoolean("success") && r.optString("error").contains("2 MTA-STS records"));

        System.out.println("\n== the MTA-STS row of the DNS page ==");
        // Reads built from dig outputs in the real shape, and a fake policy that answers or not: no
        // DNS, no network.
        String head = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32535\n;; ANSWER SECTION:\n";
        String rightLine = NAME_PATTERN + ".\t3498\tIN\tTXT\t\"" + RIGHT + "\"\n";
        String oldLine = NAME_PATTERN + ".\t3498\tIN\tTXT\t\"" + OLD + "\"\n";
        java.util.function.Function<String, JSONObject> answers = d -> new JSONObject().put("ok", true);
        java.util.function.Function<String, JSONObject> silent =
                d -> new JSONObject().put("ok", false).put("error", "526 (fake).");
        DnsRecordsGenerator.DnsCheck c = DnsRecordsGenerator.mtaStsCheck("domain-d.test",
                org.mail_panel.system.MtaStsSetup.parseTxt(0, head + rightLine), answers);
        require("one record and the policy answering: green (" + c.message + ")", c.passed);
        c = DnsRecordsGenerator.mtaStsCheck("domain-d.test",
                org.mail_panel.system.MtaStsSetup.parseTxt(0, head + rightLine + oldLine), answers);
        require("two records, even with the policy answering: NOT green", !c.passed);
        require("the message says why: " + c.message, c.message.contains("RFC 8461") && c.message.contains("2 v=STSv1 records"));
        require("and it shows both records: " + c.currentValue,
                c.currentValue.contains(RIGHT) && c.currentValue.contains(OLD));
        require("it is not grey (informational): it is a fault", !c.informational);
        c = DnsRecordsGenerator.mtaStsCheck("domain-d.test",
                org.mail_panel.system.MtaStsSetup.parseTxt(0, head + rightLine), silent);
        require("one record and the policy not answering: red (" + c.message.substring(0, 40) + "...)", !c.passed);
        c = DnsRecordsGenerator.mtaStsCheck("domain-d.test",
                org.mail_panel.system.MtaStsSetup.parseTxt(0,
                        ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 37005\n"), answers);
        require("a SERVFAIL: not \"Not active\", but the real reason (" + c.message + ")",
                !c.passed && !c.informational && c.message.contains("SERVFAIL"));
        c = DnsRecordsGenerator.mtaStsCheck("domain-d.test",
                org.mail_panel.system.MtaStsSetup.parseTxt(0,
                        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 2902\n"), answers);
        require("no record: grey, \"Not active\"", !c.passed && c.informational && c.message.startsWith("Not active"));

        System.out.println("\n== the old writing, in front of the two-record case ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + RIGHT + "\"").put(NAME_PATTERN, "\"" + OLD + "\"");
        String before = howItWroteBefore(cf);
        System.out.println("  it said: " + before + "; " + cf.mtaSts().size() + " records were left on the name");
        require("before, it said \"unchanged\" and left two records: the checks above see it",
                before.equals("unchanged") && cf.mtaSts().size() == 2);

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }

    /** The loop of AutoDns.createTxtMtaSts as it was before, reduced to the outcome. */
    static String howItWroteBefore(FakeCloudflare cf) {
        for (CloudflareManager.TxtRecordInfo t : cf.listTxtRecordsContaining("token", "zone", null)) {
            if (!t.name.equals(NAME_PATTERN)) continue;
            String c = DnsRules.cloudflareContent(t.content);
            if (!c.toLowerCase(java.util.Locale.ROOT).startsWith("v=stsv1")) continue;
            if (c.trim().equals(RIGHT.trim())) return "unchanged";
            cf.updateTxtRecord("token", "zone", t.id, NAME_PATTERN, RIGHT, 3600);
            return "updated";
        }
        cf.createTxtRecord("token", "zone", NAME_PATTERN, RIGHT, 3600);
        return "created";
    }
}
