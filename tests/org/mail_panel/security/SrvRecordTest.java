package org.mail_panel.security;

/**
 * Comparing an SRV record with the one the panel wants.
 *
 * It is the function that made production rewrite two SRV records that were already right, at
 * every run, announcing each time a difference that did not exist.
 */
public class SrvRecordTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static CloudflareManager.DnsRecordInfo srv(String content, Integer priority, Integer weight,
                                               Integer port, String dest) {
        CloudflareManager.DnsRecordInfo t = new CloudflareManager.DnsRecordInfo();
        t.type = "SRV"; t.name = "_imaps._tcp.domain-a.test"; t.content = content;
        t.srvPriority = priority; t.srvWeight = weight; t.srvPort = port; t.srvDestination = dest;
        return t;
    }

    public static void main(String[] a) {
        final String HOST = "mail.domain-b.test";

        System.out.println("\n== the real case: content with THREE fields, plus the structured fields ==");
        require("the record shows as ALREADY RIGHT (it used to be rewritten every time)",
                AutoDns.coincide(srv("1 993 mail.domain-b.test", 0, 1, 993, HOST), true, HOST, 993));

        System.out.println("\n== and without the structured fields, only the three-field string ==");
        require("recognised all the same: 'weight port destination'",
                AutoDns.coincide(srv("1 993 mail.domain-b.test", null, null, null, null), true, HOST, 993));
        require("different port: does NOT match",
                !AutoDns.coincide(srv("1 995 mail.domain-b.test", null, null, null, null), true, HOST, 993));
        require("different destination: does NOT match",
                !AutoDns.coincide(srv("1 993 other.host", null, null, null, null), true, HOST, 993));

        System.out.println("\n== the FOUR-field form (dig output) still holds ==");
        require("'0 1 993 host' recognised",
                AutoDns.coincide(srv("0 1 993 mail.domain-b.test", null, null, null, null), true, HOST, 993));
        require("'0 1 995 host' not",
                !AutoDns.coincide(srv("0 1 995 mail.domain-b.test", null, null, null, null), true, HOST, 993));

        System.out.println("\n== the structured fields take precedence over the string ==");
        require("right structured port, wrong string -> matches",
                AutoDns.coincide(srv("1 995 other.host", 0, 1, 993, HOST), true, HOST, 993));
        require("wrong structured port, right string -> does NOT match",
                !AutoDns.coincide(srv("1 993 mail.domain-b.test", 0, 1, 995, HOST), true, HOST, 993));

        System.out.println("\n== the priority is NOT part of the question ==");
        require("priority 10 instead of 0: matches anyway",
                AutoDns.coincide(srv("1 993 mail.domain-b.test", 10, 1, 993, HOST), true, HOST, 993));

        System.out.println("\n== garbage: it does not pass for right ==");
        require("empty string: does NOT match",
                !AutoDns.coincide(srv("", null, null, null, null), true, HOST, 993));
        require("three non-numeric fields: does NOT match",
                !AutoDns.coincide(srv("a b c", null, null, null, null), true, HOST, 993));
        require("only two fields: does NOT match",
                !AutoDns.coincide(srv("993 mail.domain-b.test", null, null, null, null), true, HOST, 993));

        System.out.println("\n== and the NON-SRV comparison stays as before ==");
        CloudflareManager.DnsRecordInfo cn = new CloudflareManager.DnsRecordInfo();
        cn.type = "CNAME"; cn.content = "mail.domain-b.test.";
        require("CNAME with the trailing dot matches", AutoDns.coincide(cn, false, HOST, 0));
        cn.content = "xmail.domain-b.test";
        require("'xmail...' does not pass for 'mail...'", !AutoDns.coincide(cn, false, HOST, 0));

        System.out.println("\n== and the OLD logic on the same real case ==");
        // As it was: only analyzeSrv() on the content. If it passed here too, this test's first
        // check would be checking nothing.
        DnsRules.Srv old = DnsRules.analyzeSrv("1 993 mail.domain-b.test");
        boolean oldOutcome = old != null && old.port == 993
                && DnsRules.sameName(old.destination, HOST);
        System.out.println("  analyzeSrv(\"1 993 mail.domain-b.test\") -> "
                + (old == null ? "null (not recognised)" : "recognised"));
        require("the old logic REJECTS the right record: the defect reproduces", !oldOutcome);

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }
}
