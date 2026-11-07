package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.util.List;

/**
 * Tests the logic the MTA-STS plan uses to decide, with the server's real cases. It does not test
 * that the code compiles: it tests that it tells the truth.
 *
 * Reading the TXT record is tested in two ways. The meaning of every dig output, with real recorded
 * outputs (plus variants built on them): it holds everywhere, even without a network. Then the real
 * DNS: if it can be reached from here the real facts are required (on domain-d.test the record is
 * there, a SERVFAIL is not "absent"), otherwise the reading is required to say NOT_ASKED and never a
 * made-up ABSENT. Before, the test took the DNS for granted and failed on every machine that did not
 * have it, while the reading answered right.
 *
 * Two v=STSv1 records on the same name are worth zero for senders (RFC 8461 §3.1): the reading must
 * say TOO_MANY, and the record step in the plan must not show as done.
 *
 * The panel's texts are read in English (I18n.setCurrent): outside a request it writes Italian.
 */
public class MtaStsTest {

    static int failed = 0;

    static void require(String what, boolean condition) {
        System.out.println((condition ? "  OK   " : "  FAILED ") + what);
        if (!condition) failed++;
    }

    static void randomBytes(String what, int digOutput, String printed, MtaStsSetup.TxtOutcome outcome, String content) {
        MtaStsSetup.TxtReading l = MtaStsSetup.parseTxt(digOutput, printed);
        require(what + " -> " + l.outcome + (l.content.isEmpty() ? "" : " \"" + l.content + "\""),
                l.outcome == outcome && l.content.equals(content));
    }

    /** The state of dig's answer for a TXT (NOERROR, NXDOMAIN, SERVFAIL...), or "". */
    static String digState(String name) {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+noall", "+comments", "+time=3", "+tries=1", "TXT", name);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("status:\\s*([A-Z]+)").matcher(out);
            return m.find() ? m.group(1) : "";
        } catch (Exception e) {
            return "";
        }
    }

    /** Does dig reach a DNS from here? It asks who serves the root, with little patience. */
    static boolean digAnswers() {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", "+time=3", "+tries=1", ".", "NS");
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            return p.waitFor() == 0 && !out.isEmpty();
        } catch (Exception e) {
            return false;   // dig not there
        }
    }

    /** The "txt" step among those testAndTxtSteps() returns. */
    static MtaStsSetup.Step txtStep(List<MtaStsSetup.TxtReview> reviews, String expected) {
        for (MtaStsSetup.Step p : MtaStsSetup.testAndTxtSteps(reviews, expected))
            if ("txt".equals(p.key)) return p;
        throw new IllegalStateException("the txt step is missing");
    }

    static MtaStsSetup.NameReview e(String d, MtaStsSetup.NameState s, String m,
                                    boolean resolves, boolean proxy, boolean crooked) {
        return new MtaStsSetup.NameReview(d, s, m, resolves, proxy, crooked);
    }

    public static void main(String[] a) throws Exception {

        org.mail_panel.i18n.I18n.setCurrent("en");
        System.out.println("\n== split(): the real case of domain-d.test ==");
        // mta-sts.domain-d.test is not in the zone; the wildcard *.domain-d.test answers, proxied.
        var rip = MtaStsSetup.split(List.of(
                e("domain-d.test", MtaStsSetup.NameState.ABSENT, "not in the zone", true, true, false)));
        require("the domain ends up among the absent ones", rip.absent.size() == 1);
        require("and ALSO among those that go through the proxy (it was the false green)", rip.proxied.size() == 1);
        require("the plan knows the proxy comes from a wildcard", rip.proxyFromWildcard);
        require("the proxy line names the wildcard", rip.proxied.get(0).contains("*.domain-d.test"));

        System.out.println("\n== split(): a record both WRONG and PROXIED ==");
        // Before, it ended up only in the proxy count, because the reason contained "Cloudflare": the
        // CNAME step declared "all present and right" a record that pointed elsewhere.
        rip = MtaStsSetup.split(List.of(
                e("x.it", MtaStsSetup.NameState.TO_FIX,
                  "points to \"other.host\" instead of \"mail.domain-b.test\"; goes through Cloudflare",
                  true, true, true)));
        require("it appears among the crooked ones", rip.crooked.size() == 1);
        require("it ALSO appears among the proxied ones", rip.proxied.size() == 1);
        require("the proxy does not come from a wildcard", !rip.proxyFromWildcard);

        System.out.println("\n== split(): right record but proxied ==");
        rip = MtaStsSetup.split(List.of(
                e("y.it", MtaStsSetup.NameState.TO_FIX, "goes through Cloudflare", true, true, false)));
        require("it is not crooked", rip.crooked.isEmpty());
        require("it is proxied", rip.proxied.size() == 1);

        System.out.println("\n== split(): blind, propagating, all in place ==");
        rip = MtaStsSetup.split(List.of(
                e("c.it", MtaStsSetup.NameState.BLIND, "zone not visible", false, false, false),
                e("p.it", MtaStsSetup.NameState.RIGHT, "points straight", false, false, false),
                e("ok.it", MtaStsSetup.NameState.RIGHT, "points straight", true, false, false)));
        require("the blind one stays blind", rip.blind.size() == 1);
        require("the right one that does not resolve yet is propagating", rip.propagating.size() == 1);
        require("the right one that resolves appears nowhere",
                rip.absent.isEmpty() && rip.crooked.isEmpty() && rip.proxied.isEmpty());

        System.out.println("\n== parseTxt(): what every dig output means ==");
        // REAL outputs of "dig +noall +comments +answer TXT _mta-sts.<domain>", recorded on 2/10/2026
        // with BIND 9.18 and the resolver 8.8.8.8 (which validates DNSSEC).
        String domainD = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32535\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n;; ANSWER SECTION:\n_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; id=0fec393151a7c577266a\"\n\n";
        String servfail = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 37005\n;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n; EDE: 9 (DNSKEY Missing): (No DNSKEY matches DS RRs of dnssec-failed.org)\n";
        String nxdomain = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 2902\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n";
        String withoutTxt = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19074\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n";
        String unreachable = ";; communications error to 192.0.2.1#53: connection refused\n;; no servers could be reached\n";
        randomBytes("domain-d.test, record published", 0, domainD,
                MtaStsSetup.TxtOutcome.PRESENT, "v=STSv1; id=0fec393151a7c577266a");
        randomBytes("dnssec-failed.org, SERVFAIL: the DNS does not say what is there", 0, servfail,
                MtaStsSetup.TxtOutcome.NOT_ASKED, "");
        randomBytes("non-existent name (NXDOMAIN)", 0, nxdomain, MtaStsSetup.TxtOutcome.ABSENT, "");
        randomBytes("example.com, the name is there but without TXT", 0, withoutTxt, MtaStsSetup.TxtOutcome.ABSENT, "");
        randomBytes("DNS not answering (dig exits with 9)", 9, unreachable, MtaStsSetup.TxtOutcome.NOT_ASKED, "");
        // The plan writes the why next to the domain: a SERVFAIL is looked for in the zone, a DNS
        // that does not answer in this server's network.
        String why = MtaStsSetup.parseTxt(0, servfail).reason;
        require("the plan says the DNS answered SERVFAIL: \"" + why + "\"", why.contains("SERVFAIL"));
        why = MtaStsSetup.parseTxt(9, unreachable).reason;
        require("and that no DNS answered: \"" + why + "\"", why.equals("no DNS answers"));
        // Variants built on domain-d.test's real answer.
        String line = "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; id=0fec393151a7c577266a\"";
        randomBytes("record split into two strings", 0,
                domainD.replace(line, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; \" \"id=0fec393151a7c577266a\""),
                MtaStsSetup.TxtOutcome.PRESENT, "v=STSv1; id=0fec393151a7c577266a");
        randomBytes("next to another TXT on the same name", 0,
                domainD.replace(line, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"google-site-verification=abc\"\n" + line),
                MtaStsSetup.TxtOutcome.PRESENT, "v=STSv1; id=0fec393151a7c577266a");
        randomBytes("behind a CNAME", 0,
                domainD.replace(line, "_mta-sts.domain-d.test.\t300\tIN\tCNAME\t_mta-sts.other.net.\n_mta-sts.other.net.\t300\tIN\tTXT\t\"v=STSv1; id=7\""),
                MtaStsSetup.TxtOutcome.PRESENT, "v=STSv1; id=7");
        randomBytes("upper case", 0, domainD.replace("v=STSv1; id=0fec393151a7c577266a", "V=STSV1; id=2"),
                MtaStsSetup.TxtOutcome.PRESENT, "V=STSV1; id=2");
        randomBytes("only other TXT records", 0, domainD.replace(line, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"google-site-verification=abc\""),
                MtaStsSetup.TxtOutcome.ABSENT, "");
        randomBytes("REFUSED", 0, servfail.replace("SERVFAIL", "REFUSED"), MtaStsSetup.TxtOutcome.NOT_ASKED, "");
        randomBytes("output without the answer's state", 0, "something that is not dig\n", MtaStsSetup.TxtOutcome.NOT_ASKED, "");
        // With "dig +short" (as it was) SERVFAIL and NXDOMAIN print the same thing, that is nothing:
        // that is why the reading asks for the answer's state.
        randomBytes("the dig +short output of a SERVFAIL is not enough to say ABSENT", 0, "", MtaStsSetup.TxtOutcome.NOT_ASKED, "");

        System.out.println("\n== parseTxt(): two v=STSv1 records on the same name ==");
        // For senders they are worth zero (RFC 8461 §3.1). Before, the reading took the first and said
        // PRESENT: here the first is exactly the right one, the most deceiving case.
        String old = "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; id=1700000000000\"";
        String two = domainD.replace(line, line + "\n" + old);
        randomBytes("the right one and one with the old id", 0, two, MtaStsSetup.TxtOutcome.TOO_MANY, "");
        MtaStsSetup.TxtReading l2 = MtaStsSetup.parseTxt(0, two);
        require("and it reports both: " + l2.values,
                l2.values.equals(List.of("v=STSv1; id=0fec393151a7c577266a", "v=STSv1; id=1700000000000")));
        randomBytes("one written in upper case (mailauth counts it)", 0,
                domainD.replace(line, line + "\n_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"V=STSV1; id=2\""),
                MtaStsSetup.TxtOutcome.TOO_MANY, "");
        randomBytes("two records and a TXT that has nothing to do with it", 0,
                domainD.replace(line, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"google-site-verification=abc\"\n"
                        + line + "\n" + old),
                MtaStsSetup.TxtOutcome.TOO_MANY, "");
        randomBytes("same text, but two records (one split): they are two", 0,
                domainD.replace(line, line + "\n_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; \" \"id=0fec393151a7c577266a\""),
                MtaStsSetup.TxtOutcome.TOO_MANY, "");
        randomBytes("two records behind a CNAME", 0,
                domainD.replace(line, "_mta-sts.domain-d.test.\t300\tIN\tCNAME\t_mta-sts.other.net.\n"
                        + "_mta-sts.other.net.\t300\tIN\tTXT\t\"v=STSv1; id=7\"\n"
                        + "_mta-sts.other.net.\t300\tIN\tTXT\t\"v=STSv1; id=8\""),
                MtaStsSetup.TxtOutcome.TOO_MANY, "");

        System.out.println("\n== testAndTxtSteps(): the record step in the plan ==");
        String expected = "v=STSv1; id=0fec393151a7c577266a";
        MtaStsSetup.TxtReading one = MtaStsSetup.parseTxt(0, domainD);
        MtaStsSetup.Step p = txtStep(List.of(
                new MtaStsSetup.TxtReview("domain-d.test", true, one)), expected);
        require("a right record and the policy answering: done (" + p.detail + ")", "done".equals(p.state));
        p = txtStep(List.of(new MtaStsSetup.TxtReview("domain-d.test", true, l2)), expected);
        require("two records, even with the first right: NOT done -> " + p.state + " (" + p.detail + ")",
                "todo".equals(p.state));
        require("the detail names both records",
                p.detail.contains("id=0fec393151a7c577266a") && p.detail.contains("id=1700000000000"));
        require("and the reason says why it matters", p.reason != null && p.reason.contains("RFC 8461"));
        p = txtStep(List.of(new MtaStsSetup.TxtReview("domain-d.test", true, l2),
                             new MtaStsSetup.TxtReview("domain-a.test", true, one)), expected);
        require("a domain in place does not cover the one with two records: " + p.state, "todo".equals(p.state));
        p = txtStep(List.of(new MtaStsSetup.TxtReview("domain-d.test", false, l2)), expected);
        require("two records and the policy not answering: reported as not kept (" + p.detail + ")",
                "todo".equals(p.state) && p.detail.contains("NOT kept"));
        p = txtStep(List.of(new MtaStsSetup.TxtReview("domain-d.test", true,
                MtaStsSetup.parseTxt(0, servfail))), expected);
        require("a SERVFAIL stays uncertain, with the reason (" + p.detail + ")",
                "uncertain".equals(p.state) && p.detail.contains("SERVFAIL"));

        System.out.println("\n== readTxt(): the real DNS, on the real domains ==");
        if (digAnswers()) {
            for (String d : new String[]{"domain-d.test", "domain-a.test", "domain-b.test",
                                         "name-that-does-not-exist-99887.invalid"}) {
                MtaStsSetup.TxtReading l = MtaStsSetup.readTxt(d);
                System.out.println("  " + d + " -> " + l.outcome + "  \"" + l.content + "\"");
                if (d.equals("domain-d.test")) {
                    require("on domain-d.test the TXT is SEEN (before, the plan did not get there)",
                            l.outcome == MtaStsSetup.TxtOutcome.PRESENT);
                    require("and its content is read", l.content.startsWith("v=STSv1"));
                }
                if (d.endsWith(".invalid"))
                    require("a non-existent name is ABSENT, not NOT_ASKED",
                            l.outcome == MtaStsSetup.TxtOutcome.ABSENT);
            }
            // dnssec-failed.org has a deliberately broken DNSSEC: a validating resolver answers
            // SERVFAIL. If this one does, the reading must say NOT_ASKED, not ABSENT.
            if (digState("_mta-sts.dnssec-failed.org").equals("SERVFAIL")) {
                MtaStsSetup.TxtReading l = MtaStsSetup.readTxt("dnssec-failed.org");
                System.out.println("  dnssec-failed.org -> " + l.outcome + " (" + l.reason + ")");
                require("a SERVFAIL is NOT_ASKED, not ABSENT", l.outcome == MtaStsSetup.TxtOutcome.NOT_ASKED);
            } else {
                System.out.println("  (this machine's resolver does not validate DNSSEC: SERVFAIL tested only above)");
            }
        } else {
            // dig missing or network closed: nobody was asked anything, and the reading must say so.
            // An ABSENT here would make it propose publishing a record that may already be there.
            System.out.println("  from here dig does not reach a DNS: the reading must say NOT_ASKED");
            for (String d : new String[]{"domain-d.test", "name-that-does-not-exist-99887.invalid"}) {
                MtaStsSetup.TxtReading l = MtaStsSetup.readTxt(d);
                require(d + " -> " + l.outcome + ", neither ABSENT nor PRESENT",
                        l.outcome == MtaStsSetup.TxtOutcome.NOT_ASKED);
            }
        }

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }
}
