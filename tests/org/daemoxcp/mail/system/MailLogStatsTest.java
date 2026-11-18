package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * The sent and received counts read from Postfix's log (MailLogStats), without the real log: which line counts what,
 * the day in UTC of a syslog date, the sums written once per group, the complete lines read from a position, and the
 * rest of a turned-over file from its .bz2 (where bzcat is). The real mail is in mail-stats-browser-test.js.
 *
 *   java -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.system.MailLogStatsTest
 */
public class MailLogStatsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final ZoneId ROME = ZoneId.of("Europe/Rome");
    static final ZonedDateTime NOW = ZonedDateTime.parse("2026-11-18T03:00:00Z");

    static List<MailLogStats.Event> feed(MailLogStats.Parser p, String... lines) {
        List<MailLogStats.Event> out = new ArrayList<>();
        for (String l : lines) out.addAll(p.line(l, NOW));
        return out;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== A message a mailbox sent, to a mailbox and outside ==");
        MailLogStats.Parser p = new MailLogStats.Parser(ROME);
        List<MailLogStats.Event> e = feed(p,
                "Nov 18 03:07:18 mail postfix/submission/smtpd[76808]: 9DEB422FA1: client=localhost[127.0.0.1], sasl_method=PLAIN, sasl_username=Ann@Example.test",
                "Nov 18 03:07:18 mail postfix/cleanup[1]: 9DEB422FA1: message-id=<x@example.test>",
                "Nov 18 03:07:18 mail postfix/qmgr[2]: 9DEB422FA1: from=<ann@example.test>, size=1234, nrcpt=2 (queue active)",
                "Nov 18 03:07:19 mail postfix/lmtp[3]: 9DEB422FA1: to=<bob@example.test>, relay=mail.example.test[private/dovecot-lmtp], delay=0.1, delays=0/0/0/0, dsn=2.0.0, status=sent (250 2.0.0 Ok)",
                "Nov 18 03:07:20 mail postfix/smtp[4]: 9DEB422FA1: to=<someone@example.net>, relay=mx.example.net[192.0.2.1]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)",
                "Nov 18 03:07:20 mail postfix/qmgr[2]: 9DEB422FA1: removed");
        check("received by bob, sent by ann twice (once per recipient): " + e, e.size() == 3
                && e.contains(new MailLogStats.Event(LocalDate.of(2026, 11, 18), "received", "bob@example.test", 1234))
                && e.stream().filter(x -> x.type().equals("sent") && x.address().equals("ann@example.test") && x.bytes() == 1234).count() == 2);
        check("the queue entry goes with «removed»", p.queued() == 0);

        System.out.println("\n== Incoming mail, a bounce, a delay ==");
        e = feed(p,
                "Nov 18 03:10:00 mail postfix/smtpd[5]: 1111AAAA11: client=mx.example.org[198.51.100.7]",
                "Nov 18 03:10:00 mail postfix/qmgr[2]: 1111AAAA11: from=<news@example.org>, size=500, nrcpt=1 (queue active)",
                "Nov 18 03:10:01 mail postfix/lmtp[3]: 1111AAAA11: to=<bob@example.test>, relay=x, delay=0.1, delays=0/0/0/0, dsn=2.0.0, status=sent (250 ok)",
                "Nov 18 03:11:00 mail postfix/lmtp[3]: 2222BBBB22: to=<full@example.test>, relay=x, dsn=5.2.2, status=bounced (host said: 552 5.2.2 Quota exceeded)",
                "Nov 18 03:12:00 mail postfix/submission/smtpd[6]: 3333CCCC33: client=localhost[127.0.0.1], sasl_method=PLAIN, sasl_username=ann@example.test",
                "Nov 18 03:12:01 mail postfix/smtp[4]: 3333CCCC33: to=<nobody@example.net>, relay=x, dsn=5.1.1, status=bounced (550 no such user)",
                "Nov 18 03:12:02 mail postfix/smtp[4]: 3333CCCC33: to=<slow@example.net>, relay=none, delay=30, dsn=4.4.1, status=deferred (connect timed out)");
        check("incoming: received, no sender counted", e.contains(new MailLogStats.Event(LocalDate.of(2026, 11, 18), "received", "bob@example.test", 500))
                && e.stream().noneMatch(x -> x.type().equals("sent") && x.address().equals("news@example.org")));
        check("a bounce of incoming mail: the mailbox that should have received", e.contains(new MailLogStats.Event(LocalDate.of(2026, 11, 18), "bounced", "full@example.test", 0)));
        check("a bounce of mail a mailbox sent: that mailbox", e.contains(new MailLogStats.Event(LocalDate.of(2026, 11, 18), "bounced", "ann@example.test", 0)));
        check("deferred: nothing (it may still go)", e.stream().noneMatch(x -> x.address().equals("ann@example.test") && !x.type().equals("bounced")));

        System.out.println("\n== Refused by Rspamd ==");
        e = feed(p,
                "Nov 18 03:20:00 mail postfix/cleanup[7]: 4444DDDD44: milter-reject: END-OF-MESSAGE from x[198.51.100.9]: 5.7.1 Spam message rejected; from=<spam@example.org> to=<Bob@example.test> proto=ESMTP helo=<x>",
                "Nov 18 03:21:00 mail postfix/cleanup[7]: 5555EEEE55: milter-reject: END-OF-MESSAGE from x[198.51.100.9]: 5.7.1 Virus found: EICAR; from=<v@example.org> to=<bob@example.test> proto=ESMTP helo=<x>",
                "Nov 18 03:22:00 mail postfix/smtpd[5]: NOQUEUE: reject: RCPT from x[198.51.100.9]: 554 5.7.1 <a@example.test>: Relay access denied; from=<a@b> to=<a@example.test>");
        check("spam, for the mailbox it was going to (" + e + ")", e.size() == 2 && e.contains(new MailLogStats.Event(LocalDate.of(2026, 11, 18), "spam", "bob@example.test", 0)));
        check("a virus says so", e.contains(new MailLogStats.Event(LocalDate.of(2026, 11, 18), "virus", "bob@example.test", 0)));

        System.out.println("\n== The day, in UTC ==");
        check("00:30 in Rome (winter) is the day before in UTC", LocalDate.of(2026, 11, 17).equals(p.day("Nov 18 00:30:00", NOW)));
        check("a single-digit day with two spaces", LocalDate.of(2026, 11, 5).equals(p.day("Nov  5 12:00:00", NOW)));
        check("December read in January: last year", LocalDate.of(2025, 12, 31).equals(p.day("Dec 31 12:00:00", ZonedDateTime.parse("2026-01-01T10:00:00Z"))));
        check("an RFC 5424 date with its offset", LocalDate.of(2026, 11, 17).equals(p.day("2026-11-18T00:30:00.123+01:00", NOW)));
        check("not a date: nothing", p.day("yesterday", NOW) == null);

        System.out.println("\n== Summed once per group ==");
        LocalDate d = LocalDate.of(2026, 11, 18);
        Map<List<Object>, long[]> g = MailLogStats.aggregate(List.of(new MailLogStats.Event(d, "sent", "a@x", 10),
                new MailLogStats.Event(d, "sent", "a@x", 20), new MailLogStats.Event(d, "received", "a@x", 5)));
        check("two groups, counts and bytes added", g.size() == 2 && g.get(List.of(d, "sent", "a@x"))[0] == 2 && g.get(List.of(d, "sent", "a@x"))[1] == 30);

        System.out.println("\n== Reading the file ==");
        Path dir = Files.createTempDirectory("mail-log-stats-test");
        try {
            Path f = dir.resolve("maillog");
            Files.writeString(f, "one\ntwo\nthree-half");
            List<String> out = new ArrayList<>();
            long n = MailLogStats.readLines(f, 0, Files.size(f), out);
            check("only complete lines, and the bytes consumed (" + out + ", " + n + ")", out.equals(List.of("one", "two")) && n == 8);
            out.clear();
            Files.writeString(f, "one\ntwo\nthree-half\n");
            check("then the rest from there", MailLogStats.readLines(f, 8, Files.size(f), out) == 11 && out.equals(List.of("three-half")));
            if (Files.isExecutable(Path.of("/usr/bin/bzip2"))) {
                Files.writeString(dir.resolve("old"), "first\nsecond\nthird\n");
                Process z = new ProcessBuilder("/usr/bin/bzip2", "-k", dir.resolve("old").toString()).start();
                z.waitFor(30, TimeUnit.SECONDS);
                List<String> rest = MailLogStats.rotatedRest(dir.resolve("old.bz2"), 6);
                check("a turned-over file: what was not read yet, from its .bz2 (" + rest + ")", rest.equals(List.of("second", "third")));
            } else {
                System.out.println("  SKIPPED the .bz2 part: no bzip2 here");
            }
            check("no .bz2: nothing, and no error", MailLogStats.rotatedRest(dir.resolve("missing.bz2"), 0).isEmpty());
        } finally {
            new ProcessBuilder("rm", "-rf", dir.toString()).start().waitFor(10, TimeUnit.SECONDS);
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
