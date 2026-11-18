package org.daemoxcp.mail.system;

import org.json.JSONObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;

/**
 * Which sendmail the report leaves from, and how the panel understands how it went.
 *
 * The defect of 25/09/2026: sendmail was looked for in the PATH, /usr/sbin/sendmail was found, that
 * is mailwrapper, that is dma. dma delivered by itself, in clear and without a DKIM signature, and
 * the panel wrote "succeeded" because it only looked at the exit code. Here it is tested that
 * mailwrapper is never chosen, and that with dma's lines in the log the outcome does NOT become
 * "delivered": Postfix did not see that message.
 *
 * The panel's messages are read in English (I18n.setCurrent): outside a request it writes Italian.
 */
public class ReportDeliveryTest {

    private static int failed = 0;

    private static final String ID = "report.20260925155210.0f3a9c1d2b4e5f60718293a4b5c6d7e8@domain-b.test";
    private static final String A = "owner@example.com";

    public static void main(String[] args) throws Exception {
        org.daemoxcp.mail.i18n.I18n.setCurrent("en");
        // --- Delivered to Gmail, with TLS: what must happen after the fix ---
        // In between there are the lines of another message, which must confuse nothing.
        List<String> gmail = List.of(
            "Sep 25 17:52:10 mail postfix/pickup[81234]: 4hB2Kq3Xz9zB6: uid=0 from=<noreply-mailserver@domain-b.test>",
            "Sep 25 17:52:10 mail postfix/cleanup[81240]: 4hB2Kq3Xz9zB6: message-id=<" + ID + ">",
            "Sep 25 17:52:10 mail postfix/qmgr[1022]: 4hB2Kq3Xz9zB6: from=<noreply-mailserver@domain-b.test>, size=4211, nrcpt=1 (queue active)",
            "Sep 25 17:52:11 mail postfix/smtpd[81250]: 4hB2Kr0ABCzB7: client=mail-wr1-f41.google.com[209.85.221.41]",
            "Sep 25 17:52:11 mail postfix/cleanup[81240]: 4hB2Kr0ABCzB7: message-id=<CAF=abc123@mail.gmail.com>",
            "Sep 25 17:52:11 mail postfix/lmtp[81255]: 4hB2Kr0ABCzB7: to=<info@domain-b.test>, relay=127.0.0.1[127.0.0.1]:24, delay=0.2, delays=0.1/0/0/0.1, dsn=2.0.0, status=sent (250 2.0.0 <info@domain-b.test> xyz Saved)",
            "Sep 25 17:52:11 mail postfix/smtp[81242]: Trusted TLS connection established to gmail-smtp-in.l.google.com[142.250.102.27]:25: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519 server-signature ECDSA (P-256) server-digest SHA256",
            "Sep 25 17:52:12 mail postfix/smtp[81242]: 4hB2Kq3Xz9zB6: to=<owner@example.com>, relay=gmail-smtp-in.l.google.com[142.250.102.27]:25, delay=1.6, delays=0.1/0.01/0.52/0.97, dsn=2.0.0, status=sent (250 2.0.0 OK  1727279532 5b1f17b1804b1-42cb5a5ba8esi12345f9.123 - gsmtp)",
            "Sep 25 17:52:12 mail postfix/qmgr[1022]: 4hB2Kq3Xz9zB6: removed");
        JSONObject e = PeriodicReport.outcomeInLog(gmail, ID, A);
        real("gmail: it finds the queue number from the Message-ID", "4hB2Kq3Xz9zB6".equals(e.optString("queue")));
        real("gmail: delivered", "delivered".equals(e.optString("state")));
        real("gmail: right relay", "gmail-smtp-in.l.google.com[142.250.102.27]:25".equals(e.optString("relay")));
        real("gmail: the server's answer", e.optString("answer").startsWith("250 2.0.0 OK"));
        real("gmail: TLS read from the smtp line", "TLSv1.3 (TLS_AES_256_GCM_SHA384)".equals(e.optString("tls")));
        real("gmail: the other message's lines stay out",
            !e.getJSONArray("lines").toString().contains("4hB2Kr0ABCzB7"));
        JSONObject v = PeriodicReport.verdict(e);
        real("gmail: verdict succeeded and without a warning", v.optBoolean("success") && !v.optBoolean("warning"));
        real("gmail: the recorded outcome says where and with which TLS",
            v.optString("outcome").startsWith("delivered to gmail-smtp-in.l.google.com") && v.optString("outcome").contains("TLSv1.3"));

        // --- TLS is taken only from the smtp process that delivered ---
        // A review: with the relay alone, the TLS line of ANOTHER smtp process towards the same
        // server was attributed to the report, and a report sent in clear came out "with TLS". Here
        // process 501 delivers in clear while 500 opens its own encrypted connection towards the same
        // Gmail for another message.
        String R = "gmail-smtp-in.l.google.com[142.250.102.27]:25";
        String opening13 = "Trusted TLS connection established to " + R + ": TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519 server-signature ECDSA (P-256) server-digest SHA256";
        String opening12 = "Untrusted TLS connection established to " + R + ": TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits)";
        String cleanup = "Sep 25 19:00:00 mail postfix/cleanup[1]: 4TLS00001: message-id=<" + ID + ">";
        String delivered = "4TLS00001: to=<owner@example.com>, relay=" + R + ", delay=1, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)";
        List<String> otherProcess = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[500]: " + opening13,
            "Sep 25 19:00:02 mail postfix/smtp[501]: " + delivered,
            "Sep 25 19:00:02 mail postfix/smtp[500]: 4OTHER0001: to=<other@example.com>, relay=" + R + ", delay=1, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)");
        real("tls: the test really contains a TLS opening towards the same relay",
            otherProcess.get(1).contains("TLS connection established to " + R + ": "));
        e = PeriodicReport.outcomeInLog(otherProcess, ID, A);
        real("tls of another process: delivered", "delivered".equals(e.optString("state")));
        real("tls of another process: NOT attributed to the report", !e.has("tls"));
        v = PeriodicReport.verdict(e);
        real("tls of another process: the outcome does not say TLS", !v.optString("outcome").contains("TLS"));
        real("tls of another process: its line stays out of the extract",
            !e.getJSONArray("lines").toString().contains("smtp[500]"));

        // The two openings interleave: the one of the process that delivered counts.
        List<String> interleaved = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[81242]: " + opening13,
            "Sep 25 19:00:01 mail postfix/smtp[81243]: " + opening12,
            "Sep 25 19:00:02 mail postfix/smtp[81242]: " + delivered);
        real("interleaved tls: the one of the process that delivered counts",
            "TLSv1.3 (TLS_AES_256_GCM_SHA384)".equals(PeriodicReport.outcomeInLog(interleaved, ID, A).optString("tls")));
        List<String> interleavedBackwards = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[81243]: " + opening12,
            "Sep 25 19:00:01 mail postfix/smtp[81242]: " + opening13,
            "Sep 25 19:00:02 mail postfix/smtp[81243]: " + delivered);
        real("interleaved tls, the other way round: still the one of whoever delivered counts",
            "TLSv1.2 (ECDHE-RSA-AES128-GCM-SHA256)".equals(PeriodicReport.outcomeInLog(interleavedBackwards, ID, A).optString("tls")));

        // Same process: first another message on an encrypted connection, then the report on a new
        // connection, in clear (without conn_use). The opening belongs to the earlier connection.
        List<String> connectionBefore = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[600]: " + opening13,
            "Sep 25 19:00:01 mail postfix/smtp[600]: 4OTHER0002: to=<other@example.com>, relay=" + R + ", delay=1, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)",
            "Sep 25 19:00:02 mail postfix/smtp[600]: " + delivered);
        real("same process, earlier connection: no TLS", !PeriodicReport.outcomeInLog(connectionBefore, ID, A).has("tls"));

        // Reused connection: it was opened before, for another message.
        List<String> reused = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[700]: " + opening13,
            "Sep 25 19:00:02 mail postfix/smtp[700]: " + delivered.replace(", delay=1,", ", conn_use=2, delay=1,"));
        real("reused connection (conn_use): no TLS", !PeriodicReport.outcomeInLog(reused, ID, A).has("tls"));

        // TLS dropped halfway and fallback in clear towards the SAME server (smtp_tls_security_level=may):
        // the opening is there, the relay is the same, but the message left on the next connection.
        List<String> fallback = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[800]: " + opening13,
            "Sep 25 19:00:02 mail postfix/smtp[800]: 4TLS00001: lost connection with " + R.substring(0, R.lastIndexOf(':')) + " while sending end of data -- message may be sent more than once",
            "Sep 25 19:00:03 mail postfix/smtp[800]: " + delivered);
        real("fallback in clear after a dropped TLS: no TLS", !PeriodicReport.outcomeInLog(fallback, ID, A).has("tls"));

        // First encrypted MX refusing, second MX in clear: the opening is towards another relay.
        List<String> otherMx = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[900]: Trusted TLS connection established to alt1.gmail-smtp-in.l.google.com[142.250.150.27]:25: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)",
            "Sep 25 19:00:01 mail postfix/smtp[900]: 4TLS00001: host alt1.gmail-smtp-in.l.google.com[142.250.150.27] said: 421 4.7.0 Try again later (in reply to MAIL FROM command)",
            "Sep 25 19:00:02 mail postfix/smtp[900]: " + delivered);
        real("opening towards another MX: no TLS", !PeriodicReport.outcomeInLog(otherMx, ID, A).has("tls"));

        // smtp_tls_loglevel 2: after the opening the process writes lines of the TLS session, and the
        // message also goes to a second recipient on the same connection. The test holds.
        List<String> loglevel2 = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[1000]: " + opening13,
            "Sep 25 19:00:01 mail postfix/smtp[1000]: SSL_connect:SSL negotiation finished successfully",
            "Sep 25 19:00:01 mail postfix/smtp[1000]: save session smtp&gmail.com&gmail-smtp-in.l.google.com&142.250.102.27&&3C7A5B to smtp cache",
            "Sep 25 19:00:02 mail postfix/smtp[1000]: 4TLS00001: to=<other@example.com>, relay=" + R + ", delay=1, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)",
            "Sep 25 19:00:02 mail postfix/smtp[1000]: " + delivered);
        e = PeriodicReport.outcomeInLog(loglevel2, ID, A);
        real("loglevel 2 and two recipients: TLS recognised", "TLSv1.3 (TLS_AES_256_GCM_SHA384)".equals(e.optString("tls")));
        real("loglevel 2: the opening is in the extract", e.getJSONArray("lines").toString().contains("TLS connection established"));

        // RFC 5424: the pid is a field of its own. Same pid, TLS; different pid, nothing.
        String t5424 = "<22>1 2026-09-25T19:00:01.000001+02:00 mail postfix/smtp ";
        List<String> tls5424 = List.of(
            "<22>1 2026-09-25T19:00:00.000001+02:00 mail postfix/cleanup 1 - - 4TLS00001: message-id=<" + ID + ">",
            t5424 + "81242 - - " + opening13,
            t5424 + "81242 - - " + delivered);
        real("rfc 5424, same pid: TLS", "TLSv1.3 (TLS_AES_256_GCM_SHA384)".equals(PeriodicReport.outcomeInLog(tls5424, ID, A).optString("tls")));
        List<String> tls5424other = List.of(tls5424.get(0), t5424 + "81243 - - " + opening13, tls5424.get(2));
        real("rfc 5424, different pid: no TLS", !PeriodicReport.outcomeInLog(tls5424other, ID, A).has("tls"));
        PeriodicReport.Row rr = PeriodicReport.line("Sep  5 07:02:11 mail postfix/smtp[81242]: " + delivered);
        real("classic line with a one-digit day: process and text",
            rr != null && "postfix/smtp[81242]".equals(rr.process()) && delivered.equals(rr.text()));

        // --- The production case: the message went through dma, not Postfix ---
        // The old code said "succeeded" here. The new one must not say "delivered".
        List<String> dma = List.of(
            "Sep 25 17:40:01 mail dma[2c1a4]: new mail from user=root uid=0 envelope_from=<noreply-mailserver@domain-b.test>",
            "Sep 25 17:40:01 mail dma[2c1a4]: mail to=<owner@example.com> queued as 2c1a4.2a0b5c048000",
            "Sep 25 17:40:01 mail dma[2c1a4.2a0b5c048000]: <owner@example.com> trying delivery",
            "Sep 25 17:40:01 mail dma[2c1a4.2a0b5c048000]: trying remote delivery to gmail-smtp-in.l.google.com [142.250.102.27] pref 5",
            "Sep 25 17:40:02 mail dma[2c1a4.2a0b5c048000]: <owner@example.com> delivery successful");
        e = PeriodicReport.outcomeInLog(dma, ID, A);
        real("dma: Postfix did not see it", e.optString("state").isEmpty() && !e.has("queue"));
        v = PeriodicReport.verdict(e);
        real("dma: the verdict is a warning, not 'delivered'",
            v.optBoolean("warning") && !v.optString("outcome").startsWith("delivered"));

        // --- Deferred: Postfix retries by itself, the panel must not send it again ---
        List<String> postponed = List.of(
            "Sep 25 18:00:00 mail postfix/cleanup[1]: 4ABCDEF123: message-id=<" + ID + ">",
            "Sep 25 18:00:30 mail postfix/smtp[2]: 4ABCDEF123: to=<owner@example.com>, relay=none, delay=30, delays=0.02/0.01/30/0, dsn=4.4.1, status=deferred (connect to gmail-smtp-in.l.google.com[142.250.102.27]:25: Connection timed out)");
        e = PeriodicReport.outcomeInLog(postponed, ID, A);
        real("deferred: state", "deferred".equals(e.optString("state")));
        real("deferred: reason", e.optString("answer").contains("Connection timed out"));
        v = PeriodicReport.verdict(e);
        real("deferred: succeeded with a warning, so the scheduler does not send it again",
            v.optBoolean("success") && v.optBoolean("warning"));

        // --- Deferred and then delivered: the last line counts ---
        List<String> thenDelivered = new java.util.ArrayList<>(postponed);
        thenDelivered.add("Sep 25 18:05:00 mail postfix/smtp[3]: 4ABCDEF123: to=<owner@example.com>, relay=alt1.gmail-smtp-in.l.google.com[142.250.150.27]:25, delay=300, delays=299/0/0.4/0.6, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)");
        real("deferred and then delivered: delivered",
            "delivered".equals(PeriodicReport.outcomeInLog(thenDelivered, ID, A).optString("state")));

        // --- Bounced by Gmail for DMARC: the answer has brackets inside the brackets ---
        List<String> rejected = List.of(
            "Sep 25 18:10:00 mail postfix/cleanup[1]: 4ABCDEF124: message-id=<" + ID + ">",
            "Sep 25 18:10:01 mail postfix/smtp[2]: 4ABCDEF124: to=<owner@example.com>, relay=gmail-smtp-in.l.google.com[142.250.102.27]:25, delay=1.1, delays=0.05/0/0.4/0.6, dsn=5.7.26, status=bounced (host gmail-smtp-in.l.google.com[142.250.102.27] said: 550-5.7.26 Unauthenticated email from domain-b.test is not accepted due to domain's 550-5.7.26 DMARC policy. (in reply to end of DATA command))",
            "Sep 25 18:10:01 mail postfix/bounce[3]: 4ABCDEF124: sender non-delivery notification: 4ABCDEF125");
        e = PeriodicReport.outcomeInLog(rejected, ID, A);
        real("bounced: state", "rejected".equals(e.optString("state")));
        real("bounced: the whole answer, brackets included", e.optString("answer").endsWith("(in reply to end of DATA command)"));
        v = PeriodicReport.verdict(e);
        real("bounced: NOT succeeded", !v.optBoolean("success"));
        real("bounced: the error says by whom", v.optString("error").startsWith("bounced by gmail-smtp-in.l.google.com"));
        v = PeriodicReport.verdict(new JSONObject().put("state", "rejected").put("relay", "none").put("answer", "x"));
        real("bounced without a relay: no 'by none'", "bounced: x".equals(v.optString("error")));

        // --- Refused by the milter before leaving; if the code is 4.x.x, it is only deferred ---
        List<String> milter5 = List.of(
            "Sep 25 18:20:00 mail postfix/cleanup[1]: 4ABCDEF126: message-id=<" + ID + ">",
            "Sep 25 18:20:00 mail postfix/cleanup[1]: 4ABCDEF126: milter-reject: END-OF-MESSAGE from localhost[127.0.0.1]: 5.7.1 Spam message rejected; from=<noreply-mailserver@domain-b.test> to=<owner@example.com>");
        e = PeriodicReport.outcomeInLog(milter5, ID, A);
        real("milter 5.7.1: refused", "refused".equals(e.optString("state")));
        real("milter 5.7.1: NOT succeeded", !PeriodicReport.verdict(e).optBoolean("success"));
        List<String> milter4 = List.of(milter5.get(0), milter5.get(1).replace("5.7.1 Spam message rejected", "4.7.1 Try again later"));
        real("milter 4.7.1: deferred", "deferred".equals(PeriodicReport.outcomeInLog(milter4, ID, A).optString("state")));

        // --- Seen by Postfix, outcome not written yet ---
        e = PeriodicReport.outcomeInLog(gmail.subList(0, 3), ID, A);
        real("queued: state", "queued".equals(e.optString("state")));
        v = PeriodicReport.verdict(e);
        real("queued: succeeded with a warning and the command to look for it",
            v.optBoolean("success") && v.optBoolean("warning") && v.optString("note").contains("grep 4hB2Kq3Xz9zB6"));

        // --- Alias and hidden copy: the line of the report's recipient counts ---
        String mine = "owner@domain-b.test";
        List<String> alias = List.of(
            "Sep 25 18:30:00 mail postfix/cleanup[1]: 4ABCDEF127: message-id=<" + ID + ">",
            "Sep 25 18:30:02 mail postfix/smtp[2]: 4ABCDEF127: to=<owner@example.com>, orig_to=<owner@domain-b.test>, relay=gmail-smtp-in.l.google.com[142.250.102.27]:25, delay=2, delays=0.1/0/1/0.9, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)",
            "Sep 25 18:30:02 mail postfix/lmtp[3]: 4ABCDEF127: to=<archive@domain-b.test>, relay=127.0.0.1[127.0.0.1]:24, delay=2, delays=0.1/0/0/0.1, dsn=4.2.2, status=deferred (host 127.0.0.1[127.0.0.1] said: 452 4.2.2 Mailbox is full (in reply to end of DATA command))");
        e = PeriodicReport.outcomeInLog(alias, ID, mine);
        real("alias: orig_to counts, not the copy for the archive", "delivered".equals(e.optString("state")));

        // --- RFC 5424 format, if syslogd uses it ---
        List<String> rfc5424 = List.of(
            "<22>1 2026-09-25T17:52:10.123456+02:00 mail postfix/cleanup 81240 - - 4hB2Kq3Xz9zB6: message-id=<" + ID + ">",
            "<22>1 2026-09-25T17:52:12.654321+02:00 mail postfix/smtp 81242 - - 4hB2Kq3Xz9zB6: to=<owner@example.com>, relay=gmail-smtp-in.l.google.com[142.250.102.27]:25, delay=1.6, delays=0.1/0.01/0.52/0.97, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)");
        real("rfc 5424: delivered", "delivered".equals(PeriodicReport.outcomeInLog(rfc5424, ID, A).optString("state")));

        // --- Literal comparisons, not regular expressions ---
        // In the Message-ID the dot is a dot: "reportX..." is not our message.
        List<String> almost = List.of(
            "Sep 25 18:40:00 mail postfix/cleanup[1]: 4ABCDEF128: message-id=<" + ID.replace("report.", "reportX") + ">",
            "Sep 25 18:40:01 mail postfix/smtp[2]: 4ABCDEF128: to=<owner@example.com>, relay=x[1.2.3.4]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)");
        real("an almost equal Message-ID is not ours", PeriodicReport.outcomeInLog(almost, ID, A).optString("state").isEmpty());
        // A queue number that ends like ours is not ours.
        List<String> suffix = List.of(
            "Sep 25 18:50:00 mail postfix/cleanup[1]: 4ABC12: message-id=<" + ID + ">",
            "Sep 25 18:50:01 mail postfix/smtp[2]: X4ABC12: to=<owner@example.com>, relay=x[1.2.3.4]:25, delay=1, delays=0/0/0/1, dsn=5.0.0, status=bounced (no)");
        real("a queue number that ends like ours does not count",
            "queued".equals(PeriodicReport.outcomeInLog(suffix, ID, A).optString("state")));

        // --- The Message-ID the panel generates ---
        String id1 = PeriodicReport.newMessageId("report", "noreply-mailserver@domain-b.test");
        String id2 = PeriodicReport.newMessageId("report", "noreply-mailserver@domain-b.test");
        real("Message-ID: shape", id1.matches("report\\.\\d{14}\\.[0-9a-f]{24}@domain-b\\.test"));
        real("Message-ID: two sendings, two identifiers", !id1.equals(id2));
        real("Message-ID: the codes' one is recognised by its type",
            PeriodicReport.newMessageId("code", "noreply-mailserver@domain-b.test").startsWith("code."));
        // With the real server (domain-b.test) the whole header fits in the recommended 78 characters.
        real("Message-ID: the header fits in 78 characters", ("Message-ID: <" + id1 + ">").length() <= 78);

        // --- Which sendmail ---
        Path d = Files.createTempDirectory("sendmail-test");
        Path mw = runnable(d.resolve("mailwrapper"));
        Path postfix = runnable(d.resolve("postfix-sendmail"));
        Path other = runnable(d.resolve("other-sendmail"));
        Path symbolic = Files.createSymbolicLink(d.resolve("sendmail-symbolic"), mw);
        Path physical = Files.createLink(d.resolve("sendmail-hard"), mw);
        Path stopped = Files.writeString(d.resolve("non-runnable"), "x");
        String nobody = d.resolve("does-not-exist").toString();

        JSONObject s = PeriodicReport.sendmailChoice(symbolic.toString(), postfix.toString(), mw.toString());
        real("sendmail_path pointing to mailwrapper: the port's one is used",
            s.optBoolean("success") && postfix.toString().equals(s.optString("path")));
        s = PeriodicReport.sendmailChoice(other.toString(), postfix.toString(), mw.toString());
        real("what postconf says counts", other.toString().equals(s.optString("path")));
        s = PeriodicReport.sendmailChoice("", postfix.toString(), mw.toString());
        real("silent postconf: the port's one is used", postfix.toString().equals(s.optString("path")));
        s = PeriodicReport.sendmailChoice("postconf: warning: /usr/local/etc/postfix/main.cf: unused parameter", postfix.toString(), mw.toString());
        real("postconf saying something else: ignored", postfix.toString().equals(s.optString("path")));
        s = PeriodicReport.sendmailChoice(symbolic.toString(), physical.toString(), mw.toString());
        real("only mailwrapper available: error, no fallback",
            !s.optBoolean("success") && s.optString("error").contains("mailwrapper"));
        s = PeriodicReport.sendmailChoice(stopped.toString(), nobody, mw.toString());
        real("not runnable and missing: error", !s.optBoolean("success") && s.optString("error").contains("is not there"));
        real("hard link to mailwrapper: recognised", PeriodicReport.notPostfix(physical.toString(), mw.toString()) != null);
        real("a real sendmail: accepted", PeriodicReport.notPostfix(postfix.toString(), mw.toString()) == null);
        real("mailwrapper missing (not FreeBSD): it does not block",
            PeriodicReport.notPostfix(postfix.toString(), nobody) == null);

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    private static Path runnable(Path p) throws Exception {
        Files.writeString(p, "#!/bin/sh\n");
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxr-xr-x"));
        return p;
    }

    private static void real(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failed++;
    }
}
