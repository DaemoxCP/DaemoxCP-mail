package org.daemoxcp.mail.system;

import org.daemoxcp.mail.database.MailDatabase;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The sending limits (SendingLimits): the panel as Postfix's policy service. Without Postfix: the decision and its
 * counting, which limit applies to a mailbox, the reading of a request, the counts kept across a restart, the place in
 * smtpd_data_restrictions; and a real Unix socket with several requests on one connection, as Postfix sends them. The
 * real mail is in sending-limits-browser-test.js, on the test machine.
 *
 *   java -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.system.SendingLimitsTest
 */
public class SendingLimitsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static Map<String, String> req(String user, int recipients, String state) {
        Map<String, String> a = new HashMap<>();
        a.put("request", "smtpd_access_policy");
        a.put("protocol_state", state);
        if (user != null) a.put("sasl_username", user);
        a.put("recipient_count", String.valueOf(recipients));
        return a;
    }

    static MailDatabase.RateLimit row(String type, String email, int hour, int day, int recipients, boolean enabled) {
        MailDatabase.RateLimit r = new MailDatabase.RateLimit();
        r.targetType = type;
        r.targetName = email;
        r.maxPerHour = hour;
        r.maxPerDay = day;
        r.maxRecipients = recipients;
        r.enabled = enabled;
        return r;
    }

    public static void main(String[] args) throws Exception {
        long t = 1_800_000_000L;

        System.out.println("== Which limit applies ==");
        Function<String, SendingLimits.Limit> lim = SendingLimits.limitsOf(List.of(
                row("global", "Global", 50, 500, 50, true),
                row("mailbox", "Busy@Example.test", 3, 5, 2, true),
                row("mailbox", "off@example.test", 1, 1, 1, false)));
        check("a mailbox with its own active limit: its own (any case)", new SendingLimits.Limit(3, 5, 2).equals(lim.apply("busy@example.test")));
        check("its own limit off: the global one", new SendingLimits.Limit(50, 500, 50).equals(lim.apply("off@example.test")));
        check("no limit of its own: the global one", new SendingLimits.Limit(50, 500, 50).equals(lim.apply("other@example.test")));
        check("no global saved and none of its own: no limit",
                SendingLimits.limitsOf(List.of(row("mailbox", "a@example.test", 1, 1, 1, true))).apply("b@example.test") == null);

        System.out.println("\n== What is not counted ==");
        SendingLimits.Counter c = new SendingLimits.Counter();
        check("not a policy request: DUNNO", "DUNNO".equals(SendingLimits.decide(Map.of("request", "other"), lim, c, t)));
        check("not at DATA (RCPT, END-OF-MESSAGE): DUNNO", "DUNNO".equals(SendingLimits.decide(req("busy@example.test", 1, "RCPT"), lim, c, t))
                && "DUNNO".equals(SendingLimits.decide(req("busy@example.test", 1, "END-OF-MESSAGE"), lim, c, t)));
        check("incoming mail (no sasl_username): DUNNO", "DUNNO".equals(SendingLimits.decide(req(null, 9, "DATA"), lim, c, t))
                && "DUNNO".equals(SendingLimits.decide(req("", 9, "DATA"), lim, c, t)));
        check("none of these counted", c.since("busy@example.test", 0) == 0);

        System.out.println("\n== Per message, per hour, per day ==");
        String tooMany = SendingLimits.decide(req("busy@example.test", 3, "DATA"), lim, c, t);
        check("more recipients than its maximum: 550 5.5.3 (" + tooMany + ")", tooMany.startsWith("550 5.5.3") && tooMany.contains("at most 2"));
        check("and not counted", c.since("busy@example.test", 0) == 0);
        check("2 recipients: DUNNO, 2 counted", "DUNNO".equals(SendingLimits.decide(req("busy@example.test", 2, "DATA"), lim, c, t))
                && c.since("busy@example.test", t - 3_600) == 2);
        String hour = SendingLimits.decide(req("Busy@Example.test", 2, "DATA"), lim, c, t + 10);
        check("2 more in the same hour (4 > 3): 450 4.7.1, per hour (" + hour + ")", hour.startsWith("450 4.7.1") && hour.contains("per hour"));
        check("1 more: DUNNO (3)", "DUNNO".equals(SendingLimits.decide(req("busy@example.test", 1, "DATA"), lim, c, t + 20)));
        check("then 1: refused", SendingLimits.decide(req("busy@example.test", 1, "DATA"), lim, c, t + 30).startsWith("450"));
        check("an hour later: 2 more go (5 in the day)", "DUNNO".equals(SendingLimits.decide(req("busy@example.test", 2, "DATA"), lim, c, t + 3_601)));
        String day = SendingLimits.decide(req("busy@example.test", 1, "DATA"), lim, c, t + 3_700);
        check("then the day is full (6 > 5): 450, per day (" + day + ")", day.startsWith("450 4.7.1") && day.contains("per day"));
        check("the next day: it goes again", "DUNNO".equals(SendingLimits.decide(req("busy@example.test", 1, "DATA"), lim, c, t + 86_401 + 3_601)));
        check("a bad recipient_count counts as 1", "DUNNO".equals(SendingLimits.decide(Map.of("request", "smtpd_access_policy",
                "protocol_state", "DATA", "sasl_username", "x@example.test", "recipient_count", "lots"), lim, c, t)) && c.since("x@example.test", 0) == 1);

        System.out.println("\n== Kept across a restart ==");
        SendingLimits.Counter a = new SendingLimits.Counter();
        a.add("a@example.test", t - 100, 2);
        a.add("a@example.test", t - 90_000, 7);
        a.add("b@example.test", t - 10, 1);
        String dump = a.dump(t);
        SendingLimits.Counter b = new SendingLimits.Counter();
        b.load(dump + "junk line\nx@example.test 12 1\nlong@example.test " + (t + 99_999) + " 3\n", t);
        check("the dump leaves out what is older than 24 hours, even out of order", !dump.contains(String.valueOf(t - 90_000)));
        check("what is younger than 24 hours comes back (" + dump.trim().replace('\n', ',') + ")",
                b.since("a@example.test", 0) == 2 && b.since("b@example.test", 0) == 1);
        check("junk lines, old or future times: skipped", b.since("x@example.test", 0) == 0 && b.since("long@example.test", 0) == 0);
        check("nothing to save after a load", !b.dirty());

        System.out.println("\n== Reading a request ==");
        Map<String, String> r = SendingLimits.read(new BufferedReader(new StringReader("request=smtpd_access_policy\nsasl_username=a@b\n\n")));
        check("name=value lines up to an empty one", r != null && "a@b".equals(r.get("sasl_username")));
        check("a line over " + SendingLimits.MAX_LINE + " characters: the connection ends",
                SendingLimits.read(new BufferedReader(new StringReader("a=" + "x".repeat(SendingLimits.MAX_LINE) + "\n\n"))) == null);
        check("a name that is not lowercase letters and _: refused", SendingLimits.read(new BufferedReader(new StringReader("A-b=1\n\n"))) == null
                && SendingLimits.read(new BufferedReader(new StringReader("=1\n\n"))) == null);
        check("more than " + SendingLimits.MAX_ATTRIBUTES + " attributes: refused",
                SendingLimits.read(new BufferedReader(new StringReader("a=1\n".repeat(1) + attrs(SendingLimits.MAX_ATTRIBUTES + 1) + "\n"))) == null);
        check("the end of the connection: null", SendingLimits.read(new BufferedReader(new StringReader(""))) == null);

        System.out.println("\n== Postfix ==");
        check("empty smtpd_data_restrictions: just the question", SendingLimits.POLICY.equals(SendingLimits.withPolicy("")));
        check("other rules: the question first", (SendingLimits.POLICY + ", reject_unauth_pipelining").equals(SendingLimits.withPolicy("reject_unauth_pipelining")));
        check("already there: the same", SendingLimits.withPolicy(SendingLimits.POLICY).equals(SendingLimits.POLICY));
        check("with the panel stopped the mail passes (default_action=DUNNO)", SendingLimits.POLICY.contains("default_action=DUNNO"));

        System.out.println("\n== A real socket, several requests on one connection ==");
        Path dir = Files.createTempDirectory("sending-limits-test");
        Path sock = dir.resolve("policy");
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));
            Thread th = new Thread(() -> { try { SendingLimits.serve(server.accept()); } catch (Exception ignored) { } });
            th.start();
            try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
                ch.connect(UnixDomainSocketAddress.of(sock));
                BufferedReader in = new BufferedReader(new InputStreamReader(Channels.newInputStream(ch), StandardCharsets.US_ASCII));
                ch.write(ByteBuffer.wrap("request=smtpd_access_policy\nprotocol_state=RCPT\n\n".getBytes(StandardCharsets.US_ASCII)));
                String first = in.readLine(), blank1 = in.readLine();
                ch.write(ByteBuffer.wrap("request=smtpd_access_policy\nprotocol_state=DATA\nrecipient_count=1\n\n".getBytes(StandardCharsets.US_ASCII)));
                String second = in.readLine(), blank2 = in.readLine();
                check("first answer, then an empty line (" + first + ")", "action=DUNNO".equals(first) && "".equals(blank1));
                check("second answer on the same connection (" + second + ")", "action=DUNNO".equals(second) && "".equals(blank2));
            }
            th.join(5000);
        } finally {
            Files.deleteIfExists(sock);
            Files.deleteIfExists(dir);
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    static String attrs(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append("a").append((char) ('a' + i % 26)).append("_").append("x".repeat(i / 26)).append("=1\n");
        return sb.toString();
    }
}
