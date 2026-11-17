package org.daemoxcp.mail.monitoring;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The Postfix queue as the panel reads and changes it, with a fake command runner that records
 * every command instead of running it.
 *
 * What it guards against:
 *  - the queue ID reaching a shell: it used to go straight into "sh -c postcat -q <id>", so
 *    /api/queue?action=message&id=X;command ran the command. Now every command is an argv list
 *    and an ID that is not alphanumeric never reaches a command at all;
 *  - the deferral reason getting lost: postqueue -p prints it on a line the old parser took for
 *    the recipient, so the Error column stayed empty and "Delete failed" never found anything.
 *    postqueue -j gives it per recipient;
 *  - deleting mail nobody confirmed: only the confirmed IDs that STILL have a permanent error for
 *    every recipient are deleted.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.monitoring.MailQueueTest
 */
public class MailQueueTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** Answers by the first two words of the command and records everything it is asked. */
    static class FakeRunner implements MailQueueManager.Runner {
        final List<List<String>> commands = new ArrayList<>();
        final Map<String, Shell.Result> answers = new java.util.HashMap<>();

        void answer(String prefix, int exit, String output) {
            answers.put(prefix, new Shell.Result(exit, output, false, List.of()));
        }

        @Override
        public Shell.Result run(String... cmd) {
            commands.add(List.of(cmd));
            String key = cmd[0].substring(cmd[0].lastIndexOf('/') + 1) + " " + cmd[1];
            return answers.getOrDefault(key, new Shell.Result(0, "", false, List.of(cmd)));
        }

        boolean ranAnything(String program) {
            return commands.stream().anyMatch(c -> c.get(0).endsWith("/" + program));
        }
    }

    // Three messages as postqueue -j prints them: one JSON object per line.
    static final String PERMANENT = "{\"queue_name\": \"deferred\", \"queue_id\": \"3A1F2B4C5D\", \"arrival_time\": 1760090400, "
            + "\"message_size\": 2048, \"forced_expire\": false, \"sender\": \"news@example.org\", \"recipients\": ["
            + "{\"address\": \"gone@example.com\", \"delay_reason\": \"host mx.example.com[192.0.2.1] said: 550 5.1.1 <gone@example.com>: Recipient address rejected (in reply to RCPT TO command)\"}]}";
    static final String MIXED = "{\"queue_name\": \"deferred\", \"queue_id\": \"4Nq8Zk1yQPz9Lm2\", \"arrival_time\": 1760094000, "
            + "\"message_size\": 512, \"sender\": \"\", \"recipients\": ["
            + "{\"address\": \"a@example.net\", \"delay_reason\": \"host mx.example.net said: 550 5.7.1 rejected\"},"
            + "{\"address\": \"b@example.net\", \"delay_reason\": \"connect to mx.example.net[198.51.100.7]:25: Connection timed out\"}]}";
    static final String ACTIVE = "{\"queue_name\": \"active\", \"queue_id\": \"5B2C3D4E6F\", \"arrival_time\": 1760097600, "
            + "\"message_size\": 100, \"sender\": \"me@example.org\", \"recipients\": [{\"address\": \"you@Example.COM\"}]}";
    static final String HOLD = "{\"queue_name\": \"hold\", \"queue_id\": \"6C3D4E5F7A\", \"arrival_time\": 1760001000, "
            + "\"message_size\": 300, \"sender\": \"me@example.org\", \"recipients\": [{\"address\": \"x@example.com\"}]}";
    static final String QUEUE = PERMANENT + "\n" + MIXED + "\npostqueue: warning: this line is not JSON\n" + ACTIVE + "\n" + HOLD + "\n";

    public static void main(String[] args) {
        I18n.setCurrent("en");

        System.out.println("\n== Reading postqueue -j ==");
        List<MailQueueManager.QueuedMessage> q = MailQueueManager.parseJsonQueue(QUEUE);
        check("four messages, the line that is not JSON skipped", q.size() == 4);
        MailQueueManager.QueuedMessage p = q.get(0);
        check("ID, state, sender and size", p.id.equals("3A1F2B4C5D") && p.state == MailQueueManager.QueueState.DEFERRED
                && p.sender.equals("news@example.org") && p.size == 2048);
        check("arrival in UTC: " + p.arrival, Instant.parse("2025-10-10T10:00:00Z").equals(p.arrival));
        check("the deferral reason is read, per recipient", p.errorReason() != null && p.errorReason().contains("550 5.1.1")
                && p.recipients.get(0).address().equals("gone@example.com"));
        check("550 for every recipient: permanent", p.isPermanentFailure());
        MailQueueManager.QueuedMessage m = q.get(1);
        check("one 5xx and one timeout: NOT permanent (deleting it would drop the second recipient)",
                m.recipients.size() == 2 && !m.isPermanentFailure());
        check("a bounce has an empty sender", m.sender.isEmpty());
        check("active and hold queues", q.get(2).state == MailQueueManager.QueueState.ACTIVE
                && q.get(3).state == MailQueueManager.QueueState.HOLD);
        check("never tried: no reason, not permanent", q.get(2).errorReason() == null && !q.get(2).isPermanentFailure());
        check("nothing in, nothing out", MailQueueManager.parseJsonQueue("").isEmpty() && MailQueueManager.parseJsonQueue(null).isEmpty());

        System.out.println("\n== Statistics ==");
        MailQueueManager.QueueStats s = MailQueueManager.statsOf(q);
        check("total 4: 1 active, 2 deferred, 1 held, 1 permanent", s.totalMessages == 4 && s.active == 1
                && s.deferred == 2 && s.hold == 1 && s.permanent == 1 && s.totalSize == 2960);
        check("oldest message: the held one", Instant.ofEpochSecond(1760001000).equals(s.oldestMessage));
        check("destination domains in lower case, the empty sender not counted",
                s.topDestinations.get("example.com") == 3 && s.topDestinations.get("example.net") == 2
                && !s.topSenders.containsKey("") && s.topSenders.get("me@example.org") == 2);

        System.out.println("\n== Queue IDs ==");
        for (String ok : new String[]{"3A1F2B4C5D", "4Nq8Zk1yQPz9Lm2", "ABCDE"}) {
            check("accepted: " + ok, MailQueueManager.isQueueId(ok));
        }
        for (String bad : new String[]{"3A1F;id", "$(id)", "`id`", "A B C D E", "../../etc/passwd", "ABCD", "", null,
                "3A1F2B4C5D\n", "-d ALL", "A".repeat(33), "3A1F2B4C5D|sh"}) {
            check("refused: " + (bad == null ? "null" : bad.replace("\n", "\\n")), !MailQueueManager.isQueueId(bad));
        }

        System.out.println("\n== Nothing reaches a shell ==");
        FakeRunner r = new FakeRunner();
        MailQueueManager mq = new MailQueueManager(r);
        MailQueueManager.MessageContent c = mq.getMessage("x;touch /tmp/owned");
        check("a bad ID for the message view: refused, no command run", !c.found && !r.ranAnything("postcat")
                && "Invalid queue ID.".equals(c.error));
        MailQueueManager.QueueAction a = mq.removeMessage("3A1F2B4C5D; rm -rf /");
        check("a bad ID to delete: refused, postsuper never started", !a.success && !r.ranAnything("postsuper"));
        a = mq.scheduleMessage("$(reboot)");
        check("a bad ID to requeue: refused too", !a.success && r.commands.isEmpty());

        r.answer("postsuper -d", 0, "postsuper: 3A1F2B4C5D: removed\npostsuper: Deleted: 1 message\n");
        a = mq.removeMessage("3A1F2B4C5D");
        check("delete: the command is an argv list, the ID a single argument", r.commands.get(0).equals(
                List.of("/usr/local/sbin/postsuper", "-d", "3A1F2B4C5D")));
        check("and the message says so: " + a.message, a.success && a.message.equals("Message 3A1F2B4C5D deleted from the queue."));
        r.answer("postsuper -d", 0, "");
        a = mq.removeMessage("3A1F2B4C5D");
        check("already gone (postsuper prints nothing): not a success", !a.success && a.message.contains("no longer in the queue"));
        r.answer("postsuper -r", 0, "postsuper: 3A1F2B4C5D: requeued\npostsuper: Requeued: 1 message\n");
        check("requeue", mq.scheduleMessage("3A1F2B4C5D").success
                && r.commands.get(r.commands.size() - 1).equals(List.of("/usr/local/sbin/postsuper", "-r", "3A1F2B4C5D")));
        r.answer("postsuper -d", 1, "postsuper: fatal: queue directory missing");
        a = mq.removeMessage("3A1F2B4C5D");
        check("a Postfix error is reported with its text", !a.success && a.message.contains("queue directory missing"));

        System.out.println("\n== The message view ==");
        r.answer("postcat -h", 0, "*** MESSAGE CONTENTS deferred/3A1F2B4C5D ***\nFrom: News <news@example.org>\nTo: gone@example.com\n"
                + "Subject: <script>alert(1)</script>\nDate: Fri, 10 Oct 2025 10:00:00 +0000\n\nHello,\nthis is the text.\n"
                + "*** HEADER EXTRACTED deferred/3A1F2B4C5D ***\n");
        c = mq.getMessage("3A1F2B4C5D");
        check("postcat -h -b -q <id>", r.commands.get(r.commands.size() - 1).equals(
                List.of("/usr/local/sbin/postcat", "-h", "-b", "-q", "3A1F2B4C5D")));
        check("headers read (the subject stays text: the page escapes it)", c.found && c.fromHeader.equals("News <news@example.org>")
                && c.toHeader.equals("gone@example.com") && c.subject.equals("<script>alert(1)</script>"));
        check("the body without the postcat markers", c.bodyPreview.equals("Hello,\nthis is the text.\n") && !c.bodyTruncated);
        r.answer("postcat -h", 0, "Subject: long\n\n" + "x".repeat(5000));
        c = mq.getMessage("3A1F2B4C5D");
        check("a long body is cut and marked", c.bodyTruncated && c.bodyPreview.length() == MailQueueManager.BODY_PREVIEW);
        r.answer("postcat -h", 1, "postcat: fatal: open queue file 3A1F2B4C5D: No such file or directory");
        c = mq.getMessage("3A1F2B4C5D");
        check("postcat failing: not found, not the error text shown as headers", !c.found && c.error.contains("no longer in the queue"));

        System.out.println("\n== Hold and release ==");
        r.answer("postsuper -h", 0, "postsuper: Placed on hold: 3 messages\n");
        a = mq.holdAll();
        check("hold all: " + a.message, a.success && a.message.startsWith("3 messages held"));
        r.answer("postsuper -H", 0, "postsuper: Released from hold: 1 message\n");
        a = mq.releaseAll();
        check("release: " + a.message, a.success && a.message.startsWith("1 message released"));
        r.answer("postsuper -H", 0, "");
        check("nothing held: 0 messages", mq.releaseAll().message.startsWith("0 messages released"));

        System.out.println("\n== Deleting the permanent failures ==");
        r.commands.clear();
        r.answer("postqueue -j", 0, QUEUE);
        r.answer("postsuper -d", 0, "postsuper: 3A1F2B4C5D: removed\npostsuper: Deleted: 1 message\n");
        check("the preview lists only the permanent one", mq.permanentFailures().stream().map(x -> x.id).toList()
                .equals(List.of("3A1F2B4C5D")));
        r.commands.clear();
        a = mq.purgePermanentFailures(List.of("3A1F2B4C5D", "4Nq8Zk1yQPz9Lm2", "bad;id"));
        List<List<String>> deletions = r.commands.stream().filter(x -> x.get(0).endsWith("/postsuper")).toList();
        check("only the confirmed AND still permanent one is deleted", deletions.equals(
                List.of(List.of("/usr/local/sbin/postsuper", "-d", "3A1F2B4C5D"))));
        check("message: " + a.message, a.success && a.count == 1 && a.message.startsWith("1 message with a permanent error deleted."));
        r.commands.clear();
        a = mq.purgePermanentFailures(List.of("6C3D4E5F7A"));
        check("a confirmed ID that is not permanent: nothing deleted", a.count == 0 && !r.ranAnything("postsuper"));
        r.answer("postsuper -d", 0, "");
        a = mq.purgePermanentFailures(List.of("3A1F2B4C5D"));
        check("gone in the meantime: counted as not deleted", !a.success && a.count == 0 && a.message.contains("1 not deleted"));

        System.out.println("\n== postqueue failing ==");
        r.answer("postqueue -j", 1, "postqueue: fatal: Queue report unavailable - mail system is down");
        try {
            mq.getQueue();
            check("an exception", false);
        } catch (IllegalStateException e) {
            check("an exception, in English, with the Postfix text: " + e.getMessage(),
                    e.getMessage().startsWith("postqueue -j failed") && e.getMessage().contains("mail system is down"));
        }

        System.out.println("\n== Permanent or temporary ==");
        check("said: 550 5.1.1: permanent", MailQueueManager.isPermanentFailure("host x said: 550 5.1.1 user unknown"));
        check("5.7.1 alone: permanent", MailQueueManager.isPermanentFailure("rejected: 5.7.1 policy"));
        check("4.4.1 connection timed out: temporary", !MailQueueManager.isPermanentFailure("4.4.1 Connection timed out"));
        check("an IP with .5. in it: temporary", !MailQueueManager.isPermanentFailure("connect to 10.5.0.1[10.5.0.1]:25: refused"));
        check("size=550: temporary", !MailQueueManager.isPermanentFailure("message size=550 exceeds nothing"));
        check("empty: temporary", !MailQueueManager.isPermanentFailure("") && !MailQueueManager.isPermanentFailure(null));

        System.out.println("\n== In Italian ==");
        I18n.setCurrent("it");
        r.answer("postsuper -d", 0, "postsuper: 3A1F2B4C5D: removed\n");
        check("the same message in the request language", mq.removeMessage("3A1F2B4C5D").message
                .equals(I18n.t("it", "server.queue.removed", Map.of("id", "3A1F2B4C5D"))));
        I18n.clearCurrent();

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
