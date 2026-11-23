package org.daemoxcp.mail.monitoring;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The Postfix queue: list, content of a message, deletion, new attempt,
 * held and released messages, statistics.
 *
 * Postfix commands:
 *  - postqueue -j        the list, one JSON object per message (Postfix 3.1 and later)
 *  - postcat -h -b -q    headers and body of a message
 *  - postsuper -d / -r   deletes a message / puts it back in the queue
 *  - postsuper -h / -H   holds / releases
 *  - postqueue -f        retries everything right away
 *
 * The commands start with separate arguments, never through sh -c, and the queue identifier
 * is checked BEFORE using it (isQueueId). Before, the identifier came from the request
 * straight into a shell line: /api/queue?action=message&id=X;command ran the command, and
 * a link opened by a logged-in administrator was enough.
 *
 * The list is read from postqueue -j and not from the text of postqueue -p: the text puts the reason
 * for the deferral in parentheses on a line that the old reader mistook for the recipient,
 * so the "Error" column always stayed empty and "Delete failed" never found anything.
 *
 * The messages for those who use the panel go through I18n.tr (keys server.queue.*), in the language
 * of the request; the exceptions and the logs stay in English.
 */
public class MailQueueManager {

    private static final String POSTQUEUE = "/usr/local/sbin/postqueue";
    private static final String POSTCAT = "/usr/local/sbin/postcat";
    private static final String POSTSUPER = "/usr/local/sbin/postsuper";

    /**
     * Postfix queue identifiers are alphanumeric: short in hexadecimal (3A1F2B4C5D)
     * or long in base 52 (4Nq8Zk1yQPz9Lm2). Anything else is refused without throwing anything.
     */
    private static final Pattern QUEUE_ID = Pattern.compile("[0-9A-Za-z]{5,32}");

    /** How much of the message text is shown at most. */
    static final int BODY_PREVIEW = 2000;

    /** Who runs the commands: Shell.run, replaceable in tests. */
    public interface Runner {
        Shell.Result run(String... cmd);
    }

    private final Runner runner;

    public MailQueueManager() {
        this(Shell::run);
    }

    public MailQueueManager(Runner runner) {
        this.runner = runner;
    }

    public enum QueueState {
        ACTIVE,       // being delivered now
        DEFERRED,     // deferred: temporary error, Postfix will retry
        HOLD,         // held: it does not leave until it is released
        INCOMING,     // just arrived (incoming or maildrop)
        CORRUPT,      // unreadable queue file
        UNKNOWN
    }

    /** true if the text is an acceptable queue identifier. */
    public static boolean isQueueId(String id) {
        return id != null && QUEUE_ID.matcher(id).matches();
    }

    // ------------------------------------------------------------------ list

    /**
     * All the messages in the queue.
     *
     * @throws IllegalStateException if postqueue does not answer as it should
     */
    public List<QueuedMessage> getQueue() {
        Shell.Result r = runner.run(POSTQUEUE, "-j");
        if (!r.success()) {
            throw new IllegalStateException("postqueue -j failed (exit " + r.exitCode() + "): " + r.outputTrim());
        }
        return parseJsonQueue(r.output());
    }

    /**
     * The output of postqueue -j: one JSON object per line. Lines that are not JSON (a Postfix warning
     * that ended up in the same stream) are skipped.
     */
    public static List<QueuedMessage> parseJsonQueue(String output) {
        List<QueuedMessage> messages = new ArrayList<>();
        if (output == null) return messages;
        for (String line : output.split("\n")) {
            line = line.trim();
            if (!line.startsWith("{")) continue;
            JSONObject o;
            try {
                o = new JSONObject(line);
            } catch (JSONException e) {
                continue;
            }
            QueuedMessage m = new QueuedMessage();
            m.id = o.optString("queue_id", "");
            m.state = stateOf(o.optString("queue_name", ""));
            m.sender = o.optString("sender", "");
            m.size = o.optLong("message_size", 0);
            long arrival = o.optLong("arrival_time", 0);
            m.arrival = arrival > 0 ? Instant.ofEpochSecond(arrival) : null;
            JSONArray recipients = o.optJSONArray("recipients");
            if (recipients != null) {
                for (int i = 0; i < recipients.length(); i++) {
                    JSONObject rcpt = recipients.optJSONObject(i);
                    if (rcpt == null) continue;
                    String reason = rcpt.optString("delay_reason", "");
                    m.recipients.add(new Recipient(rcpt.optString("address", ""), reason.isBlank() ? null : reason));
                }
            }
            messages.add(m);
        }
        return messages;
    }

    private static QueueState stateOf(String queueName) {
        return switch (queueName) {
            case "active" -> QueueState.ACTIVE;
            case "deferred" -> QueueState.DEFERRED;
            case "hold" -> QueueState.HOLD;
            case "incoming", "maildrop" -> QueueState.INCOMING;
            case "corrupt" -> QueueState.CORRUPT;
            default -> QueueState.UNKNOWN;
        };
    }

    // ------------------------------------------------------------------ one message

    /** Headers and the start of the text of a queued message. */
    public MessageContent getMessage(String id) {
        MessageContent content = new MessageContent();
        content.id = id;
        if (!isQueueId(id)) {
            content.error = I18n.tr("server.queue.badId");
            return content;
        }
        Shell.Result r = runner.run(POSTCAT, "-h", "-b", "-q", id);
        if (!r.success() || r.outputTrim().isEmpty()) {
            content.error = I18n.tr("server.queue.notFound", Map.of("id", id));
            return content;
        }
        parseMessage(r.output(), content);
        content.found = true;
        return content;
    }

    /** The headers up to the first empty line, then the body; postcat's "*** ... ***" lines are left out. */
    static void parseMessage(String output, MessageContent content) {
        StringBuilder headers = new StringBuilder();
        StringBuilder body = new StringBuilder();
        boolean inBody = false;
        for (String line : output.split("\n")) {
            if (line.startsWith("*** ") && line.endsWith(" ***")) continue;
            if (!inBody) {
                if (line.isEmpty()) {
                    inBody = true;
                    continue;
                }
                headers.append(line).append("\n");
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.startsWith("from:")) content.fromHeader = line.substring(5).trim();
                else if (lower.startsWith("to:")) content.toHeader = line.substring(3).trim();
                else if (lower.startsWith("subject:")) content.subject = line.substring(8).trim();
                else if (lower.startsWith("date:")) content.dateHeader = line.substring(5).trim();
            } else {
                body.append(line).append("\n");
            }
        }
        content.headers = headers.toString();
        String text = body.toString();
        content.bodyTruncated = text.length() > BODY_PREVIEW;
        content.bodyPreview = content.bodyTruncated ? text.substring(0, BODY_PREVIEW) : text;
    }

    // ------------------------------------------------------------------ actions

    /** Deletes a message from the queue. */
    public QueueAction removeMessage(String id) {
        if (!isQueueId(id)) return QueueAction.failed(I18n.tr("server.queue.badId"));
        Shell.Result r = runner.run(POSTSUPER, "-d", id);
        if (!r.success()) return QueueAction.failed(commandFailed(r));
        // postsuper writes "ID: removed" for every deleted message, and nothing if it was not there
        if (!r.output().contains(id + ": removed")) {
            return QueueAction.failed(I18n.tr("server.queue.notFound", Map.of("id", id)));
        }
        return QueueAction.done(I18n.tr("server.queue.removed", Map.of("id", id)));
    }

    /** Puts a message back in the queue for a new attempt. */
    public QueueAction scheduleMessage(String id) {
        if (!isQueueId(id)) return QueueAction.failed(I18n.tr("server.queue.badId"));
        Shell.Result r = runner.run(POSTSUPER, "-r", id);
        if (!r.success()) return QueueAction.failed(commandFailed(r));
        if (!r.output().contains(id + ": requeued")) {
            return QueueAction.failed(I18n.tr("server.queue.notFound", Map.of("id", id)));
        }
        return QueueAction.done(I18n.tr("server.queue.requeued", Map.of("id", id)));
    }

    /** Asks Postfix to retry all the messages right away. */
    public QueueAction flushQueue() {
        Shell.Result r = runner.run(POSTQUEUE, "-f");
        if (!r.success()) return QueueAction.failed(commandFailed(r));
        return QueueAction.done(I18n.tr("server.queue.flushed"));
    }

    /** Holds all the messages in the queue now (those arriving later leave normally). */
    public QueueAction holdAll() {
        Shell.Result r = runner.run(POSTSUPER, "-h", "ALL");
        if (!r.success()) return QueueAction.failed(commandFailed(r));
        return QueueAction.done(I18n.trn("server.queue.held", countIn(r.output(), "Placed on hold"), Map.of()));
    }

    /** Releases all the held messages. */
    public QueueAction releaseAll() {
        Shell.Result r = runner.run(POSTSUPER, "-H", "ALL");
        if (!r.success()) return QueueAction.failed(commandFailed(r));
        return QueueAction.done(I18n.trn("server.queue.released", countIn(r.output(), "Released from hold"), Map.of()));
    }

    /** The number in postsuper's summary ("Placed on hold: 3 messages"); 0 if it is not there. */
    static long countIn(String output, String label) {
        Matcher m = Pattern.compile(Pattern.quote(label) + ":\\s*(\\d{1,9})").matcher(output == null ? "" : output);
        return m.find() ? Long.parseLong(m.group(1)) : 0;
    }

    private static String commandFailed(Shell.Result r) {
        String out = r.outputTrim();
        if (out.length() > 300) out = out.substring(0, 300) + "...";
        return I18n.tr("server.queue.commandFailed", Map.of("output", out));
    }

    // ------------------------------------------------------------------ statistics

    /** How many messages per state, the oldest one, the most frequent senders and destination domains. */
    public QueueStats getStats() {
        return statsOf(getQueue());
    }

    static QueueStats statsOf(List<QueuedMessage> messages) {
        QueueStats stats = new QueueStats();
        stats.totalMessages = messages.size();
        for (QueuedMessage msg : messages) {
            stats.totalSize += msg.size;
            switch (msg.state) {
                case ACTIVE -> stats.active++;
                case DEFERRED -> stats.deferred++;
                case HOLD -> stats.hold++;
                case INCOMING -> stats.incoming++;
                default -> stats.unknown++;
            }
            if (msg.isPermanentFailure()) stats.permanent++;
            if (msg.sender != null && !msg.sender.isEmpty()) stats.topSenders.merge(msg.sender, 1, Integer::sum);
            for (Recipient r : msg.recipients) {
                int at = r.address().lastIndexOf('@');
                if (at >= 0 && at < r.address().length() - 1) {
                    stats.topDestinations.merge(r.address().substring(at + 1).toLowerCase(Locale.ROOT), 1, Integer::sum);
                }
            }
            if (msg.arrival != null && (stats.oldestMessage == null || msg.arrival.isBefore(stats.oldestMessage))) {
                stats.oldestMessage = msg.arrival;
            }
        }
        return stats;
    }

    // ------------------------------------------------------------------ permanent errors

    /**
     * A PERMANENT delivery error.
     *
     * The criterion is not "it has been in the queue for a long time": it is the reply code. SMTP tells
     * 4xx (try again later) apart from 5xx (do not try again), and the latter will never resolve
     * by themselves in the queue. They are recognised by the extended status code 5.x.x (RFC 3463)
     * or by the three-digit code starting with 5 reported in the error message.
     *
     * The comparison is NOT on a substring: looking for "5." inside the text would also find a
     * size "1.5.", a time or an IP address, and good mail would be deleted.
     */
    public static boolean isPermanentFailure(String error) {
        if (error == null || error.isBlank()) return false;
        // 1. extended status code 5.x.y (RFC 3463), isolated: "10.5.0.1" must not count
        if (Pattern.compile("(?<![0-9.])5\\.[0-9]{1,3}\\.[0-9]{1,3}(?![0-9.])").matcher(error).find()) return true;
        // 2. three-digit reply code, but ONLY where a code can really be:
        //    after "said:" or at the start of the line. Accepting it anywhere would mistake
        //    "size=550" for a permanent refusal, and a good message would be deleted.
        return Pattern.compile("(?:said:\\s*|^\\s*)5[0-9]{2}(?![0-9])", Pattern.CASE_INSENSITIVE).matcher(error).find();
    }

    /** The messages in the queue that have failed permanently. Read only. */
    public List<QueuedMessage> permanentFailures() {
        List<QueuedMessage> out = new ArrayList<>();
        for (QueuedMessage m : getQueue()) if (m.isPermanentFailure()) out.add(m);
        return out;
    }

    /**
     * Deletes, among the messages that whoever uses the panel has seen and confirmed (ids), those that
     * STILL have a permanent error. One by one.
     *
     * Only the confirmed ones: between the preview and the confirmation the queue changes, and a message
     * that arrived in the meantime has not been seen by anyone. Only those still permanent: one
     * that has been delivered or requeued in the meantime is not touched.
     *
     * "postsuper -d ALL deferred" is not used: it would delete the WHOLE deferred queue, including the
     * messages with a temporary error that would have left at the next attempt.
     */
    public QueueAction purgePermanentFailures(Collection<String> ids) {
        Set<String> confirmed = new HashSet<>();
        for (String id : ids) if (isQueueId(id)) confirmed.add(id);
        int deleted = 0, failed = 0;
        StringBuilder log = new StringBuilder();
        for (QueuedMessage m : permanentFailures()) {
            if (!confirmed.contains(m.id)) continue;
            Shell.Result r = runner.run(POSTSUPER, "-d", m.id);
            if (r.success() && r.output().contains(m.id + ": removed")) {
                deleted++;
            } else {
                failed++;
                log.append(m.id).append(": ").append(r.outputTrim()).append("\n");
            }
        }
        String message = I18n.trn("server.queue.purged", deleted, Map.of());
        if (failed > 0) message += " " + I18n.trn("server.queue.purgeFailed", failed, Map.of());
        message += " " + I18n.tr("server.queue.purgeUntouched");
        QueueAction action = failed == 0 ? QueueAction.done(message) : QueueAction.failed(message);
        action.count = deleted;
        action.output = log.toString();
        return action;
    }

    // ------------------------------------------------------------------ data

    /** A recipient and, if Postfix has already tried, the reason for the deferral. */
    public record Recipient(String address, String reason) {}

    public static class QueuedMessage {
        public String id;
        public QueueState state = QueueState.UNKNOWN;
        /** Empty for non-delivery notices (null sender). */
        public String sender;
        public final List<Recipient> recipients = new ArrayList<>();
        public long size;
        /** Arrival in the queue, in UTC. */
        public Instant arrival;

        /** The first deferral reason among the recipients, or null. */
        public String errorReason() {
            for (Recipient r : recipients) if (r.reason() != null) return r.reason();
            return null;
        }

        /**
         * Permanent only if it is so for EVERY recipient: deleting the message removes it for
         * everyone, and one with a temporary error (or not yet tried) would have left.
         */
        public boolean isPermanentFailure() {
            if (recipients.isEmpty()) return false;
            for (Recipient r : recipients) if (!MailQueueManager.isPermanentFailure(r.reason())) return false;
            return true;
        }
    }

    public static class MessageContent {
        public String id;
        public boolean found;
        public String headers;
        public String bodyPreview;
        public boolean bodyTruncated;
        public String fromHeader;
        public String toHeader;
        public String subject;
        public String dateHeader;
        public String error;
    }

    public static class QueueAction {
        public boolean success;
        public String message;
        public String output;
        public int count;

        static QueueAction done(String message) {
            QueueAction a = new QueueAction();
            a.success = true;
            a.message = message;
            return a;
        }

        static QueueAction failed(String message) {
            QueueAction a = new QueueAction();
            a.message = message;
            return a;
        }
    }

    public static class QueueStats {
        public int totalMessages;
        public long totalSize;
        public int active;
        public int deferred;
        public int hold;
        public int incoming;
        public int unknown;
        /** Messages with a permanent error for every recipient. */
        public int permanent;
        public Instant oldestMessage;
        public final Map<String, Integer> topSenders = new HashMap<>();
        public final Map<String, Integer> topDestinations = new HashMap<>();
    }
}
