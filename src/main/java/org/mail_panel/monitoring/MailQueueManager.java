package org.mail_panel.monitoring;

import java.io.*;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.regex.*;

/**
 * Mail Queue Manager for FreeBSD Mail Panel
 *
 * Manages the Postfix mail queue:
 * - View queued messages
 * - View message details
 * - Remove/delete messages
 * - Retry/flush messages
 * - Queue statistics
 *
 * Uses Postfix commands:
 * - postqueue -p     - List all queued messages
 * - postcat -q       - Show message content
 * - postsuper -d     - Delete message from queue
 * - postsuper -r     - Requeue message for delivery
 * - postqueue -f     - Flush queue (attempt immediate delivery)
 * - postsuper -h/-H  - Hold/release messages
 */
public class MailQueueManager {

    // Commands
    private static final String POSTQUEUE = "/usr/local/sbin/postqueue";
    private static final String POSTCAT = "/usr/local/sbin/postcat";
    private static final String POSTSUPER = "/usr/local/sbin/postsuper";

    // Queue states
    public enum QueueState {
        ACTIVE,       // Currently being delivered
        DEFERRED,     // Temporary failure, will retry
        HOLD,         // On hold
        INCOMING,     // Just received
        CORRUPT,      // Corrupted message
        UNKNOWN
    }

    /**
     * Get all messages in queue
     */
    public List<QueuedMessage> getQueue() {
        List<QueuedMessage> messages = new ArrayList<>();

        try {
            String output = executeCommand(POSTQUEUE + " -p");

            if (output.isEmpty() || output.contains("Mail queue is empty")) {
                return messages;
            }

            // Parse queue output
            // Format:
            // -Queue ID- --Size-- ----Arrival Time---- -Sender/Recipient-------
            // ABCD1234567*     1234 Sun Dec 29 10:30:45  sender@example.com
            //                                          recipient@example.com

            QueuedMessage currentMsg = null;
            for (String line : output.split("\n")) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("-Queue ID-") || line.startsWith("--")) {
                    continue;
                }

                // Check if this is a new message (starts with queue ID)
                if (line.matches("^[A-F0-9]+[*!]?\\s+.*")) {
                    if (currentMsg != null) {
                        messages.add(currentMsg);
                    }
                    currentMsg = parseQueueLine(line);
                } else if (currentMsg != null && line.contains("@")) {
                    // This is a recipient line
                    currentMsg.recipient = line.trim();
                }
            }

            // Add last message
            if (currentMsg != null) {
                messages.add(currentMsg);
            }

        } catch (Exception e) {
            System.err.println("Failed to get queue: " + e.getMessage());
        }

        return messages;
    }

    /**
     * Parse a queue line into QueuedMessage
     */
    private QueuedMessage parseQueueLine(String line) {
        try {
            QueuedMessage msg = new QueuedMessage();

            // Format: ABCD1234567*     1234 Sun Dec 29 10:30:45  sender@example.com
            // The * means active, ! means held
            Pattern pattern = Pattern.compile(
                "^([A-F0-9]+)([*!]?)\\s+(\\d+)\\s+(.+?)\\s{2,}(.+)$"
            );

            Matcher matcher = pattern.matcher(line);
            if (matcher.matches()) {
                msg.messageId = matcher.group(1);
                msg.envelopeId = msg.messageId;

                String stateChar = matcher.group(2);
                if ("*".equals(stateChar)) {
                    msg.state = QueueState.ACTIVE;
                } else if ("!".equals(stateChar)) {
                    msg.state = QueueState.HOLD;
                } else {
                    msg.state = QueueState.DEFERRED;
                }

                msg.size = Long.parseLong(matcher.group(3));

                String dateStr = matcher.group(4).trim();
                msg.created = parseDateTime(dateStr);

                msg.sender = matcher.group(5).trim();

                return msg;
            }

            // Fallback: try simpler parsing
            String[] parts = line.split("\\s+");
            if (parts.length >= 2) {
                msg.messageId = parts[0].replaceAll("[*!]", "");
                msg.envelopeId = msg.messageId;
                msg.state = parts[0].contains("*") ? QueueState.ACTIVE :
                           parts[0].contains("!") ? QueueState.HOLD : QueueState.DEFERRED;
                msg.rawLine = line;
                return msg;
            }

        } catch (Exception e) {
            System.err.println("Failed to parse queue line: " + line);
        }

        return null;
    }

    /**
     * Get message content
     */
    public MessageContent getMessage(String messageId) {
        MessageContent content = new MessageContent();
        content.messageId = messageId;

        try {
            String output = executeCommand(POSTCAT + " -q " + messageId);

            if (output.isEmpty()) {
                content.error = "Message not found";
                return content;
            }

            content.found = true;
            content.rawContent = output;

            // Parse headers and body
            StringBuilder headers = new StringBuilder();
            StringBuilder body = new StringBuilder();
            boolean inBody = false;

            for (String line : output.split("\n")) {
                // Skip postcat metadata lines
                if (line.startsWith("*** ")) {
                    continue;
                }

                if (!inBody) {
                    if (line.isEmpty()) {
                        inBody = true;
                    } else {
                        headers.append(line).append("\n");

                        // Extract common headers
                        String lowerLine = line.toLowerCase();
                        if (lowerLine.startsWith("from:")) {
                            content.fromHeader = line.substring(5).trim();
                        } else if (lowerLine.startsWith("to:")) {
                            content.toHeader = line.substring(3).trim();
                        } else if (lowerLine.startsWith("subject:")) {
                            content.subject = line.substring(8).trim();
                        } else if (lowerLine.startsWith("date:")) {
                            content.dateHeader = line.substring(5).trim();
                        } else if (lowerLine.startsWith("message-id:")) {
                            content.messageIdHeader = line.substring(11).trim();
                        }
                    }
                } else {
                    body.append(line).append("\n");
                }
            }

            content.headers = headers.toString();
            content.body = body.toString();

            // Limit body preview
            if (content.body.length() > 2000) {
                content.bodyPreview = content.body.substring(0, 2000) + "\n... [truncated]";
            } else {
                content.bodyPreview = content.body;
            }

        } catch (Exception e) {
            content.error = e.getMessage();
        }

        return content;
    }

    /**
     * Remove/delete message from queue
     */
    public QueueAction removeMessage(String messageId) {
        QueueAction action = new QueueAction();
        action.action = "remove";
        action.envelopeId = messageId;

        try {
            String output = executeCommand(POSTSUPER + " -d " + messageId);
            action.success = !output.toLowerCase().contains("error") &&
                            !output.toLowerCase().contains("cannot");
            action.output = output;

            if (action.success) {
                action.message = "Message removed from queue";
            } else {
                action.message = "Failed to remove message: " + output;
            }

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Requeue message for delivery
     */
    public QueueAction scheduleMessage(String messageId) {
        QueueAction action = new QueueAction();
        action.action = "requeue";
        action.envelopeId = messageId;

        try {
            String output = executeCommand(POSTSUPER + " -r " + messageId);
            action.success = !output.toLowerCase().contains("error");
            action.output = output;

            if (action.success) {
                action.message = "Message requeued for delivery";
            } else {
                action.message = "Failed to requeue message: " + output;
            }

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Flush queue - attempt immediate delivery of all messages
     */
    public QueueAction flushQueue() {
        QueueAction action = new QueueAction();
        action.action = "flush";

        try {
            String output = executeCommand(POSTQUEUE + " -f");
            action.success = true;  // postqueue -f doesn't output on success
            action.output = output;
            action.message = "Queue flush initiated";

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Hold all messages in queue
     */
    public QueueAction pauseQueue() {
        QueueAction action = new QueueAction();
        action.action = "hold";

        try {
            String output = executeCommand(POSTSUPER + " -h ALL");
            action.success = true;
            action.message = "All messages put on hold";
            action.output = output;

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Release all held messages
     */
    public QueueAction resumeQueue() {
        QueueAction action = new QueueAction();
        action.action = "release";

        try {
            String output = executeCommand(POSTSUPER + " -H ALL");
            action.success = true;
            action.message = "All held messages released";
            action.output = output;

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Get queue statistics
     */
    public QueueStats getStats() {
        QueueStats stats = new QueueStats();

        try {
            List<QueuedMessage> messages = getQueue();

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

                // Track senders
                if (msg.sender != null) {
                    stats.topSenders.merge(msg.sender, 1, Integer::sum);
                }

                // Track recipients/destinations
                if (msg.recipient != null) {
                    String domain = extractDomain(msg.recipient);
                    if (domain != null) {
                        stats.topDestinations.merge(domain, 1, Integer::sum);
                    }
                }

                // Track oldest message
                if (msg.created != null) {
                    if (stats.oldestMessage == null || msg.created.isBefore(stats.oldestMessage)) {
                        stats.oldestMessage = msg.created;
                    }
                }
            }

        } catch (Exception e) {
            stats.error = e.getMessage();
        }

        return stats;
    }

    /**
     * Delete all deferred messages
     */
    public QueueAction purgeDeferred() {
        QueueAction action = new QueueAction();
        action.action = "purge_deferred";

        try {
            String output = executeCommand(POSTSUPER + " -d ALL deferred");
            action.success = true;
            action.message = "All deferred messages removed";
            action.output = output;

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    // Utility methods

    private String extractDomain(String email) {
        if (email == null || !email.contains("@")) {
            return null;
        }
        return email.substring(email.lastIndexOf('@') + 1);
    }

    private LocalDateTime parseDateTime(String dateStr) {
        if (dateStr == null || dateStr.isEmpty()) {
            return null;
        }

        try {
            // Postfix format: Sun Dec 29 10:30:45
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern(
                "EEE MMM d HH:mm:ss", Locale.ENGLISH
            );
            // Add current year since Postfix doesn't include it
            int year = LocalDateTime.now().getYear();
            return LocalDateTime.parse(dateStr.trim(), formatter).withYear(year);

        } catch (Exception e) {
            // Try other formats
            try {
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern(
                    "EEE MMM dd HH:mm:ss yyyy", Locale.ENGLISH
                );
                return LocalDateTime.parse(dateStr.trim(), formatter);
            } catch (Exception e2) {
                // Ignore parse errors
            }
        }

        return null;
    }

    private String executeCommand(String command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }

        process.waitFor();
        return output.toString().trim();
    }

    // Data classes

    public static class QueuedMessage {
        public String messageId;
        public String envelopeId;
        public QueueState state = QueueState.UNKNOWN;
        public String sender;
        public String recipient;
        public long size;
        public LocalDateTime created;
        public LocalDateTime lastAttempt;
        public String errorReason;
        public String rawLine;
    }

    public static class MessageEnvelope {
        public String envelopeId;
        public boolean found;
        public String sender;
        public String recipient;
        public String destination;
        public LocalDateTime created;
        public LocalDateTime expires;
        public LocalDateTime lastRetry;
        public int retryCount;
        public String flags;
        public String status;
        public String errorLine;
        public String rawContent;
        public String error;
    }

    public static class MessageContent {
        public String messageId;
        public boolean found;
        public String headers;
        public String body;
        public String bodyPreview;
        public String fromHeader;
        public String toHeader;
        public String subject;
        public String dateHeader;
        public String messageIdHeader;
        public String rawContent;
        public String error;
    }

    public static class QueueAction {
        public String action;
        public String envelopeId;
        public boolean success;
        public String message;
        public String output;
    }

    public static class QueueStats {
        public int totalMessages;
        public long totalSize;
        public int active;
        public int deferred;
        public int hold;
        public int incoming;
        public int unknown;
        public boolean paused;
        public LocalDateTime oldestMessage;
        public Map<String, Integer> topSenders = new HashMap<>();
        public Map<String, Integer> topDestinations = new HashMap<>();
        public String error;
    }
}
