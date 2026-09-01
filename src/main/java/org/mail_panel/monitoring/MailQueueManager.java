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

    /**
     * Un messaggio in coda ha fallito in modo PERMANENTE.
     *
     * Il criterio non e' "e' in coda da tanto": e' il codice di risposta. SMTP distingue il
     * 4xx (riprova piu' tardi) dal 5xx (non riprovarci), e i secondi in coda non si
     * risolveranno mai da soli. Si riconoscono dal codice di stato esteso 5.x.x (RFC 3463)
     * oppure dal codice a tre cifre che comincia per 5 riportato nel messaggio d'errore.
     *
     * Il confronto NON e' su sottostringa: cercare "5." dentro il testo troverebbe anche una
     * dimensione "1.5.", un orario o un indirizzo IP, e si cancellerebbe posta buona.
     */
    public static boolean fallimentoPermanente(String errore) {
        if (errore == null || errore.isBlank()) return false;
        // 1. codice di stato esteso 5.x.y (RFC 3463), isolato: "10.5.0.1" non deve contare
        if (java.util.regex.Pattern.compile("(?<![0-9.])5\\.[0-9]{1,3}\\.[0-9]{1,3}(?![0-9.])")
                .matcher(errore).find()) return true;
        // 2. codice di risposta a tre cifre, ma SOLO dove un codice puo' stare davvero:
        //    dopo "said:" o all'inizio della riga. Accettarlo ovunque farebbe scambiare
        //    "size=550" per un rifiuto definitivo, e si cancellerebbe un messaggio buono.
        return java.util.regex.Pattern
                .compile("(?:said:\\s*|^\\s*)5[0-9]{2}(?![0-9])", java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(errore).find();
    }

    /** I messaggi in coda che hanno fallito in modo permanente. Legge e basta. */
    public List<QueuedMessage> permanentFailures() {
        List<QueuedMessage> fuori = new java.util.ArrayList<>();
        for (QueuedMessage m : getQueue())
            if (fallimentoPermanente(m.errorReason)) fuori.add(m);
        return fuori;
    }

    /**
     * Cancella i soli messaggi con errore permanente, uno per uno.
     *
     * Non si usa "postsuper -d ALL deferred" come fa purgeDeferred: quello cancella TUTTA la
     * coda differita, compresi i messaggi con errore temporaneo che sarebbero stati
     * consegnati al prossimo tentativo. Qui si cancella solo cio' che non partira' mai.
     */
    public QueueAction purgePermanentFailures() {
        QueueAction action = new QueueAction();
        action.action = "purge_permfails";
        try {
            List<QueuedMessage> da = permanentFailures();
            if (da.isEmpty()) {
                action.success = true;
                action.message = "Nessun messaggio con errore permanente: non c'e' niente da eliminare.";
                return action;
            }
            StringBuilder log = new StringBuilder();
            int fatti = 0, falliti = 0;
            for (QueuedMessage m : da) {
                String id = m.envelopeId != null ? m.envelopeId : m.messageId;
                // L'identificativo di coda e' alfanumerico: si controlla prima di passarlo a
                // un comando, invece di fidarsi di come e' stato letto.
                if (id == null || !id.matches("[A-Za-z0-9]{1,32}")) {
                    falliti++;
                    log.append("saltato (identificativo inatteso): ").append(id).append("\n");
                    continue;
                }
                try {
                    log.append(executeCommand(POSTSUPER + " -d " + id)).append("\n");
                    fatti++;
                } catch (Exception e) {
                    falliti++;
                    log.append("errore su ").append(id).append(": ").append(e.getMessage()).append("\n");
                }
            }
            action.success = falliti == 0;
            action.message = fatti + " messaggi con errore permanente eliminati"
                    + (falliti > 0 ? ", " + falliti + " non eliminati (vedi output)" : "")
                    + ". La coda differita con errori temporanei non e' stata toccata.";
            action.output = log.toString();
        } catch (Exception e) {
            action.success = false;
            action.message = "Errore: " + e.getMessage();
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
        // TODO: migrate to Shell.run when touched
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
        org.mail_panel.util.Shell.applicaPath(pb);
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
