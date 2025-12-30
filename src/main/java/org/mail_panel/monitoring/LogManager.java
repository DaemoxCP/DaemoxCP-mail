package org.mail_panel.monitoring;

import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import java.util.stream.*;

/**
 * Log Manager for FreeBSD Mail Panel
 *
 * Handles reading, parsing, and streaming of mail server logs:
 * - Postfix: /var/log/maillog
 * - Dovecot: /var/log/dovecot.log, /var/log/dovecot-info.log
 * - Rspamd: /var/log/rspamd/rspamd.log
 * - ClamAV: /var/log/clamav/clamd.log
 *
 * Provides:
 * - Real-time log streaming (tail -f equivalent)
 * - Log parsing with structured data
 * - Statistics aggregation
 * - Search functionality
 */
public class LogManager {

    // Log file paths
    public static final String MAILLOG = "/var/log/maillog";
    public static final String DOVECOT_LOG = "/var/log/dovecot.log";
    public static final String DOVECOT_INFO_LOG = "/var/log/dovecot-info.log";
    public static final String RSPAMD_LOG = "/var/log/rspamd/rspamd.log";
    public static final String CLAMAV_LOG = "/var/log/clamav/clamd.log";

    // Log file registry
    private final Map<String, LogFile> logFiles;

    // Active tail processes
    private final Map<String, Process> tailProcesses;

    // Statistics cache
    private MailStats cachedStats;
    private LocalDateTime lastStatsUpdate;
    private static final int STATS_CACHE_SECONDS = 60;

    public LogManager() {
        this.logFiles = new LinkedHashMap<>();
        this.tailProcesses = new ConcurrentHashMap<>();

        // Register log files
        registerLogFile("maillog", MAILLOG, "Postfix/Sistema", LogType.SMTP);
        registerLogFile("dovecot", DOVECOT_LOG, "Dovecot IMAP/POP3", LogType.IMAP);
        registerLogFile("dovecot-info", DOVECOT_INFO_LOG, "Dovecot Info", LogType.IMAP);
        registerLogFile("rspamd", RSPAMD_LOG, "Rspamd Anti-Spam", LogType.ANTISPAM);
        registerLogFile("clamav", CLAMAV_LOG, "ClamAV Antivirus", LogType.ANTIVIRUS);
    }

    private void registerLogFile(String id, String path, String description, LogType type) {
        LogFile logFile = new LogFile();
        logFile.id = id;
        logFile.path = path;
        logFile.description = description;
        logFile.type = type;
        logFile.exists = Files.exists(Paths.get(path));
        logFiles.put(id, logFile);
    }

    /**
     * Get list of available log files
     */
    public List<LogFile> getAvailableLogFiles() {
        // Update existence status
        logFiles.values().forEach(lf -> lf.exists = Files.exists(Paths.get(lf.path)));
        return new ArrayList<>(logFiles.values());
    }

    /**
     * Read last N lines from a log file
     */
    public List<LogEntry> readLog(String logId, int lines, String filter) {
        LogFile logFile = logFiles.get(logId);
        if (logFile == null || !logFile.exists) {
            return Collections.emptyList();
        }

        try {
            // Use tail command for efficiency
            ProcessBuilder pb;
            if (filter != null && !filter.isEmpty()) {
                pb = new ProcessBuilder("/bin/sh", "-c",
                    String.format("tail -n %d '%s' | grep -i '%s'", lines * 2, logFile.path, filter.replace("'", "\\'")));
            } else {
                pb = new ProcessBuilder("tail", "-n", String.valueOf(lines), logFile.path);
            }

            pb.redirectErrorStream(true);
            Process process = pb.start();

            List<String> rawLines = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    rawLines.add(line);
                }
            }

            process.waitFor();

            // Parse lines based on log type
            return rawLines.stream()
                .map(line -> parseLogLine(line, logFile.type))
                .filter(Objects::nonNull)
                .limit(lines)
                .collect(Collectors.toList());

        } catch (Exception e) {
            System.err.println("Error reading log " + logId + ": " + e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Search logs with regex pattern
     */
    public List<LogEntry> searchLogs(String logId, String pattern, int maxResults, LocalDateTime from, LocalDateTime to) {
        LogFile logFile = logFiles.get(logId);
        if (logFile == null || !logFile.exists) {
            return Collections.emptyList();
        }

        try {
            // Use grep for efficient searching
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c",
                String.format("grep -E '%s' '%s' | tail -n %d",
                    pattern.replace("'", "'\\''"), logFile.path, maxResults));

            pb.redirectErrorStream(true);
            Process process = pb.start();

            List<LogEntry> results = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    LogEntry entry = parseLogLine(line, logFile.type);
                    if (entry != null) {
                        // Filter by time if specified
                        if ((from == null || entry.timestamp == null || !entry.timestamp.isBefore(from)) &&
                            (to == null || entry.timestamp == null || !entry.timestamp.isAfter(to))) {
                            results.add(entry);
                        }
                    }
                }
            }

            process.waitFor();
            return results;

        } catch (Exception e) {
            System.err.println("Error searching log: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Start real-time log streaming
     * Returns a reader that can be polled for new lines
     */
    public BufferedReader startLogStream(String logId) {
        LogFile logFile = logFiles.get(logId);
        if (logFile == null || !logFile.exists) {
            return null;
        }

        try {
            // Stop any existing stream for this log
            stopLogStream(logId);

            ProcessBuilder pb = new ProcessBuilder("tail", "-f", "-n", "0", logFile.path);
            Process process = pb.start();
            tailProcesses.put(logId, process);

            return new BufferedReader(new InputStreamReader(process.getInputStream()));

        } catch (Exception e) {
            System.err.println("Error starting log stream: " + e.getMessage());
            return null;
        }
    }

    /**
     * Stop log streaming
     */
    public void stopLogStream(String logId) {
        Process process = tailProcesses.remove(logId);
        if (process != null) {
            process.destroy();
        }
    }

    /**
     * Stop all log streams
     */
    public void stopAllStreams() {
        tailProcesses.values().forEach(Process::destroy);
        tailProcesses.clear();
    }

    /**
     * Parse a log line based on log type
     */
    public LogEntry parseLogLine(String line, LogType type) {
        if (line == null || line.isEmpty()) {
            return null;
        }

        LogEntry entry = new LogEntry();
        entry.raw = line;
        entry.logType = type;

        try {
            switch (type) {
                case SMTP -> parseSmtpLogLine(line, entry);
                case IMAP -> parseDovecotLogLine(line, entry);
                case ANTISPAM -> parseRspamdLogLine(line, entry);
                case ANTIVIRUS -> parseClamavLogLine(line, entry);
                default -> {
                    entry.message = line;
                    entry.level = LogLevel.INFO;
                }
            }
        } catch (Exception e) {
            entry.message = line;
            entry.level = LogLevel.INFO;
        }

        return entry;
    }

    /**
     * Parse Postfix/maillog line
     * Format: Dec 27 10:30:45 hostname postfix/smtpd[1234]: message
     */
    private void parseSmtpLogLine(String line, LogEntry entry) {
        // Pattern: timestamp hostname process[pid]: message
        Pattern pattern = Pattern.compile(
            "^(\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(\\S+)\\s+(\\S+)\\[(\\d+)\\]:\\s*(.*)$"
        );

        Matcher matcher = pattern.matcher(line);
        if (matcher.matches()) {
            entry.timestamp = parseMaillogTimestamp(matcher.group(1));
            entry.hostname = matcher.group(2);
            entry.process = matcher.group(3);
            entry.pid = matcher.group(4);
            entry.message = matcher.group(5);

            // Determine level and event type
            String msg = entry.message.toLowerCase();
            if (msg.contains("error") || msg.contains("failed") || msg.contains("reject")) {
                entry.level = LogLevel.ERROR;
            } else if (msg.contains("warn")) {
                entry.level = LogLevel.WARNING;
            } else {
                entry.level = LogLevel.INFO;
            }

            // Parse SMTP events (Postfix format)
            // Distinguish between outgoing (smtp) and local delivery (lmtp/local/virtual/dovecot)
            String proc = entry.process != null ? entry.process.toLowerCase() : "";
            if (msg.contains("status=sent")) {
                // Check if it's outgoing (smtp client) or local delivery
                if (proc.contains("smtp") && !proc.contains("smtpd")) {
                    // postfix/smtp or smtp = Outgoing mail to external server
                    entry.eventType = "sent";
                } else if (proc.contains("lmtp") || proc.contains("local") ||
                           proc.contains("virtual") || proc.contains("dovecot") ||
                           msg.contains("delivered to maildir") || msg.contains("saved to")) {
                    // Local delivery = incoming mail received
                    entry.eventType = "received";
                }
            } else if (msg.contains("status=deferred")) {
                entry.eventType = "deferred";
            } else if (msg.contains("status=bounced")) {
                entry.eventType = "bounced";
            } else if (msg.contains("reject") || msg.contains("rejected") || msg.contains("noqueue: reject")) {
                entry.eventType = "rejected";
            }

            // Extract email addresses
            Pattern emailPattern = Pattern.compile("from=<([^>]*)>");
            Matcher emailMatcher = emailPattern.matcher(entry.message);
            if (emailMatcher.find()) {
                entry.from = emailMatcher.group(1);
            }

            emailPattern = Pattern.compile("to=<([^>]*)>");
            emailMatcher = emailPattern.matcher(entry.message);
            if (emailMatcher.find()) {
                entry.to = emailMatcher.group(1);
            }

        } else {
            entry.message = line;
            entry.level = LogLevel.INFO;
        }
    }

    /**
     * Parse Dovecot log line
     * Format: 2024-12-27 10:30:45 service(user)<pid>: message
     */
    private void parseDovecotLogLine(String line, LogEntry entry) {
        Pattern pattern = Pattern.compile(
            "^(\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\w+)\\(([^)]+)\\)<(\\d+)>:\\s*(.*)$"
        );

        Matcher matcher = pattern.matcher(line);
        if (matcher.matches()) {
            try {
                entry.timestamp = LocalDateTime.parse(matcher.group(1),
                    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            } catch (Exception e) {
                // ignore
            }
            entry.process = matcher.group(2);
            entry.user = matcher.group(3);
            entry.pid = matcher.group(4);
            entry.message = matcher.group(5);

            String msg = entry.message.toLowerCase();
            if (msg.contains("error") || msg.contains("failed")) {
                entry.level = LogLevel.ERROR;
            } else if (msg.contains("warn")) {
                entry.level = LogLevel.WARNING;
            } else {
                entry.level = LogLevel.INFO;
            }

            // Event types
            if (msg.contains("login")) {
                entry.eventType = "login";
            } else if (msg.contains("logout") || msg.contains("disconnected")) {
                entry.eventType = "logout";
            } else if (msg.contains("auth failed")) {
                entry.eventType = "auth_failed";
                entry.level = LogLevel.WARNING;
            }

        } else {
            entry.message = line;
            entry.level = LogLevel.INFO;
        }
    }

    /**
     * Parse Rspamd log line
     */
    private void parseRspamdLogLine(String line, LogEntry entry) {
        // Rspamd uses JSON or custom format
        Pattern pattern = Pattern.compile(
            "^(\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+#\\d+\\s+(\\w+)\\s+(.*)$"
        );

        Matcher matcher = pattern.matcher(line);
        if (matcher.matches()) {
            try {
                entry.timestamp = LocalDateTime.parse(matcher.group(1),
                    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            } catch (Exception e) {
                // ignore
            }
            entry.process = "rspamd";
            String levelStr = matcher.group(2).toLowerCase();
            entry.level = switch (levelStr) {
                case "error" -> LogLevel.ERROR;
                case "warn", "warning" -> LogLevel.WARNING;
                case "debug" -> LogLevel.DEBUG;
                default -> LogLevel.INFO;
            };
            entry.message = matcher.group(3);

            // Parse spam detection
            String msg = entry.message.toLowerCase();
            if (msg.contains("spam")) {
                entry.eventType = "spam_detected";
            } else if (msg.contains("ham")) {
                entry.eventType = "ham";
            } else if (msg.contains("reject")) {
                entry.eventType = "rejected";
            }

            // Extract spam score
            Pattern scorePattern = Pattern.compile("score:\\s*(\\d+\\.?\\d*)");
            Matcher scoreMatcher = scorePattern.matcher(entry.message);
            if (scoreMatcher.find()) {
                entry.spamScore = Double.parseDouble(scoreMatcher.group(1));
            }

        } else {
            entry.message = line;
            entry.level = LogLevel.INFO;
        }
    }

    /**
     * Parse ClamAV log line
     */
    private void parseClamavLogLine(String line, LogEntry entry) {
        Pattern pattern = Pattern.compile(
            "^(\\w+\\s+\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+\\s+\\d{4})\\s+->\\s+(.*)$"
        );

        Matcher matcher = pattern.matcher(line);
        if (matcher.matches()) {
            entry.timestamp = parseFlexibleTimestamp(matcher.group(1));
            entry.process = "clamd";
            entry.message = matcher.group(2);

            String msg = entry.message.toLowerCase();
            if (msg.contains("virus") || msg.contains("found")) {
                entry.level = LogLevel.ERROR;
                entry.eventType = "virus_found";
            } else if (msg.contains("error")) {
                entry.level = LogLevel.ERROR;
            } else {
                entry.level = LogLevel.INFO;
            }

        } else {
            entry.message = line;
            entry.level = LogLevel.INFO;
        }
    }

    /**
     * Parse maillog timestamp (e.g., "Dec 27 10:30:45")
     */
    private LocalDateTime parseMaillogTimestamp(String timestamp) {
        try {
            // Add current year since maillog doesn't include it
            int year = LocalDateTime.now().getYear();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM dd HH:mm:ss yyyy", Locale.ENGLISH);
            return LocalDateTime.parse(timestamp + " " + year, formatter);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Parse flexible timestamp formats
     */
    private LocalDateTime parseFlexibleTimestamp(String timestamp) {
        String[] patterns = {
            "EEE MMM dd HH:mm:ss yyyy",
            "yyyy-MM-dd HH:mm:ss",
            "MMM dd HH:mm:ss yyyy"
        };

        for (String pattern : patterns) {
            try {
                return LocalDateTime.parse(timestamp, DateTimeFormatter.ofPattern(pattern, Locale.ENGLISH));
            } catch (Exception e) {
                // Try next pattern
            }
        }
        return null;
    }

    // ============== Statistics ==============

    /**
     * Get mail statistics
     */
    public MailStats getStats() {
        // Return cached if recent
        if (cachedStats != null && lastStatsUpdate != null &&
            Duration.between(lastStatsUpdate, LocalDateTime.now()).getSeconds() < STATS_CACHE_SECONDS) {
            return cachedStats;
        }

        MailStats stats = new MailStats();
        stats.generatedAt = LocalDateTime.now();
        stats.period = "last_24h";

        try {
            // Parse maillog for SMTP stats
            List<LogEntry> mailEntries = readLog("maillog", 10000, null);

            LocalDateTime yesterday = LocalDateTime.now().minusDays(1);

            for (LogEntry entry : mailEntries) {
                if (entry.timestamp != null && entry.timestamp.isBefore(yesterday)) {
                    continue;
                }

                switch (entry.eventType != null ? entry.eventType : "") {
                    case "received" -> stats.messagesReceived++;
                    case "sent" -> stats.messagesSent++;
                    case "rejected" -> stats.messagesRejected++;
                    case "bounced" -> stats.messagesBounced++;
                    case "deferred" -> stats.messagesDeferred++;
                }
            }

            // Parse Dovecot for IMAP stats
            List<LogEntry> imapEntries = readLog("dovecot", 5000, null);
            Set<String> uniqueUsers = new HashSet<>();

            for (LogEntry entry : imapEntries) {
                if (entry.timestamp != null && entry.timestamp.isBefore(yesterday)) {
                    continue;
                }

                if ("login".equals(entry.eventType)) {
                    stats.imapLogins++;
                    if (entry.user != null) {
                        uniqueUsers.add(entry.user);
                    }
                } else if ("auth_failed".equals(entry.eventType)) {
                    stats.authFailures++;
                }
            }
            stats.activeUsers = uniqueUsers.size();

            // Parse Rspamd for spam stats
            List<LogEntry> spamEntries = readLog("rspamd", 5000, null);
            for (LogEntry entry : spamEntries) {
                if (entry.timestamp != null && entry.timestamp.isBefore(yesterday)) {
                    continue;
                }

                if ("spam_detected".equals(entry.eventType)) {
                    stats.spamDetected++;
                }
            }

            // Parse ClamAV for virus stats
            List<LogEntry> virusEntries = readLog("clamav", 1000, null);
            for (LogEntry entry : virusEntries) {
                if ("virus_found".equals(entry.eventType)) {
                    stats.virusesFound++;
                }
            }

            // Calculate totals
            stats.totalMessages = stats.messagesReceived + stats.messagesSent;
            if (stats.totalMessages > 0) {
                stats.spamPercentage = (stats.spamDetected * 100.0) / stats.messagesReceived;
                stats.rejectionRate = (stats.messagesRejected * 100.0) / (stats.messagesReceived + stats.messagesRejected);
            }

        } catch (Exception e) {
            System.err.println("Error calculating stats: " + e.getMessage());
        }

        cachedStats = stats;
        lastStatsUpdate = LocalDateTime.now();

        return stats;
    }

    /**
     * Get hourly message distribution (for charts)
     */
    public Map<Integer, Integer> getHourlyDistribution() {
        Map<Integer, Integer> distribution = new LinkedHashMap<>();
        for (int i = 0; i < 24; i++) {
            distribution.put(i, 0);
        }

        try {
            List<LogEntry> entries = readLog("maillog", 5000, null);
            LocalDateTime yesterday = LocalDateTime.now().minusDays(1);

            for (LogEntry entry : entries) {
                if (entry.timestamp != null && entry.timestamp.isAfter(yesterday)) {
                    if ("received".equals(entry.eventType) || "sent".equals(entry.eventType)) {
                        int hour = entry.timestamp.getHour();
                        distribution.merge(hour, 1, Integer::sum);
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("Error calculating hourly distribution: " + e.getMessage());
        }

        return distribution;
    }

    // ============== Model Classes ==============

    public enum LogType {
        SMTP, IMAP, ANTISPAM, ANTIVIRUS, SYSTEM
    }

    public enum LogLevel {
        DEBUG, INFO, WARNING, ERROR
    }

    public static class LogFile {
        public String id;
        public String path;
        public String description;
        public LogType type;
        public boolean exists;
    }

    public static class LogEntry {
        public String raw;
        public LocalDateTime timestamp;
        public LogLevel level;
        public LogType logType;
        public String hostname;
        public String process;
        public String pid;
        public String user;
        public String message;
        public String eventType;  // received, sent, rejected, login, spam_detected, etc.
        public String from;
        public String to;
        public String messageId;
        public Double spamScore;
    }

    public static class MailStats {
        public LocalDateTime generatedAt;
        public String period;

        // SMTP stats
        public int messagesReceived;
        public int messagesSent;
        public int messagesRejected;
        public int messagesBounced;
        public int messagesDeferred;
        public int totalMessages;

        // IMAP stats
        public int imapLogins;
        public int activeUsers;
        public int authFailures;

        // Security stats
        public int spamDetected;
        public int virusesFound;
        public double spamPercentage;
        public double rejectionRate;
    }
}
