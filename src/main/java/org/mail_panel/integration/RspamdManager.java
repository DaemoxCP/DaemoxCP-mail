package org.mail_panel.integration;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Rspamd Integration Manager
 * Handles spam/ham training, statistics, and quarantine management
 */
public class RspamdManager {

    private static final String RSPAMD_HOST = "http://127.0.0.1:11334";
    private static final String RSPAMD_PASSWORD = ""; // Set if password is configured

    // ========== TRAINING ==========

    public static class TrainingResult {
        public boolean success;
        public String message;
        public int learned;

        public TrainingResult(boolean success, String message) {
            this.success = success;
            this.message = message;
            this.learned = 0;
        }
    }

    /**
     * Train Rspamd with a message as spam
     */
    public TrainingResult trainSpam(String messageContent) {
        return train(messageContent, "learnspam");
    }

    /**
     * Train Rspamd with a message as ham (not spam)
     */
    public TrainingResult trainHam(String messageContent) {
        return train(messageContent, "learnham");
    }

    /**
     * Train Rspamd with a message file
     */
    public TrainingResult trainSpamFromFile(String filePath) {
        try {
            String content = Files.readString(Path.of(filePath));
            return trainSpam(content);
        } catch (IOException e) {
            return new TrainingResult(false, "Cannot read file: " + e.getMessage());
        }
    }

    public TrainingResult trainHamFromFile(String filePath) {
        try {
            String content = Files.readString(Path.of(filePath));
            return trainHam(content);
        } catch (IOException e) {
            return new TrainingResult(false, "Cannot read file: " + e.getMessage());
        }
    }

    private TrainingResult train(String messageContent, String endpoint) {
        try {
            URL url = new URL(RSPAMD_HOST + "/" + endpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "message/rfc822");

            if (!RSPAMD_PASSWORD.isEmpty()) {
                conn.setRequestProperty("Password", RSPAMD_PASSWORD);
            }

            try (OutputStream os = conn.getOutputStream()) {
                os.write(messageContent.getBytes(StandardCharsets.UTF_8));
            }

            int responseCode = conn.getResponseCode();

            if (responseCode == 200) {
                String response = readResponse(conn.getInputStream());
                JSONObject json = new JSONObject(response);
                TrainingResult result = new TrainingResult(true, "Trained successfully");
                result.learned = json.optInt("success", 1);
                return result;
            } else {
                String error = readResponse(conn.getErrorStream());
                return new TrainingResult(false, "Training failed: " + error);
            }

        } catch (Exception e) {
            return new TrainingResult(false, "Error: " + e.getMessage());
        }
    }

    // ========== STATISTICS ==========

    public static class RspamdStats {
        public long scanned;
        public long learned;
        public long spamCount;
        public long hamCount;
        public double spamPercent;
        public long uptime;
        public String version;
    }

    /**
     * Get Rspamd statistics
     */
    public RspamdStats getStatistics() {
        try {
            URL url = new URL(RSPAMD_HOST + "/stat");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            if (!RSPAMD_PASSWORD.isEmpty()) {
                conn.setRequestProperty("Password", RSPAMD_PASSWORD);
            }

            if (conn.getResponseCode() == 200) {
                String response = readResponse(conn.getInputStream());
                JSONObject json = new JSONObject(response);

                RspamdStats stats = new RspamdStats();
                stats.scanned = json.optLong("scanned", 0);
                stats.learned = json.optLong("learned", 0);

                JSONArray actions = json.optJSONArray("actions");
                if (actions != null) {
                    for (int i = 0; i < actions.length(); i++) {
                        JSONObject action = actions.getJSONObject(i);
                        String name = action.optString("action", "");
                        long count = action.optLong("count", 0);

                        if (name.equals("reject") || name.equals("add header") || name.equals("rewrite subject")) {
                            stats.spamCount += count;
                        } else if (name.equals("no action")) {
                            stats.hamCount += count;
                        }
                    }
                }

                if (stats.scanned > 0) {
                    stats.spamPercent = (stats.spamCount * 100.0) / stats.scanned;
                }

                stats.uptime = json.optLong("uptime", 0);
                stats.version = json.optString("version", "unknown");

                return stats;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ========== FUZZY HASHES ==========

    /**
     * Add a message to fuzzy hash storage (for spam patterns)
     */
    public TrainingResult addFuzzySpam(String messageContent, int weight) {
        return fuzzyAction(messageContent, "fuzzyadd", weight, 1); // flag 1 = spam
    }

    /**
     * Delete a message from fuzzy hash storage
     */
    public TrainingResult deleteFuzzy(String messageContent) {
        return fuzzyAction(messageContent, "fuzzydel", 0, 1);
    }

    private TrainingResult fuzzyAction(String messageContent, String endpoint, int weight, int flag) {
        try {
            URL url = new URL(RSPAMD_HOST + "/" + endpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "message/rfc822");
            conn.setRequestProperty("Flag", String.valueOf(flag));
            conn.setRequestProperty("Weight", String.valueOf(weight));

            if (!RSPAMD_PASSWORD.isEmpty()) {
                conn.setRequestProperty("Password", RSPAMD_PASSWORD);
            }

            try (OutputStream os = conn.getOutputStream()) {
                os.write(messageContent.getBytes(StandardCharsets.UTF_8));
            }

            int responseCode = conn.getResponseCode();

            if (responseCode == 200) {
                return new TrainingResult(true, "Fuzzy hash updated");
            } else {
                String error = readResponse(conn.getErrorStream());
                return new TrainingResult(false, "Fuzzy action failed: " + error);
            }

        } catch (Exception e) {
            return new TrainingResult(false, "Error: " + e.getMessage());
        }
    }

    // ========== SCAN MESSAGE ==========

    public static class ScanResult {
        public boolean isSpam;
        public double score;
        public double requiredScore;
        public String action;
        public List<String> symbols;

        public ScanResult() {
            symbols = new ArrayList<>();
        }
    }

    /**
     * Scan a message and get spam score
     */
    public ScanResult scanMessage(String messageContent) {
        try {
            URL url = new URL(RSPAMD_HOST + "/checkv2");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "message/rfc822");

            if (!RSPAMD_PASSWORD.isEmpty()) {
                conn.setRequestProperty("Password", RSPAMD_PASSWORD);
            }

            try (OutputStream os = conn.getOutputStream()) {
                os.write(messageContent.getBytes(StandardCharsets.UTF_8));
            }

            if (conn.getResponseCode() == 200) {
                String response = readResponse(conn.getInputStream());
                JSONObject json = new JSONObject(response);

                ScanResult result = new ScanResult();
                result.score = json.optDouble("score", 0);
                result.requiredScore = json.optDouble("required_score", 15);
                result.action = json.optString("action", "no action");
                result.isSpam = result.action.equals("reject") ||
                               result.action.equals("add header") ||
                               result.action.equals("rewrite subject");

                JSONObject symbols = json.optJSONObject("symbols");
                if (symbols != null) {
                    for (String key : symbols.keySet()) {
                        JSONObject sym = symbols.getJSONObject(key);
                        double symScore = sym.optDouble("score", 0);
                        result.symbols.add(String.format("%s (%.2f)", key, symScore));
                    }
                }

                return result;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ========== QUARANTINE ==========

    public static class QuarantinedMessage {
        public String id;
        public String from;
        public String to;
        public String subject;
        public double score;
        public long timestamp;
        public String filePath;
    }

    /**
     * Get quarantined messages from Rspamd quarantine directory
     */
    public List<QuarantinedMessage> getQuarantinedMessages(int limit) {
        List<QuarantinedMessage> messages = new ArrayList<>();

        // Common quarantine locations
        String[] quarantineDirs = {
            "/var/db/rspamd/quarantine",
            "/var/spool/rspamd/quarantine",
            "/var/mail/quarantine"
        };

        for (String dirPath : quarantineDirs) {
            Path dir = Path.of(dirPath);
            if (Files.exists(dir) && Files.isDirectory(dir)) {
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
                    int count = 0;
                    for (Path file : stream) {
                        if (count >= limit) break;

                        if (Files.isRegularFile(file)) {
                            QuarantinedMessage msg = parseQuarantinedMessage(file);
                            if (msg != null) {
                                messages.add(msg);
                                count++;
                            }
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
                break;
            }
        }

        return messages;
    }

    private QuarantinedMessage parseQuarantinedMessage(Path file) {
        try {
            QuarantinedMessage msg = new QuarantinedMessage();
            msg.id = file.getFileName().toString();
            msg.filePath = file.toString();
            msg.timestamp = Files.getLastModifiedTime(file).toMillis();

            // Read first lines to extract headers
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            for (String line : lines) {
                if (line.isEmpty()) break; // End of headers

                if (line.toLowerCase().startsWith("from:")) {
                    msg.from = line.substring(5).trim();
                } else if (line.toLowerCase().startsWith("to:")) {
                    msg.to = line.substring(3).trim();
                } else if (line.toLowerCase().startsWith("subject:")) {
                    msg.subject = line.substring(8).trim();
                } else if (line.toLowerCase().startsWith("x-spam-score:")) {
                    try {
                        msg.score = Double.parseDouble(line.substring(13).trim());
                    } catch (NumberFormatException ignored) {}
                }
            }

            return msg;
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Release a message from quarantine (deliver it)
     */
    public boolean releaseFromQuarantine(String messageId) {
        // This would typically involve:
        // 1. Reading the quarantined message
        // 2. Reinjecting it into the mail queue
        // 3. Deleting from quarantine

        // For now, we just delete from quarantine as "released"
        return deleteFromQuarantine(messageId);
    }

    /**
     * Delete a message from quarantine
     */
    public boolean deleteFromQuarantine(String messageId) {
        String[] quarantineDirs = {
            "/var/db/rspamd/quarantine",
            "/var/spool/rspamd/quarantine",
            "/var/mail/quarantine"
        };

        for (String dirPath : quarantineDirs) {
            Path file = Path.of(dirPath, messageId);
            if (Files.exists(file)) {
                try {
                    Files.delete(file);
                    return true;
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return false;
    }

    // ========== UTILITIES ==========

    /**
     * Check if Rspamd is running
     */
    public boolean isRunning() {
        try {
            URL url = new URL(RSPAMD_HOST + "/ping");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2000);
            return conn.getResponseCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Reload Rspamd configuration
     */
    public boolean reloadConfig() {
        try {
            ProcessBuilder pb = new ProcessBuilder("service", "rspamd", "reload");
            Process p = pb.start();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private String readResponse(InputStream is) throws IOException {
        if (is == null) return "";
        BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        return response.toString();
    }
}
