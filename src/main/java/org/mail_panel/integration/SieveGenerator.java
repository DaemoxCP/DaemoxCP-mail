package org.mail_panel.integration;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.database.MailDatabase;

import java.io.*;
import java.nio.file.*;
import java.util.List;

/**
 * Sieve Script Generator
 * Converts database filter rules to Sieve scripts for Dovecot
 */
public class SieveGenerator {

    private static final String SIEVE_DIR = "/var/mail/sieve";
    private static final String GLOBAL_SIEVE = "/usr/local/etc/dovecot/sieve/global.sieve";

    /**
     * Generate Sieve script for a mailbox
     */
    public String generateSieveScript(int mailboxId, MailDatabase database) {
        StringBuilder script = new StringBuilder();

        // Sieve requires capabilities
        script.append("require [\"fileinto\", \"reject\", \"vacation\", \"copy\", \"imap4flags\", \"regex\", \"relational\", \"comparator-i;ascii-numeric\"];\n\n");

        // Get auto-responder
        MailDatabase.AutoResponder autoResponder = database.getAutoResponder(mailboxId);
        if (autoResponder != null && autoResponder.enabled) {
            script.append(generateVacationRule(autoResponder));
        }

        // Get forwarding rules
        List<MailDatabase.ForwardingRule> forwardingRules = database.getForwardingRules(mailboxId);
        for (MailDatabase.ForwardingRule rule : forwardingRules) {
            if (rule.enabled) {
                script.append(generateForwardingRule(rule));
            }
        }

        // Get custom filters
        List<MailDatabase.SieveFilter> filters = database.getSieveFilters(mailboxId);
        for (MailDatabase.SieveFilter filter : filters) {
            if (filter.enabled) {
                script.append(generateFilterRule(filter));
            }
        }

        // Default: keep in inbox
        script.append("\n# Default action\nkeep;\n");

        return script.toString();
    }

    /**
     * Generate vacation auto-responder rule
     */
    private String generateVacationRule(MailDatabase.AutoResponder ar) {
        StringBuilder rule = new StringBuilder();
        rule.append("# Auto-responder / Vacation\n");

        // Date conditions if set
        if (ar.startDate != null || ar.endDate != null) {
            rule.append("if allof (\n");
            if (ar.startDate != null) {
                rule.append("  currentdate :value \"ge\" \"date\" \"").append(ar.startDate).append("\",\n");
            }
            if (ar.endDate != null) {
                rule.append("  currentdate :value \"le\" \"date\" \"").append(ar.endDate).append("\"");
            }
            rule.append("\n) {\n");
        }

        rule.append("  vacation :days ").append(ar.intervalHours / 24).append("\n");
        rule.append("    :subject \"").append(escapeString(ar.subject)).append("\"\n");
        rule.append("    \"").append(escapeString(ar.body)).append("\";\n");

        if (ar.startDate != null || ar.endDate != null) {
            rule.append("}\n");
        }

        rule.append("\n");
        return rule.toString();
    }

    /**
     * Generate forwarding rule
     */
    private String generateForwardingRule(MailDatabase.ForwardingRule rule) {
        StringBuilder sieve = new StringBuilder();
        sieve.append("# Forwarding to ").append(rule.destination).append("\n");

        if (rule.keepCopy) {
            sieve.append("redirect :copy \"").append(escapeString(rule.destination)).append("\";\n");
        } else {
            sieve.append("redirect \"").append(escapeString(rule.destination)).append("\";\n");
        }

        sieve.append("\n");
        return sieve.toString();
    }

    /**
     * Generate custom filter rule from JSON conditions/actions
     */
    private String generateFilterRule(MailDatabase.SieveFilter filter) {
        StringBuilder rule = new StringBuilder();
        rule.append("# Filter: ").append(filter.name).append("\n");

        try {
            JSONArray conditions = new JSONArray(filter.conditions);
            JSONArray actions = new JSONArray(filter.actions);

            // Build condition
            if (conditions.length() > 0) {
                rule.append("if ");

                if (conditions.length() > 1) {
                    rule.append("allof (\n");
                }

                for (int i = 0; i < conditions.length(); i++) {
                    JSONObject cond = conditions.getJSONObject(i);
                    String condStr = buildCondition(cond);

                    if (conditions.length() > 1) {
                        rule.append("  ").append(condStr);
                        if (i < conditions.length() - 1) {
                            rule.append(",\n");
                        }
                    } else {
                        rule.append(condStr);
                    }
                }

                if (conditions.length() > 1) {
                    rule.append("\n)");
                }

                rule.append(" {\n");

                // Build actions
                for (int i = 0; i < actions.length(); i++) {
                    JSONObject action = actions.getJSONObject(i);
                    rule.append("  ").append(buildAction(action)).append("\n");
                }

                rule.append("}\n");
            }
        } catch (Exception e) {
            rule.append("# Error parsing filter: ").append(e.getMessage()).append("\n");
        }

        rule.append("\n");
        return rule.toString();
    }

    /**
     * Build a single condition from JSON
     */
    private String buildCondition(JSONObject cond) {
        String field = cond.optString("field", "subject");
        String operator = cond.optString("operator", "contains");
        String value = cond.optString("value", "");

        String sieveField = switch (field.toLowerCase()) {
            case "from" -> "From";
            case "to" -> "To";
            case "cc" -> "Cc";
            case "subject" -> "Subject";
            case "body" -> ":text";
            case "size" -> ":size";
            default -> field;
        };

        String sieveOp = switch (operator.toLowerCase()) {
            case "contains" -> ":contains";
            case "is" -> ":is";
            case "matches" -> ":matches";
            case "regex" -> ":regex";
            case "not_contains" -> ":contains"; // Will negate
            case "greater" -> ":value \"gt\"";
            case "less" -> ":value \"lt\"";
            default -> ":contains";
        };

        boolean negate = operator.toLowerCase().startsWith("not_");

        StringBuilder result = new StringBuilder();
        if (negate) {
            result.append("not ");
        }

        if (field.equals("size")) {
            // Size comparison
            result.append("size ").append(sieveOp).append(" ").append(value);
        } else if (field.equals("body")) {
            // Body comparison
            result.append("body ").append(sieveOp).append(" \"").append(escapeString(value)).append("\"");
        } else {
            // Header comparison
            result.append("header ").append(sieveOp).append(" \"").append(sieveField).append("\" \"").append(escapeString(value)).append("\"");
        }

        return result.toString();
    }

    /**
     * Build a single action from JSON
     */
    private String buildAction(JSONObject action) {
        String type = action.optString("type", "keep");
        String value = action.optString("value", "");

        return switch (type.toLowerCase()) {
            case "move", "fileinto" -> "fileinto \"" + escapeString(value) + "\";";
            case "copy" -> "fileinto :copy \"" + escapeString(value) + "\";";
            case "delete", "discard" -> "discard;";
            case "reject" -> "reject \"" + escapeString(value) + "\";";
            case "forward", "redirect" -> "redirect \"" + escapeString(value) + "\";";
            case "flag" -> "addflag \"" + escapeString(value) + "\";";
            case "mark_read" -> "addflag \"\\\\Seen\";";
            case "mark_important" -> "addflag \"\\\\Flagged\";";
            case "stop" -> "stop;";
            default -> "keep;";
        };
    }

    /**
     * Escape string for Sieve
     */
    private String escapeString(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    /**
     * Save Sieve script for a mailbox
     */
    public boolean saveSieveScript(String email, String script) {
        try {
            // Create user sieve directory
            String[] parts = email.split("@");
            if (parts.length != 2) return false;

            String user = parts[0];
            String domain = parts[1];

            Path userDir = Path.of(SIEVE_DIR, domain, user);
            Files.createDirectories(userDir);

            Path sieveFile = userDir.resolve(".dovecot.sieve");
            Files.writeString(sieveFile, script);

            // Compile the script
            compileScript(sieveFile.toString());

            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Compile a Sieve script using sievec
     */
    public boolean compileScript(String scriptPath) {
        try {
            ProcessBuilder pb = new ProcessBuilder("sievec", scriptPath);
            Process p = pb.start();
            return p.waitFor() == 0;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Validate a Sieve script
     */
    public static class ValidationResult {
        public boolean valid;
        public String error;
        public int errorLine;

        public ValidationResult(boolean valid, String error) {
            this.valid = valid;
            this.error = error;
        }
    }

    public ValidationResult validateScript(String script) {
        try {
            // Write to temp file
            Path tempFile = Files.createTempFile("sieve_validate_", ".sieve");
            Files.writeString(tempFile, script);

            // Run sievec to validate
            ProcessBuilder pb = new ProcessBuilder("sievec", "-d", tempFile.toString());
            pb.redirectErrorStream(true);
            Process p = pb.start();

            String output = new String(p.getInputStream().readAllBytes());
            int exitCode = p.waitFor();

            Files.delete(tempFile);

            if (exitCode == 0) {
                return new ValidationResult(true, null);
            } else {
                // Parse error line
                ValidationResult result = new ValidationResult(false, output.trim());
                // Try to extract line number from error
                if (output.contains("line ")) {
                    try {
                        int idx = output.indexOf("line ") + 5;
                        int end = output.indexOf(":", idx);
                        if (end > idx) {
                            result.errorLine = Integer.parseInt(output.substring(idx, end));
                        }
                    } catch (NumberFormatException ignored) {}
                }
                return result;
            }
        } catch (Exception e) {
            return new ValidationResult(false, "Validation error: " + e.getMessage());
        }
    }

    /**
     * Get raw Sieve script for a mailbox
     */
    public String getSieveScript(String email) {
        try {
            String[] parts = email.split("@");
            if (parts.length != 2) return null;

            Path sieveFile = Path.of(SIEVE_DIR, parts[1], parts[0], ".dovecot.sieve");
            if (Files.exists(sieveFile)) {
                return Files.readString(sieveFile);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Create example filter conditions/actions for UI
     */
    public static String getExampleConditions() {
        JSONArray conditions = new JSONArray();

        JSONObject cond = new JSONObject();
        cond.put("field", "from");
        cond.put("operator", "contains");
        cond.put("value", "@example.com");
        conditions.put(cond);

        return conditions.toString();
    }

    public static String getExampleActions() {
        JSONArray actions = new JSONArray();

        JSONObject action = new JSONObject();
        action.put("type", "move");
        action.put("value", "INBOX.Work");
        actions.put(action);

        return actions.toString();
    }
}
