package org.daemoxcp.mail.integration;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.database.MailDatabase;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.logging.Logger;

/**
 * Sieve Script Generator
 * Converts database filter rules to Sieve scripts for Dovecot
 */
public class SieveGenerator {

    private static final Logger LOGGER = Logger.getLogger(SieveGenerator.class.getName());

    private static final String SIEVE_DIR = "/var/mail/sieve";
    /** The panel's rules file in every domain/name folder: Dovecot runs it before those of the mailbox. */
    private static final String SCRIPT = ".dovecot.sieve";
    private static final String GLOBAL_SIEVE = "/usr/local/etc/dovecot/sieve/global.sieve";

    /**
     * The first line of every panel script (date is needed by currentdate, in the auto-reply; mailbox by
     * fileinto :create, finding 229). Pigeonhole has mailbox among the extensions enabled by default, on
     * 2.3 (sieve_extensions adds with +) as on 2.4.
     */
    public static final String REQUIRE = "require [\"fileinto\", \"reject\", \"vacation\", \"copy\", \"imap4flags\", \"regex\", \"relational\", \"comparator-i;ascii-numeric\", \"date\", \"mailbox\"];\n\n";

    /**
     * The require line the panel wrote before adding mailbox (up to finding 229): SieveForcedKeep and
     * SieveRulesRefresh recognise it, to know that a script belongs to the panel.
     */
    public static final String REQUIRE_BEFORE_MAILBOX = REQUIRE.replace(", \"mailbox\"];", "];");

    /**
     * The tail the panel put at the end of every script until 2026-11-09: an explicit keep. SieveForcedKeep
     * removes it at boot from the scripts already written.
     */
    public static final String OLD_FORCED_KEEP = "\n# Default action\nkeep;\n";

    /**
     * Generate Sieve script for a mailbox
     *
     * No keep at the end. The implicit keep (RFC 5228, 2.10.2) already puts the message in the INBOX when no
     * rule removes it; an explicit keep at the end put it in the INBOX ALWAYS, so "Move" left the message in
     * the folder and in the INBOX, "Forward" without a copy kept one and "Delete" deleted nothing (measured on the
     * VM on 2026-11-09: after a fileinto "Junk", doveadm search gave INBOX 1, Junk 1). The actions that also leave
     * the message in the INBOX say so themselves: fileinto :copy, redirect :copy (RFC 3894).
     *
     * The script runs as a "before" script (sieve_before in 2.3, type = before in 2.4, finding 214). In
     * Pigeonhole's documentation (2.3, "Executing Multiple Scripts Sequentially"): the next script, the mailbox's
     * one, runs only if a keep is in effect, implicit or explicit; and the INBOX is written only by the keep of the
     * last script. So without the forced keep: if the panel's rules keep the message, the mailbox's script runs and
     * decides for itself; if they move it, forward it without a copy or delete it, the mailbox's script does not
     * run on that message.
     */
    public String generateSieveScript(int mailboxId, MailDatabase database) {
        StringBuilder script = new StringBuilder();

        // Sieve requires capabilities (date extension needed for currentdate)
        script.append(REQUIRE);

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

        // No keep at the end: the implicit keep keeps the message in the INBOX if no rule above removes it
        // (see above). A script without rules is just the require, and Sieve accepts it.
        return script.toString();
    }

    /**
     * Generate vacation auto-responder rule
     */
    private String generateVacationRule(MailDatabase.AutoResponder ar) {
        StringBuilder rule = new StringBuilder();
        rule.append("# Auto-responder / Vacation\n");

        // Date conditions if set
        boolean hasStartDate = ar.startDate != null;
        boolean hasEndDate = ar.endDate != null;

        if (hasStartDate || hasEndDate) {
            if (hasStartDate && hasEndDate) {
                // Both dates - use allof
                rule.append("if allof (\n");
                rule.append("  currentdate :value \"ge\" \"date\" \"").append(ar.startDate).append("\",\n");
                rule.append("  currentdate :value \"le\" \"date\" \"").append(ar.endDate).append("\"\n");
                rule.append(") {\n");
            } else if (hasStartDate) {
                // Only start date
                rule.append("if currentdate :value \"ge\" \"date\" \"").append(ar.startDate).append("\" {\n");
            } else {
                // Only end date
                rule.append("if currentdate :value \"le\" \"date\" \"").append(ar.endDate).append("\" {\n");
            }
        }

        // Ensure :days is at least 1
        int days = ar.intervalHours / 24;
        if (days < 1) days = 1;

        rule.append("  vacation :days ").append(days).append("\n");
        rule.append("    :subject \"").append(escapeString(ar.subject)).append("\"\n");
        rule.append("    \"").append(escapeString(ar.body)).append("\";\n");

        if (hasStartDate || hasEndDate) {
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
            // :create (RFC 5490, mailbox extension): the folder that does not exist is created. Without it, a "Move"
            // filter to a new folder moved nothing: Dovecot answered "Mailbox doesn't exist" and the message stayed
            // in the INBOX (measured on the VM and seen on the production server, finding 229). The folder proposed by
            // the filters window, INBOX.Filtered, does not exist at first either.
            case "move", "fileinto" -> "fileinto :create \"" + escapeString(value) + "\";";
            case "copy" -> "fileinto :copy :create \"" + escapeString(value) + "\";";
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
     * Note: Sieve quoted strings can contain real newlines, don't escape them
     */
    private String escapeString(String s) {
        if (s == null) return "";
        // Convert literal \n text to actual newlines (in case stored that way)
        s = s.replace("\\n", "\n");
        // Remove carriage returns, escape quotes
        return s.replace("\r", "")
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }

    /**
     * Save Sieve script for a mailbox
     *
     * As root, without following links and only in folders that nobody else can change (RootOnlyPath, finding 221):
     * before, Files.writeString followed a .dovecot.sieve that was a link, and root rewrote the file it pointed to
     * (measured on the VM with a file owned by nobody, 0600). The script belongs to root, rw-r--r--: Dovecot, which
     * delivers as vmail, reads it and cannot change it. False, with the reason in the log, if a folder from / to the
     * mailbox does not pass.
     */
    public boolean saveSieveScript(String email, String script) {
        try {
            // Create user sieve directory
            // The address comes from MySQL, which with the separated panel the web part also writes, and root turns
            // it into a path: it must have the form of an address, and the file must stay under SIEVE_DIR. Before, a
            // mailbox like ../x made root write a file outside its folder.
            if (!org.daemoxcp.mail.security.SafeNames.address(email)) return false;
            String[] parts = email.split("@");

            String user = parts[0];
            String domain = parts[1];

            Path rules = Path.of(SIEVE_DIR);
            org.daemoxcp.mail.security.SafeNames.under(rules, domain, user);
            Path userDir = org.daemoxcp.mail.security.RootOnlyPath.folders(rules.getParent(), rules.getFileName().toString(), domain, user);
            org.daemoxcp.mail.security.RootOnlyPath.replace(userDir, SCRIPT, script.getBytes(StandardCharsets.UTF_8), null, null,
                    PosixFilePermissions.fromString("rw-r--r--"));

            // Compile the script
            compileScript(userDir.resolve(SCRIPT).toString());

            // The mailbox's Dovecot home, where the auto-reply and the forward remember whom they have already
            // answered: it exists before the first delivery, and Dovecot does not write an error in the log
            // (finding 217).
            org.daemoxcp.mail.system.DovecotHome.ensureHome(domain, user);

            return true;
        } catch (IOException | IllegalArgumentException e) {
            LOGGER.warning("[SieveGenerator] Sieve rules of " + email + " not saved: " + e.getMessage());
            return false;
        }
    }

    /**
     * Compiles the script and puts the compiled one next to it, so that Dovecot does not recompile at every delivery
     * (the folder belongs to root, and Dovecot cannot save it there). sievec runs as the sievec user, never as root
     * (SieveCompiler, finding 218). False only if sievec refuses the script; if it could not be compiled (sievec
     * missing, a user that cannot be obtained) it is true, with a warning: Dovecot compiles at every delivery, as it
     * did without it.
     */
    public boolean compileScript(String scriptPath) {
        org.daemoxcp.mail.system.SieveCompiler.Outcome o = org.daemoxcp.mail.system.SieveCompiler.compile(Path.of(scriptPath));
        switch (o.status()) {
            case COMPILED -> { if (!o.message().isEmpty()) System.err.println("sievec: " + scriptPath + ": " + o.message()); }
            case REFUSED -> System.err.println("sievec refuses " + scriptPath + ": " + o.message());
            case NOT_COMPILED -> System.err.println("sievec: " + scriptPath + " not precompiled, Dovecot compiles it at each delivery: "
                    + o.message());
        }
        return !o.refused();
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

    /**
     * Checks a Sieve text with sievec, which runs as the sievec user and not as root (SieveCompiler, finding 218):
     * the text comes from whoever writes the filters. Nobody calls it today. If sievec is missing or cannot be run,
     * the text passes: Dovecot will check it at delivery, as before.
     */
    public ValidationResult validateScript(String script) {
        org.daemoxcp.mail.system.SieveCompiler.Outcome o = org.daemoxcp.mail.system.SieveCompiler.validate(script);
        if (!o.refused()) return new ValidationResult(true, null);
        String output = o.message();
        ValidationResult result = new ValidationResult(false, output);
        // The error line: "script: line 2: error: ..."
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

    /**
     * Get raw Sieve script for a mailbox
     */
    public String getSieveScript(String email) {
        try {
            if (!org.daemoxcp.mail.security.SafeNames.address(email)) return null;
            String[] parts = email.split("@");

            Path sieveFile = org.daemoxcp.mail.security.SafeNames.under(Path.of(SIEVE_DIR), parts[1], parts[0], SCRIPT);
            if (Files.exists(sieveFile, LinkOption.NOFOLLOW_LINKS)) {
                // Root does not follow a link: it would show the caller the file it points to (finding 221).
                return new String(org.daemoxcp.mail.security.RootOnlyPath.read(sieveFile, 1 << 20), StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            LOGGER.warning("[SieveGenerator] Sieve rules of " + email + " not read: " + e.getMessage());
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
