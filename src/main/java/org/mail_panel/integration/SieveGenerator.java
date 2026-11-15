package org.mail_panel.integration;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.database.MailDatabase;

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
    /** Il file delle regole del pannello in ogni cartella dominio/nome: lo esegue Dovecot prima di quelli della casella. */
    private static final String SCRIPT = ".dovecot.sieve";
    private static final String GLOBAL_SIEVE = "/usr/local/etc/dovecot/sieve/global.sieve";

    /**
     * La prima riga di ogni script del pannello (date serve a currentdate, nella risposta automatica; mailbox a
     * fileinto :create, reperto 229). Pigeonhole ha mailbox fra le estensioni attive per impostazione predefinita, sulla
     * 2.3 (sieve_extensions aggiunge con +) come sulla 2.4.
     */
    public static final String REQUIRE = "require [\"fileinto\", \"reject\", \"vacation\", \"copy\", \"imap4flags\", \"regex\", \"relational\", \"comparator-i;ascii-numeric\", \"date\", \"mailbox\"];\n\n";

    /**
     * La riga require che il pannello scriveva prima di aggiungere mailbox (fino al reperto 229): la riconoscono
     * SieveForcedKeep e SieveRulesRefresh, per sapere che uno script e' del pannello.
     */
    public static final String REQUIRE_BEFORE_MAILBOX = REQUIRE.replace(", \"mailbox\"];", "];");

    /**
     * La coda che il pannello metteva in fondo a ogni script fino al 09/11/2026: un keep esplicito. SieveForcedKeep la
     * toglie all'avvio dagli script gia' scritti.
     */
    public static final String OLD_FORCED_KEEP = "\n# Default action\nkeep;\n";

    /**
     * Generate Sieve script for a mailbox
     *
     * Nessun keep in fondo. Il keep implicito (RFC 5228, 2.10.2) mette gia' il messaggio nella INBOX quando nessuna
     * regola lo toglie; un keep esplicito in fondo lo metteva nella INBOX SEMPRE, quindi «Sposta» lasciava il messaggio
     * nella cartella e nella INBOX, «Inoltra» senza copia ne teneva una e «Elimina» non eliminava niente (misurato sulla
     * VM il 09/11/2026: dopo un fileinto "Junk", doveadm search dava INBOX 1, Junk 1). Le azioni che lasciano anche la
     * INBOX lo dicono da sole: fileinto :copy, redirect :copy (RFC 3894).
     *
     * Lo script gira come script «before» (sieve_before nella 2.3, type = before nella 2.4, reperto 214). Nella
     * documentazione di Pigeonhole (2.3, «Executing Multiple Scripts Sequentially»): lo script dopo, quello della casella,
     * gira solo se e' in vigore un keep, implicito o esplicito; e la INBOX la scrive solo il keep dell'ultimo script.
     * Quindi senza il keep forzato: se le regole del pannello tengono il messaggio, gira lo script della casella e decide
     * lui; se lo spostano, inoltrano senza copia o eliminano, lo script della casella su quel messaggio non gira.
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

        // Niente keep in fondo: il keep implicito tiene il messaggio nella INBOX se nessuna regola qui sopra lo toglie
        // (vedi sopra). Uno script senza regole e' solo il require, e Sieve lo accetta.
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
            // :create (RFC 5490, estensione mailbox): la cartella che non c'e' si crea. Senza, un filtro «Sposta» verso
            // una cartella nuova non spostava niente: Dovecot rispondeva «Mailbox doesn't exist» e il messaggio restava
            // nella INBOX (misurato sulla VM e visto sul server vero, reperto 229). Anche la cartella proposta dalla
            // finestra dei filtri, INBOX.Filtered, all'inizio non c'e'.
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
     * Da root, senza seguire collegamenti e solo in cartelle che nessun altro puo' cambiare (RootOnlyPath, reperto 221):
     * prima Files.writeString seguiva un .dovecot.sieve che era un collegamento, e root riscriveva il file a cui puntava
     * (misurato sulla VM con un file di nobody, 0600). Lo script e' di root, rw-r--r--: Dovecot, che consegna come vmail,
     * lo legge e non lo puo' cambiare. Falso, col motivo nel registro, se una cartella da / alla casella non passa.
     */
    public boolean saveSieveScript(String email, String script) {
        try {
            // Create user sieve directory
            // L'indirizzo viene da MySQL, che col pannello separato scrive anche la parte web, e root ne fa un
            // percorso: deve avere la forma di un indirizzo, e il file restare sotto SIEVE_DIR. Prima una casella
            // come ../x faceva scrivere a root un file fuori dalla sua cartella.
            if (!org.mail_panel.security.SafeNames.address(email)) return false;
            String[] parts = email.split("@");

            String user = parts[0];
            String domain = parts[1];

            Path rules = Path.of(SIEVE_DIR);
            org.mail_panel.security.SafeNames.under(rules, domain, user);
            Path userDir = org.mail_panel.security.RootOnlyPath.folders(rules.getParent(), rules.getFileName().toString(), domain, user);
            org.mail_panel.security.RootOnlyPath.replace(userDir, SCRIPT, script.getBytes(StandardCharsets.UTF_8), null, null,
                    PosixFilePermissions.fromString("rw-r--r--"));

            // Compile the script
            compileScript(userDir.resolve(SCRIPT).toString());

            // La home di Dovecot della casella, dove la risposta automatica e l'inoltro ricordano a chi hanno gia'
            // risposto: c'e' prima della prima consegna, e Dovecot non scrive un errore nel registro (reperto 217).
            org.mail_panel.system.DovecotHome.ensureHome(domain, user);

            return true;
        } catch (IOException | IllegalArgumentException e) {
            LOGGER.warning("[SieveGenerator] Sieve rules of " + email + " not saved: " + e.getMessage());
            return false;
        }
    }

    /**
     * Compila lo script e mette il compilato accanto, perche' Dovecot non ricompili a ogni consegna (la cartella e' di
     * root, e Dovecot non ce lo puo' salvare). sievec gira con l'utente sievec, mai da root (SieveCompiler, reperto
     * 218). Falso solo se sievec rifiuta lo script; se non si e' potuto compilare (sievec mancante, utente che non si
     * puo' avere) e' vero, con un avviso: Dovecot compila a ogni consegna, come faceva senza.
     */
    public boolean compileScript(String scriptPath) {
        org.mail_panel.system.SieveCompiler.Outcome o = org.mail_panel.system.SieveCompiler.compile(Path.of(scriptPath));
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
     * Controlla un testo Sieve con sievec, che gira con l'utente sievec e non da root (SieveCompiler, reperto 218): il
     * testo viene da chi scrive i filtri. Oggi nessuno la chiama. Se sievec manca o non si puo' far girare, il testo
     * passa: lo controllera' Dovecot alla consegna, come prima.
     */
    public ValidationResult validateScript(String script) {
        org.mail_panel.system.SieveCompiler.Outcome o = org.mail_panel.system.SieveCompiler.validate(script);
        if (!o.refused()) return new ValidationResult(true, null);
        String output = o.message();
        ValidationResult result = new ValidationResult(false, output);
        // La riga dell'errore: «script: line 2: error: ...»
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
            if (!org.mail_panel.security.SafeNames.address(email)) return null;
            String[] parts = email.split("@");

            Path sieveFile = org.mail_panel.security.SafeNames.under(Path.of(SIEVE_DIR), parts[1], parts[0], SCRIPT);
            if (Files.exists(sieveFile, LinkOption.NOFOLLOW_LINKS)) {
                // Root non segue un collegamento: mostrerebbe a chi chiama il file a cui punta (reperto 221).
                return new String(org.mail_panel.security.RootOnlyPath.read(sieveFile, 1 << 20), StandardCharsets.UTF_8);
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
