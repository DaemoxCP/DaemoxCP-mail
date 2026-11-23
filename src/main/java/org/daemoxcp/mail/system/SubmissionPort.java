package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Makes port 465 a real submission port, adding to master.cf the line that
 * rejects whoever has not authenticated.
 *
 * Why it is needed, verified against the specifications and not by intuition:
 *  - RFC 8314 Section 3.3: the "submissions" service on 465 gives access to a Message Submission
 *    Agent according to RFC 6409, and the rules for MSAs apply to that port too.
 *  - RFC 6409 Section 4.3 ("Require Authentication"): the MSA MUST reject the MAIL command if the
 *    session has not been authenticated.
 *
 * Today the smtps entry has smtpd_sasl_auth_enable=yes, which ENABLES authentication but does not
 * REQUIRE it: whoever does not authenticate is served anyway, as on port 25. The difference
 * goes unseen until someone notices it.
 *
 * Beware of the asymmetry: the same line on port 25 would stop all incoming mail,
 * because that is where the servers of the world deliver without authenticating. That is why
 * only ONE entry is touched here, identified by the first field of the line and not by searching
 * for the word "smtps" in the file: that word also appears inside the options (syslog_name).
 */
public class SubmissionPort {

    public static final String RESTRICTION = "smtpd_client_restrictions=permit_sasl_authenticated,reject";
    private static final String MASTER = "/usr/local/etc/postfix/master.cf";
    private static final String COPY = "/var/db/daemoxcp-mail/master.cf-before-465";

    /** The names under which port 465 can appear in master.cf. */
    private static final List<String> NAMES = List.of("smtps", "submissions");

    private SubmissionPort() {}

    /*
     * ===================================================================
     * The part that can be tested without a server
     * ===================================================================
     */

    public enum Outcome { ADDED, ALREADY_PRESENT, ENTRY_MISSING }

    public static class Change {
        public Outcome outcome;
        public String content;   // the new file, only when outcome == ADDED
        public String entry;        // the name found: smtps or submissions
        public int line;           // where the entry starts, so it can be reported
        public String already;         // the restriction already present, when there is one
    }

    /**
     * Adds the restriction to the 465 entry, and to no other.
     *
     * The recognition looks at the FIRST FIELD of a non-indented line: in master.cf the
     * lines that start with a space are options of the previous entry, and a line that
     * starts with '#' is commented out. Searching for the word "smtps" in the text would also catch
     * "-o syslog_name=postfix/smtps", which is an option, not an entry.
     */
    public static Change addRestriction(String masterCf) {
        Change m = new Change();
        if (masterCf == null) { m.outcome = Outcome.ENTRY_MISSING; return m; }

        String[] lines = masterCf.split("\n", -1);
        int start = -1;
        for (int i = 0; i < lines.length; i++) {
            String r = lines[i];
            if (r.isEmpty() || Character.isWhitespace(r.charAt(0))) continue;  // opzione
            if (r.startsWith("#")) continue;                                   // commented out
            String first = r.trim().split("\\s+")[0];
            if (NAMES.contains(first)) { start = i; m.entry = first; break; }
        }
        if (start < 0) { m.outcome = Outcome.ENTRY_MISSING; return m; }
        m.line = start + 1;

        // The options of the entry: the indented lines that follow, up to the next entry.
        int end = start + 1;
        while (end < lines.length && !lines[end].isEmpty()
                && Character.isWhitespace(lines[end].charAt(0))) end++;

        // BOTH forms are accepted. Of the panel's two installation scripts, one
        // writes "smtpd_recipient_restrictions=permit_sasl_authenticated,reject" on this
        // entry and the other writes nothing: looking only for the "client" form would have
        // added a redundant line to a server that was already fine, and would have made the
        // panel say that the port was open when it was not.
        for (int i = start; i < end; i++) {
            String compact = lines[i].replace(" ", "");
            if (compact.contains("smtpd_client_restrictions=")
                    || compact.contains("smtpd_recipient_restrictions=")) {
                m.outcome = Outcome.ALREADY_PRESENT;
                m.already = lines[i].trim();
                return m;
            }
        }

        List<String> outside = new ArrayList<>();
        for (int i = 0; i < end; i++) outside.add(lines[i]);
        outside.add("  -o " + RESTRICTION);
        for (int i = end; i < lines.length; i++) outside.add(lines[i]);

        m.outcome = Outcome.ADDED;
        m.content = String.join("\n", outside);
        return m;
    }

    /*
     * ===================================================================
     * The part that touches the server
     * ===================================================================
     */

    /** Reads the state without changing anything. */
    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);
        try {
            Path p = Path.of(MASTER);
            if (!Files.isReadable(p))
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.subm.cannotRead", java.util.Map.of("file", String.valueOf(MASTER))));
            Change m = addRestriction(Files.readString(p));
            r.put("entry", m.entry == null ? JSONObject.NULL : m.entry)
             .put("line", m.line)
             .put("state", m.outcome.name())
             .put("restriction", RESTRICTION);

            // The check that is not taken for granted: if the restrictions were evaluated
            // BEFORE authentication, the line would also reject legitimate users.
            RunResult d = run("postconf", "-h", "smtpd_delay_reject");
            String value = d.output.trim();
            r.put("delayReject", value).put("delayRejectRead", d.code == 0);
            r.put("safe", d.code == 0 && value.equalsIgnoreCase("yes"));

            switch (m.outcome) {
                case ALREADY_PRESENT -> r.put("note", I18n.tr("server.subm.already", java.util.Map.of("svc", String.valueOf(m.entry), "line", String.valueOf(m.already))))
                        .put("already", m.already);
                case ENTRY_MISSING -> r.put("note", I18n.tr("server.subm.noEntry"));
                case ADDED -> r.put("note", I18n.tr("server.subm.acceptsUnauth", java.util.Map.of("svc", String.valueOf(m.entry), "line", String.valueOf(m.line))));
            }
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.subm.readError", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("SubmissionPort", e))));
        }
    }

    /**
     * Applies the change. Backup copy, write, postfix check, reload, and if
     * something does not add up the previous file is put back and it reloads again.
     */
    public static JSONObject apply() {
        JSONObject r = new JSONObject();
        try {
            JSONObject st = state();
            if (!st.optBoolean("success", false))
                return r.put("success", false).put("error", st.optString("error", I18n.tr("server.subm.stateUnreadable")));

            String state = st.optString("state", "");
            if ("ALREADY_PRESENT".equals(state))
                return r.put("success", true).put("alreadyDone", true).put("note", st.optString("note"));
            if ("ENTRY_MISSING".equals(state))
                return r.put("success", false).put("error", st.optString("note"));

            // The check that matters most of all: without delay_reject set to "yes" the line
            // would also reject whoever authenticates, because it would be evaluated before AUTH.
            if (!st.optBoolean("safe", false))
                return r.put("success", false)
                        .put("error", st.optBoolean("delayRejectRead", false)
                                ? I18n.tr("server.subm.delayReject", java.util.Map.of("v", String.valueOf(st.optString("delayReject", "?"))))
                                : I18n.tr("server.subm.delayRejectUnread", java.util.Map.of("v", String.valueOf(st.optString("delayReject", "?")))));

            Path p = Path.of(MASTER);
            String before = Files.readString(p);
            Change m = addRestriction(before);
            if (m.outcome != Outcome.ADDED)
                return r.put("success", false).put("error", I18n.tr("server.subm.changed", java.util.Map.of("state", String.valueOf(m.outcome.name()))));

            Path copy = Path.of(COPY);
            Files.createDirectories(copy.getParent());
            Files.writeString(copy, before);
            r.put("copy", copy.toString()).put("entry", m.entry).put("line", m.line);

            Files.writeString(p, m.content);

            RunResult check = run("postfix", "check");
            if (check.code != 0) {
                Files.writeString(p, before);
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.subm.checkFailed", java.util.Map.of("out", String.valueOf(check.output.trim()))));
            }

            RunResult reload = run("postfix", "reload");
            if (reload.code != 0) {
                Files.writeString(p, before);
                run("postfix", "reload");
                return r.put("success", false).put("restored", true)
                        .put("error", I18n.tr("server.subm.reloadFailed", java.util.Map.of("out", String.valueOf(reload.output.trim()))));
            }

            // It is not enough that the commands did not complain: the file is read again and checked.
            Change after = addRestriction(Files.readString(p));
            if (after.outcome != Outcome.ALREADY_PRESENT)
                return r.put("success", false)
                        .put("error", I18n.tr("server.subm.notPresent", java.util.Map.of("file", String.valueOf(MASTER))));

            RunResult m465 = run("postconf", "-M", m.entry + "/inet");
            r.put("postfixEntry", m465.output.trim());

            return r.put("success", true)
                    .put("note", I18n.tr("server.subm.done", java.util.Map.of("svc", String.valueOf(m.entry), "copy", String.valueOf(copy))));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.subm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("SubmissionPort", e))));
        }
    }

    private record RunResult(int code, String output) {}

    private static RunResult run(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return new RunResult(p.waitFor(), out);
        } catch (Exception e) {
            return new RunResult(-1, String.valueOf(e.getMessage()));
        }
    }
}
