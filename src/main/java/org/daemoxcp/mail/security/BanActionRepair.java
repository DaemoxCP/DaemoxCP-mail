package org.daemoxcp.mail.security;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Makes the jails that banned with iptables ban with pf.
 *
 * What had happened. Of the seven active jails, five declared their own action
 * ("action = pf[name=...]") and two did not: the public surface (today daemoxcp-mail-public, back then
 * `mailpanel-pubblico`) and daemoxcp-mail-auth, that is, precisely the
 * two that protect the panel. By not declaring it they inherited the default value of
 * jail.conf, which is built on iptables, a command that does not exist on FreeBSD. The result
 * was not a visible error: the jails detected, counted the attempts and increased the bans
 * regularly. On the public surface there were 14,370 attempts and 46 bans, none of which ever
 * blocked anything. A jail with the wrong ban command is indistinguishable from one that works,
 * until you look at the firewall.
 *
 * Why fixing the code is not enough. The file of the public surface is rewritten by the panel
 * at every installation, so there the fix arrives by itself. The [daemoxcp-mail-auth] section does not:
 * it is added to jail.local only once and then never touched again, so as not to trample the
 * changes of whoever customizes it. An excellent rule, which however means that on an existing
 * installation that section would stay on iptables forever. An intervention is needed that
 * updates it, and does so with the same caution: it changes the action line and nothing else.
 *
 * How it behaves. First it copies, then writes, then reloads, then ASKS fail2ban again which command
 * it runs now: without this last step it would say "repaired" having only written a file, and
 * that is exactly the kind of confirmation that let the fault slip by all this time.
 * If something goes wrong it restores the copy and reloads.
 */
public final class BanActionRepair {

    private static final String JAIL_LOCAL = "/usr/local/etc/fail2ban/jail.local";
    private static final String PUBLIC_JAIL = org.daemoxcp.mail.system.WebProtection.JAIL;
    private static final String PUBLIC_NAME = org.daemoxcp.mail.system.WebProtection.NAME;
    private static final String CLIENT = "/usr/local/bin/fail2ban-client";

    private BanActionRepair() { }

    /** The jails whose ban command cannot be executed on this system. It only reads. */
    public static JSONObject diagnosis() {
        JSONObject r = new JSONObject();
        JSONArray broken = new JSONArray();
        JSONArray notJudged = new JSONArray();
        int reviewed = 0;
        for (String jail : activeJails()) {
            String cmd = banCommand(jail);
            if (cmd == null || cmd.isEmpty()) {
                // Without the raw output this line is a dead end: it says that it is not known, and
                // leaves the reader no way of knowing. With the output, the next step can be
                // taken by anyone looking at the page.
                notJudged.put(new JSONObject().put("jail", jail)
                    .put("why", I18n.tr("server.banfix.noCommand"))
                    .put("output", actionsOutput(jail))
                    .put("log", logErrorsFor(jail))
                    .put("sections", sectionsDefining(jail))
                    .put("dump", readConfiguration(jail)));
                continue;
            }
            String runnable = firstRunnable(cmd);
            if (runnable == null) {
                // Deliberate skip: the line does not clearly name a program. It must be SAID, not
                // kept quiet: a jail skipped silently turns green a check that
                // simply did not look at it, which is the defect being hunted here.
                notJudged.put(new JSONObject().put("jail", jail)
                    .put("why", I18n.tr("server.banfix.noProgram"))
                    .put("command", cmd));
                continue;
            }
            reviewed++;
            if (exists(runnable)) continue;
            broken.put(new JSONObject()
                .put("jail", jail).put("command", cmd).put("runnable", runnable));
        }
        return r.put("success", true).put("broken", broken)
                .put("reviewed", reviewed)
                .put("not_judged", notJudged)
                .put("repairable", broken.length() > 0);
    }

    /** Writes the pf action where it is missing, reloads, and verifies by asking fail2ban again. */
    public static JSONObject repair() {
        JSONObject r = new JSONObject();
        JSONArray steps = new JSONArray();
        List<Path> copies = new ArrayList<>();
        try {
            boolean touched = false;
            boolean toReviewByHand = false;

            // 1. The public surface: the file belongs to the panel, it is rewritten whole.
            Path pub = Paths.get(PUBLIC_JAIL);
            if (Files.exists(pub)) {
                String before = Files.readString(pub, StandardCharsets.UTF_8);
                String after = org.daemoxcp.mail.system.WebProtection.jail();
                // Rewriting the whole file is legitimate only if it is the file the panel writes.
                // If someone replaced it with their own, overwriting it would delete their
                // work without warning, and this is a fix, not a restore.
                if (!org.daemoxcp.mail.system.PanelMarker.writtenByPanel(before)) {
                    steps.put(step(PUBLIC_NAME, false,
                        I18n.tr("server.banfix.notOurFile", java.util.Map.of("file", String.valueOf(PUBLIC_JAIL), "jail", PUBLIC_NAME))));
                    toReviewByHand = true;
                } else if (!before.equals(after)) {
                    copies.add(copy(pub));
                    Files.writeString(pub, after, StandardCharsets.UTF_8);
                    touched = true;
                    steps.put(step(PUBLIC_NAME, true,
                        I18n.tr("server.banfix.rewritten", java.util.Map.of("file", String.valueOf(PUBLIC_JAIL), "line", String.valueOf(actionLineOf(after))))));
                } else {
                    steps.put(step(PUBLIC_NAME, true, I18n.tr("server.banfix.alreadyOk")));
                }
            } else {
                steps.put(step(PUBLIC_NAME, true,
                    I18n.tr("server.banfix.notInstalled")));
            }

            // 2. daemoxcp-mail-auth: a section inside jail.local, only the action line is changed.
            Path loc = Paths.get(JAIL_LOCAL);
            if (Files.exists(loc)) {
                String before = Files.readString(loc, StandardCharsets.UTF_8);
                Outcome e = withPfAction(before, "daemoxcp-mail-auth");
                switch (e.type) {
                    case ABSENT -> steps.put(step("daemoxcp-mail-auth", true,
                        I18n.tr("server.banfix.noSection")));
                    case ALREADY_IN_PLACE -> steps.put(step("daemoxcp-mail-auth", true,
                        I18n.tr("server.banfix.alreadyOk")));
                    case TO_REVIEW -> {
                        steps.put(step("daemoxcp-mail-auth", false, e.reason));
                        toReviewByHand = true;
                    }
                    case MODIFIED -> {
                        copies.add(copy(loc));
                        Files.writeString(loc, e.content, StandardCharsets.UTF_8);
                        touched = true;
                        steps.put(step("daemoxcp-mail-auth", true,
                            I18n.tr("server.banfix.lineUpdated", java.util.Map.of("file", String.valueOf(JAIL_LOCAL), "line", String.valueOf(actionLineOf(e.content))))));
                    }
                }
            } else {
                steps.put(step("daemoxcp-mail-auth", true, I18n.tr("server.banfix.noJailLocal")));
            }

            if (!touched && !toReviewByHand) {
                // The files may already be correct while the running process still has the
                // previous configuration in memory: they are two different things, and stopping here
                // would say "it was not needed" looking only at the disk. If the runtime does not report
                // the action of some jail, the job is not finished: reload and look again.
                java.util.List<String> mute = new ArrayList<>();
                for (String jail : new String[] { PUBLIC_NAME, "daemoxcp-mail-auth" }) {
                    String c = banCommand(jail);
                    if (c == null || c.isEmpty()) mute.add(jail);
                }
                if (mute.isEmpty())
                    return r.put("success", true).put("steps", steps)
                            .put("message", I18n.tr("server.banfix.nothingNeeded"));

                steps.put(step("configuration", true,
                    I18n.tr("server.banfix.diskVsRuntime", java.util.Map.of("list", String.valueOf(String.join(", ", mute))))));
                touched = true;
            }
            if (!touched)
                return r.put("success", false).put("steps", steps)
                        .put("message", I18n.tr("server.banfix.untouched"));

            // 3. Reload.
            Shell.Result rel = Shell.run(Duration.ofSeconds(30), CLIENT, "reload");
            if (!rel.success()) {
                restore(copies);
                Shell.run(Duration.ofSeconds(30), CLIENT, "reload");
                steps.put(step("reload", false,
                    I18n.tr("server.banfix.rejected", java.util.Map.of("out", String.valueOf(rel.output().trim())))));
                return r.put("success", false).put("steps", steps)
                        .put("message", I18n.tr("server.banfix.cancelled"));
            }
            steps.put(step("reload", true,
                I18n.tr("server.banfix.accepted")));

            // A plain reload may not be enough. fail2ban-client(1): "reload ... reloads the
            // configuration without restarting of the server, the option '--restart' activates
            // completely restarting of affected jails". If after the reload the action does not show,
            // the configuration is right but has not been applied: the jail is recreated. Without
            // "--unban", which the manual indicates as the option that would instead remove the bans.
            java.util.List<String> stillMute = new ArrayList<>();
            for (String jail : new String[] { PUBLIC_NAME, "daemoxcp-mail-auth" }) {
                String c = banCommand(jail);
                if (c == null || c.isEmpty()) stillMute.add(jail);
            }
            if (!stillMute.isEmpty()) {
                Shell.Result rs = Shell.run(Duration.ofSeconds(60), CLIENT, "reload", "--restart");
                steps.put(step("reload --restart", rs.success(),
                    I18n.tr("server.banfix.restarted", java.util.Map.of("list", String.valueOf(String.join(", ", stillMute)), "out", String.valueOf(rs.output() == null || rs.output().isBlank() ? I18n.tr("server.banfix.none") : rs.output().trim())))));
            }

            // 4. The check that counts: what it runs NOW, asked of fail2ban.
            JSONArray verification = new JSONArray();
            boolean allOk = true;
            for (String jail : new String[] { PUBLIC_NAME, "daemoxcp-mail-auth" }) {
                String cmd = banCommand(jail);
                boolean ok = cmd != null && cmd.contains("pfctl");
                if (cmd == null || cmd.isEmpty()) {
                    // Telling "it is not there" from "it is there and does not talk": the first is not
                    // a fault, the second is, and confusing them would acquit exactly the case we are
                    // chasing. It is decided by asking whether the jail exists, not by assuming it.
                    Shell.Result st = Shell.run(Duration.ofSeconds(10), CLIENT, "status", jail);
                    boolean jailExists = st.success() && !st.output().contains("does not exist");
                    if (!jailExists) {
                        verification.put(new JSONObject().put("jail", jail).put("ok", true)
                            .put("note", I18n.tr("server.banfix.notActive")));
                        continue;
                    }
                    allOk = false;
                    verification.put(new JSONObject().put("jail", jail).put("ok", false)
                        .put("note", I18n.tr("server.banfix.noActionAfter", java.util.Map.of("out", String.valueOf(actionsOutput(jail)))))
                        .put("log", logErrorsFor(jail))
                        .put("sections", sectionsDefining(jail))
                        .put("dump", readConfiguration(jail)));
                    continue;
                }
                if (!ok) allOk = false;
                verification.put(new JSONObject().put("jail", jail).put("ok", ok)
                    .put("command", cmd));
            }
            steps.put(step("review", allOk,
                allOk ? I18n.tr("server.banfix.allBan")
                        : I18n.tr("server.banfix.stillNotBan")));

            return r.put("success", allOk).put("steps", steps).put("verification", verification)
                    .put("message", allOk
                        ? I18n.tr("server.banfix.verified")
                        : I18n.tr("server.banfix.notConfirmed"));
        } catch (Exception e) {
            try { restore(copies); Shell.run(Duration.ofSeconds(30), CLIENT, "reload"); } catch (Exception ignore) { }
            return r.put("success", false).put("steps", steps)
                    .put("message", I18n.tr("server.banfix.errorRestored", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("BanActionRepair", e))));
        }
    }

    /**
     * The content of jail.local with the pf action in place of the one that was there.
     *
     * ONE line is touched, inside ONE section: the rest of the file, the spaces, the comments and the
     * sections of others stay identical byte for byte. It is a live configuration file, also written
     * by hand, and a fix that rearranges pieces of it nobody asked for does more damage than the fault.
     *
     * The case that would call for caution is the action written over several lines: in a .conf file
     * an indented line continues the one above, so replacing only the first would leave attached
     * to the new command a tail that belongs to the old one. No attempt is made to guess how to put
     * it back together: it is declared that it must be looked at by hand, and nothing is touched.
     * Better not to repair than to half-repair a file that decides who gets in.
     */
    static Outcome withPfAction(String content, String jail) {
        String[] lines = content.split("\n", -1);
        int start = -1;
        for (int i = 0; i < lines.length; i++)
            if (lines[i].trim().equals("[" + jail + "]")) { start = i; break; }
        if (start < 0) return Outcome.absent();

        int end = lines.length;
        for (int i = start + 1; i < lines.length; i++) {
            String t = lines[i].trim();
            if (t.startsWith("[") && t.endsWith("]")) { end = i; break; }
        }

        // First look, then write: the action line is searched for and judged on whether it can
        // be touched, without having modified anything yet.
        int actionLine = -1;
        for (int i = start + 1; i < end; i++) {
            String t = lines[i].trim();
            if (t.isEmpty() || t.startsWith("#") || !t.contains("=")) continue;
            String key = t.substring(0, t.indexOf('=')).trim().toLowerCase();
            if (key.equals("action") || key.equals("banaction")) { actionLine = i; break; }
        }

        if (actionLine >= 0) {
            String t = lines[actionLine].trim();
            String value = t.substring(t.indexOf('=') + 1).trim();
            // "Starts with pf" is not enough to say it is fine, and neither is "contains no
            // placeholders". The WHOLE form known to work here must be recognized:
            // pf[name=..., port="..."]. I say this after getting it wrong twice with the same
            // mechanism (first "actiontype=<allports>", then "actiontype=any"), and both
            // would have been promoted by a more permissive check and left there
            // forever, while fail2ban answered "No actions for jail ...", that is, that jail
            // banned nothing. A declared port is the condition that distinguishes the
            // four jails with a table AND a rule from those without.
            boolean pf = value.equals("pf") || value.startsWith("pf[") || value.startsWith("pf ");
            boolean goodForm = pf && !value.contains("<")
                              && value.contains("port=") && value.contains("name=");
            if (goodForm) return Outcome.alreadyInPlace();
            int seg = actionLine + 1;
            if (seg < end && !lines[seg].trim().isEmpty()
                && (lines[seg].startsWith(" ") || lines[seg].startsWith("\t")))
                return Outcome.toReview(I18n.tr("server.banfix.multiline", java.util.Map.of("jail", String.valueOf(jail), "file", String.valueOf(JAIL_LOCAL), "line", String.valueOf(actionLine + 1))));
        }

        // allports, not the port: the pf action builds "... to any port $port" and without a port
        // pf rejects the rule, leaving the table with nobody reading it.
        String action = "action   = pf[name=" + jail + ", port=\"0:65535\"]";
        java.util.List<String> out = new ArrayList<>(java.util.Arrays.asList(lines));
        if (actionLine >= 0) {
            out.set(actionLine, action);
        } else {
            // After the last configuration line of the section, so that it is read where
            // one expects to find it and not at the bottom of empty lines.
            int after = start;
            for (int i = start + 1; i < end; i++) {
                String t = lines[i].trim();
                if (!t.isEmpty() && !t.startsWith("#")) after = i;
            }
            out.add(after + 1, action);
        }
        return Outcome.modified(String.join("\n", out));
    }

    /** What happened to the section, without having to reread its text to understand it. */
    static final class Outcome {
        enum Kind { ABSENT, ALREADY_IN_PLACE, MODIFIED, TO_REVIEW }
        final Kind type;
        final String content;
        final String reason;
        private Outcome(Kind t, String c, String m) { type = t; content = c; reason = m; }
        static Outcome absent()            { return new Outcome(Kind.ABSENT, null, null); }
        static Outcome alreadyInPlace()          { return new Outcome(Kind.ALREADY_IN_PLACE, null, null); }
        static Outcome modified(String c) { return new Outcome(Kind.MODIFIED, c, null); }
        static Outcome toReview(String m) { return new Outcome(Kind.TO_REVIEW, null, m); }
    }

    /**
     * The first executable command named by a ban command, or null if it cannot be told.
     *
     * Null is not a failure but an answer: on it is built the accusation "this jail
     * bans with a command that does not exist", and a wrong accusation would make someone who
     * does not need it press a repair button. So only what is clearly the
     * name of a program is judged: if the line starts with a shell construct, a variable or a
     * word with metacharacters, nothing is concluded.
     */
    static String firstRunnable(String command) {
        if (command == null) return null;
        for (String line : command.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            String first = t.split("\\s+")[0];
            // fail2ban leaves placeholders in angle brackets: <iptables> still names
            // the command, and must be judged for what it names.
            first = first.replace("<", "").replace(">", "");
            if (first.isEmpty()) continue;
            if (SHELL_CONSTRUCTS.contains(first)) return null;
            if (!first.matches("[A-Za-z0-9._/+-]+")) return null;
            return first;
        }
        return null;
    }

    /** Words that open a shell construct: they are not programs to look for on disk. */
    private static final java.util.Set<String> SHELL_CONSTRUCTS = java.util.Set.of(
        "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done",
        "case", "esac", "test", "[", "[[", "echo", "true", "false", ":", "exec",
        "eval", "export", "set", "unset", "local", "return", "exit", "printf", "cd");

    private static boolean exists(String runnable) {
        if (runnable.startsWith("/")) return Files.isExecutable(Paths.get(runnable));
        for (String dir : new String[] { "/sbin", "/bin", "/usr/sbin", "/usr/bin",
                                         "/usr/local/sbin", "/usr/local/bin" })
            if (Files.isExecutable(Paths.get(dir, runnable))) return true;
        return false;
    }

    private static List<String> activeJails() {
        List<String> out = new ArrayList<>();
        Shell.Result r = Shell.run(Duration.ofSeconds(10), CLIENT, "status");
        if (!r.success()) return out;
        java.util.regex.Matcher m =
            java.util.regex.Pattern.compile("Jail list:\\s*(.+)").matcher(r.output());
        if (m.find())
            for (String n : m.group(1).split(","))
                if (!n.trim().isEmpty()) out.add(n.trim());
        return out;
    }

    /** The action line inside a configuration text: what was written is shown. */
    private static String actionLineOf(String content) {
        for (String r : content.split("\n")) {
            String t = r.trim();
            if (t.startsWith("action") && t.contains("=")) return t;
        }
        return I18n.tr("server.banfix.noActionLine");
    }

    /**
     * The lines of /var/log/fail2ban.log that talk about this jail and about errors.
     *
     * When fail2ban says "No actions for jail X" it does not explain why there, but it has already
     * written it in its own log at load time. Showing it is the only way for whoever looks at
     * the page (and whoever reads their account of it) to know the cause instead of guessing it.
     */
    static String logErrorsFor(String jail) {
        try {
            Path log = Paths.get("/var/log/fail2ban.log");
            if (!Files.exists(log)) return I18n.tr("server.banfix.noLog");
            java.util.List<String> all = Files.readAllLines(log, StandardCharsets.UTF_8);
            StringBuilder out = new StringBuilder();

            // 1. The last lines that name this jail, of any level. The level is not
            //    filtered: the most informative line so far was a routine WARNING
            //    ("already banned") which, coming from the actions module, proved that the
            //    jail does have the actions, the opposite of what I suspected.
            java.util.List<String> theirs = new ArrayList<>();
            for (int i = all.size() - 1; i >= 0 && theirs.size() < 8; i--)
                if (all.get(i).contains(jail)) theirs.add(0, all.get(i));
            out.append("— ").append(I18n.tr("server.banfix.lastLines", java.util.Map.of("jail", String.valueOf(jail)))).append(":\n")
               .append(theirs.isEmpty() ? I18n.tr("server.banfix.none") : String.join("\n", theirs));

            // 2. The WHOLE window of the last reload, without filters of any kind.
            //
            // The two previous versions of this box hid the answer, each in
            // its own way: the first filtered by jail name, and a loading error often
            // does not have the name; the second started from the last line containing "reload",
            // which is "Reload finished", showing only what comes AFTER, while the explanation lies
            // inside the reload. Two filters, twice the same answer thrown away.
            //
            // So here nothing is filtered: the window is taken and shown whole. A box
            // that shows too much can be read; one that shows the wrong thing wastes days.
            int end = -1;
            for (int i = all.size() - 1; i >= 0; i--)
                if (all.get(i).contains("Reload finished")) { end = i; break; }
            if (end < 0)
                for (int i = all.size() - 1; i >= 0; i--)
                    if (all.get(i).contains("Reload jail")) { end = i; break; }

            out.append("\n\n— ").append(I18n.tr("server.banfix.lastReload"));
            if (end < 0) {
                out.append(": ").append(I18n.tr("server.banfix.noReload"));
            } else {
                int start = Math.max(0, end - 80);
                // We go back up to the real start of the reload, if it is found in the window.
                for (int i = end; i >= start; i--)
                    if (all.get(i).contains("Reload jail") || all.get(i).contains("Stopping all jails")
                        || all.get(i).contains("Reloading")) { start = i; break; }
                int last = Math.min(all.size() - 1, end + 20);
                out.append(" (").append(I18n.tr("server.banfix.linesRange", java.util.Map.of("a", String.valueOf(start + 1), "b", String.valueOf(last + 1)))).append("):\n");
                for (int i = start; i <= last; i++) out.append(all.get(i)).append("\n");
            }
            return out.toString();
        } catch (Exception e) {
            return "(" + I18n.tr("server.banfix.logUnreadable", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("BanActionRepair", e))) + ")";
        }
    }

    /**
     * Every configuration file that defines this jail, with the whole section.
     *
     * It serves to answer "what does fail2ban see", which is not the same question as "what did I
     * write". Fail2ban reads jail.conf, then jail.local, then all of jail.d in order, and the last
     * definition wins: a second section with the same name, in a file that nobody looks at,
     * would by itself explain why the action just written has no effect. Until one looks,
     * it remains one hypothesis among many.
     */
    static String sectionsDefining(String jail) {
        StringBuilder out = new StringBuilder();
        try {
            java.util.List<Path> file = new ArrayList<>();
            file.add(Paths.get("/usr/local/etc/fail2ban/jail.conf"));
            file.add(Paths.get(JAIL_LOCAL));
            Path d = Paths.get("/usr/local/etc/fail2ban/jail.d");
            if (Files.isDirectory(d))
                try (var s2 = Files.list(d)) { s2.sorted().forEach(file::add); }

            for (Path f : file) {
                if (!Files.isRegularFile(f)) continue;
                java.util.List<String> lines = Files.readAllLines(f, StandardCharsets.UTF_8);
                for (int i = 0; i < lines.size(); i++) {
                    if (!lines.get(i).trim().equals("[" + jail + "]")) continue;
                    out.append(out.length() > 0 ? "\n\n" : "")
                       .append(f).append(" (").append(I18n.tr("server.banfix.lineN", java.util.Map.of("n", String.valueOf(i + 1)))).append("):\n");
                    for (int j = i; j < lines.size(); j++) {
                        String t = lines.get(j).trim();
                        if (j > i && t.startsWith("[") && t.endsWith("]")) break;
                        out.append("  ").append(lines.get(j)).append("\n");
                    }
                }
            }
        } catch (Exception e) {
            return "(" + I18n.tr("server.banfix.confUnreadable", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("BanActionRepair", e))) + ")";
        }
        return out.length() == 0
            ? "(" + I18n.tr("server.banfix.noFileDefines", java.util.Map.of("jail", String.valueOf(jail))) + ")"
            : out.toString();
    }

    /**
     * What fail2ban has INTERPRETED from the files for this jail.
     *
     * fail2ban-client(1): "-d  dump configuration. For debugging". It is the only source that answers
     * "what does fail2ban read", which is neither "what I wrote" nor "what is loaded now":
     * they are three different things, and for half a day I confused the first with the third. If
     * "addaction" appears here the configuration is read correctly and the problem is in applying it;
     * if it does not appear, the problem is in the file.
     *
     * It only reads.
     */
    static String readConfiguration(String jail) {
        Shell.Result r = Shell.run(Duration.ofSeconds(20), CLIENT, "--dp");
        if (!r.success() || r.output() == null || r.output().isBlank())
            r = Shell.run(Duration.ofSeconds(20), CLIENT, "-d");
        if (!r.success() || r.output() == null || r.output().isBlank())
            return I18n.tr("server.banfix.noDump");
        java.util.List<String> theirs = new ArrayList<>();
        for (String line : r.output().split("\n"))
            if (line.contains("'" + jail + "'") || line.contains("\"" + jail + "\"")) theirs.add(line);
        return theirs.isEmpty()
            ? "(" + I18n.tr("server.banfix.dumpNoLine", java.util.Map.of("jail", String.valueOf(jail))) + ")"
            : String.join("\n", theirs);
    }

    /** What fail2ban answers when asked for the actions of a jail, verbatim. */
    private static String actionsOutput(String jail) {
        Shell.Result a = Shell.run(Duration.ofSeconds(10), CLIENT, "get", jail, "actions");
        String u = a.output() == null ? "" : a.output().trim();
        return u.isEmpty() ? I18n.tr("server.banfix.noAnswer") : u;
    }

    private static String banCommand(String jail) {
        Shell.Result a = Shell.run(Duration.ofSeconds(10), CLIENT, "get", jail, "actions");
        if (!a.success()) return null;
        String queue = a.output().contains(":")
            ? a.output().substring(a.output().lastIndexOf(':') + 1) : a.output();
        for (String az : queue.split(",")) {
            String name = az.trim();
            if (name.isEmpty() || !name.matches("[A-Za-z0-9._-]+")) continue;
            Shell.Result c = Shell.run(Duration.ofSeconds(10), CLIENT, "get", jail, "action", name, "actionban");
            if (c.success() && !c.output().trim().isEmpty()) return c.output().trim();
        }
        return null;
    }

    private static final String BACKUP_FOLDER = "/var/db/daemoxcp-mail/fail2ban-backups";

    /**
     * The backup copy goes OUTSIDE jail.d.
     *
     * Fail2ban loads the files of that folder, and a copy left in there is a second
     * file that defines the same jail one step away from being read: a name ending in
     * .conf is enough. The first copies today ended up right there, and in the diagnosis they
     * appeared next to the real file as if they were active configurations: an ambiguity that
     * must not exist in a file that decides who gets in.
     */
    private static Path copy(Path f) throws Exception {
        Path dir = Paths.get(BACKUP_FOLDER);
        Files.createDirectories(dir);
        Path c = dir.resolve(f.getFileName().toString() + ".before-pf-"
            + java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")));
        Files.copy(f, c);
        copies.put(c, f);
        return c;
    }

    /** Where to restore each copy: the file name is no longer enough to tell. */
    private static final java.util.Map<Path, Path> copies = new java.util.concurrent.ConcurrentHashMap<>();

    private static void restore(List<Path> done) {
        for (Path c : done) {
            try {
                Path orig = BanActionRepair.copies.get(c);
                if (orig != null) Files.copy(c, orig, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception ignore) { }
        }
    }

    private static JSONObject step(String name, boolean ok, String text) {
        return new JSONObject().put("step", name).put("ok", ok).put("text", text);
    }
}
