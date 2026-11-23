package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * At startup: the startup script that the panel wrote on the day of the installation
 * (/usr/local/etc/rc.d/mailpanel) still cites the files by their previous names.
 *
 * <p>PathMigration renames `/var/db/daemoxcp-mail/pannello.log` to panel.log, but the script of a server
 * installed before the rename makes daemon(8) write exactly that name (mailpanel_log). At the next
 * restart the log would start again under the old name, next to the new one: PathMigration would see
 * the two names and, rightly, would not choose, and the panel would show a log that has stopped. Seen on
 * the production server on 2026-10-31, where the script had been written by the version of 11 October.
 * On the VM it did not show: there the panel was started by hand, without a script.
 *
 * <p>And the two messages of the script, which were born in Italian (`Avvio mailpanel (solo web). Registro: ...`,
 * "Starting mailpanel (web only). Log: ...", after service mailpanel start): outside the language files the
 * panel speaks English, and the installation guide is in English. Seen following the guide on the clean VM
 * on 2026-11-16 (MESSAGES).
 *
 * <p>Only the script written by the panel is touched (recognized by the MARKER line), and inside it only the
 * whole paths that the data file gives as renamed (LegacyNames, section "files") and the whole lines of the
 * previous messages. The new script is written alongside, tested with sh -n, takes the owner and
 * permissions of the old one and replaces it with a rename: rc(8) never sees a half-written script.
 * Repeating it changes nothing.
 */
public final class RcScriptRepair {

    private static final Logger LOGGER = Logger.getLogger(RcScriptRepair.class.getName());

    /** The line with which the panel signs the script (UpdateManager writes it from here). */
    static final String MARKER = "Generato dal pannello il giorno dell'installazione";

    /**
     * The current script and those with the previous names (section "rcNames"), which PanelServiceRename could
     * not move.
     */
    static final List<Path> SCRIPTS = scripts();

    private static List<Path> scripts() {
        List<Path> out = new ArrayList<>(List.of(Path.of(PanelRcScript.PATH)));
        for (String[] p : LegacyNames.pairs("rcNames")) {
            out.add(Path.of("/usr/local/etc/rc.d", p[0]));
            out.add(Path.of("/etc/rc.d", p[0]));
        }
        return List.copyOf(out);
    }

    /** The script was written by the panel: the line of the previous versions or the current signature (PanelMarker). */
    static boolean writtenByPanel(String script) {
        return script.contains(MARKER) || PanelMarker.writtenByPanel(script);
    }

    /**
     * The two messages as it repairs them in the previous scripts (their variable is mailpanel_log); the current
     * script has them written by PanelRcScript.
     */
    static final String STARTING = "echo \"Starting ${name} (web only). Log: ${mailpanel_log}\"";
    static final String RUNNING = "echo \"${name}: already running (pid $(cat ${pidfile}))\"";

    /** The message lines as the previous versions wrote them, and the current ones. */
    static final List<String[]> MESSAGES = List.of(
            new String[] {"echo \"Avvio ${name} (solo web). Registro: ${mailpanel_log}\"", STARTING},
            new String[] {"echo \"${name}: gia' in esecuzione (pid $(cat ${pidfile}))\"", RUNNING});

    private RcScriptRepair() {}

    enum Outcome { NOTHING, NOT_OURS, REFUSED, DONE }

    record Report(Outcome outcome, String detail) {}

    /**
     * The script with the current paths in place of the previous ones. A path counts only as a whole:
     * followed by quotes, by a space, by ";" or "/", or by the end of the line.
     */
    static String current(String script, List<String[]> pairs) {
        String s = script;
        for (String[] p : pairs)
            s = Pattern.compile(Pattern.quote(p[0]) + "(?=[\"'\\s;/]|$)", Pattern.MULTILINE)
                    .matcher(s).replaceAll(Matcher.quoteReplacement(p[1]));
        return s;
    }

    /** The script with the current messages in place of the previous ones: only whole lines. */
    static String currentMessages(String script) {
        String s = script;
        for (String[] m : MESSAGES)
            s = Pattern.compile("^([ \\t]*)" + Pattern.quote(m[0]) + "$", Pattern.MULTILINE)
                    .matcher(s).replaceAll("$1" + Matcher.quoteReplacement(m[1]));
        return s;
    }

    /** The previous paths that the script cites, in the order of the data file. */
    static List<String> oldPathsIn(String script, List<String[]> pairs) {
        List<String> out = new ArrayList<>();
        for (String[] p : pairs)
            if (Pattern.compile(Pattern.quote(p[0]) + "(?=[\"'\\s;/]|$)", Pattern.MULTILINE).matcher(script).find()) out.add(p[0]);
        return out;
    }

    /** Repairs a script. syntaxCheck tests the file written alongside (sh -n on the server). */
    static Report repair(Path script, List<String[]> pairs, Function<Path, Shell.Result> syntaxCheck) throws IOException {
        if (!Files.isRegularFile(script, LinkOption.NOFOLLOW_LINKS)) return new Report(Outcome.NOTHING, "");
        String text = Files.readString(script, StandardCharsets.UTF_8);
        List<String> old = oldPathsIn(text, pairs);
        String repaired = currentMessages(current(text, pairs));
        boolean messages = !currentMessages(text).equals(text);
        if (repaired.equals(text)) return new Report(Outcome.NOTHING, "");
        if (!writtenByPanel(text))
            return new Report(Outcome.NOT_OURS, script + " cites " + (old.isEmpty() ? "the old messages" : old)
                    + " but was not written by the panel: left alone");
        // A file that starts with a dot: rc(8) takes the rc.d scripts with a glob, which does not see it.
        Path temp = script.resolveSibling("." + script.getFileName() + ".panel-new");
        try {
            Files.writeString(temp, repaired, StandardCharsets.UTF_8);
            Shell.Result check = syntaxCheck.apply(temp);
            if (!check.success())
                return new Report(Outcome.REFUSED, "sh -n refused the repaired " + script + ": " + check.outputTrim() + "; left as it was");
            sameOwnerAndMode(script, temp);
            Files.move(temp, script, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            return new Report(Outcome.DONE, script + ": " + (old.isEmpty() ? "" : old + " now with the current names")
                    + (old.isEmpty() || !messages ? "" : ", ") + (messages ? "messages in English" : ""));
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static void sameOwnerAndMode(Path from, Path to) throws IOException {
        PosixFileAttributes a = Files.readAttributes(from, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        PosixFileAttributeView v = Files.getFileAttributeView(to, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        v.setOwner(a.owner());
        v.setGroup(a.group());
        v.setPermissions(a.permissions());
    }

    public static void ensureAtBoot() {
        for (Path p : SCRIPTS) {
            try {
                Report r = repair(p, LegacyNames.pairs("files"),
                        f -> Shell.run(Duration.ofSeconds(30), "sh", "-n", f.toString()));
                if (r.outcome() == Outcome.NOTHING) continue;
                String line = "[RcScriptRepair] " + r.outcome() + ": " + r.detail();
                if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
            } catch (Throwable t) {
                LOGGER.warning("[RcScriptRepair] " + p + ": " + t);
            }
        }
    }
}
