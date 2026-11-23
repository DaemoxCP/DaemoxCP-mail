package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.Fail2banAutoSetup;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * At service startup: the fail2ban jail for panel logins takes the new name (DaemoxCP Mail,
 * 2026-11-17): mail-panel-auth becomes daemoxcp-mail-auth.
 *
 * <p>The name travels between four places, like that of the public surface (PublicSurfaceRename): the login
 * log the panel writes (/var/log/NAME.log), the filter (filter.d/NAME.conf), the [NAME] section of
 * jail.local that reads it and bans in pf (still f2b/NAME), and the newsyslog rotation. If only one of them moves, the
 * jail watches a log nobody writes any more and bans nothing, without giving errors. So all or nothing:
 * <ol>
 *   <li>the log with its rotated copies takes the new name (the panel, just started, has not opened it
 *       yet: it will already write to the new name);</li>
 *   <li>the filter takes the new name, with the current signature;</li>
 *   <li>in jail.local the section changes name, filter, log and action name; the rest stays as it was, even
 *       what the administrator changed by hand;</li>
 *   <li>the newsyslog rotation takes the new name and log;</li>
 *   <li>in the fail2ban database the bans and the position in the log move to the new jail (without banning again: the
 *       recidive jail would count them, see PublicSurfaceRename);</li>
 *   <li>fail2ban-client -t, reload, and the new jail must be there.</li>
 * </ol>
 * At the first step that does not work out everything is put back as it was and fail2ban is reloaded: at the next
 * startup it tries again.
 *
 * <p>The previous name is in legacy-names.json (section "authJail").
 */
public final class AuthJailRename {

    private static final Logger LOGGER = Logger.getLogger(AuthJailRename.class.getName());

    enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Where the files are: fixed on the server, temporary folders in the test. */
    record Places(Path f2bDir, Path logDir, Path newsyslogDir) {}

    /** fail2ban, kept separate to test it without the real service. */
    interface Services {
        /** fail2ban is running and answers. */
        boolean running();
        /** fail2ban-client -t: null if the configuration works, otherwise what it says. */
        String test();
        /** fail2ban-client reload: null if it worked. */
        String reload();
        /** The jail exists in fail2ban. */
        boolean jailExists(String jail);
        /** Bans and log position of the jail {@code from} move to {@code to}. */
        boolean moveState(String from, String to, String fromLog, String toLog);
    }

    private AuthJailRename() {}

    public static void ensureAtBoot() {
        Places at = new Places(Path.of("/usr/local/etc/fail2ban"), Path.of("/var/log"), Path.of("/usr/local/etc/newsyslog.conf.d"));
        for (String[] p : LegacyNames.pairs("authJail")) {
            try {
                Report r = rename(p[0], p[1], at, new RealServices());
                if (r.outcome() == Outcome.NOTHING) continue;
                String line = "[AuthJailRename] " + r.outcome() + ": " + r.detail();
                if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
            } catch (Throwable t) {
                LOGGER.warning("[AuthJailRename] failed: " + t);
            }
        }
    }

    // ===================== pure functions =====================

    /**
     * jail.local with the [oldName] section called [newName]: inside the section the filter name, the log and the
     * action name change; the rest of the file and of the section stays as it was. Null if the section is not there.
     */
    static String renamedSection(String jailLocal, String oldName, String newName, String oldLog, String newLog) {
        Matcher h = Pattern.compile("(?m)^\\[" + Pattern.quote(oldName) + "\\]\\s*$").matcher(jailLocal);
        if (!h.find()) return null;
        int start = h.start();
        Matcher next = Pattern.compile("(?m)^\\[").matcher(jailLocal);
        int end = next.find(h.end()) ? next.start() : jailLocal.length();
        String section = jailLocal.substring(start, end)
                .replace("[" + oldName + "]", "[" + newName + "]")
                .replace(oldLog, newLog);
        section = Pattern.compile("(?m)^(filter\\s*=\\s*)" + Pattern.quote(oldName) + "\\s*$").matcher(section)
                .replaceAll("$1" + Matcher.quoteReplacement(newName));
        section = section.replace("name=" + oldName + ",", "name=" + newName + ",").replace("name=" + oldName + "]", "name=" + newName + "]");
        // The header line the panel writes above the section, if present, takes the current signature.
        String before = PanelMarker.current(jailLocal.substring(0, start), "productComments");
        return before + section + jailLocal.substring(end);
    }

    // ===================== the switchover =====================

    private record Step(Path from, Path to, String before) {}

    static Report rename(String oldName, String newName, Places at, Services sv) throws IOException {
        Path jailLocal = at.f2bDir().resolve("jail.local");
        Path oldFilter = at.f2bDir().resolve("filter.d").resolve(oldName + ".conf");
        Path newFilter = at.f2bDir().resolve("filter.d").resolve(newName + ".conf");
        Path oldNewsyslog = at.newsyslogDir().resolve(oldName + ".conf");
        Path newNewsyslog = at.newsyslogDir().resolve(newName + ".conf");
        String oldLog = at.logDir().resolve(oldName + ".log").toString();
        String newLog = at.logDir().resolve(newName + ".log").toString();

        String jail = Files.isRegularFile(jailLocal) ? Files.readString(jailLocal, StandardCharsets.UTF_8) : "";
        boolean section = Pattern.compile("(?m)^\\[" + Pattern.quote(oldName) + "\\]\\s*$").matcher(jail).find();
        boolean anything = section || Files.exists(oldFilter, LinkOption.NOFOLLOW_LINKS) || Files.exists(Path.of(oldLog), LinkOption.NOFOLLOW_LINKS)
                || Files.exists(oldNewsyslog, LinkOption.NOFOLLOW_LINKS);
        if (!anything) return new Report(Outcome.NOTHING, "");
        if (Pattern.compile("(?m)^\\[" + Pattern.quote(newName) + "\\]\\s*$").matcher(jail).find() || Files.exists(newFilter, LinkOption.NOFOLLOW_LINKS))
            return new Report(Outcome.LEFT, "both " + oldName + " and " + newName + " exist in fail2ban: " + oldName + " left as it is");
        if (Files.exists(oldFilter) && !Fail2banAutoSetup.ownFilter(Files.readString(oldFilter, StandardCharsets.UTF_8)))
            return new Report(Outcome.LEFT, oldFilter + " was not written by the panel: left as it is");

        List<Path[]> movedLogs = new ArrayList<>();
        List<Step> written = new ArrayList<>();
        boolean filterMoved = false, newsyslogMoved = false;
        String newJail = section ? renamedSection(jail, oldName, newName, oldLog, newLog) : null;
        try {
            // 1. the log and its rotated copies (NAME.log.0.bz2 ...)
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(at.logDir(), oldName + ".log*")) {
                for (Path f : ds) {
                    Path to = at.logDir().resolve(newName + f.getFileName().toString().substring(oldName.length()));
                    if (Files.exists(to, LinkOption.NOFOLLOW_LINKS)) continue;
                    Files.move(f, to, StandardCopyOption.ATOMIC_MOVE);
                    movedLogs.add(new Path[] {f, to});
                }
            }
            // 2. the filter, with the current signature
            if (Files.exists(oldFilter, LinkOption.NOFOLLOW_LINKS)) {
                String f = Files.readString(oldFilter, StandardCharsets.UTF_8);
                Files.move(oldFilter, newFilter, StandardCopyOption.ATOMIC_MOVE);
                filterMoved = true;
                String n = PanelMarker.current(f, Fail2banAutoSetup.MARKER_SECTION).replace(oldLog, newLog)
                        .replace("/" + oldName + ".conf", "/" + newName + ".conf");
                if (!n.equals(f)) {
                    PanelMarker.replaceKeeping(newFilter, n);
                    written.add(new Step(newFilter, newFilter, f));
                }
            }
            // 3. the jail.local section
            if (newJail != null) {
                PanelMarker.replaceKeeping(jailLocal, newJail);
                written.add(new Step(jailLocal, jailLocal, jail));
            }
            // 4. newsyslog
            if (Files.exists(oldNewsyslog, LinkOption.NOFOLLOW_LINKS)) {
                String f = Files.readString(oldNewsyslog, StandardCharsets.UTF_8);
                Files.move(oldNewsyslog, newNewsyslog, StandardCopyOption.ATOMIC_MOVE);
                newsyslogMoved = true;
                String n = PanelMarker.current(f, "newsyslogHeaders").replace(oldLog, newLog);
                if (!n.equals(f)) {
                    PanelMarker.replaceKeeping(newNewsyslog, n);
                    written.add(new Step(newNewsyslog, newNewsyslog, f));
                }
            }
        } catch (IOException | RuntimeException e) {
            String back = putBack(movedLogs, written, filterMoved ? new Path[] {oldFilter, newFilter} : null,
                    newsyslogMoved ? new Path[] {oldNewsyslog, newNewsyslog} : null);
            return new Report(Outcome.ROLLED_BACK, "moving failed (" + e.getMessage() + ")" + back);
        }

        if (!sv.running())
            return new Report(Outcome.DONE, oldName + " -> " + newName + " (fail2ban is not running: it reads the new names when it starts)");
        String problem = sv.test();
        if (problem == null) {
            if (section && !sv.moveState(oldName, newName, oldLog, newLog))
                LOGGER.warning("[AuthJailRename] the bans of " + oldName + " were not carried over: they expire within the hour");
            problem = sv.reload();
            if (problem == null && section && !sv.jailExists(newName)) problem = "fail2ban has no jail " + newName + " after the reload";
        }
        if (problem != null) {
            String back = putBack(movedLogs, written, filterMoved ? new Path[] {oldFilter, newFilter} : null,
                    newsyslogMoved ? new Path[] {oldNewsyslog, newNewsyslog} : null);
            sv.reload();
            return new Report(Outcome.ROLLED_BACK, problem + back);
        }
        return new Report(Outcome.DONE, oldName + " -> " + newName + ": log " + newLog + (movedLogs.size() > 1 ? " (with "
                + (movedLogs.size() - 1) + " rotated copies)" : "") + ", filter, jail.local, newsyslog; fail2ban reloaded");
    }

    private static String putBack(List<Path[]> logs, List<Step> written, Path[] filter, Path[] newsyslog) {
        List<String> problems = new ArrayList<>();
        for (int i = written.size() - 1; i >= 0; i--) {
            Step s = written.get(i);
            try { PanelMarker.replaceKeeping(s.to(), s.before()); } catch (IOException e) { problems.add(s.to() + ": " + e.getMessage()); }
        }
        for (Path[] p : new Path[][] {newsyslog, filter}) {
            if (p == null) continue;
            try { Files.move(p[1], p[0], StandardCopyOption.ATOMIC_MOVE); } catch (IOException e) { problems.add(p[1] + ": " + e.getMessage()); }
        }
        for (Path[] l : logs) {
            try { Files.move(l[1], l[0], StandardCopyOption.ATOMIC_MOVE); } catch (IOException e) { problems.add(l[1] + ": " + e.getMessage()); }
        }
        return problems.isEmpty() ? "; everything put back as it was" : "; NOT put back: " + String.join(", ", problems);
    }

    static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(20);
        private static final Duration LONG = Duration.ofSeconds(120);

        @Override public boolean running() {
            return Shell.resolve("fail2ban-client") != null && Shell.run(SHORT, "fail2ban-client", "ping").success();
        }
        @Override public String test() {
            Shell.Result r = Shell.run(LONG, "fail2ban-client", "-t");
            return r.success() ? null : r.outputTrim();
        }
        @Override public String reload() {
            Shell.Result r = Shell.run(LONG, "fail2ban-client", "reload");
            return r.success() ? null : r.outputTrim();
        }
        @Override public boolean jailExists(String jail) {
            Shell.Result r = Shell.run(SHORT, "fail2ban-client", "status", jail);
            return r.success() && !r.output().contains("does not exist");
        }
        @Override public boolean moveState(String from, String to, String fromLog, String toLog) {
            return PublicSurfaceRename.moveFail2banJailState(from, to, fromLog, toLog, "AuthJailRename");
        }
    }
}
