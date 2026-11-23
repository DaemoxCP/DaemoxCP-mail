package org.daemoxcp.mail.system;

import org.daemoxcp.mail.database.SqlCatalog;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * At startup: the public surface on 443 moves from `mailpanel-pubblico` to "mailpanel-public"
 * on the servers installed before the rename (r26, 2026-10-30).
 *
 * <p>PathMigration moves the files that only the panel reads. Not these: the name travels
 * between three services. nginx includes NAME.conf and writes /var/log/nginx/NAME-access.log;
 * fail2ban reads that log with filter.d/NAME.conf and jail.d/NAME.conf, and bans in pf in the
 * anchor f2b/NAME, table f2b-NAME. If only one of them is moved, the jail watches a log that
 * nobody writes any more, and bans nothing without giving any error. So all or nothing.
 *
 * <p>How it behaves:
 * <ul>
 *   <li>nothing with the old name: it does nothing, and does not even run nginx -T (that is the
 *       case of every startup after the first);</li>
 *   <li>an old file not written by the panel (the signature is missing, see PanelMarker), the
 *       new name already present next to the old one, or two old files in two nginx folders:
 *       it touches nothing and writes so in the log, like PathMigration: choosing is not its job;</li>
 *   <li>otherwise: it moves the log with its rotated copies and the three files, changing the
 *       name inside; then nginx -t and nginx reload; it moves the jail state in the fail2ban
 *       database; fail2ban reload, and it asks fail2ban whether the new jail exists. At the first
 *       step that fails it puts everything back as it was, state included, and reloads: at the
 *       next startup it tries again.</li>
 * </ul>
 *
 * <p>The content of the old files stays the same, changed only in the name and in the signature
 * (which moves to English as PanelMarker does for the files already renamed): it is a rename, not
 * a repair (that is done by installJail and BanActionRepair). In the files written by the panel
 * the old name appears only where it is a name.
 *
 * <p>Together with the surface, the folder of its files moves too, `/var/db/daemoxcp-mail/pubblico`
 * -> public: nginx reads it (alias .../mta-sts.txt), so it is not in PathMigration but here, in
 * the same all-or-nothing, and the path inside the nginx file changes with it. Measured on the
 * production server on 2026-10-31: with the folder moved by PathMigration and the nginx file still
 * citing the old one, the MTA-STS policy would have become a 404. If the folder is already the new
 * one and the nginx file (already renamed) still cites the old one, only that file is rewritten.
 *
 * <p>The bans: fail2ban keeps them per jail, in its database, and when a jail starts it restores
 * those not yet expired. A jail with another name would start empty. So before the reload the bans
 * and the position reached in the log are handed over to the new jail, in the database: the new
 * jail picks them up with the time that was left, and does not read the already-read log again from
 * the start. They are NOT banned again with "banip": every ban writes a "Ban" line in the fail2ban
 * log, and the recidive jail counts them (three in a day: one week on all ports). Banning again for
 * a rename could have locked out for a week, mail included, an address that already had two bans:
 * it happened to the Mac in the test on the VM on 2026-10-30. If the database cannot be updated the
 * rename goes ahead all the same, and the bans of the old jail expire within the hour.
 */
public final class PublicSurfaceRename {

    private static final Logger LOGGER = Logger.getLogger(PublicSurfaceRename.class.getName());

    /** The previous name, from the data file: it is needed only to find it on disk. */
    static String OLD_NAME = LegacyNames.single("publicSurface");
    static final String NEW_NAME = WebProtection.NAME;
    /** The folder of the public files: the previous one from the data file, the current one from WebProtection. */
    static final String OLD_FOLDER = LegacyNames.single("publicFolder");
    static final String NEW_FOLDER = WebProtection.PUBLIC_DIR;

    private PublicSurfaceRename() {}

    enum Outcome { NOTHING, SAME_NAMES, NOT_OURS, BOTH_NAMES, AMBIGUOUS, NGINX_UNREADABLE, DONE, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Where the files are: fixed on the server, temporary folders in the test. */
    record Places(Path f2bDir, Path logDir, Path defaultNginxFolder, Path oldFolder, Path newFolder) {}

    /** What is needed from nginx and fail2ban, kept apart so that it can be tested without the real services. */
    interface Services {
        /** The folders nginx includes (nginx -T); empty without nginx, null if nginx does not answer. */
        List<String> nginxFolders();
        boolean nginxRunning();
        Shell.Result nginxTest();
        Shell.Result nginxReload();
        boolean fail2banRunning();
        Shell.Result fail2banReload();
        /** The addresses banned by the jail, or null if fail2ban does not have that jail. */
        List<String> banned(String jail);
        /**
         * In the fail2ban database, the bans and the log position of the jail {@code from} move to
         * {@code to} (with the log {@code toLog} in place of {@code fromLog}). False if it could not be done.
         */
        boolean moveJailState(String from, String to, String fromLog, String toLog);
    }

    public static void ensureAtBoot() {
        try {
            Places at = new Places(Path.of(WebProtection.F2B_DIR), Path.of(WebProtection.LOG_DIR),
                    Path.of(WebProtection.PROPOSED_FOLDER), OLD_FOLDER.isEmpty() ? null : Path.of(OLD_FOLDER), Path.of(NEW_FOLDER));
            // Every previous name, in the order of the data file: in Italian, then with the previous
            // product name (mailpanel-public, until 2026-11-17). A server has at most one of them.
            for (String[] p : LegacyNames.pairs("publicSurface")) {
                OLD_NAME = p[0];
                Report r = migrate(at, new RealServices());
                if (r.outcome() == Outcome.NOTHING) continue;
                String line = "[PublicSurfaceRename] " + r.outcome() + ": " + r.detail();
                if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
            }
        } catch (Throwable t) {
            LOGGER.warning("[PublicSurfaceRename] failed: " + t);
        }
    }

    static Report migrate(Places at, Services sv) throws IOException {
        if (OLD_NAME.isEmpty()) return new Report(Outcome.NOTHING, "");
        // A rename pass over the code can ALSO change the old name in here:
        // without this guard the result would be a false "nothing to do".
        if (OLD_NAME.equals(NEW_NAME))
            return new Report(Outcome.SAME_NAMES, "old and new name are the same: the old name was renamed too");

        Path oldJail = at.f2bDir().resolve("jail.d").resolve(OLD_NAME + ".conf");
        Path newJail = oldJail.resolveSibling(NEW_NAME + ".conf");
        Path oldFilter = at.f2bDir().resolve("filter.d").resolve(OLD_NAME + ".conf");
        List<Path> oldLogs = logsNamed(at.logDir(), OLD_NAME);
        Path defaultConf = at.defaultNginxFolder().resolve(OLD_NAME + ".conf");
        Path oldFolder = at.oldFolder(), newFolder = at.newFolder();
        boolean folderMoves = oldFolder != null && exists(oldFolder);
        Path defaultNewConf = at.defaultNginxFolder().resolve(NEW_NAME + ".conf");
        boolean staleDefault = oldFolder != null && exists(defaultNewConf)
                && citesFolder(Files.readString(defaultNewConf, StandardCharsets.UTF_8), oldFolder);
        if (!exists(oldJail) && !exists(oldFilter) && oldLogs.isEmpty() && !exists(defaultConf) && !folderMoves && !staleDefault)
            return new Report(Outcome.NOTHING, "");

        // The nginx file is in one of the folders nginx includes: nginx is asked which ones.
        List<String> folders = sv.nginxFolders();
        if (folders == null)
            return new Report(Outcome.NGINX_UNREADABLE, "nginx -T failed: nothing moved, retrying at the next start");
        Set<Path> confs = new LinkedHashSet<>();
        for (String f : folders) {
            Path c = Path.of(f).resolve(OLD_NAME + ".conf");
            if (exists(c)) confs.add(c);
        }
        if (exists(defaultConf)) confs.add(defaultConf);
        if (confs.size() > 1)
            return new Report(Outcome.AMBIGUOUS, "more than one " + OLD_NAME + ".conf for nginx " + confs + ": nothing moved");
        Path oldConf = confs.isEmpty() ? null : confs.iterator().next();
        // The file with the new name that still cites the old folder: it is rewritten in place.
        Path staleConf = null;
        if (oldConf == null && oldFolder != null) {
            Set<Path> stale = new LinkedHashSet<>();
            for (String f : folders) {
                Path c = Path.of(f).resolve(NEW_NAME + ".conf");
                if (exists(c) && citesFolder(Files.readString(c, StandardCharsets.UTF_8), oldFolder)) stale.add(c);
            }
            if (staleDefault) stale.add(defaultNewConf);
            if (stale.size() > 1)
                return new Report(Outcome.AMBIGUOUS, "more than one " + NEW_NAME + ".conf for nginx " + stale + ": nothing moved");
            staleConf = stale.isEmpty() ? null : stale.iterator().next();
        }

        // The pairs to move: old -> new, and how the content changes (null: it does not change).
        java.util.function.UnaryOperator<String> rewrite = c -> renamed(c, oldFolder, newFolder);
        List<Move> moves = new ArrayList<>();
        for (Path p : oldLogs)
            moves.add(new Move(p, p.resolveSibling(NEW_NAME + p.getFileName().toString().substring(OLD_NAME.length())), null));
        if (folderMoves) moves.add(new Move(oldFolder, newFolder, null));
        if (oldConf != null) moves.add(new Move(oldConf, oldConf.resolveSibling(NEW_NAME + ".conf"), rewrite));
        if (staleConf != null) moves.add(new Move(staleConf, staleConf, rewrite));
        if (exists(oldFilter)) moves.add(new Move(oldFilter, oldFilter.resolveSibling(NEW_NAME + ".conf"), rewrite));
        boolean jailMoves = exists(oldJail);
        if (jailMoves) moves.add(new Move(oldJail, newJail, rewrite));
        boolean confTouched = oldConf != null || staleConf != null;

        // First look at everything, then touch: no step starts if even one of them cannot start.
        for (Move m : moves) {
            if (!m.from().equals(m.to()) && exists(m.to()))
                return new Report(Outcome.BOTH_NAMES, "both " + m.from() + " and " + m.to() + " exist: nothing moved");
            if (m.rewrites() && !PanelMarker.writtenByPanel(Files.readString(m.from(), StandardCharsets.UTF_8)))
                return new Report(Outcome.NOT_OURS, m.from() + " was not written by the panel: nothing moved, rename it by hand");
        }

        boolean f2bRunning = (jailMoves || exists(oldFilter)) && sv.fail2banRunning();
        List<String> bans = new ArrayList<>();
        if (f2bRunning) {
            List<String> b = sv.banned(OLD_NAME);
            if (b != null) bans.addAll(b);
        }
        String oldLog = at.logDir().resolve(OLD_NAME + "-access.log").toString();
        String newLog = at.logDir().resolve(NEW_NAME + "-access.log").toString();
        boolean stateMoved = false;
        boolean nginxRunning = confTouched && sv.nginxRunning();

        Deque<Move> done = new ArrayDeque<>();
        try {
            try {
                for (Move m : moves) { m.apply(); done.push(m); }
            } catch (IOException e) {
                return rollBack(done, sv, false, false, "could not move the files: " + e.getMessage());
            }

            if (confTouched) {
                Shell.Result t = sv.nginxTest();
                if (!t.success()) return rollBack(done, sv, false, false, "nginx -t refused the renamed file: " + t.outputTrim());
                if (nginxRunning) {
                    Shell.Result rl = sv.nginxReload();
                    if (!rl.success()) return rollBack(done, sv, true, false, "nginx reload failed: " + rl.outputTrim());
                }
            }
            if (f2bRunning) {
                if (jailMoves) stateMoved = sv.moveJailState(OLD_NAME, NEW_NAME, oldLog, newLog);
                Shell.Result rl = sv.fail2banReload();
                if (!rl.success()) {
                    if (stateMoved) sv.moveJailState(NEW_NAME, OLD_NAME, newLog, oldLog);
                    return rollBack(done, sv, nginxRunning, true, "fail2ban reload failed: " + rl.outputTrim());
                }
                if (jailMoves && sv.banned(NEW_NAME) == null) {
                    if (stateMoved) sv.moveJailState(NEW_NAME, OLD_NAME, newLog, oldLog);
                    return rollBack(done, sv, nginxRunning, true, "fail2ban does not report the jail " + NEW_NAME + " after the reload");
                }
            }
        } catch (RuntimeException e) {
            if (stateMoved) sv.moveJailState(NEW_NAME, OLD_NAME, newLog, oldLog);
            return rollBack(done, sv, nginxRunning, f2bRunning, "unexpected error: " + e);
        }

        StringBuilder d = new StringBuilder("moved");
        for (Move m : moves) d.append(' ').append(m.from()).append(" -> ").append(m.to().getFileName()).append(';');
        if (f2bRunning && sv.banned(OLD_NAME) != null)
            d.append(" WARNING: fail2ban still reports the old jail ").append(OLD_NAME).append(';');
        if (f2bRunning && jailMoves && !stateMoved)
            d.append(" WARNING: fail2ban database not updated, ").append(bans.size())
             .append(" bans of ").append(OLD_NAME).append(" not carried over (they expire within the hour);");
        else if (!bans.isEmpty()) {
            List<String> now = sv.banned(NEW_NAME);
            int kept = 0;
            if (now != null) for (String ip : bans) if (now.contains(ip)) kept++;
            d.append(' ').append(kept).append(" of ").append(bans.size()).append(" bans kept by ").append(NEW_NAME);
            if (kept < bans.size()) d.append(" (WARNING: some were not)");
        }
        return new Report(Outcome.DONE, d.toString());
    }

    /**
     * Puts every file back as it was, in reverse order, and reloads the services already reloaded.
     * The jail state in the fail2ban database has already been restored by the caller: on restarting,
     * the old jail picks up its bans from there.
     */
    private static Report rollBack(Deque<Move> done, Services sv,
                                   boolean reloadNginx, boolean reloadF2b, String why) {
        List<String> problems = new ArrayList<>();
        while (!done.isEmpty()) {
            Move m = done.pop();
            try { m.undo(); } catch (IOException e) { problems.add(m.from() + ": " + e.getMessage()); }
        }
        if (reloadNginx) {
            Shell.Result r = sv.nginxReload();
            if (!r.success()) problems.add("nginx reload: " + r.outputTrim());
        }
        if (reloadF2b) {
            Shell.Result r = sv.fail2banReload();
            if (!r.success()) problems.add("fail2ban reload: " + r.outputTrim());
        }
        return new Report(Outcome.ROLLED_BACK, why + "; everything put back"
                + (problems.isEmpty() ? "" : " EXCEPT: " + String.join("; ", problems)));
    }

    /**
     * A move (a file or a folder), with what is needed to undo it. Does not follow links.
     * from equal to to: the file stays where it is and changes only inside.
     */
    private static final class Move {
        private final Path from, to;
        private final java.util.function.UnaryOperator<String> rewrite;
        private String before;

        Move(Path from, Path to, java.util.function.UnaryOperator<String> rewrite) { this.from = from; this.to = to; this.rewrite = rewrite; }
        Path from() { return from; }
        Path to() { return to; }
        boolean rewrites() { return rewrite != null; }

        void apply() throws IOException {
            if (rewrite != null) before = Files.readString(from, StandardCharsets.UTF_8);
            // The file is moved instead of writing a new one: owner and permissions stay.
            if (!from.equals(to)) Files.move(from, to);
            if (rewrite != null) Files.writeString(to, rewrite.apply(before), StandardCharsets.UTF_8);
        }

        void undo() throws IOException {
            if (rewrite != null) Files.writeString(to, before, StandardCharsets.UTF_8);
            if (!from.equals(to)) Files.move(to, from);
        }
    }

    /** The content with the new name, the current signature and, if present, the new folder in place of the old one. */
    static String renamed(String content, Path oldFolder, Path newFolder) {
        String c = content.replace(OLD_NAME, NEW_NAME);
        if (oldFolder != null && newFolder != null)
            c = folderReference(oldFolder).matcher(c).replaceAll(Matcher.quoteReplacement(newFolder.toString()));
        return PanelMarker.current(c, PanelMarker.SIGNATURE);
    }

    /** The folder as a whole path: followed by "/", by a separator or by the end, not by other letters. */
    private static Pattern folderReference(Path folder) {
        return Pattern.compile(Pattern.quote(folder.toString()) + "(?=[/;\\s\"']|$)", Pattern.MULTILINE);
    }

    static boolean citesFolder(String content, Path folder) {
        return folderReference(folder).matcher(content).find();
    }

    /** NAME-access.log and its rotated copies (NAME-access.log.0.bz2, ...), not those of others. */
    static List<Path> logsNamed(Path dir, String name) throws IOException {
        if (!Files.isDirectory(dir)) return List.of();
        String log = name + "-access.log";
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> {
                String f = p.getFileName().toString();
                return (f.equals(log) || f.startsWith(log + ".")) && Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS);
            }).sorted().toList();
        }
    }

    private static boolean exists(Path p) {
        return Files.exists(p, LinkOption.NOFOLLOW_LINKS);
    }

    /** The database file from the output of "fail2ban-client get dbfile", or null if it does not use one. */
    static String fail2banDatabase(String output) {
        if (output == null) return null;
        for (String line : output.split("\n")) {
            String t = line.replaceFirst("^[`|\\s-]+", "").trim();
            if (t.startsWith("/") && !t.contains(" ")) return t;
        }
        return null;
    }

    private static final Pattern BANNED = Pattern.compile("Banned IP list:\\s*(.*)");

    /** The addresses from the "Banned IP list:" line of fail2ban-client status. */
    static List<String> bannedFrom(String status) {
        Matcher m = BANNED.matcher(status == null ? "" : status);
        if (!m.find()) return List.of();
        String list = m.group(1).trim();
        return list.isEmpty() ? List.of() : Arrays.asList(list.split("\\s+"));
    }

    private static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(20);
        private static final Duration LONG = Duration.ofSeconds(90);

        @Override public List<String> nginxFolders() {
            if (Shell.resolve("nginx") == null) return List.of();
            Shell.Result r = Shell.run(SHORT, "nginx", "-T");
            return r.success() ? WebProtection.includedFolders(r.output()) : null;
        }
        // "one": they work even if nginx_enable is not YES in rc.conf.
        @Override public boolean nginxRunning() { return Shell.run(SHORT, "service", "nginx", "onestatus").success(); }
        @Override public Shell.Result nginxTest() { return Shell.run(SHORT, "nginx", "-t"); }
        @Override public Shell.Result nginxReload() { return Shell.run(SHORT, "service", "nginx", "onereload"); }
        @Override public boolean fail2banRunning() {
            return Shell.resolve("fail2ban-client") != null && Shell.run(SHORT, "fail2ban-client", "ping").success();
        }
        @Override public Shell.Result fail2banReload() { return Shell.run(LONG, "fail2ban-client", "reload"); }
        @Override public List<String> banned(String jail) {
            Shell.Result r = Shell.run(SHORT, "fail2ban-client", "status", jail);
            // As in BanActionRepair: "does not exist" is read in the text too, not only in the exit code.
            return r.success() && !r.output().contains("does not exist") ? bannedFrom(r.output()) : null;
        }
        @Override public boolean moveJailState(String from, String to, String fromLog, String toLog) {
            return moveFail2banJailState(from, to, fromLog, toLog, "PublicSurfaceRename");
        }
    }

    /**
     * In the fail2ban database, the bans and the log position of the jail {@code from} move to {@code to}: the
     * renamed jail restarts with the bans it had, without banning again (see above, recidive). Also used by
     * AuthJailRename.
     */
    static boolean moveFail2banJailState(String from, String to, String fromLog, String toLog, String who) {
        String db = fail2banDatabase(Shell.run(Duration.ofSeconds(20), "fail2ban-client", "get", "dbfile").output());
        if (db == null) {
            LOGGER.warning("[" + who + "] fail2ban has no database file: bans not carried over");
            return false;
        }
        try (java.sql.Connection c = org.daemoxcp.mail.database.CatalogGuard.open("jdbc:sqlite:" + db);
             java.sql.Statement st = c.createStatement()) {
            // fail2ban keeps the database open: we wait for our turn instead of failing.
            st.execute(SqlCatalog.RENAME_BUSY_TIMEOUT);
            c.setAutoCommit(false);
            try {
                // The schema is fail2ban's (server/database.py): jails, bips, bans, logs.
                exec(c, SqlCatalog.RENAME_ADD_JAIL, to);
                exec(c, SqlCatalog.RENAME_MOVE_JAIL_BIPS, to, from);
                exec(c, SqlCatalog.RENAME_MOVE_JAIL_BANS, to, from);
                exec(c, SqlCatalog.RENAME_MOVE_JAIL_LOGS, to, toLog, from, fromLog);
                c.commit();
                return true;
            } catch (java.sql.SQLException e) {
                c.rollback();
                throw e;
            }
        } catch (Exception e) {
            LOGGER.warning("[" + who + "] cannot move the state of " + from + " to " + to
                    + " in " + db + ": " + e.getMessage());
            return false;
        }
    }

    private static void exec(java.sql.Connection c, String sql, String... args) throws java.sql.SQLException {
        try (java.sql.PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) ps.setString(i + 1, args[i]);
            ps.executeUpdate();
        }
    }
}
