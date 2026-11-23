package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Roundcube with its own user: the "roundcube" user and group, a php-fpm pool of its own with a
 * socket of its own, and the webmail files belonging to it and to nobody else.
 *
 * <p>Before, Roundcube ran in the "www" php-fpm pool, that is with the same user as the nginx
 * processes. A flaw in either of the two handed the other everything it could touch: the
 * Roundcube configuration (the database password, the des_key), the one of the SSO plugin (the
 * key that opens the tokens with the Dovecot master password), the webmail sessions. Now
 * nginx can only open the socket (listen.group = www), and only roundcube reads those files.
 *
 * <p>Three things measured on the FreeBSD 15.1 VM on 2026-10-31 decide how it is made:
 * <ul>
 *   <li>the php84 post-install copies www.conf.default to www.conf if www.conf is missing: removing
 *       the file would bring back, at the first PHP upgrade, a pool running as www. So
 *       www.conf stays, with only comments: php-fpm accepts it (php-fpm -t), as long as the comments
 *       start with ";" -- with "#" it rejects it and does not start;</li>
 *   <li>the roundcube-php84 post-install runs "chown www:www" on logs and temp at every installation
 *       and upgrade: the ownership is reasserted at every startup and after the webmail upgrade
 *       done by the panel ({@link #repairOwnership()});</li>
 *   <li>the rotation the package installs (newsyslog.conf.d/roundcube.conf) recreates the logs as
 *       www:www: after the first rotation Roundcube could no longer write them.</li>
 * </ul>
 *
 * <p>At startup ({@link #ensureAtBoot()}), on servers installed earlier: it creates user and group,
 * writes the roundcube pool carrying over the pm.* values of the www one, leaves www.conf without a
 * pool, fixes the ownership of the files, moves nginx's fastcgi_pass to the new socket. It checks with
 * php-fpm -t and nginx -t, reloads, checks that the pool processes run as roundcube and that the
 * webmail responds with its login page. At the first step that fails it puts everything back as it
 * was and reloads: at the next startup it tries again. It does not choose for anyone: a www.conf that
 * is not the panel's, a www pool that also serves another site, a webmail that already does not
 * respond, all leave everything as it is and write it in the log.
 */
public final class RoundcubeUser {

    private static final Logger LOGGER = Logger.getLogger(RoundcubeUser.class.getName());

    public static final String USER = "roundcube";
    public static final String GROUP = "roundcube";
    /** The group of the nginx processes: it can open the pool's socket, and nothing else. */
    public static final String WEB_GROUP = "www";
    public static final String POOL = "roundcube";
    /**
     * php-fpm's own folder, roundcube's: the master process runs as roundcube (PhpFpmMaster) and makes its socket
     * and its pidfile here; in /var/run, root's, it could not.
     */
    public static final String FPM_RUN_DIR = "/var/run/php-fpm";
    public static final String SOCKET = FPM_RUN_DIR + "/roundcube.sock";
    /** The group that may open the socket: roundcube, which makes it, and nginx's www. Nobody else. */
    public static final String SOCKET_GROUP = "roundcube_fpm";
    /** The socket up to 1.0.1, in /var/run, made by a master process running as root. */
    public static final String ROOT_MASTER_SOCKET = "/var/run/php-fpm-roundcube.sock";
    /** The www pool's socket, as the earlier installation scripts wrote it. */
    public static final String OLD_SOCKET = "/var/run/php-fpm.sock";

    public static final String FPM_DIR = "/usr/local/etc/php-fpm.d";
    public static final String ROUNDCUBE_DIR = "/usr/local/www/roundcube";
    public static final String SESSIONS_DIR = "/var/db/daemoxcp-mail/php_sessions";
    public static final String PHP_ERRORS_LOG = "/var/log/php_errors.log";
    public static final String NEWSYSLOG_DIR = "/usr/local/etc/newsyslog.conf.d";
    public static final String SSO_KEY = "/var/db/daemoxcp-mail/roundcube_sso.key";
    /** The rotation the Roundcube package installs, and the sample it copies it from. */
    static final String ROUNDCUBE_ROTATION_SAMPLE = "/usr/local/share/examples/roundcube/newsyslog.conf";
    /** The copies of the files before the migration, for whoever wants to look at them: outside php-fpm.d. */
    static final String BACKUP_DIR = "/var/db/daemoxcp-mail/service-users-backup";

    /** The pool lines the panel chooses; the others (pm.*) are carried over from the previous one. */
    private static final Set<String> OWN_KEYS = Set.of("user", "group", "listen",
            "listen.owner", "listen.group", "listen.mode");

    private static final String DEFAULT_PM = """
            pm = dynamic
            pm.max_children = 10
            pm.start_servers = 3
            pm.min_spare_servers = 2
            pm.max_spare_servers = 5
            """;

    private RoundcubeUser() {}

    // ===================== the files the panel writes =====================

    /** The Roundcube pool: its own user, its own socket, nginx in the group that opens it. */
    public static String poolConf(String otherLines) {
        String rest = otherLines == null || otherLines.isBlank() ? DEFAULT_PM : otherLines;
        if (!rest.endsWith("\n")) rest += "\n";
        return "; " + PanelMarker.WRITTEN + "\n"
             + "; Roundcube's pool, with its own user: not nginx's (www), not root.\n"
             + "; nginx opens the socket because www is in the " + SOCKET_GROUP + " group (listen.group), with\n"
             + "; roundcube alone: www gets the socket and nothing of roundcube's. Only roundcube reads the\n"
             + "; webmail's files. php-fpm's master runs as roundcube too (php_fpm_user in rc.conf).\n"
             + "[" + POOL + "]\n"
             + "user = " + USER + "\n"
             + "group = " + GROUP + "\n"
             + "listen = " + SOCKET + "\n"
             + "listen.owner = " + USER + "\n"
             + "listen.group = " + SOCKET_GROUP + "\n"
             + "listen.mode = 0660\n"
             + PhpHardening.LIMIT_COMMENT + PhpHardening.LIMIT
             + rest;
    }

    /** www.conf without a pool: it exists only so that the PHP package does not recreate it. */
    public static String wwwPlaceholder() {
        return "; " + PanelMarker.WRITTEN + "\n"
             + "; Here was the \"www\" pool, with which Roundcube ran as nginx's user.\n"
             + "; Now Roundcube has its own pool, in " + POOL + ".conf, with its own user.\n"
             + "; The file stays, without a pool, on purpose: if www.conf is missing, installing or\n"
             + "; upgrading php84 copies www.conf.default here again, and php-fpm would start\n"
             + "; a pool running as www again. Comments start with ';': php-fpm refuses '#'.\n";
    }

    /** The rotation of the Roundcube logs, like the package's one but with the right owner. */
    static String roundcubeRotation() {
        return "# " + PanelMarker.WRITTEN + "\n"
             + "# The rotation of Roundcube's logs: the package's one recreated them as www:www,\n"
             + "# and after the first rotation the webmail could no longer have written them.\n"
             + "# logfilename                 [owner:group] mode count size when  flags [/pid_file] [sig_num]\n"
             + ROUNDCUBE_DIR + "/logs/errors.log    " + USER + ":" + GROUP + "  640  10    1000 *     XCBN\n"
             + ROUNDCUBE_DIR + "/logs/sendmail.log  " + USER + ":" + GROUP + "  640  10    1000 *     XCBN\n";
    }

    /**
     * The piece of the installation scripts that gives Roundcube its user and its pool. It goes
     * where www.conf used to be written; the ownership of the files is done by {@link #shellOwnership()},
     * after the files are there.
     */
    public static String shellPool() {
        return "\n# Roundcube with its own user and its own php-fpm pool, not nginx's (www).\n"
             + "pw groupshow " + GROUP + " >/dev/null 2>&1 || pw groupadd " + GROUP + "\n"
             + "pw usershow " + USER + " >/dev/null 2>&1 || pw useradd " + USER + " -g " + GROUP
             + " -d /nonexistent -s /usr/sbin/nologin -c \"Roundcube webmail\"\n"
             + "mkdir -p " + FPM_DIR + "\n"
             + "# The socket's group: roundcube and nginx's www, nobody else; the socket's folder, roundcube's.\n"
             + "pw groupshow " + SOCKET_GROUP + " >/dev/null 2>&1 || pw groupadd " + SOCKET_GROUP + "\n"
             + "pw groupmod " + SOCKET_GROUP + " -M " + USER + "," + WEB_GROUP + "\n"
             + "install -d -o " + USER + " -g " + SOCKET_GROUP + " -m 750 " + FPM_RUN_DIR + "\n"
             + "cat > " + FPM_DIR + "/" + POOL + ".conf << 'ROUNDCUBE_POOL'\n" + poolConf(null) + "ROUNDCUBE_POOL\n"
             + "chown root:" + GROUP + " " + FPM_DIR + "/" + POOL + ".conf\n"
             + "chmod 640 " + FPM_DIR + "/" + POOL + ".conf\n"
             + "cat > " + FPM_DIR + "/www.conf << 'WWW_PLACEHOLDER'\n" + wwwPlaceholder() + "WWW_PLACEHOLDER\n";
    }

    /** The piece of the installation scripts that gives roundcube its files. */
    public static String shellOwnership() {
        StringBuilder b = new StringBuilder("\n# Roundcube's files: its own, and nobody else's.\n");
        for (Ownership o : ownershipPlan(Places.real())) {
            String p = o.path().toString();
            // The contents without the files with more than one name: logs, temp and the sessions are written by
            // roundcube, and "chown -R" also gave it a root file linked in there with a hard link (finding 252).
            if (o.contents()) {
                b.append("if [ -d ").append(p).append(" ] && [ ! -L ").append(p).append(" ]; then\n")
                 .append(org.daemoxcp.mail.security.SafeOwnership.shell(p, o.user(), o.group()))
                 .append("chmod ").append(octal(o.mode())).append(' ').append(p).append("; fi\n");
                continue;
            }
            b.append("if [ -e ").append(p).append(" ]; then ");
            b.append("chown ");
            b.append(o.user()).append(':').append(o.group()).append(' ').append(p)
             .append("; chmod ").append(octal(o.mode())).append(' ').append(p).append("; fi\n");
        }
        // The package's rotation, if it is still the package's one.
        b.append("if [ -f ").append(ROUNDCUBE_ROTATION_SAMPLE).append(" ] && cmp -s ")
         .append(ROUNDCUBE_ROTATION_SAMPLE).append(' ').append(NEWSYSLOG_DIR).append("/roundcube.conf; then\n")
         .append("cat > ").append(NEWSYSLOG_DIR).append("/roundcube.conf << 'ROUNDCUBE_ROTATION'\n")
         .append(roundcubeRotation()).append("ROUNDCUBE_ROTATION\nfi\n");
        return b.toString();
    }

    /** The newsyslog line of the PHP error log: it is written by the roundcube processes. */
    public static String phpErrorsRotationLine() {
        return PHP_ERRORS_LOG + "    " + USER + ":" + GROUP + "    640    7    1024    *    JC";
    }

    /**
     * Where nginx must pass Roundcube's PHP requests: the new socket if the roundcube pool
     * exists, the previous one if the migration has not succeeded yet (regenerating nginx.conf with
     * the new socket, without the pool, would turn the webmail off).
     */
    public static String fastcgiPass() {
        return "unix:" + (migrated(Places.real()) ? SOCKET : OLD_SOCKET);
    }

    /** The user Roundcube's PHP runs as: roundcube after the migration, www before. */
    public static String runtimeUser() {
        return migrated(Places.real()) ? USER : WEB_GROUP;
    }

    /** The group that reads the webmail configurations: roundcube after the migration, www before. */
    public static String runtimeGroup() {
        return migrated(Places.real()) ? GROUP : WEB_GROUP;
    }

    static boolean migrated(Places at) {
        try {
            Path pool = at.fpmDir().resolve(POOL + ".conf");
            return Files.isRegularFile(pool, LinkOption.NOFOLLOW_LINKS)
                    && PanelMarker.writtenByPanel(Files.readString(pool, StandardCharsets.UTF_8));
        } catch (IOException e) {
            return false;
        }
    }

    // ===================== file ownership =====================

    /**
     * A file or a folder with owner, group and permissions. contents: also what is inside
     * (without following links), with the permissions for others removed.
     */
    record Ownership(Path path, String user, String group, String mode, boolean contents) {}

    /** Where the files are: fixed on the server, temporary folders in the test. */
    record Places(Path fpmDir, Path roundcubeDir, Path sessionsDir, Path phpErrorsLog,
                  Path newsyslogDir, Path rotationSample, Path ssoKey, Path backupDir) {
        static Places real() {
            return new Places(Path.of(FPM_DIR), Path.of(ROUNDCUBE_DIR), Path.of(SESSIONS_DIR),
                    Path.of(PHP_ERRORS_LOG), Path.of(NEWSYSLOG_DIR), Path.of(ROUNDCUBE_ROTATION_SAMPLE),
                    Path.of(SSO_KEY), Path.of(BACKUP_DIR));
        }
    }

    /**
     * Who the webmail files must belong to. The configurations are written by root (the panel) and
     * roundcube reads them through the group: it cannot change them. The SSO plugin's code belongs to
     * root. The SSO key is read only by the panel: the plugin has the secret in its configuration.
     */
    static List<Ownership> ownershipPlan(Places at) {
        Path rc = at.roundcubeDir();
        Path sso = rc.resolve("plugins/daemoxcp_mail_sso");
        List<Ownership> l = new ArrayList<>();
        l.add(new Ownership(rc.resolve("config/config.inc.php"), "root", GROUP, "rw-r-----", false));
        l.add(new Ownership(sso, "root", "wheel", "rwxr-xr-x", false));
        l.add(new Ownership(sso.resolve("daemoxcp_mail_sso.php"), "root", "wheel", "rw-r--r--", false));
        l.add(new Ownership(sso.resolve("config.inc.php"), "root", GROUP, "rw-r-----", false));
        l.add(new Ownership(rc.resolve("temp"), USER, GROUP, "rwx------", true));
        l.add(new Ownership(rc.resolve("logs"), USER, GROUP, "rwxr-x---", true));
        l.add(new Ownership(at.sessionsDir(), USER, GROUP, "rwx------", true));
        l.add(new Ownership(at.phpErrorsLog(), USER, GROUP, "rw-r-----", false));
        l.add(new Ownership(at.ssoKey(), "root", "wheel", "rw-------", false));
        return l;
    }

    private static String octal(String mode) {
        int v = 0;
        for (char c : mode.toCharArray()) v = (v << 1) | (c == '-' ? 0 : 1);
        return String.format("%o", v);
    }

    /** What a file had before: to put it back. */
    private record Snapshot(Path path, String user, String group, Set<PosixFilePermission> perms) {}

    /**
     * Sets the right owner, group and permissions, and remembers the previous ones in {@code undo}.
     * It never follows links: logs, temp and the sessions were writable by www, and a link placed in
     * there by whoever had taken over www, followed by root, would have given roundcube any file.
     * Returns the changed paths.
     */
    static List<String> apply(List<Ownership> plan, Deque<Snapshot> undo) throws IOException {
        List<String> changed = new ArrayList<>();
        for (Ownership o : plan) {
            if (!Files.exists(o.path(), LinkOption.NOFOLLOW_LINKS) || !org.daemoxcp.mail.security.SafeOwnership.safeToChange(o.path())) continue;
            if (set(o.path(), o.user(), o.group(), PosixFilePermissions.fromString(o.mode()), undo))
                changed.add(o.path().toString());
            if (!o.contents() || !Files.isDirectory(o.path(), LinkOption.NOFOLLOW_LINKS)) continue;
            List<Path> inside;
            try (Stream<Path> s = Files.walk(o.path())) {
                inside = s.filter(p -> !p.equals(o.path())).toList();
            }
            for (Path p : inside) {
                // No links and no files with several names: a hard link to a root file is that file (finding 252)
                if (!org.daemoxcp.mail.security.SafeOwnership.safeToChange(p)) continue;
                Set<PosixFilePermission> perms = Files.readAttributes(p, PosixFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS).permissions();
                perms.remove(PosixFilePermission.OTHERS_READ);
                perms.remove(PosixFilePermission.OTHERS_WRITE);
                perms.remove(PosixFilePermission.OTHERS_EXECUTE);
                if (set(p, o.user(), o.group(), perms, undo)) changed.add(p.toString());
            }
        }
        return changed;
    }

    private static boolean set(Path p, String user, String group, Set<PosixFilePermission> perms,
                               Deque<Snapshot> undo) throws IOException {
        PosixFileAttributeView v = Files.getFileAttributeView(p, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        PosixFileAttributes a = v.readAttributes();
        if (a.owner().getName().equals(user) && a.group().getName().equals(group) && a.permissions().equals(perms))
            return false;
        undo.push(new Snapshot(p, a.owner().getName(), a.group().getName(), a.permissions()));
        UserPrincipalLookupService names = p.getFileSystem().getUserPrincipalLookupService();
        UserPrincipal u = names.lookupPrincipalByName(user);
        GroupPrincipal g = names.lookupPrincipalByGroupName(group);
        if (!a.owner().getName().equals(user)) v.setOwner(u);
        if (!a.group().getName().equals(group)) v.setGroup(g);
        if (!a.permissions().equals(perms)) v.setPermissions(perms);
        return true;
    }

    private static List<String> restore(Deque<Snapshot> undo) {
        List<String> problems = new ArrayList<>();
        while (!undo.isEmpty()) {
            Snapshot s = undo.pop();
            try {
                PosixFileAttributeView v = Files.getFileAttributeView(s.path(), PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
                UserPrincipalLookupService names = s.path().getFileSystem().getUserPrincipalLookupService();
                // Only what changed: a file that could not be changed is not touched again.
                PosixFileAttributes a = v.readAttributes();
                if (!a.owner().getName().equals(s.user())) v.setOwner(names.lookupPrincipalByName(s.user()));
                if (!a.group().getName().equals(s.group())) v.setGroup(names.lookupPrincipalByGroupName(s.group()));
                if (!a.permissions().equals(s.perms())) v.setPermissions(s.perms());
            } catch (IOException e) {
                problems.add(s.path() + ": " + e.getMessage());
            }
        }
        return problems;
    }

    /**
     * The ownership reasserted, without touching the services: after a Roundcube upgrade (the
     * package post-install sets logs and temp back to www:www) and at every startup. Only if the
     * migration has already happened: before it, the files still belong to www because the www pool
     * reads them.
     */
    public static List<String> repairOwnership() {
        Places at = Places.real();
        if (!migrated(at)) return List.of();
        List<String> changed = new ArrayList<>();
        try {
            changed.addAll(apply(ownershipPlan(at), new ArrayDeque<>()));
            Deque<FileEdit> edits = new ArrayDeque<>();
            for (FileEdit e : rotationEdits(at)) { e.apply(); edits.push(e); changed.add(e.path().toString()); }
        } catch (IOException e) {
            LOGGER.warning("[RoundcubeUser] cannot repair the ownership of the webmail files: " + e.getMessage());
        }
        return changed;
    }

    // ===================== the log rotations =====================

    /** A rewritten file, with the previous text to put it back. */
    record FileEdit(Path path, String before, String after) {
        void apply() throws IOException { write(path, after); }
        void undo() throws IOException {
            if (before == null) Files.deleteIfExists(path); else write(path, before);
        }
    }

    /**
     * The two rotations that recreate the logs with the owner: the PHP errors one (written by the
     * panel installation) and the Roundcube one (the package copies it from its sample).
     * The package's one is rewritten only if it is still equal to the sample: if someone has
     * changed it, it is theirs, and the service users check says so.
     */
    static List<FileEdit> rotationEdits(Places at) throws IOException {
        List<FileEdit> l = new ArrayList<>();
        Path php = at.newsyslogDir().resolve("php-errors.conf");
        if (Files.isRegularFile(php, LinkOption.NOFOLLOW_LINKS)) {
            String before = Files.readString(php, StandardCharsets.UTF_8);
            String after = before.replaceAll("(?m)^(" + Pattern.quote(at.phpErrorsLog().toString()) + "\\s+)www:www(\\s)",
                    "$1" + USER + ":" + GROUP + "$2");
            if (!after.equals(before)) l.add(new FileEdit(php, before, after));
        }
        Path rc = at.newsyslogDir().resolve("roundcube.conf");
        if (Files.isRegularFile(rc, LinkOption.NOFOLLOW_LINKS) && Files.isRegularFile(at.rotationSample())) {
            String before = Files.readString(rc, StandardCharsets.UTF_8);
            if (before.equals(Files.readString(at.rotationSample(), StandardCharsets.UTF_8)))
                l.add(new FileEdit(rc, before, roundcubeRotation().replace(ROUNDCUBE_DIR, at.roundcubeDir().toString())));
        }
        return l;
    }

    // ===================== the previous pool =====================

    /** A pool read from a php-fpm.d file: the name and its key = value lines, in order. */
    record Pool(String name, Map<String, String> values, List<String> lines) {
        String get(String k) { return values.get(k); }
    }

    /** The pools of a php-fpm file (";" comment lines, [name] sections). */
    static List<Pool> pools(String content) {
        List<Pool> out = new ArrayList<>();
        Pool cur = null;
        for (String raw : content.split("\n")) {
            String t = raw.trim();
            if (t.isEmpty() || t.startsWith(";")) continue;
            if (t.startsWith("[") && t.endsWith("]")) {
                cur = new Pool(t.substring(1, t.length() - 1).trim(), new LinkedHashMap<>(), new ArrayList<>());
                out.add(cur);
                continue;
            }
            if (cur == null) continue;
            int eq = t.indexOf('=');
            if (eq < 0) continue;
            String k = t.substring(0, eq).trim(), v = t.substring(eq + 1).trim();
            cur.values().put(k, v);
            cur.lines().add(k + " = " + v);
        }
        return out;
    }

    /** The value of listen as nginx writes it in fastcgi_pass: a path becomes unix:path. */
    static String nginxForm(String listen) {
        return listen.startsWith("/") ? "unix:" + listen : listen;
    }

    // ===================== nginx =====================

    /** An nginx server block that passes to php-fpm: the file, the name and the port it answers on. */
    record Site(Path file, String name, String port, boolean roundcube) {}

    /** The nginx configuration files as they really are, from the output of nginx -T. */
    static Map<Path, String> configFiles(String dump) {
        Map<Path, String> out = new LinkedHashMap<>();
        Matcher m = Pattern.compile("(?m)^# configuration file (.+):$").matcher(dump == null ? "" : dump);
        Path cur = null;
        int from = 0;
        while (m.find()) {
            if (cur != null) out.put(cur, dump.substring(from, m.start()));
            cur = Path.of(m.group(1).trim());
            from = m.end() + 1;
        }
        if (cur != null) out.put(cur, dump.substring(Math.min(from, dump.length())));
        return out;
    }

    /** The text without the nginx comments (from # to the end of the line, outside quotes). */
    static String withoutComments(String c) {
        StringBuilder b = new StringBuilder();
        boolean inQuote = false;
        char q = 0;
        for (int i = 0; i < c.length(); i++) {
            char ch = c.charAt(i);
            if (inQuote) {
                b.append(ch);
                if (ch == q) inQuote = false;
            } else if (ch == '"' || ch == '\'') {
                inQuote = true; q = ch; b.append(ch);
            } else if (ch == '#') {
                while (i < c.length() && c.charAt(i) != '\n') i++;
                if (i < c.length()) b.append('\n');
            } else b.append(ch);
        }
        return b.toString();
    }

    private static final Pattern SERVER_OPEN = Pattern.compile("(?:^|[;{}\\s])server\\s*\\{");

    /** The server { ... } blocks of a file, already without comments. */
    static List<String> serverBlocks(String c) {
        List<String> out = new ArrayList<>();
        Matcher m = SERVER_OPEN.matcher(c);
        int pos = 0;
        while (m.find(pos)) {
            int open = c.indexOf('{', m.start() + 1);
            int depth = 0, i = open;
            for (; i < c.length(); i++) {
                if (c.charAt(i) == '{') depth++;
                else if (c.charAt(i) == '}' && --depth == 0) break;
            }
            out.add(c.substring(open, Math.min(i + 1, c.length())));
            pos = Math.min(i + 1, c.length());
        }
        return out;
    }

    /** The sites that pass requests to {@code pass}, and whether they are the webmail. */
    static List<Site> sitesPassingTo(Map<Path, String> files, String pass, Path roundcubeDir) {
        Pattern passes = Pattern.compile("fastcgi_pass\\s+" + Pattern.quote(pass) + "\\s*;");
        Pattern root = Pattern.compile("(?m)\\broot\\s+" + Pattern.quote(roundcubeDir.toString()) + "(/public_html)?/?\\s*;");
        Pattern name = Pattern.compile("(?m)\\bserver_name\\s+([^\\s;]+)");
        Pattern listen = Pattern.compile("(?m)\\blisten\\s+([^\\s;]+)");
        List<Site> out = new ArrayList<>();
        for (Map.Entry<Path, String> f : files.entrySet()) {
            for (String b : serverBlocks(withoutComments(f.getValue()))) {
                if (!passes.matcher(b).find()) continue;
                Matcher n = name.matcher(b), l = listen.matcher(b);
                String port = l.find() ? l.group(1).replaceFirst("^.*:", "") : "";
                out.add(new Site(f.getKey(), n.find() ? n.group(1) : "", port, root.matcher(b).find()));
            }
        }
        return out;
    }

    /** The same file with fastcgi_pass moved from {@code from} to the socket of the roundcube pool. */
    static String repointed(String content, String from) {
        return content.replaceAll("fastcgi_pass(\\s+)" + Pattern.quote(from) + "(\\s*);",
                Matcher.quoteReplacement("fastcgi_pass") + "$1" + Matcher.quoteReplacement("unix:" + SOCKET) + "$2;");
    }

    // ===================== the boot migration =====================

    enum Outcome { NOTHING, REPAIRED, NOT_INSTALLED, NOT_OURS, OTHER_SITES, NOT_SERVED, NGINX_UNREADABLE,
                   NOT_ANSWERING, DONE, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** What is needed from php-fpm, nginx and the system, kept separate to test it without the real services. */
    interface Services {
        /** The output of nginx -T, or null if nginx does not answer. */
        String nginxDump();
        Shell.Result nginxTest();
        Shell.Result nginxReload();
        Shell.Result phpFpmTest();
        Shell.Result phpFpmReload();
        /** Creates group and user if they are missing; false if it does not succeed. */
        boolean ensureUser();
        /** The process users of each running php-fpm pool: pool -> users. */
        Map<String, Set<String>> poolUsers();
        /** The webmail responds with its login page, on that name and that port. */
        boolean webmailAnswers(String name, String port);
        /** A pause between one check and the next (in the test it does not wait). */
        void pause();
    }

    public static void ensureAtBoot() {
        try {
            Report r = migrate(Places.real(), new RealServices());
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[RoundcubeUser] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE || r.outcome() == Outcome.REPAIRED) LOGGER.info(line);
            else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[RoundcubeUser] failed: " + t);
        }
    }

    static Report migrate(Places at, Services sv) throws IOException {
        if (!Files.isDirectory(at.roundcubeDir()))
            return new Report(Outcome.NOTHING, "");
        Path poolFile = at.fpmDir().resolve(POOL + ".conf");
        Path wwwFile = at.fpmDir().resolve("www.conf");

        // Already migrated: only the ownership of the files, which a Roundcube upgrade sets back to www.
        if (Files.exists(poolFile, LinkOption.NOFOLLOW_LINKS)) {
            if (!migrated(at))
                return new Report(Outcome.NOT_OURS, poolFile + " exists and was not written by the panel: nothing changed");
            List<String> changed = new ArrayList<>(apply(ownershipPlan(at), new ArrayDeque<>()));
            for (FileEdit e : rotationEdits(at)) { e.apply(); changed.add(e.path().toString()); }
            String www = wwwPoolBack(at, wwwFile, sv);
            if (www != null && !www.startsWith("replaced"))
                return new Report(Outcome.NOT_OURS, www + (changed.isEmpty() ? "" : "; ownership put back on " + String.join(", ", changed)));
            if (www != null) changed.add(wwwFile + " (" + www + ")");
            return changed.isEmpty() ? new Report(Outcome.NOTHING, "")
                    : new Report(Outcome.REPAIRED, "put back: " + String.join(", ", changed));
        }

        if (!Files.isRegularFile(wwwFile, LinkOption.NOFOLLOW_LINKS))
            return new Report(Outcome.NOT_INSTALLED, wwwFile + " is missing: no php-fpm pool for the webmail, nothing changed");
        String wwwBefore = Files.readString(wwwFile, StandardCharsets.UTF_8);
        List<Pool> pools = pools(wwwBefore);
        if (pools.size() != 1 || !"www".equals(pools.get(0).name()) || !"www".equals(pools.get(0).get("user"))
                || pools.get(0).get("listen") == null)
            return new Report(Outcome.NOT_OURS, wwwFile + " is not the panel's www pool (one pool [www], user = www): nothing changed");
        Pool www = pools.get(0);
        String oldPass = nginxForm(www.get("listen"));

        String dump = sv.nginxDump();
        if (dump == null)
            return new Report(Outcome.NGINX_UNREADABLE, "nginx -T failed: nothing changed, retrying at the next start");
        Map<Path, String> nginxFiles = configFiles(dump);
        List<Site> sites = sitesPassingTo(nginxFiles, oldPass, at.roundcubeDir());
        List<Site> webmail = sites.stream().filter(Site::roundcube).toList();
        if (sites.size() > webmail.size())
            return new Report(Outcome.OTHER_SITES, "the www pool (" + oldPass + ") also serves sites that are not the webmail: nothing changed");
        if (webmail.isEmpty())
            return new Report(Outcome.NOT_SERVED, "no nginx server passes the webmail to " + oldPass + ": nothing changed");

        // Before the migration the webmail must respond: otherwise afterwards nobody could tell
        // whether the migration broke it.
        for (Site s : webmail)
            if (!sv.webmailAnswers(s.name(), s.port()))
                return new Report(Outcome.NOT_ANSWERING, "the webmail does not answer now on " + s.name() + ":" + s.port()
                        + ": nothing changed, retrying at the next start");

        if (!sv.ensureUser())
            return new Report(Outcome.ROLLED_BACK, "cannot create the user " + USER + ": nothing changed");

        // The new pool carries over the lines of the previous one that are not about who and where.
        StringBuilder rest = new StringBuilder();
        for (String l : www.lines()) {
            String k = l.substring(0, l.indexOf('=')).trim();
            if (!OWN_KEYS.contains(k)) rest.append(l).append('\n');
        }

        Deque<FileEdit> edits = new ArrayDeque<>();
        Deque<Snapshot> owners = new ArrayDeque<>();
        boolean fpmReloaded = false, nginxReloaded = false;
        try {
            backup(at, wwwFile, nginxFiles.keySet());
            FileEdit pool = new FileEdit(poolFile, null, poolConf(rest.toString()));
            pool.apply(); edits.push(pool);
            FileEdit placeholder = new FileEdit(wwwFile, wwwBefore, wwwPlaceholder());
            placeholder.apply(); edits.push(placeholder);
            for (FileEdit e : rotationEdits(at)) { e.apply(); edits.push(e); }
            apply(ownershipPlan(at), owners);

            Shell.Result t = sv.phpFpmTest();
            if (!t.success()) return rollBack(edits, owners, sv, false, false, "php-fpm -t refused the new pool: " + t.outputTrim());

            Map<Path, String> touched = new LinkedHashMap<>();
            for (Site s : webmail) touched.putIfAbsent(s.file(), null);
            for (Path f : touched.keySet()) {
                String before = Files.readString(f, StandardCharsets.UTF_8);
                FileEdit e = new FileEdit(f, before, repointed(before, oldPass));
                e.apply(); edits.push(e);
            }
            t = sv.nginxTest();
            if (!t.success()) return rollBack(edits, owners, sv, false, false, "nginx -t refused the new socket: " + t.outputTrim());

            fpmReloaded = true;
            t = sv.phpFpmReload();
            if (!t.success()) return rollBack(edits, owners, sv, true, false, "php-fpm reload failed: " + t.outputTrim());
            String pools2 = waitForPool(sv);
            if (pools2 != null) return rollBack(edits, owners, sv, true, false, pools2);

            nginxReloaded = true;
            t = sv.nginxReload();
            if (!t.success()) return rollBack(edits, owners, sv, true, true, "nginx reload failed: " + t.outputTrim());
            for (Site s : webmail) {
                boolean ok = false;
                for (int i = 0; i < 10 && !ok; i++) {
                    ok = sv.webmailAnswers(s.name(), s.port());
                    if (!ok) sv.pause();
                }
                if (!ok) return rollBack(edits, owners, sv, true, true,
                        "the webmail does not answer on " + s.name() + ":" + s.port() + " after the switch");
            }
        } catch (IOException | RuntimeException e) {
            return rollBack(edits, owners, sv, fpmReloaded, nginxReloaded, "unexpected error: " + e);
        }
        return new Report(Outcome.DONE, "Roundcube runs in the pool " + POOL + " as " + USER + ", nginx passes to "
                + SOCKET + " (" + webmail.size() + " site" + (webmail.size() == 1 ? "" : "s") + "), "
                + owners.size() + " ownerships changed; copies of the old files in " + at.backupDir());
    }

    /**
     * After the migration www.conf must stay without a pool. If it has one again and the file is
     * identical to www.conf.default, the PHP package copied it back (the placeholder is missing: someone
     * removed it, and an upgrade put it back): the placeholder returns, with php-fpm -t and reload.
     * If it is different someone wrote it, and it is not touched. null: nothing to report.
     */
    private static String wwwPoolBack(Places at, Path wwwFile, Services sv) throws IOException {
        if (!Files.isRegularFile(wwwFile, LinkOption.NOFOLLOW_LINKS)) {
            new FileEdit(wwwFile, null, wwwPlaceholder()).apply();
            return "replaced: it was missing";
        }
        String w = Files.readString(wwwFile, StandardCharsets.UTF_8);
        if (pools(w).isEmpty()) return null;
        Path sample = at.fpmDir().resolve("www.conf.default");
        if (!Files.isRegularFile(sample) || !w.equals(Files.readString(sample, StandardCharsets.UTF_8)))
            return wwwFile + " defines a pool again and is not the package's www.conf.default: left as it is, php-fpm runs it";
        FileEdit e = new FileEdit(wwwFile, w, wwwPlaceholder());
        e.apply();
        Shell.Result t = sv.phpFpmTest();
        if (!t.success()) {
            e.undo();
            return "php-fpm -t refused " + wwwFile + " without its pool: put back (" + t.outputTrim() + ")";
        }
        Shell.Result r = sv.phpFpmReload();
        if (!r.success()) {
            e.undo();
            sv.phpFpmReload();
            return "php-fpm reload failed without the www pool: put back (" + r.outputTrim() + ")";
        }
        return "replaced: the PHP package had copied www.conf.default back, with a pool that runs as www";
    }

    /** Waits for the roundcube pool to run as roundcube and for no www pool to be left. null if it works. */
    private static String waitForPool(Services sv) {
        Map<String, Set<String>> users = Map.of();
        for (int i = 0; i < 20; i++) {
            users = sv.poolUsers();
            if (Set.of(USER).equals(users.get(POOL)) && !users.containsKey("www")) return null;
            sv.pause();
        }
        return "after the reload php-fpm runs " + users + " instead of " + POOL + "=[" + USER + "] alone";
    }

    private static Report rollBack(Deque<FileEdit> edits, Deque<Snapshot> owners, Services sv,
                                   boolean reloadFpm, boolean reloadNginx, String why) {
        List<String> problems = new ArrayList<>(restore(owners));
        while (!edits.isEmpty()) {
            FileEdit e = edits.pop();
            try { e.undo(); } catch (IOException x) { problems.add(e.path() + ": " + x.getMessage()); }
        }
        if (reloadFpm) {
            Shell.Result r = sv.phpFpmReload();
            if (!r.success()) problems.add("php-fpm reload: " + r.outputTrim());
        }
        if (reloadNginx) {
            Shell.Result r = sv.nginxReload();
            if (!r.success()) problems.add("nginx reload: " + r.outputTrim());
        }
        return new Report(Outcome.ROLLED_BACK, why + "; everything put back"
                + (problems.isEmpty() ? "" : " EXCEPT: " + String.join("; ", problems)));
    }

    /**
     * The copies of www.conf and of the nginx files, for whoever wants to see how they were: they are not
     * used to put things back.
     */
    private static void backup(Places at, Path www, Iterable<Path> nginx) {
        try {
            Path dir = at.backupDir().resolve("roundcube-" + java.time.LocalDate.now(java.time.ZoneOffset.UTC));
            Files.createDirectories(dir);
            try { Files.setPosixFilePermissions(at.backupDir(), PosixFilePermissions.fromString("rwx------")); }
            catch (UnsupportedOperationException ignored) {}
            Files.copy(www, dir.resolve("www.conf"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            for (Path p : nginx)
                if (Files.isRegularFile(p))
                    Files.copy(p, dir.resolve(p.toString().replace('/', '_')), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            LOGGER.warning("[RoundcubeUser] cannot keep a copy of the old files: " + e.getMessage());
        }
    }

    /** Writes a new file as root, readable by everyone (pool, rotations, nginx), or rewrites it in its place. */
    private static void write(Path p, String content) throws IOException {
        Files.writeString(p, content, StandardCharsets.UTF_8);
    }

    // ===================== the real services =====================

    private static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(20);

        @Override public String nginxDump() {
            if (Shell.resolve("nginx") == null) return null;
            Shell.Result r = Shell.run(SHORT, "nginx", "-T");
            return r.success() ? r.output() : null;
        }
        @Override public Shell.Result nginxTest() { return Shell.run(SHORT, "nginx", "-t"); }
        // "one": they work even if nginx_enable is not YES in rc.conf.
        @Override public Shell.Result nginxReload() { return Shell.run(SHORT, "service", "nginx", "onereload"); }
        @Override public Shell.Result phpFpmTest() { return Shell.run(SHORT, "php-fpm", "-t"); }
        @Override public Shell.Result phpFpmReload() { return Shell.run(SHORT, "service", "php_fpm", "onereload"); }

        @Override public boolean ensureUser() {
            if (!Shell.run(SHORT, "pw", "groupshow", GROUP).success()
                    && !Shell.run(SHORT, "pw", "groupadd", GROUP).success()) return false;
            if (!Shell.run(SHORT, "pw", "usershow", USER).success()
                    && !Shell.run(SHORT, "pw", "useradd", USER, "-g", GROUP, "-d", "/nonexistent",
                                  "-s", "/usr/sbin/nologin", "-c", "Roundcube webmail").success()) return false;
            return Shell.run(SHORT, "pw", "usershow", USER).success() && PhpFpmMaster.ensureSocketGroupAndDir();
        }

        @Override public Map<String, Set<String>> poolUsers() {
            // One -o per column: on FreeBSD "-o user=,pid=" makes ",pid=" the header of user.
            return ServiceUsers.poolUsers(Shell.run(SHORT, "ps", "-axww", "-o", "user=", "-o", "pid=", "-o", "ppid=",
                    "-o", "command=").output());
        }

        @Override public boolean webmailAnswers(String name, String port) {
            if (!name.matches("[A-Za-z0-9.-]+") || !port.matches("[0-9]+")) return false;
            Shell.Result r = Shell.run(SHORT, "curl", "-sk", "-m", "15", "--resolve", name + ":" + port + ":127.0.0.1",
                    "https://" + name + ":" + port + "/");
            return r.success() && r.output().contains("rcmloginuser");
        }

        @Override public void pause() {
            try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }
}
