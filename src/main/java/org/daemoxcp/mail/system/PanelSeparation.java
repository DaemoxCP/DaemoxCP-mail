package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;
import org.daemoxcp.mail.webserver.RootChannel;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * The panel in two processes: the root part, the process that rc.d starts
 * with --web, opens no ports; the web part (--web-part) runs as the user daemoxcp_mail, answers on the panel's
 * port and passes to the root part, over a unix socket, the API calls of whoever has logged in.
 *
 * <p>Here is what the root part does:
 * <ul>
 *   <li>the user and the group daemoxcp_mail: they are created if missing, and if present they must be the
 *       ones the panel creates (comment, folder, shell, no other member in the group): otherwise the user
 *       belongs to someone else and is not used;</li>
 *   <li>the files the web part must read: the secrets folder and the SQLite folder become 0750
 *       root:daemoxcp_mail, the web part's secrets file, master.key and the SQLite database 0640
 *       root:daemoxcp_mail. The web part reads them and does not change them: it opens SQLite read-only
 *       (dataBaseManager.readOnly), and what root writes there (names, ports, paths) the web part cannot
 *       touch. Everything else in those folders stays root-only. The authentication log, which the web
 *       part writes for fail2ban, becomes daemoxcp_mail's;</li>
 *   <li>the socket and the start of the web part with daemon(8): {@code -u daemoxcp_mail} makes the web
 *       part run as that user, while the supervisor stays root and writes the pid files and the log itself
 *       (measured on the VM on 2026-11-07: pid 0600 root, log 0600 root:wheel), so the web part cannot
 *       change them; {@code -r} restarts it if it dies;</li>
 *   <li>if a condition is missing, or the web part does not answer within {@link #ANSWER_SECONDS}, what
 *       was started is stopped and the panel serves everything as root as before, with a warning. Nothing
 *       is undone: root reads the files of daemoxcp_mail anyway.</li>
 * </ul>
 *
 * <p>To turn the separation off by hand: {@code sysrc daemoxcp_mail_opts="-Ddaemoxcp.mail.separation=off"} and
 * {@code service daemoxcp_mail restart}.
 */
public final class PanelSeparation {

    private static final Logger LOGGER = Logger.getLogger(PanelSeparation.class.getName());

    public static final String USER = Product.ID;
    public static final String GROUP = Product.ID;
    /** The comment with which the panel creates the user: a daemoxcp_mail user with a different one is not its own. */
    static final String GECOS = Product.NAME + " web part";
    static final String HOME = PanelUser.HOME;
    static final String SHELL = PanelUser.SHELL;

    /** The folder of the socket and of the pids; the tests move it with -Ddaemoxcp.mail.run.dir. */
    static Path runDir = Path.of(System.getProperty("daemoxcp.mail.run.dir", "/var/run/daemoxcp-mail"));
    static final String TITLE = "daemoxcp-mail-web";
    /**
     * The title and the earlier ones (section "webPartTitles"): a web part started by an old version is still
     * recognised.
     */
    static java.util.List<String> titles() {
        java.util.List<String> t = new java.util.ArrayList<>(java.util.List.of(TITLE));
        t.addAll(LegacyNames.oldNamesOf("webPartTitles", TITLE));
        return t;
    }
    static Path webLog = Path.of("/var/db/daemoxcp-mail/panel-web.log");
    static Path auditLog = Path.of("/var/log/daemoxcp-mail-auth.log");
    static final long LOG_LIMIT = 10L * 1024 * 1024;
    /** How long to wait for the web part to answer: JVM startup, MySQL, the routes. On the VM it takes a few seconds. */
    static final long ANSWER_SECONDS = 90;

    /**
     * The files the web part reads in the secrets folder; the rest of the folder stays root-only. No longer
     * master.key: with the asymmetric vault the web part encrypts with the public key, which is in its own file,
     * and reads no copy. The earlier symmetric key stays root-only.
     */
    static final Set<String> SECRETS_FOR_WEB = Set.of("panel-secrets.properties");
    static final Set<String> SQLITE_FOR_WEB = Set.of("daemoxcp-mail.db");

    private static volatile boolean active;
    /** This process is (or was, before going back to the single-process mode) the root part: prepare() succeeded. */
    private static volatile boolean rootPart;
    private static volatile String notSeparated = "not started yet";
    private static volatile RootChannel channel;
    private static boolean hookAdded;

    private PanelSeparation() {}

    public static Path socket() { return runDir.resolve("root.sock"); }

    static Path supervisorPid() { return runDir.resolve("web-supervisor.pid"); }

    static Path webPid() { return runDir.resolve("web.pid"); }

    /** True if the web part runs as its own user and the root part has no ports. */
    public static boolean active() { return active; }

    /**
     * True from when this process got ready to be the root part, even if it then went back to the single-process
     * mode: from that moment there is (or was) a daemoxcp_mail process writing to the database, and the root part
     * no longer takes from the database what decides where it writes (SSLMailServer.getAuditLogPath).
     */
    public static boolean rootPart() { return rootPart; }

    /** Why the panel runs entirely as root, for the service users page; null if it is separated. */
    public static String notSeparatedReason() { return active ? null : notSeparated; }

    /** Turned off by hand (daemoxcp_mail_opts) or for tests. */
    static boolean switchedOff() {
        return "off".equalsIgnoreCase(System.getProperty("daemoxcp.mail.separation", ""));
    }

    // ===================== The conditions =====================

    /**
     * Prepares the separation: user, files, free port, no web part left from an earlier start. Null if the
     * web part can be started; otherwise the reason, and the panel stays in the single-process mode.
     */
    public static String prepare(int port, boolean setupRequired, boolean mysqlAvailable) {
        String why = prepareOrReason(port, setupRequired, mysqlAvailable);
        if (why != null) notSeparated = why;
        else rootPart = true;
        return why;
    }

    private static String prepareOrReason(int port, boolean setupRequired, boolean mysqlAvailable) {
        if (!"root".equals(System.getProperty("user.name"))) return "the panel is not running as root";
        if (switchedOff()) return "switched off with -Ddaemoxcp.mail.separation=off";
        if (setupRequired) return "the first installation is not finished (/setup runs as root)";
        if (!mysqlAvailable) return "MySQL does not answer";
        if (!Files.isExecutable(Path.of("/usr/sbin/daemon"))) return "/usr/sbin/daemon is missing";
        try {
            stopLeftover();
            if (!portFree(port)) return "port " + port + " is in use";
            String user = ensureUser();
            if (user != null) return user;
            String jar = jarPath(), java = javaPath();
            if (jar == null || java == null) return "the panel's jar or java cannot be found";
            if (!asUser("/bin/test", "-r", jar)) return "the user " + USER + " cannot read " + jar;
            if (!asUser("/bin/test", "-x", java)) return "the user " + USER + " cannot run " + java;
            String files = prepareFiles();
            if (files != null) return files;
            return null;
        } catch (Exception e) {
            return "preparing the separation failed: " + e.getMessage();
        }
    }

    /**
     * A command with the web part's user and only its group, without a shell or PAM: chroot(8) with root /.
     * -G is needed: without it, the command kept root's supplementary groups, wheel and operator (measured on
     * the VM on 2026-11-07).
     */
    static boolean asUser(String... cmd) {
        List<String> c = new ArrayList<>(List.of("/usr/sbin/chroot", "-u", USER, "-g", GROUP, "-G", GROUP, "/"));
        c.addAll(List.of(cmd));
        return Shell.run(Duration.ofSeconds(20), c.toArray(new String[0])).success();
    }

    static boolean portFree(int port) {
        try (ServerSocket s = new ServerSocket()) {
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress(port));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** The web part's user as the panel creates it: the checks are in PanelUser, the same for every user of its own. */
    static final PanelUser WEB_USER = new PanelUser(USER, GECOS);

    /** The user daemoxcp_mail, created if missing. Null if it exists and is the panel's; otherwise the reason. */
    static String ensureUser() {
        PanelUser.Ensured e = WEB_USER.ensure();
        if (e.problem() != null) return e.problem();
        if (e.created()) LOGGER.info("[PanelSeparation] DONE: user and group " + USER + " created (no password, no shell,"
                + " home " + HOME + "): the panel's web part runs with it");
        return null;
    }

    /** Null if the lines from pw are those of the user created by the panel; otherwise what does not add up. Pure. */
    static String userProblem(String userLine, String groupLine) {
        return WEB_USER.problem(userLine, groupLine);
    }

    static String jarPath() {
        try {
            Path p = Path.of(org.daemoxcp.mail.Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            // With the current name if this process has just moved the jar (PanelServiceRename).
            p = Path.of(PanelServiceRename.current(p.toAbsolutePath().toString()));
            return Files.isRegularFile(p) ? p.toAbsolutePath().toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    static String javaPath() {
        return ProcessHandle.current().info().command().filter(c -> Files.isExecutable(Path.of(c))).orElse(null);
    }

    // ===================== I file =====================

    /** What changed in this start, for the DONE line (and for the tests). */
    static final List<String> changed = new ArrayList<>();

    /** Brings the files to how the separation wants them; null if everything worked, otherwise the reason. */
    static String prepareFiles() throws IOException {
        changed.clear();
        // The vault keys before starting the web part: the private one in root's file, the public one in the web
        // part's, with which the web part encrypts the copies of the new passwords.
        org.daemoxcp.mail.security.PasswordVault.ensureKeyPair();

        Path run = runDir;
        if (Files.isSymbolicLink(run) || (Files.exists(run, LinkOption.NOFOLLOW_LINKS) && !Files.isDirectory(run, LinkOption.NOFOLLOW_LINKS)))
            Files.delete(run);
        Files.createDirectories(run);
        set(run, "root", GROUP, "rwxr-x---");

        Path secrets = Path.of(org.daemoxcp.mail.security.PanelSecrets.location()).getParent();
        String s = openToWeb(secrets, SECRETS_FOR_WEB);
        if (s != null) return s;
        String d = openToWeb(Path.of("database").toAbsolutePath(), SQLITE_FOR_WEB);
        if (d != null) return d;

        String pages = openPagesToWeb(Path.of(jarPath()).getParent().resolve("admin"));
        if (pages != null) return pages;

        if (Files.isSymbolicLink(auditLog)) return auditLog + " is a symbolic link";
        if (!Files.exists(auditLog)) Files.createFile(auditLog);
        set(auditLog, USER, "wheel", "rw-r-----");

        if (!changed.isEmpty())
            LOGGER.info("[PanelSeparation] DONE: " + changed.size() + " paths readable by the web part (" + USER
                    + "), never writable, or back to root only: " + String.join(", ", changed.subList(0, Math.min(8, changed.size())))
                    + (changed.size() > 8 ? ", ..." : ""));
        return null;
    }

    /**
     * A 0750 root:daemoxcp_mail folder with the data files 0640 root:daemoxcp_mail; the folder's other files lose
     * every group and other permission, so opening the folder to the group does not open them.
     */
    static String openToWeb(Path dir, Set<String> forWeb) throws IOException {
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) return dir + " is missing";
        set(dir, "root", GROUP, "rwxr-x---");
        for (String name : forWeb) {
            Path f = dir.resolve(name);
            if (Files.isSymbolicLink(f)) return f + " is a symbolic link";
            if (!Files.isRegularFile(f)) return f + " is missing";
            set(f, "root", GROUP, "rw-r-----");
        }
        try (DirectoryStream<Path> all = Files.newDirectoryStream(dir)) {
            for (Path f : all) {
                if (forWeb.contains(f.getFileName().toString()) || Files.isSymbolicLink(f)) continue;
                PosixFileAttributes a = Files.readAttributes(f, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                Set<PosixFilePermission> own = EnumSet.noneOf(PosixFilePermission.class);
                for (PosixFilePermission x : a.permissions()) if (x.name().startsWith("OWNER")) own.add(x);
                // On FreeBSD a new file takes the folder's group (open(2)): those that are not for the
                // web part go back to root's group, besides losing the group and other permissions.
                boolean group = a.group().getName().equals(GROUP);
                if (!own.equals(a.permissions()) || group) {
                    Files.setPosixFilePermissions(f, own);
                    if (group) Files.getFileAttributeView(f, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS)
                            .setGroup(f.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByGroupName("wheel"));
                    changed.add(f + " now only root's");
                }
            }
        }
        return null;
    }

    /**
     * The panel's pages and their scripts and styles (PanelContent, PageAssets): the web part serves them, so
     * folders 0750 and files 0640 root:daemoxcp_mail, read-only. Only real folders and files, never links.
     */
    static String openPagesToWeb(Path admin) throws IOException {
        if (!Files.isDirectory(admin, LinkOption.NOFOLLOW_LINKS)) return admin + " is missing";
        for (Path dir : new Path[]{admin, admin.resolve("assets"), admin.resolve("assets").resolve("open")}) {
            if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) continue;
            set(dir, "root", GROUP, "rwxr-x---");
            try (DirectoryStream<Path> all = Files.newDirectoryStream(dir)) {
                for (Path f : all)
                    if (Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)) set(f, "root", GROUP, "rw-r-----");
            }
        }
        return null;
    }

    /** Owner, group and permissions, only if different; records what changed. */
    static void set(Path p, String owner, String group, String perms) throws IOException {
        PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        UserPrincipalLookupService lookup = p.getFileSystem().getUserPrincipalLookupService();
        PosixFileAttributeView view = Files.getFileAttributeView(p, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        boolean c = false;
        if (!a.owner().getName().equals(owner)) { view.setOwner(lookup.lookupPrincipalByName(owner)); c = true; }
        if (!a.group().getName().equals(group)) {
            GroupPrincipal g = lookup.lookupPrincipalByGroupName(group);
            view.setGroup(g);
            c = true;
        }
        Set<PosixFilePermission> want = PosixFilePermissions.fromString(perms);
        if (!a.permissions().equals(want)) { view.setPermissions(want); c = true; }
        if (c) changed.add(p + " " + owner + ":" + group + " " + perms);
    }

    // ===================== The web part =====================

    /**
     * Opens the socket, starts the web part and waits for it to answer. Null if it answers; otherwise it stops
     * what it started and says why. The dispatcher is SSLMailServer in ROOT_PART mode.
     */
    public static String startWebPart(int port, RootChannel.Dispatcher dispatcher) {
        String why = startOrReason(port, dispatcher);
        if (why != null) {
            stop();
            notSeparated = why;
        } else {
            active = true;
            notSeparated = null;
            // If the root part shuts down for any reason (even an error right after, before Main registers
            // its shutdown), the web part stops with it: on its own it would answer 503 to every API call.
            // Measured on the VM on 2026-11-07: an error in the root part after this point left the web
            // part orphaned.
            if (!hookAdded) {
                hookAdded = true;
                Runtime.getRuntime().addShutdownHook(new Thread(PanelSeparation::stop, "web-part-stop"));
            }
        }
        return why;
    }

    private static String startOrReason(int port, RootChannel.Dispatcher dispatcher) {
        try {
            channel = RootChannel.open(socket(), GROUP, USER, dispatcher);
        } catch (IOException e) {
            return "the root part's socket " + socket() + " could not be opened: " + e.getMessage();
        }
        try {
            if (Files.exists(webLog) && Files.size(webLog) > LOG_LIMIT)
                Files.move(webLog, webLog.resolveSibling(webLog.getFileName() + ".1"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            LOGGER.warning("[PanelSeparation] the web part's log could not be rotated: " + e.getMessage());
        }
        List<String> cmd = command(javaPath(), jarPath());
        Shell.Result r = Shell.run(Duration.ofSeconds(30), cmd.toArray(new String[0]));
        if (!r.success()) return "daemon(8) could not start the web part: " + r.outputTrim();
        String why = waitForWeb(new Probe() {
            @Override public int supervisor() { return PanelSeparation.supervisor(); }
            @Override public boolean answering() { return USER.equals(listener(port)) && answers(port); }
        }, ANSWER_SECONDS, () -> Thread.sleep(1000));
        if (why == null) {
            LOGGER.info("Panel web part started as " + USER + " (pid " + readPid(webPid()) + ") on port " + port
                    + "; the root part answers only on " + socket());
            return null;
        }
        return why.equals(GONE) ? "the web part stopped right away: see " + webLog
                : why.equals(SILENT) ? "the web part did not answer on port " + port + " within " + ANSWER_SECONDS + " seconds: see " + webLog
                : why;
    }

    /** What waiting for the web part needs: the supervisor's pid (or -1) and whether the web part answers on the port. */
    interface Probe {
        int supervisor();
        boolean answering();
    }

    /** A pause between one check and the next (one second; none in the tests). */
    @FunctionalInterface
    interface Pause {
        void pause() throws InterruptedException;
    }

    static final String GONE = "gone", SILENT = "silent";
    /** How many consecutive checks without a supervisor before saying that the web part has stopped. */
    static final int GONE_CHECKS = 3;

    /**
     * Waits for the web part to answer: null if it answers, GONE if the supervisor is missing for GONE_CHECKS
     * consecutive checks, SILENT if it does not answer within seconds. Before each check a pause: daemon(8) returns
     * when the parent exits, and the supervisor writes its pidfile a moment later; checking immediately read an
     * empty pidfile, or the one of the previous supervisor, already dead, and took the web part for stopped while it
     * was starting (measured on the VM on 2026-11-20: once in many starts, and the panel stayed entirely as root).
     * Pure with respect to Probe and Pause.
     */
    static String waitForWeb(Probe probe, long seconds, Pause pause) {
        int gone = 0;
        for (long i = 0; i < seconds; i++) {
            try {
                pause.pause();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return "interrupted";
            }
            if (probe.supervisor() <= 0) {
                if (++gone >= GONE_CHECKS) return GONE;
                continue;
            }
            gone = 0;
            if (probe.answering()) return null;
        }
        return SILENT;
    }

    /**
     * The daemon(8) line. From the root part's JVM only the memory and the panel's properties are passed on
     * (-Xm*, -Ddaemoxcp_mail.*), not daemoxcp.mail.separation: the web part does nothing with it.
     */
    static List<String> command(String javaBin, String jar) {
        List<String> cmd = new ArrayList<>(List.of("/usr/sbin/daemon", "-r", "-R", "5", "-u", USER,
                "-P", supervisorPid().toString(), "-p", webPid().toString(), "-o", webLog.toString(), "-H", "-t", TITLE, javaBin));
        for (String a : java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments()) {
            if (a.startsWith("-Xm") || (a.startsWith("-Ddaemoxcp.mail.") && !a.startsWith("-Ddaemoxcp.mail.separation"))) cmd.add(a);
        }
        cmd.addAll(List.of("-jar", jar, "--web-part"));
        return cmd;
    }

    /** The user of the process listening on the port, from sockstat. */
    static String listener(int port) {
        for (String l : Shell.run(Duration.ofSeconds(15), "sockstat", "-46l", "-p", String.valueOf(port)).outputTrim().split("\n")) {
            String[] f = l.trim().split("\\s+");
            if (f.length >= 6 && !"USER".equals(f[0]) && f[5].endsWith(":" + port)) return f[0];
        }
        return null;
    }

    /** True if an HTTPS server answers on the port, whatever status it gives (even 421 for the Host). */
    static boolean answers(int port) {
        Shell.Result r = Shell.run(Duration.ofSeconds(15), "curl", "-sk", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}",
                "https://127.0.0.1:" + port + "/index");
        return r.outputTrim().matches("[1-5][0-9][0-9]");
    }

    static int readPid(Path f) {
        try {
            return Integer.parseInt(Files.readString(f).trim());
        } catch (Exception e) {
            return -1;
        }
    }

    /** The pid of the web part's supervisor if it is alive and really is that one (daemon's title), otherwise -1. */
    static int supervisor() {
        int pid = readPid(supervisorPid());
        if (pid <= 1) return -1;
        String cmd = Shell.run(Duration.ofSeconds(10), "ps", "-o", "command=", "-p", String.valueOf(pid)).outputTrim();
        for (String t : titles()) if (cmd.startsWith("daemon: " + t + "[")) return pid;
        return -1;
    }

    /** A web part left over from an earlier start (the root part killed without being able to stop it): it is stopped. */
    static void stopLeftover() {
        if (supervisor() > 0) {
            LOGGER.info("[PanelSeparation] a web part of a previous start was still running: stopped");
            stopSupervisor();
        }
    }

    /** Stops the web part: SIGTERM to the supervisor, which forwards it and does not restart the web part (daemon(8)). */
    public static synchronized void stop() {
        active = false;
        stopSupervisor();
        RootChannel c = channel;
        channel = null;
        if (c != null) c.close();
    }

    private static void stopSupervisor() {
        int pid = supervisor();
        if (pid <= 0) return;
        int child = readPid(webPid());
        Shell.run(Duration.ofSeconds(10), "kill", "-TERM", String.valueOf(pid));
        for (int i = 0; i < 30; i++) {
            if (supervisor() <= 0 && !alive(child)) return;
            try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
        }
        if (supervisor() > 0) Shell.run(Duration.ofSeconds(10), "kill", "-KILL", String.valueOf(pid));
        if (alive(child)) Shell.run(Duration.ofSeconds(10), "kill", "-KILL", String.valueOf(child));
        LOGGER.warning("[PanelSeparation] the web part did not stop within 15 seconds: killed");
    }

    /** True if the pid is alive and is the web part (java ... --web-part of daemoxcp_mail). */
    static boolean alive(int pid) {
        if (pid <= 1) return false;
        String l = Shell.run(Duration.ofSeconds(10), "ps", "-o", "user=", "-o", "command=", "-p", String.valueOf(pid)).outputTrim();
        return l.startsWith(USER + " ") && l.contains("--web-part");
    }
}
