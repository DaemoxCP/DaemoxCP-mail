package org.mail_panel.system;

import org.mail_panel.util.Shell;
import org.mail_panel.webserver.RootChannel;

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
 * Il pannello in due processi: la parte root, il processo che rc.d
 * avvia con --web, non apre porte; la parte web (--web-part) gira con l'utente mailpanel, risponde sulla
 * porta del pannello e passa alla root, su un socket unix, le API di chi ha fatto l'accesso.
 *
 * <p>Qui c'e' quello che fa la parte root:
 * <ul>
 *   <li>l'utente e il gruppo mailpanel: si creano se mancano, e se ci sono devono essere quelli che crea il
 *       pannello (commento, cartella, shell, nessun altro membro nel gruppo): altrimenti l'utente e' di
 *       qualcun altro e non lo si usa;</li>
 *   <li>i file che la web deve leggere: la cartella dei segreti e quella di SQLite diventano 0750
 *       root:mailpanel, il file dei segreti della web, master.key e il database SQLite 0640 root:mailpanel.
 *       La web li legge e non li cambia: SQLite lo apre in sola lettura (dataBaseManager.readOnly), e
 *       quello che vi scrive root (nomi, porte, percorsi) la web non lo puo' toccare. Tutto il resto in
 *       quelle cartelle resta solo di root. Il registro di autenticazione, che la web scrive per fail2ban,
 *       diventa di mailpanel;</li>
 *   <li>il socket e l'avvio della web con daemon(8): {@code -u mailpanel} fa girare la web con quell'utente,
 *       mentre il supervisore resta root e scrive lui i file pid e il registro (misurato sulla VM il
 *       07/11/2026: pid 0600 root, registro 0600 root:wheel), quindi la web non li puo' cambiare;
 *       {@code -r} la riavvia se muore;</li>
 *   <li>se una condizione manca, o la web non risponde entro {@link #ANSWER_SECONDS}, si ferma quello che
 *       si e' avviato e il pannello serve tutto da root come prima, con un avviso. Non si disfa niente:
 *       root legge comunque i file di mailpanel.</li>
 * </ul>
 *
 * <p>Per spegnere la separazione a mano: {@code sysrc mailpanel_opts="-Dmailpanel.separation=off"} e
 * {@code service mailpanel restart}.
 */
public final class PanelSeparation {

    private static final Logger LOGGER = Logger.getLogger(PanelSeparation.class.getName());

    public static final String USER = "mailpanel";
    public static final String GROUP = "mailpanel";
    /** Il commento con cui il pannello crea l'utente: un utente mailpanel con un altro non e' suo. */
    static final String GECOS = "Mail panel web part";
    static final String HOME = "/nonexistent";
    static final String SHELL = "/usr/sbin/nologin";

    /** La cartella del socket e dei pid; le prove la spostano con -Dmailpanel.run.dir. */
    static Path runDir = Path.of(System.getProperty("mailpanel.run.dir", "/var/run/mailpanel"));
    static final String TITLE = "mailpanel-web";
    static Path webLog = Path.of("/var/db/mailpanel/panel-web.log");
    static Path auditLog = Path.of("/var/log/mail-panel-auth.log");
    static final long LOG_LIMIT = 10L * 1024 * 1024;
    /** Quanto si aspetta che la web risponda: avvio della JVM, MySQL, le rotte. Sulla VM ci mette pochi secondi. */
    static final long ANSWER_SECONDS = 90;

    /** I file che la web legge nella cartella dei segreti; il resto della cartella resta solo di root. */
    static final Set<String> SECRETS_FOR_WEB = Set.of("panel-secrets.properties", "master.key");
    static final Set<String> SQLITE_FOR_WEB = Set.of("mail_panel.db");

    private static volatile boolean active;
    /** Questo processo e' (o e' stato, prima di un ritorno al modo di oggi) la parte root: prepare() e' riuscito. */
    private static volatile boolean rootPart;
    private static volatile String notSeparated = "not started yet";
    private static volatile RootChannel channel;
    private static boolean hookAdded;

    private PanelSeparation() {}

    public static Path socket() { return runDir.resolve("root.sock"); }

    static Path supervisorPid() { return runDir.resolve("web-supervisor.pid"); }

    static Path webPid() { return runDir.resolve("web.pid"); }

    /** Vero se la web gira con il suo utente e la root non ha porte. */
    public static boolean active() { return active; }

    /**
     * Vero da quando questo processo si e' preparato a fare la parte root, anche se poi e' tornato al modo
     * di oggi: da quel momento c'e' (o c'e' stato) un processo mailpanel che scrive nel database, e la root
     * non prende piu' dal database quello che decide dove scrive (SSLMailServer.getAuditLogPath).
     */
    public static boolean rootPart() { return rootPart; }

    /** Perche' il pannello gira tutto da root, per la pagina degli utenti dei servizi; null se e' separato. */
    public static String notSeparatedReason() { return active ? null : notSeparated; }

    /** Spenta a mano (mailpanel_opts) o per le prove. */
    static boolean switchedOff() {
        return "off".equalsIgnoreCase(System.getProperty("mailpanel.separation", ""));
    }

    // ===================== Le condizioni =====================

    /**
     * Prepara la separazione: utente, file, porta libera, nessuna web di un avvio di prima. Null se si
     * puo' avviare la web; altrimenti il motivo, e il pannello resta com'e' oggi.
     */
    public static String prepare(int port, boolean setupRequired, boolean mysqlAvailable) {
        String why = prepareOrReason(port, setupRequired, mysqlAvailable);
        if (why != null) notSeparated = why;
        else rootPart = true;
        return why;
    }

    private static String prepareOrReason(int port, boolean setupRequired, boolean mysqlAvailable) {
        if (!"root".equals(System.getProperty("user.name"))) return "the panel is not running as root";
        if (switchedOff()) return "switched off with -Dmailpanel.separation=off";
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
     * Un comando con l'utente della web e solo il suo gruppo, senza shell ne' PAM: chroot(8) con radice /.
     * -G serve: senza, il comando teneva i gruppi aggiuntivi di root, wheel e operator (misurato sulla VM
     * il 07/11/2026).
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

    /**
     * L'utente mailpanel, creato se manca. Null se c'e' ed e' quello del pannello; altrimenti il motivo.
     * Il formato di pw usershow e' quello di master.passwd: nome:password:uid:gid:classe:cambio:scadenza:
     * commento:cartella:shell (pw(8)); quello di pw groupshow e' nome:password:gid:membri.
     */
    static String ensureUser() {
        Duration t = Duration.ofSeconds(15);
        boolean created = false;
        if (!Shell.run(t, "pw", "groupshow", GROUP).success()) {
            if (!Shell.run(t, "pw", "groupadd", GROUP).success()) return "the group " + GROUP + " could not be created";
            created = true;
        }
        if (!Shell.run(t, "pw", "usershow", USER).success()) {
            if (!Shell.run(t, "pw", "useradd", USER, "-g", GROUP, "-d", HOME, "-s", SHELL, "-c", GECOS, "-w", "no").success())
                return "the user " + USER + " could not be created";
            created = true;
        }
        String problem = userProblem(Shell.run(t, "pw", "usershow", USER).outputTrim(),
                Shell.run(t, "pw", "groupshow", GROUP).outputTrim());
        if (problem != null) return problem;
        if (created) LOGGER.info("[PanelSeparation] DONE: user and group " + USER + " created (no password, no shell,"
                + " home " + HOME + "): the panel's web part runs with it");
        return null;
    }

    /** Null se le righe di pw sono quelle dell'utente creato dal pannello; altrimenti cosa non torna. Pura. */
    static String userProblem(String userLine, String groupLine) {
        String[] u = userLine.split(":", -1);
        String[] g = groupLine.split(":", -1);
        if (u.length < 10 || g.length < 4) return "the user " + USER + " or its group cannot be read";
        String other = "the user " + USER + " exists and is not the panel's: ";
        if (!USER.equals(u[0])) return other + "name " + u[0];
        if ("0".equals(u[2])) return other + "uid 0";
        if (!GECOS.equals(u[7])) return other + "comment '" + u[7] + "'";
        if (!HOME.equals(u[8])) return other + "home " + u[8];
        if (!SHELL.equals(u[9])) return other + "shell " + u[9];
        if (!"*".equals(u[1]) && !u[1].startsWith("*LOCKED*")) return other + "it has a password";
        if (!GROUP.equals(g[0]) || !g[2].equals(u[3])) return other + "its group is not " + GROUP;
        if (!g[3].isEmpty()) return "the group " + GROUP + " has other members (" + g[3] + "): they would read the panel's files";
        return null;
    }

    static String jarPath() {
        try {
            Path p = Path.of(org.mail_panel.Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return Files.isRegularFile(p) ? p.toAbsolutePath().toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    static String javaPath() {
        return ProcessHandle.current().info().command().filter(c -> Files.isExecutable(Path.of(c))).orElse(null);
    }

    // ===================== I file =====================

    /** Cosa e' cambiato in questo avvio, per la riga DONE (e per le prove). */
    static final List<String> changed = new ArrayList<>();

    /** Porta i file a come li vuole la separazione; null se e' andato tutto, altrimenti il motivo. */
    static String prepareFiles() throws IOException {
        changed.clear();
        // La chiave del vault deve esistere prima di aprirla alla web (la crea il primo uso).
        org.mail_panel.security.PasswordVault.getInstance();

        Path run = runDir;
        if (Files.isSymbolicLink(run) || (Files.exists(run, LinkOption.NOFOLLOW_LINKS) && !Files.isDirectory(run, LinkOption.NOFOLLOW_LINKS)))
            Files.delete(run);
        Files.createDirectories(run);
        set(run, "root", GROUP, "rwxr-x---");

        Path secrets = Path.of(org.mail_panel.security.PanelSecrets.location()).getParent();
        String s = openToWeb(secrets, SECRETS_FOR_WEB);
        if (s != null) return s;
        String d = openToWeb(Path.of("database").toAbsolutePath(), SQLITE_FOR_WEB);
        if (d != null) return d;

        if (Files.isSymbolicLink(auditLog)) return auditLog + " is a symbolic link";
        if (!Files.exists(auditLog)) Files.createFile(auditLog);
        set(auditLog, USER, "wheel", "rw-r-----");

        if (!changed.isEmpty())
            LOGGER.info("[PanelSeparation] DONE: readable by the web part (" + USER + "), never writable: " + String.join(", ", changed));
        return null;
    }

    /**
     * Una cartella 0750 root:mailpanel con i file dati 0640 root:mailpanel; gli altri file della cartella
     * perdono ogni permesso di gruppo e degli altri, cosi' aprire la cartella al gruppo non apre loro.
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
                // Su FreeBSD un file nuovo prende il gruppo della cartella (open(2)): quelli che non sono per
                // la web tornano al gruppo di root, oltre a perdere i permessi di gruppo e degli altri.
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

    /** Proprietario, gruppo e permessi, solo se diversi; annota cosa e' cambiato. */
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

    // ===================== La parte web =====================

    /**
     * Apre il socket, avvia la web e aspetta che risponda. Null se risponde; altrimenti ferma quello che ha
     * avviato e dice perche'. Il dispatcher e' SSLMailServer in modo ROOT_PART.
     */
    public static String startWebPart(int port, RootChannel.Dispatcher dispatcher) {
        String why = startOrReason(port, dispatcher);
        if (why != null) {
            stop();
            notSeparated = why;
        } else {
            active = true;
            notSeparated = null;
            // Se la root si spegne per qualunque motivo (anche un errore subito dopo, prima che Main registri
            // il suo arresto), la web si ferma con lei: da sola risponderebbe 503 a ogni API. Misurato sulla
            // VM il 07/11/2026: un errore nella root dopo questo punto lasciava la web orfana.
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
        long deadline = System.currentTimeMillis() + ANSWER_SECONDS * 1000;
        while (System.currentTimeMillis() < deadline) {
            if (supervisor() <= 0) return "the web part stopped right away: see " + webLog;
            String who = listener(port);
            if (USER.equals(who) && answers(port)) {
                LOGGER.info("Panel web part started as " + USER + " (pid " + readPid(webPid()) + ") on port " + port
                        + "; the root part answers only on " + socket());
                return null;
            }
            try { Thread.sleep(1000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return "interrupted"; }
        }
        return "the web part did not answer on port " + port + " within " + ANSWER_SECONDS + " seconds: see " + webLog;
    }

    /**
     * La riga di daemon(8). Della JVM della root passano solo la memoria e le proprieta' del pannello
     * (-Xm*, -Dmailpanel.*), non mailpanel.separation: la web non ne fa niente.
     */
    static List<String> command(String javaBin, String jar) {
        List<String> cmd = new ArrayList<>(List.of("/usr/sbin/daemon", "-r", "-R", "5", "-u", USER,
                "-P", supervisorPid().toString(), "-p", webPid().toString(), "-o", webLog.toString(), "-H", "-t", TITLE, javaBin));
        for (String a : java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments()) {
            if (a.startsWith("-Xm") || (a.startsWith("-Dmailpanel.") && !a.startsWith("-Dmailpanel.separation"))) cmd.add(a);
        }
        cmd.addAll(List.of("-jar", jar, "--web-part"));
        return cmd;
    }

    /** L'utente del processo che ascolta sulla porta, da sockstat. */
    static String listener(int port) {
        for (String l : Shell.run(Duration.ofSeconds(15), "sockstat", "-46l", "-p", String.valueOf(port)).outputTrim().split("\n")) {
            String[] f = l.trim().split("\\s+");
            if (f.length >= 6 && !"USER".equals(f[0]) && f[5].endsWith(":" + port)) return f[0];
        }
        return null;
    }

    /** Vero se sulla porta risponde un server HTTPS, qualunque stato dia (anche 421 per l'Host). */
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

    /** Il pid del supervisore della web se e' vivo ed e' proprio lui (titolo di daemon), altrimenti -1. */
    static int supervisor() {
        int pid = readPid(supervisorPid());
        if (pid <= 1) return -1;
        String cmd = Shell.run(Duration.ofSeconds(10), "ps", "-o", "command=", "-p", String.valueOf(pid)).outputTrim();
        return cmd.startsWith("daemon: " + TITLE + "[") ? pid : -1;
    }

    /** Una web rimasta da un avvio di prima (la root uccisa senza potersi fermare): si ferma. */
    static void stopLeftover() {
        if (supervisor() > 0) {
            LOGGER.info("[PanelSeparation] a web part of a previous start was still running: stopped");
            stopSupervisor();
        }
    }

    /** Ferma la web: SIGTERM al supervisore, che lo passa alla web e non la riavvia (daemon(8)). */
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

    /** Vero se il pid e' vivo ed e' la web (java ... --web-part di mailpanel). */
    static boolean alive(int pid) {
        if (pid <= 1) return false;
        String l = Shell.run(Duration.ofSeconds(10), "ps", "-o", "user=", "-o", "command=", "-p", String.valueOf(pid)).outputTrim();
        return l.startsWith(USER + " ") && l.contains("--web-part");
    }
}
