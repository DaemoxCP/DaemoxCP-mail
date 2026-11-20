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
 * Il pannello in due processi: la parte root, il processo che rc.d
 * avvia con --web, non apre porte; la parte web (--web-part) gira con l'utente daemoxcp_mail, risponde sulla
 * porta del pannello e passa alla root, su un socket unix, le API di chi ha fatto l'accesso.
 *
 * <p>Qui c'e' quello che fa la parte root:
 * <ul>
 *   <li>l'utente e il gruppo daemoxcp_mail: si creano se mancano, e se ci sono devono essere quelli che crea il
 *       pannello (commento, cartella, shell, nessun altro membro nel gruppo): altrimenti l'utente e' di
 *       qualcun altro e non lo si usa;</li>
 *   <li>i file che la web deve leggere: la cartella dei segreti e quella di SQLite diventano 0750
 *       root:daemoxcp_mail, il file dei segreti della web, master.key e il database SQLite 0640 root:daemoxcp_mail.
 *       La web li legge e non li cambia: SQLite lo apre in sola lettura (dataBaseManager.readOnly), e
 *       quello che vi scrive root (nomi, porte, percorsi) la web non lo puo' toccare. Tutto il resto in
 *       quelle cartelle resta solo di root. Il registro di autenticazione, che la web scrive per fail2ban,
 *       diventa di daemoxcp_mail;</li>
 *   <li>il socket e l'avvio della web con daemon(8): {@code -u daemoxcp_mail} fa girare la web con quell'utente,
 *       mentre il supervisore resta root e scrive lui i file pid e il registro (misurato sulla VM il
 *       07/11/2026: pid 0600 root, registro 0600 root:wheel), quindi la web non li puo' cambiare;
 *       {@code -r} la riavvia se muore;</li>
 *   <li>se una condizione manca, o la web non risponde entro {@link #ANSWER_SECONDS}, si ferma quello che
 *       si e' avviato e il pannello serve tutto da root come prima, con un avviso. Non si disfa niente:
 *       root legge comunque i file di daemoxcp_mail.</li>
 * </ul>
 *
 * <p>Per spegnere la separazione a mano: {@code sysrc daemoxcp_mail_opts="-Ddaemoxcp.mail.separation=off"} e
 * {@code service daemoxcp_mail restart}.
 */
public final class PanelSeparation {

    private static final Logger LOGGER = Logger.getLogger(PanelSeparation.class.getName());

    public static final String USER = Product.ID;
    public static final String GROUP = Product.ID;
    /** Il commento con cui il pannello crea l'utente: un utente daemoxcp_mail con un altro non e' suo. */
    static final String GECOS = Product.NAME + " web part";
    static final String HOME = PanelUser.HOME;
    static final String SHELL = PanelUser.SHELL;

    /** La cartella del socket e dei pid; le prove la spostano con -Ddaemoxcp.mail.run.dir. */
    static Path runDir = Path.of(System.getProperty("daemoxcp.mail.run.dir", "/var/run/daemoxcp-mail"));
    static final String TITLE = "daemoxcp-mail-web";
    /** Il titolo e quelli di prima (sezione "webPartTitles"): una web accesa da una versione vecchia si riconosce lo stesso. */
    static java.util.List<String> titles() {
        java.util.List<String> t = new java.util.ArrayList<>(java.util.List.of(TITLE));
        t.addAll(LegacyNames.oldNamesOf("webPartTitles", TITLE));
        return t;
    }
    static Path webLog = Path.of("/var/db/daemoxcp-mail/panel-web.log");
    static Path auditLog = Path.of("/var/log/daemoxcp-mail-auth.log");
    static final long LOG_LIMIT = 10L * 1024 * 1024;
    /** Quanto si aspetta che la web risponda: avvio della JVM, MySQL, le rotte. Sulla VM ci mette pochi secondi. */
    static final long ANSWER_SECONDS = 90;

    /**
     * I file che la web legge nella cartella dei segreti; il resto della cartella resta solo di root. Non piu'
     * master.key: col vault asimmetrico la web cifra con la chiave pubblica, che sta nel suo file, e non legge
     * nessuna copia. La chiave simmetrica di prima resta solo di root.
     */
    static final Set<String> SECRETS_FOR_WEB = Set.of("panel-secrets.properties");
    static final Set<String> SQLITE_FOR_WEB = Set.of("daemoxcp-mail.db");

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
     * di oggi: da quel momento c'e' (o c'e' stato) un processo daemoxcp_mail che scrive nel database, e la root
     * non prende piu' dal database quello che decide dove scrive (SSLMailServer.getAuditLogPath).
     */
    public static boolean rootPart() { return rootPart; }

    /** Perche' il pannello gira tutto da root, per la pagina degli utenti dei servizi; null se e' separato. */
    public static String notSeparatedReason() { return active ? null : notSeparated; }

    /** Spenta a mano (daemoxcp_mail_opts) o per le prove. */
    static boolean switchedOff() {
        return "off".equalsIgnoreCase(System.getProperty("daemoxcp.mail.separation", ""));
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

    /** L'utente della web come lo crea il pannello: i controlli stanno in PanelUser, uguali per ogni utente suo. */
    static final PanelUser WEB_USER = new PanelUser(USER, GECOS);

    /** L'utente daemoxcp_mail, creato se manca. Null se c'e' ed e' quello del pannello; altrimenti il motivo. */
    static String ensureUser() {
        PanelUser.Ensured e = WEB_USER.ensure();
        if (e.problem() != null) return e.problem();
        if (e.created()) LOGGER.info("[PanelSeparation] DONE: user and group " + USER + " created (no password, no shell,"
                + " home " + HOME + "): the panel's web part runs with it");
        return null;
    }

    /** Null se le righe di pw sono quelle dell'utente creato dal pannello; altrimenti cosa non torna. Pura. */
    static String userProblem(String userLine, String groupLine) {
        return WEB_USER.problem(userLine, groupLine);
    }

    static String jarPath() {
        try {
            Path p = Path.of(org.daemoxcp.mail.Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            // Col nome di adesso se questo processo ha appena spostato il jar (PanelServiceRename).
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

    /** Cosa e' cambiato in questo avvio, per la riga DONE (e per le prove). */
    static final List<String> changed = new ArrayList<>();

    /** Porta i file a come li vuole la separazione; null se e' andato tutto, altrimenti il motivo. */
    static String prepareFiles() throws IOException {
        changed.clear();
        // Le chiavi del vault prima di accendere la web: la privata nel file di root, la pubblica in quello della
        // web, con cui la web cifra le copie delle password nuove.
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
     * Una cartella 0750 root:daemoxcp_mail con i file dati 0640 root:daemoxcp_mail; gli altri file della cartella
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

    /**
     * Le pagine del pannello e i loro script e stili (PanelContent, PageAssets): la web li serve, quindi
     * cartelle 0750 e file 0640 root:daemoxcp_mail, in sola lettura. Solo cartelle e file veri, mai collegamenti.
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

    /** Quello che serve per aspettare la web: il pid del supervisore (o -1) e se la web risponde sulla porta. */
    interface Probe {
        int supervisor();
        boolean answering();
    }

    /** Una pausa fra un controllo e l'altro (un secondo; nelle prove niente). */
    @FunctionalInterface
    interface Pause {
        void pause() throws InterruptedException;
    }

    static final String GONE = "gone", SILENT = "silent";
    /** Quanti controlli di fila senza supervisore prima di dire che la web si e' fermata. */
    static final int GONE_CHECKS = 3;

    /**
     * Aspetta che la web risponda: null se risponde, GONE se il supervisore manca per GONE_CHECKS controlli di fila,
     * SILENT se non risponde entro seconds. Prima di ogni controllo una pausa: daemon(8) torna quando il padre esce, e
     * il supervisore scrive il suo pidfile un attimo dopo; controllare subito leggeva un pidfile vuoto, o quello del
     * supervisore di prima, gia' morto, e dava la web per fermata mentre partiva (misurato sulla VM il 20/11/2026: una
     * volta su molti avvii, e il pannello restava tutto da root). Pura rispetto a Probe e Pause.
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
     * La riga di daemon(8). Della JVM della root passano solo la memoria e le proprieta' del pannello
     * (-Xm*, -Ddaemoxcp_mail.*), non daemoxcp.mail.separation: la web non ne fa niente.
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
        for (String t : titles()) if (cmd.startsWith("daemon: " + t + "[")) return pid;
        return -1;
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

    /** Vero se il pid e' vivo ed e' la web (java ... --web-part di daemoxcp_mail). */
    static boolean alive(int pid) {
        if (pid <= 1) return false;
        String l = Shell.run(Duration.ofSeconds(10), "ps", "-o", "user=", "-o", "command=", "-p", String.valueOf(pid)).outputTrim();
        return l.startsWith(USER + " ") && l.contains("--web-part");
    }
}
