package org.mail_panel.security;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.mail_panel.util.Shell;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * acme.sh col suo utente.
 *
 * <p>Per chiedere un certificato non serve root: si parla con la CA, si scrive un file o un
 * record DNS, si riceve il certificato. Root serve solo dopo, per metterlo dove lo leggono Postfix,
 * Dovecot e nginx e per ricaricarli: lo fa il pannello ({@code AcmeManager.deployCertificate}).
 * acme.sh invece e' un programma di shell di novemila righe che legge le risposte della rete, e
 * gli e' gia' successo di eseguirle: prima della 3.0.6 un server ACME poteva fargli eseguire
 * comandi attraverso un {@code eval} (CVE-2023-38198, sfruttato nel giugno 2023). Da root, quei
 * comandi avevano la macchina.
 *
 * <p>Quindi acme.sh viene dal pacchetto security/acme.sh, che crea l'utente {@code acme} (uid 169)
 * con la casa in /var/db/acme e installa il programma in /usr/local/sbin, aggiornato con gli altri
 * pacchetti invece che da se' (prima: {@code curl https://get.acme.sh | sh} da root, in /root). Il
 * pannello lo esegue come acme ({@link #run}); i certificati stanno in /var/db/acme/certs, come
 * nella configurazione del pacchetto.
 *
 * <p>La sfida HTTP: prima acme.sh apriva da se' la porta 80 (--standalone, con socat), cosa che
 * senza root non si puo'. Adesso acme.sh scrive il file della sfida in /var/db/acme/challenge e la
 * porta 80 la apre il pannello, solo per il tempo della richiesta e solo per quei file
 * ({@link Challenge}).
 *
 * <p>I rinnovi li fa il pannello, una volta al giorno, e dopo ogni rinnovo installa il certificato:
 * il cron che acme.sh si scriveva in quello di root rinnovava nella sua cartella senza installare
 * niente, e con l'utente acme non potrebbe nemmeno farlo. Per questo non c'e' piu'.
 *
 * <p>All'avvio ({@link #ensureAtBoot()}) i server installati prima passano da /root/.acme.sh a
 * /var/db/acme: si installa il pacchetto, si copiano l'account e i certificati, si chiede ad
 * acme.sh, come acme, se li vede tutti; solo dopo si toglie la riga dal cron di root e /root/.acme.sh
 * prende un altro nome (non si cancella: dentro ci sono le chiavi). Al primo passo che fallisce si
 * rimette tutto com'era e il pannello continua a usare acme.sh da root come prima, finche' un avvio
 * successivo non ci riesce.
 */
public final class AcmeUser {

    private static final Logger LOGGER = Logger.getLogger(AcmeUser.class.getName());

    public static final String USER = "acme";
    public static final String BASE = "/var/db/acme";
    public static final String HOME = BASE + "/.acme.sh";
    public static final String CERT_HOME = BASE + "/certs";
    /** La cartella delle sfide HTTP: acme.sh ci scrive, il pannello la serve sulla porta 80. */
    public static final String WEBROOT = BASE + "/challenge";
    public static final String SCRIPT = "/usr/local/sbin/acme.sh";
    public static final String PACKAGE = "security/acme.sh";
    /** Dove lo metteva l'installazione di prima, da root. */
    public static final String OLD_HOME = "/root/.acme.sh";
    /** Il nome che prende /root/.acme.sh dopo la migrazione: resta, ma nessuno lo esegue piu'. */
    public static final String MOVED_HOME = OLD_HOME + ".moved-to-var-db-acme";
    static final String BACKUP_DIR = "/var/db/mailpanel/service-users-backup";

    /** Le chiavi di account.conf che parlano di percorsi o dell'aggiornamento da se': non si portano. */
    private static final Set<String> NOT_CARRIED = Set.of("LOG_FILE", "CERT_HOME", "LE_WORKING_DIR",
            "LE_CONFIG_HOME", "USER_PATH", "AUTO_UPGRADE", "ACME_DIR");

    private static final Duration LONG = Duration.ofMinutes(20);

    private AcmeUser() {}

    // ===================== dove sta acme.sh e come si esegue =====================

    /**
     * Il programma, le sue cartelle e se si esegue come acme. Il --cert-home si passa sempre, come
     * --home e --server: un valore preso da altrove e' una dipendenza nascosta.
     */
    public record Layout(String script, String home, String certHome, boolean asAcme) {
        public String command(String args) {
            return script + " --home " + home + " --cert-home " + certHome + " " + args;
        }

        /** Le cartelle in cui acme.sh tiene il certificato di un nome: prima quella ECC. */
        public List<Path> certDirs(String host) {
            return List.of(Path.of(certHome, host + "_ecc"), Path.of(certHome, host));
        }

        /** La cartella del certificato di un nome, se acme.sh ne ha uno; null altrimenti. */
        public Path certDir(String host) {
            for (Path d : certDirs(host)) if (Files.exists(d.resolve(host + ".cer"))) return d;
            return null;
        }
    }

    /**
     * Quello che c'e' su questa macchina. /root/.acme.sh con dentro il programma vuol dire che la
     * migrazione non c'e' ancora stata (o non e' riuscita): si continua come prima, da root, perche'
     * li' stanno l'account e i certificati. null: acme.sh non c'e'.
     */
    public static Layout layout() {
        if (Files.isRegularFile(Path.of(OLD_HOME, "acme.sh")))
            return new Layout(OLD_HOME + "/acme.sh", OLD_HOME, OLD_HOME, false);
        if (Files.isRegularFile(Path.of(SCRIPT)) && userExists())
            return new Layout(SCRIPT, HOME, CERT_HOME, true);
        return null;
    }

    static boolean userExists() {
        return Shell.run(Duration.ofSeconds(10), "pw", "usershow", USER).success();
    }

    /**
     * Esegue acme.sh. Come acme: con su, in un ambiente vuoto salvo PATH, HOME e le variabili
     * passate (il token di Cloudflare), cosi' a acme.sh arriva solo quello che gli serve. Gli
     * argomenti finiscono in una riga di shell: chi chiama passa solo nomi gia' controllati, e niente
     * redirezioni (stdout e stderr si uniscono qui), cosi' la riga e' la stessa per sh e per csh.
     */
    public static String run(Layout l, String args, Map<String, String> env) throws IOException, InterruptedException {
        String line = l.command(args);
        ProcessBuilder pb = l.asAcme()
                ? new ProcessBuilder("su", "-m", USER, "-c", line)
                : new ProcessBuilder("/bin/sh", "-c", line);
        if (l.asAcme()) {
            pb.environment().clear();
            Shell.applyPath(pb);
            pb.environment().put("HOME", BASE);
            pb.directory(new java.io.File(BASE));
        } else {
            Shell.applyPath(pb);
            // rc.d non passa HOME. Senza, acme.sh calcola "$HOME/.acme.sh" = "/.acme.sh".
            pb.environment().putIfAbsent("HOME", "/root");
        }
        if (env != null) pb.environment().putAll(env);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        p.getOutputStream().close();
        java.util.concurrent.atomic.AtomicReference<String> out = new java.util.concurrent.atomic.AtomicReference<>("");
        try (InputStream in = p.getInputStream()) {
            Thread reader = Thread.ofVirtual().start(() -> {
                try { out.set(new String(in.readAllBytes(), StandardCharsets.UTF_8)); } catch (IOException ignored) {}
            });
            boolean finished = p.waitFor(LONG.toMinutes(), TimeUnit.MINUTES);
            if (!finished) p.destroyForcibly();
            reader.join(5000);
            return finished ? out.get() : out.get() + "\n[timed out after " + LONG.toMinutes() + " minutes]\n";
        }
    }

    /** La cartella delle sfide, di acme: acme.sh ci scrive, il pannello (root) la legge. */
    public static void prepareWebroot() throws IOException {
        Path w = Path.of(WEBROOT);
        Files.createDirectories(w);
        Shell.run(Duration.ofSeconds(10), "chown", USER + ":" + USER, WEBROOT);
        Shell.run(Duration.ofSeconds(10), "chmod", "755", WEBROOT);
    }

    /**
     * Una cartella scelta dall'amministratore per la sfida HTTP (il webroot di un sito che gia'
     * risponde sulla 80): acme deve poterci scrivere la sfida, e solo quella.
     */
    public static void allowChallengeIn(String webroot) throws IOException {
        Path d = Path.of(webroot, ".well-known", "acme-challenge");
        Files.createDirectories(d);
        Shell.run(Duration.ofSeconds(10), "chown", USER + ":" + USER, d.toString());
    }

    /** Il valore di Le_Webroot nella configurazione del certificato, o null. */
    public static String savedWebroot(Path certDir, String host) {
        try {
            Path conf = certDir.resolve(host + ".conf");
            if (!Files.isRegularFile(conf)) return null;
            for (String l : Files.readAllLines(conf, StandardCharsets.UTF_8))
                if (l.startsWith("Le_Webroot=")) return l.substring("Le_Webroot=".length()).replaceAll("^['\"]|['\"]$", "");
        } catch (IOException ignored) {}
        return null;
    }

    // ===================== la sfida HTTP sulla porta 80 =====================

    /**
     * La porta 80 per il tempo di una richiesta: serve /.well-known/acme-challenge/GETTONE dalla
     * cartella in cui acme.sh l'ha scritto, e nient'altro. Il gettone e' fatto di lettere, cifre,
     * "-" e "_" (RFC 8555, base64url): qualunque altra cosa e' un 404, cosi' nessun percorso esce
     * dalla cartella. Si chiude da se' alla fine del try.
     */
    public static final class Challenge implements AutoCloseable {
        private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9_-]{1,256}");
        static final String PREFIX = "/.well-known/acme-challenge/";
        private final HttpServer server;

        private Challenge(HttpServer server) { this.server = server; }

        public static Challenge open() throws IOException {
            return open(80, Path.of(WEBROOT, ".well-known", "acme-challenge"));
        }

        static Challenge open(int port, Path dir) throws IOException {
            HttpServer s = HttpServer.create(new InetSocketAddress(port), 16);
            s.createContext("/", ex -> answer(ex, dir));
            s.setExecutor(null);
            s.start();
            return new Challenge(s);
        }

        private static void answer(HttpExchange ex, Path dir) throws IOException {
            try (ex) {
                String path = ex.getRequestURI().getRawPath();
                boolean get = "GET".equals(ex.getRequestMethod()) || "HEAD".equals(ex.getRequestMethod());
                String token = path != null && path.startsWith(PREFIX) ? path.substring(PREFIX.length()) : "";
                Path f = TOKEN.matcher(token).matches() ? dir.resolve(token) : null;
                if (!get || f == null || !Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS) || Files.size(f) > 4096) {
                    ex.sendResponseHeaders(404, -1);
                    return;
                }
                byte[] body = Files.readAllBytes(f);
                ex.getResponseHeaders().set("Content-Type", "text/plain");
                boolean head = "HEAD".equals(ex.getRequestMethod());
                ex.sendResponseHeaders(200, head ? -1 : body.length);
                if (!head) try (OutputStream o = ex.getResponseBody()) { o.write(body); }
            }
        }

        @Override public void close() { server.stop(0); }
    }

    // ===================== la migrazione all'avvio =====================

    enum Outcome { NOTHING, NOT_YET, BOTH_PLACES, DONE, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Dove stanno le cose: fisse sul server, cartelle temporanee nella prova. */
    record Places(Path oldHome, Path movedHome, Path home, Path certHome, Path backupDir) {
        static Places real() {
            return new Places(Path.of(OLD_HOME), Path.of(MOVED_HOME), Path.of(HOME), Path.of(CERT_HOME), Path.of(BACKUP_DIR));
        }
    }

    /** Quello che serve da pkg, cron e acme.sh, separato per provarlo senza toccarli. */
    interface Services {
        /** Il programma del pacchetto e l'utente acme ci sono. */
        boolean packageInstalled();
        Shell.Result installPackage();
        /** Il cron di root, "" se non ne ha, null se non si legge. */
        String rootCrontab();
        boolean writeRootCrontab(String content);
        /** Proprietario e gruppo acme, su tutto quello che c'e' sotto, senza seguire i link. */
        void giveToAcme(Path p) throws IOException;
        /** L'elenco dei certificati che acme.sh vede, chiesto come acme con le cartelle nuove. */
        String list();
    }

    public static void ensureAtBoot() {
        try {
            Report r = migrate(Places.real(), new RealServices());
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[AcmeUser] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[AcmeUser] failed: " + t);
        }
    }

    static Report migrate(Places at, Services sv) throws IOException {
        if (!Files.isDirectory(at.oldHome(), LinkOption.NOFOLLOW_LINKS)) return new Report(Outcome.NOTHING, "");
        if (Files.exists(at.movedHome(), LinkOption.NOFOLLOW_LINKS))
            return new Report(Outcome.BOTH_PLACES, "both " + at.oldHome() + " and " + at.movedHome() + " exist: nothing moved");

        if (!sv.packageInstalled()) {
            Shell.Result r = sv.installPackage();
            if (!sv.packageInstalled())
                return new Report(Outcome.NOT_YET, "cannot install " + PACKAGE + " (" + r.outputTrim().lines().reduce((a, b) -> b).orElse("")
                        + "): acme.sh keeps running as root from " + at.oldHome() + ", retrying at the next start");
        }

        // Cosa si porta: l'account (ca/ e account.conf) e le cartelle dei certificati, cioe' quelle
        // che hanno dentro NOME.conf (NOME_ecc per i certificati ECC). Il programma, dnsapi/,
        // deploy/ e notify/ no: li da' il pacchetto.
        List<Path> certs = new ArrayList<>();
        try (Stream<Path> s = Files.list(at.oldHome())) {
            for (Path d : s.sorted().toList()) {
                if (!Files.isDirectory(d, LinkOption.NOFOLLOW_LINKS)) continue;
                String name = d.getFileName().toString().replaceFirst("_ecc$", "");
                if (Files.isRegularFile(d.resolve(name + ".conf"))) certs.add(d);
            }
        }
        Path oldCa = at.oldHome().resolve("ca"), newCa = at.home().resolve("ca");
        if (Files.isDirectory(oldCa) && Files.exists(newCa))
            return new Report(Outcome.BOTH_PLACES, "both " + oldCa + " and " + newCa + " exist: nothing moved");
        for (Path d : certs)
            if (Files.exists(at.certHome().resolve(d.getFileName())))
                return new Report(Outcome.BOTH_PLACES, "both " + d + " and " + at.certHome().resolve(d.getFileName()) + " exist: nothing moved");

        Deque<Path> copied = new ArrayDeque<>();
        Path accountConf = at.home().resolve("account.conf");
        String accountBefore = Files.isRegularFile(accountConf) ? Files.readString(accountConf, StandardCharsets.UTF_8) : null;
        String crontabBefore = null;
        try {
            // La crea il pacchetto, di acme; se manca, la si crea di acme.
            if (!Files.isDirectory(at.certHome())) {
                Files.createDirectories(at.certHome());
                sv.giveToAcme(at.certHome());
            }
            if (Files.isDirectory(oldCa)) { copyTree(oldCa, newCa); copied.push(newCa); sv.giveToAcme(newCa); }
            for (Path d : certs) {
                Path to = at.certHome().resolve(d.getFileName());
                copyTree(d, to);
                copied.push(to);
                String name = d.getFileName().toString().replaceFirst("_ecc$", "");
                Path conf = to.resolve(name + ".conf");
                Files.writeString(conf, withoutStandalone(Files.readString(conf, StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
                sv.giveToAcme(to);
            }
            Path oldAccount = at.oldHome().resolve("account.conf");
            if (Files.isRegularFile(oldAccount)) {
                Files.writeString(accountConf, mergedAccount(accountBefore, Files.readString(oldAccount, StandardCharsets.UTF_8),
                        at.oldHome().toString()), StandardCharsets.UTF_8);
                sv.giveToAcme(accountConf);
                Files.setPosixFilePermissions(accountConf, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r-----"));
            }

            // La prova: acme.sh, come acme, vede ogni certificato che c'era.
            String list = sv.list();
            for (Path d : certs) {
                String name = d.getFileName().toString().replaceFirst("_ecc$", "");
                if (list == null || !Pattern.compile("(?m)^" + Pattern.quote(name) + "\\s").matcher(list).find())
                    return rollBack(copied, accountConf, accountBefore, null, sv,
                            "acme.sh, run as " + USER + ", does not list " + name + " after the copy" + (list == null ? " (it did not run)" : ""));
            }

            // Solo adesso il cron di root smette di eseguire quello vecchio.
            crontabBefore = sv.rootCrontab();
            if (crontabBefore == null)
                return rollBack(copied, accountConf, accountBefore, null, sv, "cannot read root's crontab");
            String crontabAfter = withoutAcmeCron(crontabBefore, at.oldHome().toString());
            if (!crontabAfter.equals(crontabBefore)) {
                backup(at, "root-crontab", crontabBefore);
                if (!sv.writeRootCrontab(crontabAfter) || !crontabAfter.equals(sv.rootCrontab()))
                    return rollBack(copied, accountConf, accountBefore, crontabBefore, sv, "cannot rewrite root's crontab");
            }

            Files.move(at.oldHome(), at.movedHome());
        } catch (IOException | RuntimeException e) {
            return rollBack(copied, accountConf, accountBefore, crontabBefore, sv, "unexpected error: " + e);
        }
        return new Report(Outcome.DONE, "acme.sh runs as " + USER + " from " + at.home() + ": " + certs.size()
                + " certificate" + (certs.size() == 1 ? "" : "s") + " moved to " + at.certHome()
                + ", root's crontab no longer runs it, the old folder is " + at.movedHome() + " (it can be deleted)");
    }

    private static Report rollBack(Deque<Path> copied, Path accountConf, String accountBefore, String crontabBefore,
                                   Services sv, String why) {
        List<String> problems = new ArrayList<>();
        while (!copied.isEmpty()) {
            Path p = copied.pop();
            try { deleteTree(p); } catch (IOException e) { problems.add(p + ": " + e.getMessage()); }
        }
        try {
            if (accountBefore == null) Files.deleteIfExists(accountConf);
            else Files.writeString(accountConf, accountBefore, StandardCharsets.UTF_8);
        } catch (IOException e) { problems.add(accountConf + ": " + e.getMessage()); }
        if (crontabBefore != null) {
            String now = sv.rootCrontab();
            if (!crontabBefore.equals(now) && !sv.writeRootCrontab(crontabBefore)) problems.add("root's crontab not put back");
        }
        return new Report(Outcome.ROLLED_BACK, why + "; everything put back, acme.sh keeps running as root"
                + (problems.isEmpty() ? "" : " EXCEPT: " + String.join("; ", problems)));
    }

    /**
     * account.conf: quello del pacchetto (CERT_HOME, LOG_FILE) con l'account di prima (l'email, i
     * token SAVED_*, la CA predefinita). Non si portano i percorsi di /root ne' l'aggiornamento da
     * se': il programma adesso lo aggiorna pkg, e acme non puo' scriverlo.
     */
    static String mergedAccount(String pkgConf, String oldConf, String oldHome) {
        Map<String, String> lines = new LinkedHashMap<>();
        List<String> comments = new ArrayList<>();
        String[] confs = { pkgConf == null ? "" : pkgConf, oldConf };
        for (int i = 0; i < confs.length; i++) {
            boolean old = i == 1;
            for (String l : confs[i].split("\n")) {
                String t = l.trim();
                if (t.isEmpty() || t.startsWith("#") || t.indexOf('=') < 1) {
                    if (!old && !t.isEmpty()) comments.add(l);
                    continue;
                }
                String k = t.substring(0, t.indexOf('='));
                if (old && (NOT_CARRIED.contains(k) || t.contains(oldHome))) continue;
                lines.put(k, t);
            }
        }
        StringBuilder b = new StringBuilder();
        for (String c : comments) b.append(c).append('\n');
        b.append("# Account moved from ").append(oldHome).append(" by the mail panel on ")
         .append(LocalDate.now(ZoneOffset.UTC)).append('\n');
        for (String l : lines.values()) b.append(l).append('\n');
        return b.toString();
    }

    /**
     * Un certificato chiesto con --standalone ha Le_Webroot='no': rinnovarlo cosi' vorrebbe dire
     * aprire la porta 80, che acme non puo'. Lo si sposta sulla cartella delle sfide che il pannello
     * serve. Gli altri metodi (dns_cf, il DNS a mano, un webroot) restano.
     */
    static String withoutStandalone(String conf) {
        return conf.replaceAll("(?m)^Le_Webroot=(['\"]?)no\\1\\s*$", "Le_Webroot='" + WEBROOT + "'");
    }

    /** Il cron di root senza la riga con cui acme.sh si eseguiva da /root (--cron --home ...). */
    static String withoutAcmeCron(String crontab, String oldHome) {
        List<String> keep = crontab.lines()
                .filter(l -> l.trim().startsWith("#") || !(l.contains(oldHome) && l.contains("--cron")))
                .toList();
        if (keep.size() == crontab.lines().count()) return crontab;
        String s = String.join("\n", keep);
        return keep.isEmpty() ? "" : crontab.endsWith("\n") ? s + "\n" : s;
    }

    private static void backup(Places at, String name, String content) {
        try {
            Path dir = at.backupDir().resolve("acme-" + LocalDate.now(ZoneOffset.UTC));
            Files.createDirectories(dir);
            Files.writeString(dir.resolve(name), content, StandardCharsets.UTF_8);
        } catch (IOException e) {
            LOGGER.warning("[AcmeUser] cannot keep a copy of " + name + ": " + e.getMessage());
        }
    }

    /** Copia una cartella coi permessi, senza seguire e senza copiare i link. */
    static void copyTree(Path from, Path to) throws IOException {
        List<Path> all;
        try (Stream<Path> s = Files.walk(from)) { all = s.toList(); }
        for (Path p : all) {
            if (Files.isSymbolicLink(p)) continue;
            Path dest = to.resolve(from.relativize(p).toString());
            if (Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.exists(dest, LinkOption.NOFOLLOW_LINKS)) throw new FileAlreadyExistsException(dest.toString());
                Files.createDirectory(dest);
                Files.setPosixFilePermissions(dest, Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS));
            } else {
                Files.copy(p, dest, StandardCopyOption.COPY_ATTRIBUTES, LinkOption.NOFOLLOW_LINKS);
            }
        }
    }

    static void deleteTree(Path p) throws IOException {
        if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) return;
        List<Path> all;
        try (Stream<Path> s = Files.walk(p)) { all = new ArrayList<>(s.toList()); }
        java.util.Collections.reverse(all);
        for (Path x : all) Files.delete(x);
    }

    // ===================== i servizi veri =====================

    private static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(20);

        @Override public boolean packageInstalled() {
            return Files.isRegularFile(Path.of(SCRIPT)) && userExists();
        }

        @Override public Shell.Result installPackage() {
            return Shell.run(Duration.ofMinutes(10), "pkg", "install", "-y", PACKAGE);
        }

        @Override public String rootCrontab() {
            Shell.Result r = Shell.run(SHORT, "crontab", "-l", "-u", "root");
            if (r.success()) return r.output();
            // Senza cron per root crontab esce 1 e lo dice.
            return r.output().contains("no crontab") ? "" : null;
        }

        @Override public boolean writeRootCrontab(String content) {
            try {
                Path tmp = Files.createTempFile("mailpanel-crontab", "");
                try {
                    Files.writeString(tmp, content.endsWith("\n") || content.isEmpty() ? content : content + "\n", StandardCharsets.UTF_8);
                    return Shell.run(SHORT, "crontab", "-u", "root", tmp.toString()).success();
                } finally {
                    Files.deleteIfExists(tmp);
                }
            } catch (IOException e) {
                return false;
            }
        }

        @Override public void giveToAcme(Path p) throws IOException {
            UserPrincipalLookupService names = p.getFileSystem().getUserPrincipalLookupService();
            var u = names.lookupPrincipalByName(USER);
            var g = names.lookupPrincipalByGroupName(USER);
            List<Path> all;
            try (Stream<Path> s = Files.walk(p)) { all = s.toList(); }
            for (Path x : all) {
                if (Files.isSymbolicLink(x)) continue;
                PosixFileAttributeView v = Files.getFileAttributeView(x, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
                v.setOwner(u);
                v.setGroup(g);
            }
        }

        @Override public String list() {
            try {
                return run(new Layout(SCRIPT, HOME, CERT_HOME, true), "--list", null);
            } catch (IOException | InterruptedException e) {
                return null;
            }
        }
    }
}
