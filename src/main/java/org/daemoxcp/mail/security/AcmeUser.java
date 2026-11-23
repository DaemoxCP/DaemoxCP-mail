package org.daemoxcp.mail.security;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.daemoxcp.mail.util.Shell;

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
 * acme.sh with its own user.
 *
 * <p>Requesting a certificate does not need root: you talk to the CA, write a file or a
 * DNS record, receive the certificate. Root is needed only afterwards, to put it where Postfix,
 * Dovecot and nginx read it and to reload them: the panel does that ({@code AcmeManager.deployCertificate}).
 * acme.sh, instead, is a nine-thousand-line shell program that reads the answers from the network, and
 * it has already happened that it executed them: before 3.0.6 an ACME server could make it execute
 * commands through an {@code eval} (CVE-2023-38198, exploited in June 2023). As root, those
 * commands had the machine.
 *
 * <p>So acme.sh comes from the security/acme.sh package, which creates the {@code acme} user (uid 169)
 * with its home in /var/db/acme and installs the program in /usr/local/sbin, updated with the other
 * packages instead of by itself (before: {@code curl https://get.acme.sh | sh} as root, in /root). The
 * panel runs it as acme ({@link #run}); the certificates are in /var/db/acme/certs, as
 * in the configuration of the package.
 *
 * <p>The HTTP challenge: before, acme.sh opened port 80 by itself (--standalone, with socat), which
 * cannot be done without root. Now acme.sh writes the challenge file into /var/db/acme/challenge and
 * port 80 is opened by the panel, only for the duration of the request and only for those files
 * ({@link Challenge}).
 *
 * <p>Renewals are done by the panel, once a day, and after every renewal it installs the certificate:
 * the cron entry that acme.sh wrote for itself into root's renewed in its own folder without installing
 * anything, and as the acme user it could not even do that. That is why it is no longer there.
 *
 * <p>At startup ({@link #ensureAtBoot()}) servers installed earlier move from /root/.acme.sh to
 * /var/db/acme: the package is installed, the account and the certificates are copied, acme.sh is
 * asked, as acme, whether it sees them all; only then is the line removed from root's cron, and
 * /root/.acme.sh gets another name (it is not deleted: the keys are inside). At the first step that
 * fails everything is put back as it was and the panel keeps using acme.sh as root as before, until a
 * later start succeeds.
 */
public final class AcmeUser {

    private static final Logger LOGGER = Logger.getLogger(AcmeUser.class.getName());

    public static final String USER = "acme";
    public static final String BASE = "/var/db/acme";
    public static final String HOME = BASE + "/.acme.sh";
    public static final String CERT_HOME = BASE + "/certs";
    /** The HTTP challenge folder: acme.sh writes into it, the panel serves it on port 80. */
    public static final String WEBROOT = BASE + "/challenge";
    public static final String SCRIPT = "/usr/local/sbin/acme.sh";
    public static final String PACKAGE = "security/acme.sh";
    /** Where the previous installation put it, as root. */
    public static final String OLD_HOME = "/root/.acme.sh";
    /** The name /root/.acme.sh takes after the migration: it stays, but nobody runs it any more. */
    public static final String MOVED_HOME = OLD_HOME + ".moved-to-var-db-acme";
    static final String BACKUP_DIR = "/var/db/daemoxcp-mail/service-users-backup";

    /** The keys of account.conf that are about paths or about self-updating: they are not carried over. */
    private static final Set<String> NOT_CARRIED = Set.of("LOG_FILE", "CERT_HOME", "LE_WORKING_DIR",
            "LE_CONFIG_HOME", "USER_PATH", "AUTO_UPGRADE", "ACME_DIR");

    private static final Duration LONG = Duration.ofMinutes(20);

    private AcmeUser() {}

    // ===================== where acme.sh lives and how it is run =====================

    /**
     * The program, its folders and whether it runs as acme. --cert-home is always passed, like
     * --home and --server: a value taken from elsewhere is a hidden dependency.
     */
    public record Layout(String script, String home, String certHome, boolean asAcme) {
        public String command(String args) {
            return script + " --home " + home + " --cert-home " + certHome + " " + args;
        }

        /** The folders in which acme.sh keeps the certificate of a name: the ECC one first. */
        public List<Path> certDirs(String host) {
            return List.of(Path.of(certHome, host + "_ecc"), Path.of(certHome, host));
        }

        /** The certificate folder of a name, if acme.sh has one; null otherwise. */
        public Path certDir(String host) {
            for (Path d : certDirs(host)) if (Files.exists(d.resolve(host + ".cer"))) return d;
            return null;
        }
    }

    /**
     * What there is on this machine. /root/.acme.sh with the program inside means that the
     * migration has not happened yet (or did not succeed): things go on as before, as root, because
     * that is where the account and the certificates are. null: acme.sh is not there.
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
     * Runs acme.sh. As acme: with su, in an empty environment except for PATH, HOME and the variables
     * passed (the Cloudflare token), so acme.sh gets only what it needs. The
     * arguments end up in a shell line: callers pass only names already checked, and no
     * redirections (stdout and stderr are merged here), so the line is the same for sh and for csh.
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
            // rc.d does not pass HOME. Without it, acme.sh computes "$HOME/.acme.sh" = "/.acme.sh".
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

    /** The challenge folder, owned by acme: acme.sh writes into it, the panel (root) reads it. */
    public static void prepareWebroot() throws IOException {
        Path w = Path.of(WEBROOT);
        Files.createDirectories(w);
        Shell.run(Duration.ofSeconds(10), "chown", USER + ":" + USER, WEBROOT);
        Shell.run(Duration.ofSeconds(10), "chmod", "755", WEBROOT);
    }

    /**
     * A folder chosen by the administrator for the HTTP challenge (the webroot of a site that already
     * answers on 80): acme must be able to write the challenge there, and only that.
     */
    public static void allowChallengeIn(String webroot) throws IOException {
        Path d = Path.of(webroot, ".well-known", "acme-challenge");
        Files.createDirectories(d);
        Shell.run(Duration.ofSeconds(10), "chown", USER + ":" + USER, d.toString());
    }

    /** The value of Le_Webroot in the configuration of the certificate, or null. */
    public static String savedWebroot(Path certDir, String host) {
        try {
            Path conf = certDir.resolve(host + ".conf");
            if (!Files.isRegularFile(conf)) return null;
            for (String l : Files.readAllLines(conf, StandardCharsets.UTF_8))
                if (l.startsWith("Le_Webroot=")) return l.substring("Le_Webroot=".length()).replaceAll("^['\"]|['\"]$", "");
        } catch (IOException ignored) {}
        return null;
    }

    // ===================== the HTTP challenge on port 80 =====================

    /**
     * Port 80 for the duration of a request: it serves /.well-known/acme-challenge/TOKEN from the
     * folder in which acme.sh wrote it, and nothing else. The token is made of letters, digits,
     * "-" and "_" (RFC 8555, base64url): anything else is a 404, so no path gets out of the
     * folder. It closes by itself at the end of the try.
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

    // ===================== the boot migration =====================

    enum Outcome { NOTHING, NOT_YET, BOTH_PLACES, DONE, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Where things are: fixed on the server, temporary folders in the test. */
    record Places(Path oldHome, Path movedHome, Path home, Path certHome, Path backupDir) {
        static Places real() {
            return new Places(Path.of(OLD_HOME), Path.of(MOVED_HOME), Path.of(HOME), Path.of(CERT_HOME), Path.of(BACKUP_DIR));
        }
    }

    /** What is needed from pkg, cron and acme.sh, kept separate so it can be tested without touching them. */
    interface Services {
        /** The program of the package and the acme user are there. */
        boolean packageInstalled();
        Shell.Result installPackage();
        /** Root's cron, "" if it has none, null if it cannot be read. */
        String rootCrontab();
        boolean writeRootCrontab(String content);
        /** Owner and group acme, on everything below, without following links. */
        void giveToAcme(Path p) throws IOException;
        /** The list of certificates that acme.sh sees, asked as acme with the new folders. */
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

        // What is carried over: the account (ca/ and account.conf) and the certificate folders, that is, those
        // that contain NAME.conf (NAME_ecc for ECC certificates). Not the program, dnsapi/,
        // deploy/ and notify/: the package provides them.
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
        // Also whose it was and with which permissions: going back restores everything, not just the text.
        java.nio.file.attribute.PosixFileAttributes accountAttrs = accountBefore == null ? null
                : Files.readAttributes(accountConf, java.nio.file.attribute.PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        String crontabBefore = null;
        try {
            // The package creates it, owned by acme; if it is missing, it is created owned by acme.
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

            // The test: acme.sh, as acme, sees every certificate that was there.
            String list = sv.list();
            for (Path d : certs) {
                String name = d.getFileName().toString().replaceFirst("_ecc$", "");
                if (list == null || !Pattern.compile("(?m)^" + Pattern.quote(name) + "\\s").matcher(list).find())
                    return rollBack(copied, accountConf, accountBefore, accountAttrs, null, sv,
                            "acme.sh, run as " + USER + ", does not list " + name + " after the copy" + (list == null ? " (it did not run)" : ""));
            }

            // Only now does root's cron stop running the old one.
            crontabBefore = sv.rootCrontab();
            if (crontabBefore == null)
                return rollBack(copied, accountConf, accountBefore, accountAttrs, null, sv, "cannot read root's crontab");
            String crontabAfter = withoutAcmeCron(crontabBefore, at.oldHome().toString());
            if (!crontabAfter.equals(crontabBefore)) {
                backup(at, "root-crontab", crontabBefore);
                if (!sv.writeRootCrontab(crontabAfter) || !crontabAfter.equals(sv.rootCrontab()))
                    return rollBack(copied, accountConf, accountBefore, accountAttrs, crontabBefore, sv, "cannot rewrite root's crontab");
            }

            Files.move(at.oldHome(), at.movedHome());
        } catch (IOException | RuntimeException e) {
            return rollBack(copied, accountConf, accountBefore, accountAttrs, crontabBefore, sv, "unexpected error: " + e);
        }
        return new Report(Outcome.DONE, "acme.sh runs as " + USER + " from " + at.home() + ": " + certs.size()
                + " certificate" + (certs.size() == 1 ? "" : "s") + " moved to " + at.certHome()
                + ", root's crontab no longer runs it, the old folder is " + at.movedHome() + " (it can be deleted)");
    }

    private static Report rollBack(Deque<Path> copied, Path accountConf, String accountBefore,
                                   java.nio.file.attribute.PosixFileAttributes accountAttrs, String crontabBefore,
                                   Services sv, String why) {
        List<String> problems = new ArrayList<>();
        while (!copied.isEmpty()) {
            Path p = copied.pop();
            try { deleteTree(p); } catch (IOException e) { problems.add(p + ": " + e.getMessage()); }
        }
        try {
            if (accountBefore == null) Files.deleteIfExists(accountConf);
            else {
                Files.writeString(accountConf, accountBefore, StandardCharsets.UTF_8);
                PosixFileAttributeView v = Files.getFileAttributeView(accountConf, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
                v.setOwner(accountAttrs.owner());
                v.setGroup(accountAttrs.group());
                v.setPermissions(accountAttrs.permissions());
            }
        } catch (IOException e) { problems.add(accountConf + ": " + e.getMessage()); }
        if (crontabBefore != null) {
            String now = sv.rootCrontab();
            if (!crontabBefore.equals(now) && !sv.writeRootCrontab(crontabBefore)) problems.add("root's crontab not put back");
        }
        return new Report(Outcome.ROLLED_BACK, why + "; everything put back, acme.sh keeps running as root"
                + (problems.isEmpty() ? "" : " EXCEPT: " + String.join("; ", problems)));
    }

    /**
     * account.conf: the one of the package (CERT_HOME, LOG_FILE) with the previous account (the email, the
     * SAVED_* tokens, the default CA). The /root paths and self-updating are not carried over: the
     * program is now updated by pkg, and acme cannot write it.
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
        b.append("# Account moved from ").append(oldHome).append(" by DaemoxCP Mail on ")
         .append(LocalDate.now(ZoneOffset.UTC)).append('\n');
        for (String l : lines.values()) b.append(l).append('\n');
        return b.toString();
    }

    /**
     * A certificate requested with --standalone has Le_Webroot='no': renewing it that way would mean
     * opening port 80, which acme cannot do. It is moved to the challenge folder that the panel
     * serves. The other methods (dns_cf, manual DNS, a webroot) stay.
     */
    static String withoutStandalone(String conf) {
        return conf.replaceAll("(?m)^Le_Webroot=(['\"]?)no\\1\\s*$", "Le_Webroot='" + WEBROOT + "'");
    }

    /** Root's cron without the line with which acme.sh ran itself from /root (--cron --home ...). */
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

    /** Copies a folder with its permissions, without following and without copying links. */
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

    // ===================== the real services =====================

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
            // Without a cron for root, crontab exits 1 and says so.
            return r.output().contains("no crontab") ? "" : null;
        }

        @Override public boolean writeRootCrontab(String content) {
            try {
                Path tmp = Files.createTempFile("daemoxcp-mail-crontab", "");
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
                // Neither links nor files with several names: a hard link to a root file is that file (finding 252)
                if (!SafeOwnership.safeToChange(x)) continue;
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
