package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dovecot's process that looks up passwords (auth-worker) no longer runs as root.
 *
 * Measured on 2026-11-07 on the production server and on the VM (Dovecot 2.3.21): `dovecot/auth -w` runs
 * as root, because in 2.3 its default user is root. It would need root only for PAM, /etc/passwd or
 * /etc/shadow; here the passwords are in MySQL (passdb sql) and the master user in the master-users file
 * (passwd-file), so Dovecot's internal user is enough. Tested on the VM: with
 * `service auth-worker { user = dovecot }` the process runs as dovecot, a real login succeeds, a wrong
 * password is rejected, and dovecot-sql.conf can stay 0600 (Dovecot reads it before dropping privileges).
 *
 * The Dovecot 2.3 manual says so too (configuration_manual/service_configuration, auth-worker section):
 * root is the default only because PAM usually reads /etc/shadow, and if it is not needed it is better
 * to change it, for example to $default_internal_user. The user's name is written, not the variable,
 * because in 2.4 the variable syntax changed and the name works for both.
 *
 * The installer writes it from now on (DovecotConfig, conf.d/10-auth-worker.conf); on servers installed
 * earlier this boot repair does it, with the same file. Before touching anything it checks that
 * authentication works; after the reload it checks that it still works and that no auth-worker is left
 * running as root. If something does not add up it removes the file and reloads: Dovecot stays as it
 * was. At the second startup it does nothing and writes nothing.
 */
public final class DovecotAuthWorker {

    private static final Logger LOGGER = Logger.getLogger(DovecotAuthWorker.class.getName());

    static final String DOVECONF = "/usr/local/bin/doveconf";
    static final String DOVEADM = "/usr/local/bin/doveadm";
    static final String CONF_D = "/usr/local/etc/dovecot/conf.d";
    static final String FILE_NAME = "10-auth-worker.conf";

    /** The drivers that read system files or talk to PAM: with them auth-worker must stay root. */
    static final Set<String> NEED_ROOT = Set.of("pam", "passwd", "shadow", "bsdauth", "checkpassword", "vpopmail");

    /** An address that does not exist: the lookup goes through auth-worker and MySQL without finding anyone. */
    static final String PROBE = "daemoxcp-mail-auth-probe@invalid";

    /** Exit codes of `doveadm auth lookup`: found, or the user is not there (EX_NOUSER). Anything else is a fault. */
    static final Set<Integer> LOOKUP_OK = Set.of(0, 67);

    private static final Pattern USER_NAME = Pattern.compile("[a-z_][a-z0-9_-]{0,31}");
    private static final Pattern DRIVER = Pattern.compile("(?m)^\\s*driver\\s*=\\s*(\\S+)");

    private DovecotAuthWorker() {}

    enum Action { NOTHING, APPLY, STAYS_ROOT }

    record Decision(Action action, String reason) {}

    /** The content of the file: the same for the installer (DovecotConfig) and for the repair. */
    public static String fileContent(String user) {
        return "# " + PanelMarker.WRITTEN + ".\n"
             + "# The process that looks up passwords (auth-worker) does not need root: the passwords\n"
             + "# are in MySQL and the master user in a Dovecot file. Root would only be needed for PAM,\n"
             + "# /etc/passwd or /etc/shadow, which are not used here.\n"
             + "service auth-worker {\n"
             + "  user = " + user + "\n"
             + "}\n";
    }

    /** The passdb and userdb drivers, from the output of `doveconf -n`. */
    static Set<String> drivers(String doveconfN) {
        Set<String> out = new TreeSet<>();
        if (doveconfN == null) return out;
        Matcher m = DRIVER.matcher(doveconfN);
        while (m.find()) out.add(m.group(1).toLowerCase(java.util.Locale.ROOT));
        return out;
    }

    /**
     * What to do. A pure function, so that it can be tested.
     *
     * @param workerUser the auth-worker user from `doveconf -h service/auth-worker/user` ("" = root)
     * @param doveconfN  the output of `doveconf -n`
     * @param internal   Dovecot's internal user (`doveconf -h default_internal_user`)
     * @param internalExists whether that user exists on the system
     */
    static Decision decide(String workerUser, String doveconfN, String internal, boolean internalExists) {
        String u = workerUser == null ? "" : workerUser.trim();
        if (!u.isEmpty() && !u.equals("root")) return new Decision(Action.NOTHING, "auth-worker already runs as " + u);
        Set<String> needRoot = new TreeSet<>(drivers(doveconfN));
        needRoot.retainAll(NEED_ROOT);
        if (!needRoot.isEmpty())
            return new Decision(Action.STAYS_ROOT, "auth-worker stays root: the driver " + String.join(", ", needRoot) + " needs it");
        if (internal == null || !USER_NAME.matcher(internal).matches() || !internalExists)
            return new Decision(Action.STAYS_ROOT, "auth-worker stays root: Dovecot's internal user '" + internal + "' is not on the system");
        return new Decision(Action.APPLY, "auth-worker runs as root without needing it");
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(DOVECONF)) || !Files.isExecutable(Path.of(DOVEADM))) return;
            Shell.Result worker = Shell.run(Duration.ofSeconds(15), DOVECONF, "-h", "service/auth-worker/user");
            Shell.Result conf = Shell.run(Duration.ofSeconds(15), DOVECONF, "-n");
            Shell.Result internal = Shell.run(Duration.ofSeconds(15), DOVECONF, "-h", "default_internal_user");
            if (!worker.success() || !conf.success() || !internal.success()) return;
            String user = internal.outputTrim();
            boolean exists = USER_NAME.matcher(user).matches() && Shell.run(Duration.ofSeconds(10), "id", "-u", user).success();
            Decision d = decide(worker.outputTrim(), conf.output(), user, exists);
            switch (d.action()) {
                case NOTHING -> { return; }
                case STAYS_ROOT -> { LOGGER.info("[DovecotAuthWorker] " + d.reason()); return; }
                case APPLY -> apply(user);
            }
        } catch (Throwable t) {
            LOGGER.warning("[DovecotAuthWorker] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /** Writes the file, validates, reloads and verifies; if the verification fails, puts things back as they were. */
    static boolean apply(String user) throws Exception {
        if (!running()) {
            LOGGER.info("[DovecotAuthWorker] Dovecot is not running: auth-worker left as it is, retrying at the next start");
            return false;
        }
        int before = lookup();
        if (!LOOKUP_OK.contains(before)) {
            LOGGER.warning("[DovecotAuthWorker] authentication already fails before any change (doveadm auth lookup exit "
                    + before + "): auth-worker left as it is");
            return false;
        }
        Path file = Path.of(CONF_D, FILE_NAME);
        Path saved = Files.exists(file) ? Files.createTempFile(Path.of(CONF_D).getParent(), ".auth-worker-", ".saved") : null;
        if (saved != null) Files.copy(file, saved, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        try {
            write(file, fileContent(user));
            Shell.Result check = Shell.run(Duration.ofSeconds(15), DOVECONF, "-n");
            if (!check.success()) {
                putBack(file, saved, false);
                LOGGER.warning("[DovecotAuthWorker] ROLLED_BACK: doveconf refuses the setting (" + firstLine(check.outputTrim())
                        + "): nothing changed");
                return false;
            }
            if (!reload()) {
                putBack(file, saved, true);
                LOGGER.warning("[DovecotAuthWorker] ROLLED_BACK: service dovecot reload failed: everything put back");
                return false;
            }
            String problem = verify(user);
            if (problem != null) {
                putBack(file, saved, true);
                int again = lookup();
                LOGGER.warning("[DovecotAuthWorker] ROLLED_BACK: " + problem + "; everything put back (lookup now exit " + again + ")");
                return false;
            }
            LOGGER.info("[DovecotAuthWorker] DONE: auth-worker runs as " + user + ", no longer as root (" + file
                    + "); passwords still looked up in MySQL");
            return true;
        } finally {
            if (saved != null) Files.deleteIfExists(saved);
        }
    }

    /** After the reload: the lookup still goes through, and the running auth-workers all run as the right user. */
    static String verify(String user) throws InterruptedException {
        for (int i = 0; i < 10; i++) {
            int rc = lookup();
            List<String> users = workerUsers();
            if (LOOKUP_OK.contains(rc) && !users.isEmpty() && users.stream().allMatch(user::equals)) return null;
            if (i == 9) {
                if (!LOOKUP_OK.contains(rc)) return "doveadm auth lookup fails after the reload (exit " + rc + ")";
                return "auth-worker processes run as " + users + ", not only as " + user;
            }
            Thread.sleep(500);
        }
        return "unreachable";
    }

    static boolean running() {
        return Shell.run(Duration.ofSeconds(15), "service", "dovecot", "status").success();
    }

    static int lookup() {
        Shell.Result r = Shell.run(Duration.ofSeconds(20), DOVEADM, "auth", "lookup", PROBE);
        return r.timedOut() ? -1 : r.exitCode();
    }

    static boolean reload() throws InterruptedException {
        boolean ok = Shell.run(Duration.ofSeconds(30), "service", "dovecot", "reload").success();
        Thread.sleep(1000);
        return ok;
    }

    /** The users of the `dovecot/auth -w` processes running right now. */
    static List<String> workerUsers() {
        Shell.Result ps = Shell.run(Duration.ofSeconds(10), "ps", "-axww", "-o", "user=", "-o", "command=");
        List<String> out = new ArrayList<>();
        for (String l : ps.outputTrim().split("\n")) {
            String[] p = l.trim().split("\\s+", 2);
            if (p.length == 2 && p[1].trim().matches("dovecot/auth -w( .*)?")) out.add(p[0]);
        }
        return out;
    }

    private static void write(Path file, String content) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.writeString(tmp, content);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Shell.run(Duration.ofSeconds(10), "chown", "root:wheel", tmp.toString());
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(Path file, Path saved, boolean reload) throws Exception {
        if (saved != null) Files.copy(saved, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        else Files.deleteIfExists(file);
        if (reload) reload();
    }

    private static String firstLine(String s) {
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
