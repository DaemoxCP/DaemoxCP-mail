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
 * Il processo di Dovecot che cerca le password (auth-worker) non gira piu' da root.
 *
 * Misurato il 07/11/2026 sul server vero e sulla VM (Dovecot 2.3.21): `dovecot/auth -w` gira da
 * root, perche' nella 2.3 il suo utente predefinito e' root. Root gli servirebbe solo per PAM,
 * /etc/passwd o /etc/shadow; qui le password stanno in MySQL (passdb sql) e l'utente master nel
 * file master-users (passwd-file), quindi gli basta l'utente interno di Dovecot. Provato sulla VM:
 * con `service auth-worker { user = dovecot }` il processo gira come dovecot, un accesso vero
 * riesce, una password sbagliata e' rifiutata, e dovecot-sql.conf puo' restare 0600 (Dovecot lo
 * legge prima di cedere i privilegi).
 *
 * Lo dice anche il manuale di Dovecot 2.3 (configuration_manual/service_configuration, sezione
 * auth-worker): root e' il predefinito solo perche' PAM di solito legge /etc/shadow, e se non serve
 * conviene cambiarlo, per esempio in $default_internal_user. Si scrive il nome dell'utente e non
 * la variabile, perche' nella 2.4 la sintassi delle variabili e' cambiata e il nome vale per tutte e due.
 *
 * L'installatore lo scrive da adesso (DovecotConfig, conf.d/10-auth-worker.conf); sui server
 * installati prima lo fa questa riparazione all'avvio, con lo stesso file. Prima di toccare
 * qualcosa controlla che l'autenticazione funzioni; dopo il reload controlla che funzioni ancora e
 * che nessun auth-worker sia rimasto root. Se qualcosa non torna toglie il file e ricarica: Dovecot
 * resta com'era. Al secondo avvio non fa niente e non scrive niente.
 */
public final class DovecotAuthWorker {

    private static final Logger LOGGER = Logger.getLogger(DovecotAuthWorker.class.getName());

    static final String DOVECONF = "/usr/local/bin/doveconf";
    static final String DOVEADM = "/usr/local/bin/doveadm";
    static final String CONF_D = "/usr/local/etc/dovecot/conf.d";
    static final String FILE_NAME = "10-auth-worker.conf";

    /** I driver che leggono file di sistema o parlano con PAM: con loro auth-worker deve restare root. */
    static final Set<String> NEED_ROOT = Set.of("pam", "passwd", "shadow", "bsdauth", "checkpassword", "vpopmail");

    /** Un indirizzo che non esiste: la ricerca passa da auth-worker e da MySQL senza trovare nessuno. */
    static final String PROBE = "mailpanel-auth-probe@invalid";

    /** Uscite di `doveadm auth lookup`: trovato, oppure l'utente non c'e' (EX_NOUSER). Il resto e' un guasto. */
    static final Set<Integer> LOOKUP_OK = Set.of(0, 67);

    private static final Pattern USER_NAME = Pattern.compile("[a-z_][a-z0-9_-]{0,31}");
    private static final Pattern DRIVER = Pattern.compile("(?m)^\\s*driver\\s*=\\s*(\\S+)");

    private DovecotAuthWorker() {}

    enum Action { NOTHING, APPLY, STAYS_ROOT }

    record Decision(Action action, String reason) {}

    /** Il contenuto del file: lo stesso per l'installatore (DovecotConfig) e per la riparazione. */
    public static String fileContent(String user) {
        return "# " + PanelMarker.WRITTEN + ".\n"
             + "# Il processo che cerca le password (auth-worker) non ha bisogno di root: le password\n"
             + "# stanno in MySQL e l'utente master in un file di Dovecot. Root servirebbe solo per PAM,\n"
             + "# /etc/passwd o /etc/shadow, che qui non si usano.\n"
             + "service auth-worker {\n"
             + "  user = " + user + "\n"
             + "}\n";
    }

    /** I driver di passdb e userdb, dall'uscita di `doveconf -n`. */
    static Set<String> drivers(String doveconfN) {
        Set<String> out = new TreeSet<>();
        if (doveconfN == null) return out;
        Matcher m = DRIVER.matcher(doveconfN);
        while (m.find()) out.add(m.group(1).toLowerCase(java.util.Locale.ROOT));
        return out;
    }

    /**
     * Che cosa fare. Funzione pura, per provarla.
     *
     * @param workerUser l'utente di auth-worker per `doveconf -h service/auth-worker/user` ("" = root)
     * @param doveconfN  l'uscita di `doveconf -n`
     * @param internal   l'utente interno di Dovecot (`doveconf -h default_internal_user`)
     * @param internalExists se quell'utente c'e' sul sistema
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

    /** Scrive il file, valida, ricarica e verifica; se la verifica non torna, rimette com'era. */
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

    /** Dopo il reload: la ricerca passa ancora, e gli auth-worker accesi girano tutti con l'utente giusto. */
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

    /** Gli utenti dei processi `dovecot/auth -w` accesi adesso. */
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
