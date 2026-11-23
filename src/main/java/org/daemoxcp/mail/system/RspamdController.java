package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * The rspamd controller (port 11334 on 127.0.0.1 and ::1) only with a password, which the panel generates and
 * keeps in root's secrets (finding 236).
 *
 * <p>The package's worker-controller.inc has password = "q1", in clear text, and secure_ip = 127.0.0.1 and ::1:
 * any process on the machine got in without a password and could do everything: train Bayes, change weights and
 * maps, empty the history. rspamd itself writes it in the log at every startup ("enable password is not set, so
 * you should filter controller availability by using of firewall or `secure_ip` option"). The rspamd controller
 * guide: password and enable_password with the hash from "rspamadm pw", and secure_ip only for whoever must get
 * in without one.
 *
 * <p>The file is override.d/worker-controller.inc (priority=10 in rspamd.conf), so it wins over everything else.
 * Measured on the VM on 2026-11-16: rspamadm configdump gives secure_ip [] and the two passwords with the hash;
 * and even from local.d (priority=1) secure_ip = [] would have replaced the package's one (the test that assumed
 * it was merged was proved wrong by the real rspamd). Precisely because override.d wins, an administrator's
 * local.d/worker-controller.inc with their own password or secure_ip would be silently overridden: in that case
 * nothing is touched. The hash is computed by rspamd_cryptobox.pbkdf, the one of
 * rspamadm pw, with the password on standard input (in the arguments anyone with ps would see it; rspamadm pw
 * from a fake terminal hung twice). The file is root:rspamd 0640: all of rspamd runs as rspamd
 * (RspamdUser). The test, after the reload: without the password 401 on 127.0.0.1 and ::1, with the password
 * 200. An error puts everything back as it was. An override.d/worker-controller.inc written by hand stays.
 */
public final class RspamdController {

    private static final Logger LOGGER = Logger.getLogger(RspamdController.class.getName());

    private RspamdController() {}

    static final Path OVERRIDE = Path.of("/usr/local/etc/rspamd/override.d/worker-controller.inc");
    static final Path LOCAL = Path.of("/usr/local/etc/rspamd/local.d/worker-controller.inc");
    /** The controller keys the panel decides: if the administrator has put them in local.d, they are theirs. */
    static final Pattern ADMIN_KEYS = Pattern.compile("(?m)^\\s*(password|enable_password|secure_ip)\\b");
    static final String MARK = "# daemoxcp-mail (finding 236): rspamd's controller only with the panel's password.\n";
    static final Pattern HASH = Pattern.compile("\\$2\\$[a-z0-9]{8,64}\\$[a-z0-9]{16,128}");

    static String text(String hash) {
        return MARK
                + "# The password is in the panel's root secrets (rspamd_controller_password); here only its hash\n"
                + "# (rspamadm pw). secure_ip empty: before, 127.0.0.1 and ::1 got in without a password. The panel rewrites it.\n"
                + "password = \"" + hash + "\";\n"
                + "enable_password = \"" + hash + "\";\n"
                + "secure_ip = [];\n";
    }

    /** What is needed, to test it without rspamd. */
    interface Services {
        /** The file, or null if it is not there. */
        String read(Path file) throws IOException;
        /** Writes the file, root:rspamd 0640. */
        void write(Path file, String text) throws IOException;
        void delete(Path file) throws IOException;
        String secret();
        void setSecret(String value);
        /** The hash from rspamadm pw, or null. */
        String hash(String password);
        /** rspamadm configtest without errors. */
        boolean configOk();
        void reload();
        /**
         * The HTTP code of GET /stat on that address with that password (null: without), or -1 if it does not
         * answer.
         */
        int status(String host, String password);
    }

    public enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK, INCOMPLETE }

    public record Result(Outcome outcome, String detail) {}

    /** Closed: with the password it gets in, without it does not (::1 may not be listening, if IPv6 is off). */
    static boolean locked(Services sv, String password) {
        int v4 = sv.status("127.0.0.1", null), v6 = sv.status("[::1]", null);
        return sv.status("127.0.0.1", password) == 200 && (v4 == 401 || v4 == 403) && (v6 == 401 || v6 == 403 || v6 == -1);
    }

    private static boolean waitLocked(Services sv, String password, int seconds) {
        for (int i = 0; i < seconds; i++) {
            if (locked(sv, password)) return true;
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return locked(sv, password);
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    static String newPassword() {
        byte[] b = new byte[24];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /**
     * The switch, pure with respect to {@link Services}; waitSeconds how long to wait for rspamd after the
     * reload.
     */
    static Result run(Services sv, Path override, Path local, int waitSeconds) {
        String cur, admin;
        try {
        // The block written in Italian by earlier versions counts as the current one (EnglishComments).
            cur = EnglishComments.english(sv.read(override));
            admin = sv.read(local);
        } catch (IOException e) {
            return new Result(Outcome.LEFT, "worker-controller.inc cannot be read: " + e.getClass().getSimpleName());
        }
        if (cur != null && !cur.startsWith(MARK))
            return new Result(Outcome.LEFT, "override.d/worker-controller.inc was not written by the panel: left as it is");
        if (admin != null && ADMIN_KEYS.matcher(admin).find())
            return new Result(Outcome.LEFT, "local.d/worker-controller.inc sets its own password or secure_ip: left as it is");
        String old = sv.secret();
        if (cur != null && !old.isEmpty() && locked(sv, old)) return new Result(Outcome.NOTHING, "");
        if (sv.status("127.0.0.1", null) < 0) return new Result(Outcome.LEFT, "rspamd's controller does not answer now: nothing changed");

        String password = newPassword();
        String hash = sv.hash(password);
        if (hash == null || !HASH.matcher(hash).matches())
            return new Result(Outcome.LEFT, "rspamadm did not give a password hash: nothing changed");
        // The secret first: if the panel stops here, it already knows the password rspamd is about to ask for.
        sv.setSecret(password);
        try {
            sv.write(override, text(hash));
        } catch (IOException e) {
            return back(sv, override, cur, old, "the file could not be written: " + e.getClass().getSimpleName());
        }
        if (!sv.configOk()) return back(sv, override, cur, old, "rspamadm configtest refuses the controller's password");
        sv.reload();
        if (!waitLocked(sv, password, waitSeconds))
            return back(sv, override, cur, old, "after the reload the controller does not answer 401 without the password"
                    + " and 200 with it");
        return new Result(Outcome.DONE, "rspamd's controller answers only with the panel's password (root secrets), no more"
                + " open to 127.0.0.1 and ::1");
    }

    private static Result back(Services sv, Path override, String cur, String old, String why) {
        boolean ok = true;
        try {
            if (cur == null) sv.delete(override);
            else sv.write(override, cur);
        } catch (IOException e) {
            ok = false;
        }
        sv.setSecret(old);
        sv.reload();
        return new Result(ok ? Outcome.ROLLED_BACK : Outcome.INCOMPLETE,
                why + (ok ? ": everything as it was" : "; and putting the file back failed"));
    }

    // ===================== The production server =====================

    static final String RSPAMADM = "/usr/local/bin/rspamadm";

    static Services real() {
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        return new Services() {
            @Override public String read(Path file) throws IOException {
                return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ? Files.readString(file, StandardCharsets.UTF_8) : null;
            }
            @Override public void write(Path file, String text) throws IOException {
                RoundcubeDbUser.write(file, text, new RoundcubeDbUser.FileState(file, text, "root", "rspamd",
                        PosixFilePermissions.fromString("rw-r-----")));
            }
            @Override public void delete(Path file) throws IOException {
                Files.deleteIfExists(file);
            }
            @Override public String secret() {
                return PanelSecrets.reread(PanelSecrets.RSPAMD_CONTROLLER_PASSWORD);
            }
            @Override public void setSecret(String value) {
                PanelSecrets.setText(PanelSecrets.RSPAMD_CONTROLLER_PASSWORD, value);
            }
            @Override public String hash(String password) {
                Shell.Result r = Shell.runWithInput(Duration.ofSeconds(30), password + "\n", RSPAMADM, "lua", "-e",
                        "local c = require \"rspamd_cryptobox\"; print(c.pbkdf(io.read(\"*l\")))");
                return r.success() ? r.outputTrim() : null;
            }
            @Override public boolean configOk() {
                return Shell.run(Duration.ofSeconds(60), RSPAMADM, "configtest").success();
            }
            @Override public void reload() {
                Shell.run(Duration.ofSeconds(120), "service", "rspamd", "reload");
            }
            @Override public int status(String host, String password) {
                try {
                    HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://" + host + ":11334/stat"))
                            .timeout(Duration.ofSeconds(10)).GET();
                    if (password != null) b.header("Password", password);
                    return http.send(b.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
                } catch (IOException e) {
                    return -1;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return -1;
                }
            }
        };
    }

    /** At the start of the root part, after RspamdUser. */
    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(RSPAMADM))) return;
            Result r = run(real(), OVERRIDE, LOCAL, 30);
            switch (r.outcome()) {
                case NOTHING -> { }
                case DONE -> LOGGER.info("[RspamdController] DONE: " + r.detail());
                case LEFT -> LOGGER.info("[RspamdController] left as it is: " + r.detail());
                default -> LOGGER.warning("[RspamdController] " + r.outcome() + ": " + r.detail());
            }
        } catch (Throwable t) {
            LOGGER.warning("[RspamdController] failed: " + t.getClass().getName());
        }
    }
}
