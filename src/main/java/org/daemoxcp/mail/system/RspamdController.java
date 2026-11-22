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
 * Il controller di rspamd (porta 11334 su 127.0.0.1 e ::1) solo con una password, che il pannello genera e tiene nei
 * segreti di root (reperto 236).
 *
 * <p>Il worker-controller.inc del pacchetto ha password = "q1", in chiaro, e secure_ip = 127.0.0.1 e ::1: qualunque
 * processo della macchina entrava senza password e poteva tutto, addestrare Bayes, cambiare pesi e mappe, svuotare lo
 * storico. rspamd stesso lo scrive nel registro a ogni avvio («enable password is not set, so you should filter
 * controller availability by using of firewall or `secure_ip` option»). La guida del controller di rspamd: password e
 * enable_password con l'hash di «rspamadm pw», e secure_ip solo per chi deve entrare senza.
 *
 * <p>Il file e' override.d/worker-controller.inc (priority=10 in rspamd.conf), cosi' vince su tutto il resto. Misurato
 * sulla VM il 16/11/2026: rspamadm configdump da' secure_ip [] e le due password con l'hash; e anche da local.d
 * (priority=1) secure_ip = [] avrebbe preso il posto di quello del pacchetto (la prova che lo dava per unito e' stata
 * smentita dal rspamd vero). Proprio perche' override.d vince, un local.d/worker-controller.inc dell'amministratore con
 * una sua password o un suo secure_ip verrebbe scavalcato in silenzio: in quel caso non si tocca niente. L'hash lo
 * calcola rspamd_cryptobox.pbkdf, quello di
 * rspamadm pw, con la password sullo standard input (negli argomenti la vedrebbe chiunque con ps; rspamadm pw da
 * un terminale finto si e' bloccato due volte). Il file e' root:rspamd 0640: rspamd gira tutto come rspamd
 * (RspamdUser). La prova, dopo il reload: senza password 401 su 127.0.0.1 e ::1, con la password 200. Un errore
 * rimette tutto com'era. Un override.d/worker-controller.inc scritto a mano resta.
 */
public final class RspamdController {

    private static final Logger LOGGER = Logger.getLogger(RspamdController.class.getName());

    private RspamdController() {}

    static final Path OVERRIDE = Path.of("/usr/local/etc/rspamd/override.d/worker-controller.inc");
    static final Path LOCAL = Path.of("/usr/local/etc/rspamd/local.d/worker-controller.inc");
    /** Le chiavi del controller che il pannello decide: se l'amministratore le ha messe in local.d, sono sue. */
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

    /** Quello che serve, per provarlo senza rspamd. */
    interface Services {
        /** Il file, o null se non c'e'. */
        String read(Path file) throws IOException;
        /** Scrive il file, root:rspamd 0640. */
        void write(Path file, String text) throws IOException;
        void delete(Path file) throws IOException;
        String secret();
        void setSecret(String value);
        /** L'hash di rspamadm pw, o null. */
        String hash(String password);
        /** rspamadm configtest senza errori. */
        boolean configOk();
        void reload();
        /** Il codice HTTP di GET /stat su quell'indirizzo con quella password (null: senza), o -1 se non risponde. */
        int status(String host, String password);
    }

    public enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK, INCOMPLETE }

    public record Result(Outcome outcome, String detail) {}

    /** Chiuso: la password entra, senza no (::1 puo' non ascoltare, se IPv6 e' spento). */
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

    /** Il passaggio, puro rispetto a {@link Services}; waitSeconds quanto aspettare rspamd dopo il reload. */
    static Result run(Services sv, Path override, Path local, int waitSeconds) {
        String cur, admin;
        try {
        // Il blocco scritto in italiano dalle versioni di prima vale come quello di adesso (EnglishComments).
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
        // Prima il segreto: se il pannello si ferma qui, sa gia' la password che rspamd sta per chiedere.
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

    // ===================== Il server vero =====================

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

    /** All'avvio della parte root, dopo RspamdUser. */
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
