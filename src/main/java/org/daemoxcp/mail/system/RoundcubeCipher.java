package org.daemoxcp.mail.system;

import org.daemoxcp.mail.integration.RoundcubeSsoManager;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Roundcube encrypts with AES-256-CBC and a 32-character key, no longer with DES-EDE3-CBC (finding 239).
 *
 * <p>Roundcube keeps in the session the IMAP password of whoever logged in, encrypted with des_key and
 * cipher_method. The default in defaults.inc.php is DES-EDE3-CBC "for backward compatibility", and the same file
 * says "you can choose e.g. AES-256-CBC which we consider a better choice". AES-256 needs 32 bytes: with the
 * previous 24 characters openssl would pad the key with zeros, so key and method change together. Changing them
 * invalidates the open sessions: whoever is inside the webmail logs in again once (Roundcube sessions expire
 * anyway after ten minutes of inactivity). Nothing else uses des_key: the panel's SSO has its own key.
 *
 * <p>Only the des_key line written by the installer is changed, and only if cipher_method is absent (if the
 * administrator chose one, it stays). Before and after: the login page responds, PHP encrypts and decrypts with
 * that method and that key (the file as read by PHP), and, if the panel's SSO is there, a real login opens the
 * mail, that is Roundcube decrypted the password from the session. An error puts the file back as it was.
 */
public final class RoundcubeCipher {

    private static final Logger LOGGER = Logger.getLogger(RoundcubeCipher.class.getName());

    private RoundcubeCipher() {}

    static final Path CONFIG = Path.of(RoundcubeUser.ROUNDCUBE_DIR, "config/config.inc.php");
    public static final String METHOD = "AES-256-CBC";
    static final Pattern DES_KEY = Pattern.compile("(?m)^\\$config\\['des_key'\\] = '[A-Za-z0-9]{16,64}';\\n");
    static final Pattern CIPHER = Pattern.compile("(?m)^\\s*\\$config\\s*\\[\\s*['\"]cipher_method['\"]\\s*\\]");

    /** The lines that replace the des_key one. Pure. */
    static String lines(String key) {
        return "$config['des_key'] = '" + key + "';\n"
                + "// AES-256-CBC with a 32-character key, as defaults.inc.php advises: DES-EDE3-CBC is there only for\n"
                + "// compatibility (finding 239).\n"
                + "$config['cipher_method'] = '" + METHOD + "';\n";
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    static String newKey() {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 32; i++) b.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        return b.toString();
    }

    /** What is needed, to test it without Roundcube. */
    interface Services {
        String read(Path file) throws IOException;
        /** In place of the file, with the previous owner and permissions. */
        void write(Path file, String text) throws IOException;
        /** PHP reads the file and encrypts and decrypts with its cipher_method (AES-256-CBC) and its des_key. */
        boolean cipherWorks(Path config);
        boolean webmailAnswers();
        /** A real login with the panel's SSO: null if it opens the mail, otherwise the reason. */
        String realLogin();
    }

    public enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK, INCOMPLETE }

    public record Result(Outcome outcome, String detail) {}

    /** The switchover, pure with respect to {@link Services}. */
    static Result run(Services sv, Path config) {
        String c;
        try {
            c = sv.read(config);
        } catch (IOException e) {
            return new Result(Outcome.LEFT, "config.inc.php cannot be read: " + e.getClass().getSimpleName());
        }
        if (c == null) return new Result(Outcome.NOTHING, "");
        if (CIPHER.matcher(c).find())
            return c.contains("$config['cipher_method'] = '" + METHOD + "';") ? new Result(Outcome.NOTHING, "")
                    : new Result(Outcome.LEFT, "config.inc.php sets its own cipher_method: left as it is");
        Matcher m = DES_KEY.matcher(c);
        if (!m.find() || m.find(m.end()))
            return new Result(Outcome.LEFT, "config.inc.php has no des_key line as the installer writes it, or more than one: left as it is");
        m = DES_KEY.matcher(c);
        m.find();
        if (!sv.webmailAnswers()) return new Result(Outcome.LEFT, "the webmail does not answer now: nothing changed");
        String noLogin = sv.realLogin();
        boolean login = noLogin == null;

        String next = c.substring(0, m.start()) + lines(newKey()) + c.substring(m.end());
        try {
            sv.write(config, next);
        } catch (IOException e) {
            return back(sv, config, c, "config.inc.php could not be written: " + e.getClass().getSimpleName());
        }
        if (!sv.cipherWorks(config)) return back(sv, config, c, "PHP does not encrypt and decrypt with " + METHOD + " and the new key");
        if (!sv.webmailAnswers()) return back(sv, config, c, "the webmail does not answer after the change");
        if (login) {
            String why = sv.realLogin();
            if (why != null) return back(sv, config, c, "a real login no longer opens the mailbox: " + why);
        }
        return new Result(Outcome.DONE, "Roundcube encrypts with " + METHOD + " and a 32-character key"
                + (login ? "; a real login through the panel's SSO opens the mailbox" : "; without a real login: " + noLogin)
                + " (open webmail sessions log in again once)");
    }

    private static Result back(Services sv, Path config, String c, String why) {
        try {
            sv.write(config, c);
            return new Result(Outcome.ROLLED_BACK, why + ": config.inc.php as it was");
        } catch (IOException e) {
            return new Result(Outcome.INCOMPLETE, why + "; and putting config.inc.php back failed");
        }
    }

    // ===================== The production server =====================

    /**
     * Encrypts and decrypts a word with the file's method and key; prints ok only if it comes back equal and
     * the method is AES-256-CBC.
     */
    static final String PHP_PROBE = "include $argv[1]; $m = $config['cipher_method'] ?? ''; $k = $config['des_key'] ?? '';"
            + " $iv = random_bytes(openssl_cipher_iv_length($m) ?: 16);"
            + " $c = $m === '" + METHOD + "' && strlen($k) === 32 ? openssl_encrypt('daemoxcp-mail-probe', $m, $k, OPENSSL_RAW_DATA, $iv) : false;"
            + " echo $c !== false && openssl_decrypt($c, $m, $k, OPENSSL_RAW_DATA, $iv) === 'daemoxcp-mail-probe' ? 'ok' : 'no';";

    static Services real(RoundcubeSsoManager sso) {
        return new Services() {
            @Override public String read(Path file) throws IOException {
                return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ? Files.readString(file, StandardCharsets.UTF_8) : null;
            }
            @Override public void write(Path file, String text) throws IOException {
                RoundcubeDbUser.write(file, text, RoundcubeDbUser.FileState.of(file, Files.readString(file, StandardCharsets.UTF_8)));
            }
            @Override public boolean cipherWorks(Path config) {
                return "ok".equals(Shell.run(Duration.ofSeconds(30), "php", "-r", PHP_PROBE, "--", config.toString()).outputTrim());
            }
            @Override public boolean webmailAnswers() {
                PhpHardening.Services php = PhpHardening.real();
                java.util.List<PhpHardening.Site> sites = php.sites();
                if (sites.isEmpty()) return false;
                for (PhpHardening.Site s : sites) if (php.webmail(s) == null) return false;
                return true;
            }
            @Override public String realLogin() {
                if (sso == null) return "the panel's SSO is not available";
                try {
                    String db = RoundcubeDbUser.activeDsn(Files.readString(CONFIG, StandardCharsets.UTF_8)).db();
                    return RoundcubeDbUser.realLoginNow(sso, db);
                } catch (Exception e) {
                    return "cannot read the webmail's database: " + e.getClass().getSimpleName();
                }
            }
        };
    }

    /** At the start of the root part, after RoundcubeDbUser and PhpHardening. */
    public static void ensureAtBoot(RoundcubeSsoManager sso) {
        try {
            if (!Files.isDirectory(Path.of(RoundcubeUser.ROUNDCUBE_DIR))) return;
            Result r = run(real(sso), CONFIG);
            switch (r.outcome()) {
                case NOTHING -> { }
                case DONE -> LOGGER.info("[RoundcubeCipher] DONE: " + r.detail());
                case LEFT -> LOGGER.info("[RoundcubeCipher] left as it is: " + r.detail());
                default -> LOGGER.warning("[RoundcubeCipher] " + r.outcome() + ": " + r.detail());
            }
        } catch (Throwable t) {
            LOGGER.warning("[RoundcubeCipher] failed: " + t.getClass().getName());
        }
    }
}
