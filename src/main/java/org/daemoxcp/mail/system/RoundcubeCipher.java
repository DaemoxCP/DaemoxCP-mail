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
 * Roundcube cifra con AES-256-CBC e una chiave di 32 caratteri, non piu' con DES-EDE3-CBC (reperto 239).
 *
 * <p>Roundcube tiene nella sessione la password IMAP di chi e' entrato, cifrata con des_key e cipher_method. Il
 * predefinito di defaults.inc.php e' DES-EDE3-CBC «for backward compatibility», e lo stesso file dice «you can choose
 * e.g. AES-256-CBC which we consider a better choice». AES-256 vuole 32 byte: con i 24 caratteri di prima openssl
 * completerebbe la chiave con zeri, quindi chiave e metodo cambiano insieme. Cambiarli invalida le sessioni aperte:
 * chi e' dentro la webmail rientra una volta (le sessioni di Roundcube scadono comunque dopo dieci minuti senza far
 * niente). Nient'altro usa des_key: l'SSO del pannello ha una chiave sua.
 *
 * <p>Si cambia solo la riga des_key che scrive l'installatore, e solo se cipher_method non c'e' (se l'amministratore ne
 * ha scelto uno, resta). Prima e dopo: la pagina d'accesso risponde, PHP cifra e decifra con quel metodo e quella
 * chiave (il file letto da PHP), e, se l'SSO del pannello c'e', un accesso vero apre la posta, cioe' Roundcube ha
 * decifrato la password dalla sessione. Un errore rimette il file com'era.
 */
public final class RoundcubeCipher {

    private static final Logger LOGGER = Logger.getLogger(RoundcubeCipher.class.getName());

    private RoundcubeCipher() {}

    static final Path CONFIG = Path.of(RoundcubeUser.ROUNDCUBE_DIR, "config/config.inc.php");
    public static final String METHOD = "AES-256-CBC";
    static final Pattern DES_KEY = Pattern.compile("(?m)^\\$config\\['des_key'\\] = '[A-Za-z0-9]{16,64}';\\n");
    static final Pattern CIPHER = Pattern.compile("(?m)^\\s*\\$config\\s*\\[\\s*['\"]cipher_method['\"]\\s*\\]");

    /** Le righe che prendono il posto di quella di des_key. Pura. */
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

    /** Quello che serve, per provarlo senza Roundcube. */
    interface Services {
        String read(Path file) throws IOException;
        /** Al posto del file, con proprietario e permessi di prima. */
        void write(Path file, String text) throws IOException;
        /** PHP legge il file e cifra e decifra con il suo cipher_method (AES-256-CBC) e la sua des_key. */
        boolean cipherWorks(Path config);
        boolean webmailAnswers();
        /** Un accesso vero con l'SSO del pannello: null se apre la posta, se no il perche'. */
        String realLogin();
    }

    public enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK, INCOMPLETE }

    public record Result(Outcome outcome, String detail) {}

    /** Il passaggio, puro rispetto a {@link Services}. */
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

    // ===================== Il server vero =====================

    /** Cifra e decifra una parola col metodo e la chiave del file; stampa ok solo se torna uguale e il metodo e' AES-256-CBC. */
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

    /** All'avvio della parte root, dopo RoundcubeDbUser e PhpHardening. */
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
