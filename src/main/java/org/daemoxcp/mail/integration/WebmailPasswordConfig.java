package org.daemoxcp.mail.integration;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.regex.Pattern;

/**
 * Il cambio password dalla webmail passa dal pannello.
 *
 * Prima il plugin password di Roundcube scriveva da se' nella tabella mailboxes (driver sql),
 * con l'algoritmo predefinito del plugin, che e' 'clear': nella colonna finiva la password in
 * chiaro. Dovecot legge BLF-CRYPT, quindi la casella non entrava piu', e la copia cifrata del
 * pannello restava quella di prima. Adesso il plugin usa il driver httpapi e manda utente,
 * password attuale e password nuova a /api/internal/mailbox-password sul pannello (solo da
 * 127.0.0.1, con la chiave X-MailPanel-Key): il pannello controlla la password attuale e scrive
 * insieme l'hash bcrypt e la copia cifrata.
 *
 * Le impostazioni stanno in un blocco in fondo a config.inc.php, che il pannello riscrive a ogni
 * avvio; in PHP vince l'ultima assegnazione, e le righe del driver sql di prima si tolgono (dentro
 * c'era anche la password MySQL del pannello, che la webmail non deve piu' conoscere).
 */
public final class WebmailPasswordConfig {

    private WebmailPasswordConfig() {}

    static final String BEGIN = "// BEGIN mail-panel: webmail password changes (rewritten by the panel at startup)";
    static final String END = "// END mail-panel: webmail password changes";
    /** Il percorso della rotta sul pannello. */
    public static final String PATH = "/api/internal/mailbox-password";
    /** La rotta della copia nel vault dopo un accesso alla webmail (RoundcubeSsoManager, plugin mailpanel_sso). */
    public static final String VAULT_PATH = "/api/internal/mailbox-vault";

    /** Le righe del plugin password che il blocco sostituisce, scritte da noi o a mano. */
    private static final Pattern OLD_LINE = Pattern.compile(
            "(?m)^[ \\t]*\\$config\\[['\"]password_(driver|db_dsn|query|crypt_hash|algorithm|algorithm_prefix|"
            + "httpapi_[a-z_]+|http_client|minimum_length)['\"]\\][ \\t]*=[^\\n]*;[ \\t]*\\r?\\n?");
    private static final Pattern KEY = Pattern.compile("[A-Za-z0-9_-]{20,128}");

    /**
     * La configurazione con il blocco del pannello al posto delle impostazioni di prima.
     * La chiave e' base64url (solo lettere, cifre, - e _): dentro gli apici PHP non serve altro.
     */
    public static String apply(String config, int port, String key) {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Invalid panel port: " + port);
        if (key == null || !KEY.matcher(key).matches()) throw new IllegalArgumentException("Invalid webmail key");
        String s = config == null ? "" : config;
        int b = s.indexOf(BEGIN);
        while (b >= 0) {
            int e = s.indexOf(END, b);
            if (e < 0) { s = s.substring(0, b); break; }
            int after = e + END.length();
            if (after < s.length() && s.charAt(after) == '\n') after++;
            s = s.substring(0, b) + s.substring(after);
            b = s.indexOf(BEGIN);
        }
        s = OLD_LINE.matcher(s).replaceAll("");
        // Un "?>" in fondo chiuderebbe il PHP prima del blocco
        String trimmed = s.stripTrailing();
        if (trimmed.endsWith("?>")) s = trimmed.substring(0, trimmed.length() - 2);
        s = s.stripTrailing() + "\n\n" + block(port, key);
        return s;
    }

    static String block(int port, String key) {
        return BEGIN + "\n"
                + "$config['password_driver'] = 'httpapi';\n"
                + "$config['password_httpapi_url'] = 'https://127.0.0.1:" + port + PATH + "';\n"
                + "$config['password_httpapi_method'] = 'POST';\n"
                + "$config['password_httpapi_var_user'] = 'user';\n"
                + "$config['password_httpapi_var_curpass'] = 'curpass';\n"
                + "$config['password_httpapi_var_newpass'] = 'newpass';\n"
                + "$config['password_httpapi_expect'] = '/^ok$/';\n"
                + "// The panel's certificate is for its public name, not for 127.0.0.1: the key authenticates the request.\n"
                + "// http_errors off: a refusal (403) reaches the driver's own check as a password error, not as a connection error\n"
                + "$config['password_http_client'] = ['verify' => false, 'timeout' => 15, 'http_errors' => false, 'headers' => ['X-MailPanel-Key' => '" + key + "']];\n"
                + "// Same rule as the panel (SecurityUtils.isValidMailboxPassword): the panel checks it again\n"
                + "$config['password_minimum_length'] = 12;\n"
                + END + "\n";
    }

    /**
     * Riscrive config.inc.php se serve (scrittura atomica, stessi permessi e proprietario di
     * prima, mai leggibile da tutti). Ritorna true se il file e' cambiato.
     */
    public static boolean ensure(Path configFile, int port, String key) throws IOException {
        String before = Files.readString(configFile, StandardCharsets.UTF_8);
        String after = apply(before, port, key);
        if (after.equals(before)) {
            restrict(configFile);
            return false;
        }
        Path tmp = configFile.resolveSibling(configFile.getFileName() + ".daemoxcp-mail.tmp");
        Files.deleteIfExists(tmp);
        Files.createFile(tmp);
        try {
            Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r-----"));
            try {
                Files.setOwner(tmp, Files.getOwner(configFile));
                Files.setAttribute(tmp, "posix:group", Files.readAttributes(configFile,
                        java.nio.file.attribute.PosixFileAttributes.class).group());
            } catch (IOException | UnsupportedOperationException ignored) {
                // Senza permesso di cambiare proprietario resta quello del pannello
            }
        } catch (UnsupportedOperationException ignored) {
            // File system senza permessi POSIX
        }
        Files.writeString(tmp, after, StandardCharsets.UTF_8);
        try {
            Files.move(tmp, configFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, configFile, StandardCopyOption.REPLACE_EXISTING);
        }
        return true;
    }

    /** Dentro c'e' la chiave (e la password MySQL della webmail): niente lettura per gli altri utenti. */
    private static void restrict(Path f) {
        try {
            var perms = Files.getPosixFilePermissions(f);
            perms.remove(java.nio.file.attribute.PosixFilePermission.OTHERS_READ);
            perms.remove(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
            perms.remove(java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE);
            Files.setPosixFilePermissions(f, perms);
        } catch (IOException | UnsupportedOperationException ignored) {
            // Resta com'e'
        }
    }
}
