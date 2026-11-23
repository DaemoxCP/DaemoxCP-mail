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
 * The password change from the webmail goes through the panel.
 *
 * Before, Roundcube's password plugin wrote by itself into the mailboxes table (sql driver),
 * with the plugin's default algorithm, which is 'clear': the column got the password in
 * clear text. Dovecot reads BLF-CRYPT, so the mailbox could no longer log in, and the panel's encrypted
 * copy stayed the previous one. Now the plugin uses the httpapi driver and sends user,
 * current password and new password to /api/internal/mailbox-password on the panel (only from
 * 127.0.0.1, with the X-DaemoxCP-Key key): the panel checks the current password and writes
 * the bcrypt hash and the encrypted copy together.
 *
 * The settings are in a block at the end of config.inc.php, which the panel rewrites at every
 * boot; in PHP the last assignment wins, and the lines of the previous sql driver are removed (they
 * also contained the panel's MySQL password, which the webmail must no longer know).
 *
 * <p>The block also turns on the password plugin, if it is missing from the list: the full installation wrote
 * only archive and zipdownload, and the page to change the password in the webmail was not there (on the VM,
 * 2026-11-18). It adds it only when the list is in this same file: Roundcube merges the files by replacing the
 * whole list, and a new list here would remove the plugins written elsewhere.
 */
public final class WebmailPasswordConfig {

    private WebmailPasswordConfig() {}

    static final String BEGIN = "// BEGIN daemoxcp-mail: webmail password changes (rewritten by the panel at startup)";
    static final String END = "// END daemoxcp-mail: webmail password changes";
    /** The path of the route on the panel. */
    public static final String PATH = "/api/internal/mailbox-password";
    /** The route of the copy into the vault after a webmail login (RoundcubeSsoManager, plugin daemoxcp_mail_sso). */
    public static final String VAULT_PATH = "/api/internal/mailbox-vault";
    /**
     * The route of the automatic emptying of the Junk and the Trash, from the webmail settings (the plugin
     * daemoxcp_mail_cleanup): reading and choosing the days for one's own mailbox.
     */
    public static final String CLEANUP_PATH = "/api/internal/mailbox-cleanup";

    /** The lines of the password plugin that the block replaces, written by us or by hand. */
    private static final Pattern OLD_LINE = Pattern.compile(
            "(?m)^[ \\t]*\\$config\\[['\"]password_(driver|db_dsn|query|crypt_hash|algorithm|algorithm_prefix|"
            + "httpapi_[a-z_]+|http_client|minimum_length)['\"]\\][ \\t]*=[^\\n]*;[ \\t]*\\r?\\n?");
    private static final Pattern KEY = Pattern.compile("[A-Za-z0-9_-]{20,128}");

    /** The line that turns on the password plugin (see above): only if the list is in this file, and only once. */
    static final String PLUGIN_LINE = "if (isset($config['plugins']) && is_array($config['plugins']) && !in_array('password', $config['plugins'], true)) "
            + "{ $config['plugins'][] = 'password'; }";

    /**
     * The webmail's "Spam" / "Not spam" button (Roundcube's markasjunk plugin): it moves the message to the Junk or
     * to the INBOX, and Rspamd learns from that move (SpamLearning). Without a learning driver the plugin just moves
     * (its config.inc.php.dist). Same rule as the password plugin: only if the list is in this file, once.
     */
    static final String JUNK_PLUGIN_LINE = "if (isset($config['plugins']) && is_array($config['plugins']) && !in_array('markasjunk', $config['plugins'], true)) "
            + "{ $config['plugins'][] = 'markasjunk'; }";

    /**
     * The automatic emptying of the Junk and the Trash in the webmail settings (WebmailCleanupPlugin): the
     * panel's plugin, turned on like the other two, only if the list is in this file and only once.
     */
    static final String CLEANUP_PLUGIN_LINE = "if (isset($config['plugins']) && is_array($config['plugins']) && !in_array('"
            + WebmailCleanupPlugin.NAME + "', $config['plugins'], true)) { $config['plugins'][] = '" + WebmailCleanupPlugin.NAME + "'; }";

    /** The header with which Roundcube sends the webmail's key (WebmailPasswordHandler reads it). */
    public static final String KEY_HEADER = "X-DaemoxCP-Key";

    /**
     * The configuration with the panel's block in place of the previous settings.
     * The key is base64url (only letters, digits, - and _): inside the PHP quotes nothing else is needed.
     */
    public static String apply(String config, int port, String key) {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Invalid panel port: " + port);
        if (key == null || !KEY.matcher(key).matches()) throw new IllegalArgumentException("Invalid webmail key");
        // The block written by a previous version has the markers with the product's previous name: they are read
        // like the current ones (legacy-names.json, section "productComments"), so it is removed too.
        String s = org.daemoxcp.mail.system.PanelMarker.current(config == null ? "" : config, "productComments");
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
        // A "?>" at the end would close the PHP before the block
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
                + "$config['password_http_client'] = ['verify' => false, 'timeout' => 15, 'http_errors' => false, 'headers' => ['" + KEY_HEADER + "' => '" + key + "']];\n"
                + "// Same rule as the panel (SecurityUtils.isValidMailboxPassword): the panel checks it again\n"
                + "$config['password_minimum_length'] = 12;\n"
                + "// The current password is asked for: the panel checks it before the change (without the plugin's own\n"
                + "// config file Roundcube's default is off, and the form had no field for it)\n"
                + "$config['password_confirm_current'] = true;\n"
                + "// The password plugin on, if the list of plugins is in this file and does not have it yet\n"
                + PLUGIN_LINE + "\n"
                + "// The spam button (markasjunk), on the same terms: it moves a message into Junk or back to INBOX, and Rspamd\n"
                + "// learns from the move (SpamLearning)\n"
                + JUNK_PLUGIN_LINE + "\n"
                + "// The automatic emptying of Junk and Trash in the webmail's settings (daemoxcp_mail_cleanup): the panel keeps it\n"
                + "$config['daemoxcp_mail_cleanup_url'] = 'https://127.0.0.1:" + port + CLEANUP_PATH + "';\n"
                + "$config['daemoxcp_mail_cleanup_key'] = '" + key + "';\n"
                + CLEANUP_PLUGIN_LINE + "\n"
                + END + "\n";
    }

    /**
     * Rewrites config.inc.php if needed (atomic write, same permissions and owner as
     * before, never world-readable). Returns true if the file changed.
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
                // Without permission to change the owner, the panel's one stays
            }
        } catch (UnsupportedOperationException ignored) {
            // File system without POSIX permissions
        }
        Files.writeString(tmp, after, StandardCharsets.UTF_8);
        try {
            Files.move(tmp, configFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, configFile, StandardCopyOption.REPLACE_EXISTING);
        }
        return true;
    }

    /** The key is inside (and the webmail's MySQL password): no reading for other users. */
    private static void restrict(Path f) {
        try {
            var perms = Files.getPosixFilePermissions(f);
            perms.remove(java.nio.file.attribute.PosixFilePermission.OTHERS_READ);
            perms.remove(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
            perms.remove(java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE);
            Files.setPosixFilePermissions(f, perms);
        } catch (IOException | UnsupportedOperationException ignored) {
            // Stays as it is
        }
    }
}
