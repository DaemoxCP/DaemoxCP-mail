package org.daemoxcp.mail.integration;

import org.daemoxcp.mail.i18n.I18n;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The Roundcube plugin daemoxcp_mail_cleanup: in the webmail settings (Preferences, "Automatic emptying") the
 * user chooses after how many days the server empties the Junk and Trash of their mailbox by itself, or never
 * (the default). The same values as the panel (MailDatabase.CLEANUP_DAYS): the panel reads and writes them,
 * from the internal route {@link WebmailPasswordConfig#CLEANUP_PATH} (only from 127.0.0.1 and with the webmail's
 * key).
 *
 * <p>The user is the one of the Roundcube session. With the login from the panel (SSO) Roundcube logs in as
 * Dovecot's "mailbox*master-user": only the part before the asterisk is sent, the session's mailbox. The texts
 * are the panel's (lang/xx.json, keys webmailCleanup.*), written as the plugin's language files, one per language of
 * the panel (localization/en_US.inc, it_IT.inc, ...). The panel writes the files at boot,
 * owned by root and readable by everyone (code, no secret: the address and the key are in the panel's block in
 * config.inc.php, WebmailPasswordConfig), and only if they are different.
 */
public final class WebmailCleanupPlugin {

    private WebmailCleanupPlugin() {}

    public static final String NAME = "daemoxcp_mail_cleanup";

    /** The plugin's code. Pure. */
    public static String php() {
        return """
                <?php
                /**
                 * DaemoxCP Mail: automatic emptying of Junk and Trash for the signed-in mailbox (Settings > Preferences).
                 * Written by DaemoxCP Mail, which rewrites it: do not edit (WebmailCleanupPlugin).
                 */
                class daemoxcp_mail_cleanup extends rcube_plugin
                {
                    public $task = 'settings';
                    private const DAYS = [0, 7, 14, 30, 60, 90];
                    private const SECTION = 'daemoxcp_cleanup';

                    public function init()
                    {
                        $this->add_texts('localization/');
                        $this->add_hook('preferences_sections_list', [$this, 'sections']);
                        $this->add_hook('preferences_list', [$this, 'prefs']);
                        $this->add_hook('preferences_save', [$this, 'save']);
                    }

                    public function sections($args)
                    {
                        $args['list'][self::SECTION] = ['id' => self::SECTION, 'section' => $this->gettext('section')];
                        return $args;
                    }

                    public function prefs($args)
                    {
                        if ($args['section'] != self::SECTION) {
                            return $args;
                        }
                        $args['blocks']['main']['name'] = $this->gettext('title');
                        $now = $this->call('get', 0, 0);
                        if ($now === null) {
                            $args['blocks']['main']['options']['unavailable'] = ['title' => '', 'content' => rcube::Q($this->gettext('unavailable'))];
                            return $args;
                        }
                        foreach (['junk', 'trash'] as $folder) {
                            $id = 'rcmfd_daemoxcp_' . $folder;
                            $select = new html_select(['name' => '_daemoxcp_' . $folder, 'id' => $id]);
                            foreach (self::DAYS as $d) {
                                $select->add($d == 0 ? $this->gettext('never') : $this->gettext(['name' => 'afterdays', 'vars' => ['n' => $d]]), (string) $d);
                            }
                            $args['blocks']['main']['options'][$folder] = [
                                'title' => html::label($id, rcube::Q($this->gettext($folder))),
                                'content' => $select->show((string) $now[$folder]),
                            ];
                        }
                        $args['blocks']['main']['options']['help'] = ['title' => '', 'content' => html::div('hint', rcube::Q($this->gettext('help')))];
                        return $args;
                    }

                    public function save($args)
                    {
                        if ($args['section'] != self::SECTION) {
                            return $args;
                        }
                        $junk = rcube_utils::get_input_string('_daemoxcp_junk', rcube_utils::INPUT_POST);
                        $trash = rcube_utils::get_input_string('_daemoxcp_trash', rcube_utils::INPUT_POST);
                        $args['abort'] = true;
                        $args['result'] = ctype_digit($junk) && ctype_digit($trash)
                            && in_array((int) $junk, self::DAYS, true) && in_array((int) $trash, self::DAYS, true)
                            && $this->call('set', (int) $junk, (int) $trash) !== null;
                        if (!$args['result']) {
                            $args['message'] = 'daemoxcp_mail_cleanup.savefailed';
                        }
                        return $args;
                    }

                    /** The panel's answer: ['junk' => days, 'trash' => days], or null. */
                    private function call($action, $junk, $trash)
                    {
                        $rcmail = rcmail::get_instance();
                        $url = $rcmail->config->get('daemoxcp_mail_cleanup_url');
                        $key = $rcmail->config->get('daemoxcp_mail_cleanup_key');
                        // With the panel's single sign-on Roundcube logs in as mailbox*master-user: the mailbox is before the star
                        $user = strtolower(explode('*', (string) $rcmail->get_user_name(), 2)[0]);
                        if (empty($url) || empty($key) || $user === '') {
                            return null;
                        }
                        $form = ['user' => $user, 'action' => $action];
                        if ($action == 'set') {
                            $form['junk'] = (string) $junk;
                            $form['trash'] = (string) $trash;
                        }
                        try {
                            // The panel's certificate is for its public name, not for 127.0.0.1: the key authenticates the request
                            $client = $rcmail->get_http_client(['verify' => false, 'timeout' => 15, 'http_errors' => false]);
                            $response = $client->post($url, ['form_params' => $form, 'headers' => ['X-DaemoxCP-Key' => $key]]);
                            if ($response->getStatusCode() != 200
                                || !preg_match('/^junk=([0-9]{1,3}) trash=([0-9]{1,3})$/', trim((string) $response->getBody()), $m)) {
                                return null;
                            }
                            return ['junk' => (int) $m[1], 'trash' => (int) $m[2]];
                        } catch (Exception $e) {
                            rcube::raise_error($e, true, false);
                            return null;
                        }
                    }
                }
                """;
    }

    /** The plugin's labels, in the order of its language files; their texts are the panel's keys webmailCleanup.*. */
    static final List<String> LABELS = List.of("section", "title", "junk", "trash", "never", "afterdays", "help",
            "unavailable", "savefailed");

    /**
     * The plugin's texts, one Roundcube language file per language of the panel (I18n.LANGUAGES), from the panel's
     * language files: a language added to the panel (a lang/xx.json) reaches the webmail too. Until 2026-11-23 the
     * texts were written here, in English and Italian only. "$n" in afterDays is Roundcube's placeholder for the
     * number of days and stays as it is in every language. Pure.
     */
    public static Map<String, String> localization() {
        Map<String, String> m = new LinkedHashMap<>();
        for (String lang : I18n.LANGUAGES) {
            StringBuilder file = new StringBuilder("<?php\n// Written by DaemoxCP Mail, which rewrites it: do not edit (WebmailCleanupPlugin).\n$labels = [];\n");
            for (String label : LABELS) file.append(label(label, I18n.t(lang, key(label))));
            m.put(roundcubeLocale(lang), file.toString());
        }
        return m;
    }

    /** The panel's key of a label: webmailCleanup.afterDays for afterdays, webmailCleanup.saveFailed for savefailed. */
    static String key(String label) {
        return "webmailCleanup." + switch (label) {
            case "afterdays" -> "afterDays";
            case "savefailed" -> "saveFailed";
            default -> label;
        };
    }

    /**
     * Roundcube's name of a language: language and country (it_IT, en_US), the name of its localization file. The
     * panel's codes are ISO 639-1 (lang/xx.json): the country is the language's own, except where Roundcube uses
     * another one or the code alone.
     */
    public static String roundcubeLocale(String lang) {
        String exception = Map.ofEntries(Map.entry("en", "en_US"), Map.entry("pt", "pt_PT"), Map.entry("sv", "sv_SE"),
                Map.entry("da", "da_DK"), Map.entry("el", "el_GR"), Map.entry("ja", "ja_JP"), Map.entry("zh", "zh_CN"),
                Map.entry("cs", "cs_CZ"), Map.entry("uk", "uk_UA"), Map.entry("ko", "ko_KR"), Map.entry("ca", "ca_ES"),
                Map.entry("et", "et_EE"), Map.entry("sl", "sl_SI"), Map.entry("nb", "nb_NO"), Map.entry("he", "he_IL"),
                Map.entry("ar", "ar_SA"), Map.entry("fa", "fa_IR"), Map.entry("vi", "vi_VN"), Map.entry("hi", "hi_IN"),
                Map.entry("eu", "eu_ES"), Map.entry("gl", "gl_ES"), Map.entry("ga", "ga_IE"), Map.entry("sr", "sr_CS"))
                .get(lang);
        return exception != null ? exception : lang + "_" + lang.toUpperCase(java.util.Locale.ROOT);
    }

    /**
     * A line of PHP between single quotes. A quote or a backslash in a text is escaped (\' and \\): a language
     * with apostrophes (French, Italian elisions) must not break the file.
     */
    public static String label(String key, String text) {
        return "$labels['" + key + "'] = '" + text.replace("\\", "\\\\").replace("'", "\\'") + "';\n";
    }

    /**
     * Writes the plugin into Roundcube's plugins folder (folders 0755, files 0644, owned by whoever runs: root),
     * only the files that differ. True if it changed something. A plugin folder that is a link is not touched.
     */
    public static boolean install(Path pluginsDir) throws IOException {
        Path dir = pluginsDir.resolve(NAME);
        if (Files.isSymbolicLink(dir) || Files.isSymbolicLink(dir.resolve("localization")))
            throw new IOException(dir + " is a link");
        boolean changed = false;
        Files.createDirectories(dir.resolve("localization"));
        for (Path d : new Path[]{dir, dir.resolve("localization")}) Files.setPosixFilePermissions(d, PosixFilePermissions.fromString("rwxr-xr-x"));
        changed |= write(dir.resolve(NAME + ".php"), php());
        for (Map.Entry<String, String> e : localization().entrySet())
            changed |= write(dir.resolve("localization").resolve(e.getKey() + ".inc"), e.getValue());
        return changed;
    }

    private static boolean write(Path file, String content) throws IOException {
        if (Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) && content.equals(Files.readString(file, StandardCharsets.UTF_8))) return false;
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        return true;
    }
}
