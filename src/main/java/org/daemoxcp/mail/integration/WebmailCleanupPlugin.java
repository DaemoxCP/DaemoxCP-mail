package org.daemoxcp.mail.integration;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Il plugin di Roundcube daemoxcp_mail_cleanup: nelle impostazioni della webmail (Preferenze, «Svuotamento
 * automatico») l'utente sceglie dopo quanti giorni il server svuota da solo la Junk e il Cestino della sua casella, o
 * mai (il predefinito). Gli stessi valori del pannello (MailDatabase.CLEANUP_DAYS): li legge e li scrive il pannello,
 * dalla rotta interna {@link WebmailPasswordConfig#CLEANUP_PATH} (solo da 127.0.0.1 e con la chiave della webmail).
 *
 * <p>L'utente e' quello della sessione di Roundcube. Con l'accesso dal pannello (SSO) Roundcube entra come
 * «casella*utente-master» di Dovecot: si manda solo la parte prima dell'asterisco, la casella della sessione. I testi
 * sono nei file di lingua del plugin (localization/en_US.inc, it_IT.inc). I file li scrive il pannello all'avvio,
 * di root e leggibili da tutti (codice, nessun segreto: l'indirizzo e la chiave stanno nel blocco del pannello in
 * config.inc.php, WebmailPasswordConfig), e solo se sono diversi.
 */
public final class WebmailCleanupPlugin {

    private WebmailCleanupPlugin() {}

    public static final String NAME = "daemoxcp_mail_cleanup";

    /** Il codice del plugin. Puro. */
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

    /** I testi del plugin, per lingua di Roundcube. Puri. */
    public static Map<String, String> localization() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("en_US", labels("Automatic emptying", "Empty Junk and Trash by themselves", "Empty Junk", "Empty Trash", "Never",
                "After $n days",
                "Off until you choose it. The server deletes the messages that have been in the folder longer than this.",
                "The automatic emptying cannot be read right now. Try again later.",
                "The automatic emptying could not be saved. Try again later."));
        m.put("it_IT", labels("Svuotamento automatico", "Svuota da sole la Junk e il Cestino", "Svuota la Junk", "Svuota il Cestino",
                "Mai", "Dopo $n giorni",
                "Spento finché non lo scegli. Il server cancella i messaggi che stanno nella cartella da più tempo di così.",
                "Lo svuotamento automatico adesso non si riesce a leggere. Riprova più tardi.",
                "Lo svuotamento automatico non si è potuto salvare. Riprova più tardi."));
        return m;
    }

    private static String labels(String section, String title, String junk, String trash, String never, String afterdays,
                                 String help, String unavailable, String savefailed) {
        return "<?php\n// Written by DaemoxCP Mail, which rewrites it: do not edit (WebmailCleanupPlugin).\n$labels = [];\n"
             + label("section", section) + label("title", title) + label("junk", junk) + label("trash", trash)
             + label("never", never) + label("afterdays", afterdays) + label("help", help) + label("unavailable", unavailable)
             + label("savefailed", savefailed);
    }

    /** Una riga di PHP fra apici singoli: niente apici ne' barre nei testi, controllato qui. */
    private static String label(String key, String text) {
        if (text.contains("'") || text.contains("\\")) throw new IllegalArgumentException("quote in " + key);
        return "$labels['" + key + "'] = '" + text + "';\n";
    }

    /**
     * Scrive il plugin nella cartella dei plugin di Roundcube (cartelle 0755, file 0644, di chi gira: root), solo i file
     * diversi. Vero se ha cambiato qualcosa. Una cartella del plugin che e' un collegamento non si tocca.
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
