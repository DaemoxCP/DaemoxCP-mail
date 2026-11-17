package org.daemoxcp.mail.scripts;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.logging.Logger;

/**
 * Gli script d'installazione su disco sono sempre quelli del jar che gira: mai uno rimasto da una
 * versione di prima.
 *
 * <p>Perche' esiste: misurato leggendo il codice il 06/11/2026 (reperto 169). Sei classi su sette
 * scrivevano il loro script solo «se manca»: dopo un aggiornamento del pannello restava quello della
 * prima versione, per sempre, e il menu eseguiva setup_timezone_and_dns.sh com'era il primo giorno.
 * La reinstallazione staccata (Main --reinstall) usava install_mail_server.sh se c'era gia'. E cinque
 * script delle versioni di prima (Roundcube, Rspamd, ClamAV, Dovecot, Let's Encrypt) restavano nella
 * cartella senza che nessuno li scrivesse piu': chi li lanciava a mano lanciava roba vecchia.
 *
 * <p>Adesso:
 * <ul>
 *   <li>si scrivono SEMPRE, e tutto o niente: un file nuovo accanto e poi la rinomina. Chi sta
 *       eseguendo quello di prima continua a leggere il suo (il file vecchio resta aperto da lui), e
 *       non c'e' un istante in cui lo script manca;</li>
 *   <li>a ogni avvio del pannello (servizio, menu, comandi da console) e prima di ogni esecuzione;</li>
 *   <li>ognuno porta l'impronta del jar che l'ha scritto: lanciato A MANO, la confronta col jar che
 *       il servizio del pannello usa e, se sono diversi, si ferma prima di cambiare qualunque cosa;</li>
 *   <li>quelli che nessuno scrive piu' si mettono da parte all'avvio (nome.sh.retired).</li>
 * </ul>
 */
public final class InstallScripts {

    private static final Logger LOGGER = Logger.getLogger(InstallScripts.class.getName());

    private InstallScripts() {}

    /** La cartella degli script, nella cartella del pannello. */
    public static final String DIR = "./install_scripts";

    /** Quelli che le versioni di prima scrivevano e che il pannello non scrive ne' esegue piu'. */
    static final List<String> RETIRED = List.of("install_roundcube.sh", "install_rspamd.sh",
            "install_clamav.sh", "install_dovecot.sh", "generate_letsencrypt.sh");

    /** La variabile che il pannello mette nell'ambiente di ogni script che lancia lui. */
    public static final String FROM_PANEL = "DAEMOXCP_MAIL_FROM_PANEL";

    private static volatile String jarSha;

    /**
     * Scrive lo script, sempre, tutto o niente. Vero se e' scritto. Il file e' 700: lo lancia solo
     * root, e solo root deve poterlo cambiare.
     */
    public static synchronized boolean write(String path, String content) {
        Path target = Path.of(path);
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        try {
            Files.createDirectories(target.toAbsolutePath().getParent());
            Files.deleteIfExists(tmp);
            Files.writeString(tmp, stamped(content), StandardCharsets.UTF_8);
            try {
                Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rwx------"));
            } catch (UnsupportedOperationException ignored) {
                tmp.toFile().setExecutable(true);
            }
            try {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
            return true;
        } catch (IOException e) {
            System.out.println("Error writing script " + path + ": " + e.getMessage());
            try { Files.deleteIfExists(tmp); } catch (IOException ignored) { }
            return false;
        }
    }

    /**
     * Lo script con l'impronta del jar e il controllo per chi lo lancia a mano, subito dopo la riga
     * #!. Il jar del servizio lo dice rc.conf (mailpanel_jar) o, se li' non c'e', il valore
     * predefinito scritto nello script rc.d del pannello. Senza servizio del pannello, o lanciato dal
     * pannello stesso (che l'ha appena scritto), il controllo non si fa.
     *
     * <p>La riga di testa e' in inglese: la stessa frase in italiano e' uno dei marcatori di prima
     * (legacy-names.json), e LegacyNamesTest non la vuole piu' in nessun file scritto dal pannello.
     */
    static String stamped(String content) {
        String guard = """
                # --- Written by the mail panel (InstallScripts) -------------------------------------------
                # L'impronta del jar che ha scritto questo script. Lanciato a mano (non dal pannello), lo
                # script la confronta col jar che il servizio del pannello usa: se sono diversi, lo script e'
                # di un'altra versione del pannello e si ferma prima di cambiare qualunque cosa.
                DAEMOXCP_MAIL_WRITTEN_BY_JAR="%s"
                if [ -z "${DAEMOXCP_MAIL_FROM_PANEL:-}" ] && [ -n "$DAEMOXCP_MAIL_WRITTEN_BY_JAR" ]; then
                    daemoxcp_mail_jar=$(sysrc -n mailpanel_jar 2>/dev/null) || daemoxcp_mail_jar=""
                    [ -n "$daemoxcp_mail_jar" ] || daemoxcp_mail_jar=$(sed -n 's/^: \\${mailpanel_jar:="\\(.*\\)"}$/\\1/p' /usr/local/etc/rc.d/mailpanel 2>/dev/null)
                    if [ -n "$daemoxcp_mail_jar" ] && [ -f "$daemoxcp_mail_jar" ] && [ "$(sha256 -q "$daemoxcp_mail_jar" 2>/dev/null)" != "$DAEMOXCP_MAIL_WRITTEN_BY_JAR" ]; then
                        echo "STOPPED: this script was written by another version of the mail panel than the one the panel service runs ($daemoxcp_mail_jar)."
                        echo "Open the panel menu (it writes its scripts again at every start) and run it from there."
                        echo "Nothing was stopped and nothing was changed."
                        exit 1
                    fi
                fi
                # ------------------------------------------------------------------------------------------
                """.formatted(jarSha256());
        // Uno script con la riga #! rientrata (setup_timezone_and_dns.sh lo era, da sempre: lo si lancia
        // con sh, quindi nessuno se n'era accorto) la ritrova a inizio file.
        if (content.stripLeading().startsWith("#!")) content = content.stripLeading();
        if (content.startsWith("#!")) {
            int nl = content.indexOf('\n');
            if (nl < 0) return content + "\n" + guard;
            return content.substring(0, nl + 1) + guard + content.substring(nl + 1);
        }
        return guard + content;
    }

    /** L'impronta sha256 del jar da cui gira il pannello; "" se non gira da un jar (le prove). */
    public static String jarSha256() {
        String s = jarSha;
        if (s != null) return s;
        s = "";
        try {
            Path p = Path.of(InstallScripts.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (Files.isRegularFile(p) && p.getFileName().toString().endsWith(".jar")) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                try (InputStream in = Files.newInputStream(p)) {
                    byte[] b = new byte[1 << 16];
                    int n;
                    while ((n = in.read(b)) > 0) md.update(b, 0, n);
                }
                s = HexFormat.of().formatHex(md.digest());
            }
        } catch (Exception e) {
            LOGGER.warning("Cannot fingerprint the panel jar: " + e.getMessage());
        }
        jarSha = s;
        return s;
    }

    /**
     * All'avvio di ogni processo del pannello: gli script di adesso riscritti dal jar che gira, e quelli
     * che nessuno scrive piu' messi da parte. Idempotente.
     */
    public static void refreshAtStartup() {
        new FullMailServerScript().write_file();
        new SetTimeOnSystemScript().write_file();
        retire();
    }

    /**
     * Gli script che il pannello non scrive piu' diventano nome.sh.retired: non si lanciano piu' per
     * sbaglio, ma non si perdono. Se c'e' gia' un .retired accanto, non si sceglie: si lasciano tutti e
     * due e lo si dice.
     */
    static void retire() {
        for (String name : RETIRED) {
            Path p = Path.of(DIR, name);
            if (!Files.exists(p)) continue;
            Path to = Path.of(DIR, name + ".retired");
            if (Files.exists(to)) {
                LOGGER.warning("Install script " + p + " is no longer written by the panel, and " + to
                        + " is already there: both left as they are. It is a script of an older panel version: do not run it.");
                continue;
            }
            try {
                Files.move(p, to);
                try { Files.setPosixFilePermissions(to, PosixFilePermissions.fromString("rw-------")); }
                catch (UnsupportedOperationException ignored) { }
                LOGGER.info("Install script of an older panel version set aside: " + p + " -> " + to);
            } catch (IOException e) {
                LOGGER.warning("Cannot set aside " + p + ": " + e.getMessage());
            }
        }
    }
}
