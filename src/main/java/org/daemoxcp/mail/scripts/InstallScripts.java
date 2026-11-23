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
 * The installation scripts on disk are always those of the running jar: never one left over from a
 * previous version.
 *
 * <p>Why it exists: measured by reading the code on 2026-11-06 (finding 169). Six classes out of seven
 * wrote their script only "if missing": after a panel update the one from the first version
 * stayed, forever, and the menu ran setup_timezone_and_dns.sh as it was on the first day.
 * The detached reinstall (Main --reinstall) used install_mail_server.sh if it was already there. And five
 * scripts from previous versions (Roundcube, Rspamd, ClamAV, Dovecot, Let's Encrypt) stayed in the
 * folder without anyone writing them anymore: whoever launched them by hand launched old stuff.
 *
 * <p>Now:
 * <ul>
 *   <li>they are ALWAYS written, and all or nothing: a new file next to it and then the rename. Whoever is
 *       running the previous one keeps reading their own (the old file stays open for them), and
 *       there is no instant in which the script is missing;</li>
 *   <li>at every start of the panel (service, menu, console commands) and before every run;</li>
 *   <li>each one carries the fingerprint of the jar that wrote it: launched BY HAND, it compares it with
 *       the jar the panel's service uses and, if they differ, it stops before changing anything;</li>
 *   <li>those nobody writes anymore are set aside at boot (name.sh.retired).</li>
 * </ul>
 */
public final class InstallScripts {

    private static final Logger LOGGER = Logger.getLogger(InstallScripts.class.getName());

    private InstallScripts() {}

    /** The scripts folder, in the panel's folder. */
    public static final String DIR = "./install_scripts";

    /** Those that previous versions wrote and that the panel no longer writes or runs. */
    static final List<String> RETIRED = List.of("install_roundcube.sh", "install_rspamd.sh",
            "install_clamav.sh", "install_dovecot.sh", "generate_letsencrypt.sh");

    /** The variable the panel puts in the environment of every script it launches itself. */
    public static final String FROM_PANEL = "DAEMOXCP_MAIL_FROM_PANEL";

    private static volatile String jarSha;

    /**
     * Writes the script, always, all or nothing. True if it is written. The file is 700: only
     * root launches it, and only root must be able to change it.
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
     * The script with the jar's fingerprint and the check for whoever launches it by hand, right after the
     * #! line. The service's jar is given by rc.conf (daemoxcp_mail_jar) or, if it is not there, by the
     * default value written in the panel's rc.d script. Without a panel service, or when launched by the
     * panel itself (which has just written it), the check is not done.
     *
     * <p>The header line is in English: the same sentence in Italian is one of the previous markers
     * (legacy-names.json), and LegacyNamesTest no longer wants it in any file written by the panel.
     */
    static String stamped(String content) {
        String guard = """
                # --- Written by DaemoxCP Mail (InstallScripts) --------------------------------------------
                # The fingerprint of the jar that wrote this script. Started by hand (not by the panel), the
                # script compares it with the jar the panel's service uses: if they differ, the script belongs
                # to another version of the panel and stops before changing anything.
                DAEMOXCP_MAIL_WRITTEN_BY_JAR="%s"
                if [ -z "${DAEMOXCP_MAIL_FROM_PANEL:-}" ] && [ -n "$DAEMOXCP_MAIL_WRITTEN_BY_JAR" ]; then
                    daemoxcp_mail_jar=$(sysrc -n daemoxcp_mail_jar 2>/dev/null) || daemoxcp_mail_jar=""
                    [ -n "$daemoxcp_mail_jar" ] || daemoxcp_mail_jar=$(sed -n 's/^: \\${daemoxcp_mail_jar:="\\(.*\\)"}$/\\1/p' /usr/local/etc/rc.d/daemoxcp_mail 2>/dev/null)
                    if [ -n "$daemoxcp_mail_jar" ] && [ -f "$daemoxcp_mail_jar" ] && [ "$(sha256 -q "$daemoxcp_mail_jar" 2>/dev/null)" != "$DAEMOXCP_MAIL_WRITTEN_BY_JAR" ]; then
                        echo "STOPPED: this script was written by another version of DaemoxCP Mail than the one the panel service runs ($daemoxcp_mail_jar)."
                        echo "Open the panel menu (it writes its scripts again at every start) and run it from there."
                        echo "Nothing was stopped and nothing was changed."
                        exit 1
                    fi
                fi
                # ------------------------------------------------------------------------------------------
                """.formatted(jarSha256());
        // A script with an indented #! line (setup_timezone_and_dns.sh had one, always: it is launched
        // with sh, so nobody had noticed) gets it back at the start of the file.
        if (content.stripLeading().startsWith("#!")) content = content.stripLeading();
        if (content.startsWith("#!")) {
            int nl = content.indexOf('\n');
            if (nl < 0) return content + "\n" + guard;
            return content.substring(0, nl + 1) + guard + content.substring(nl + 1);
        }
        return guard + content;
    }

    /** The sha256 fingerprint of the jar the panel runs from; "" if it does not run from a jar (the tests). */
    public static String jarSha256() {
        String s = jarSha;
        if (s != null) return s;
        s = "";
        try {
            Path p = Path.of(org.daemoxcp.mail.system.PanelServiceRename.current(
                    Path.of(InstallScripts.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString()));
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
     * At the start of every panel process: the current scripts rewritten by the running jar, and those
     * nobody writes anymore set aside. Idempotent.
     */
    public static void refreshAtStartup() {
        new FullMailServerScript().write_file();
        new SetTimeOnSystemScript().write_file();
        retire();
    }

    /**
     * The scripts the panel no longer writes become name.sh.retired: they are no longer launched by
     * mistake, but they are not lost. If there is already a .retired next to one, no choice is made: both
     * are left and this is reported.
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
