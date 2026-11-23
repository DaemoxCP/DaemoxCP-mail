package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Dovecot's three sockets that are open to anyone and that the panel does not use, closed.
 *
 * In 2.4 Dovecot creates in /var/run/dovecot (0755) some sockets with mode 0666: any user on the machine can
 * connect to them. Measured on the VM and on the production server on 2026-11-17: indexer, imap-urlauth,
 * auth-token and dns-client (the other 0666 ones are in login/ and token-login/, 0750 folders of dovenull). None
 * of those three is needed by the panel:
 *   - indexer is for full-text search (fts) and for `doveadm index -q`: the panel does not configure fts. 0660
 *     root:vmail, so that the mailbox processes (vmail) can reach it if one day there is search;
 *   - imap-urlauth (of the imap-urlauth-login service, not of imap-urlauth: a wrong name and Dovecot does not
 *     start, seen on the VM) and auth-token are for IMAP URLAUTH, which is off (imap_urlauth_host empty). 0600 root.
 * dns-client stays as it is: it only does DNS lookups.
 *
 * They give data to nobody, but a service on the machine taken over by someone (the webmail, for example) must
 * not be able to talk to Dovecot where it is not needed. The installer writes the file for 2.4 (DovecotConfig,
 * conf.d/10-sockets.conf); on servers installed earlier this boot repair writes it, with the same file. Dovecot
 * creates the sockets only when it starts: a restart is needed, not a reload (reload does not recreate the
 * sockets, measured). First it checks that authentication works; after the restart, that Dovecot runs, that
 * authentication still works, that the LMTP socket and the IMAP port are there and that the three sockets have the
 * new permissions. If something does not add up, the file is removed and Dovecot restarts: it goes back to how it
 * was. Only in 2.4: in 2.3 auth-token is not necessarily there, and it has not been tested.
 */
public final class DovecotSockets {

    private static final Logger LOGGER = Logger.getLogger(DovecotSockets.class.getName());

    public static final String FILE_NAME = "10-sockets.conf";
    static final Path RUN = Path.of("/var/run/dovecot");
    static final Path LMTP_SOCKET = Path.of("/var/spool/postfix/private/dovecot-lmtp");

    /** The sockets and the permissions they must have (rwx of the user, of the group, of others). */
    static final Map<String, String> WANTED = new LinkedHashMap<>();
    static {
        WANTED.put("indexer", "rw-rw----");
        WANTED.put("imap-urlauth", "rw-------");
        WANTED.put("auth-token", "rw-------");
    }

    private DovecotSockets() {}

    /** The content of the file: the same for the installer (DovecotConfig) and for the repair. */
    public static String fileContent() {
        return "# " + PanelMarker.WRITTEN + ".\n"
             + "# Sockets Dovecot creates open to everyone (0666) that the panel does not use: indexer is for full-text\n"
             + "# search (fts, not configured), imap-urlauth and auth-token for IMAP URLAUTH (off).\n"
             + "service indexer {\n"
             + "  unix_listener indexer {\n"
             + "    mode = 0660\n"
             + "    user = root\n"
             + "    group = vmail\n"
             + "  }\n"
             + "}\n"
             + "service imap-urlauth-login {\n"
             + "  unix_listener imap-urlauth {\n"
             + "    mode = 0600\n"
             + "  }\n"
             + "}\n"
             + "service auth {\n"
             + "  unix_listener auth-token {\n"
             + "    mode = 0600\n"
             + "  }\n"
             + "}\n";
    }

    enum Action { NOTHING, NOT_24, APPLY, RESTART_ONLY }

    /**
     * What to do. A pure function, so that it can be tested.
     *
     * @param version    `dovecot --version`
     * @param fileNow    the file as it is now, or null if it is not there
     * @param wrongNow   the sockets that today do not have the wanted permissions
     */
    static Action decide(String version, String fileNow, List<String> wrongNow) {
        if (version == null || !version.trim().startsWith("2.4")) return Action.NOT_24;
        boolean fileRight = fileContent().equals(fileNow);
        if (fileRight && wrongNow.isEmpty()) return Action.NOTHING;
        return fileRight ? Action.RESTART_ONLY : Action.APPLY;
    }

    /**
     * The sockets of WANTED that exist and do not have the wanted permissions. A missing one does not count
     * (Dovecot stopped).
     */
    static List<String> wrong(Path run) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, String> e : WANTED.entrySet()) {
            Path s = run.resolve(e.getKey());
            try {
                if (!Files.exists(s, LinkOption.NOFOLLOW_LINKS)) continue;
                String perms = PosixFilePermissions.toString(Files.getPosixFilePermissions(s, LinkOption.NOFOLLOW_LINKS));
                if (!perms.equals(e.getValue())) out.add(e.getKey() + " " + perms);
            } catch (Exception x) {
                out.add(e.getKey() + " unreadable");
            }
        }
        return out;
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(DovecotAuthWorker.DOVECONF))) return;
            Shell.Result v = Shell.run(Duration.ofSeconds(15), "dovecot", "--version");
            if (!v.success()) return;
            Path file = Path.of(DovecotAuthWorker.CONF_D, FILE_NAME);
            String now = Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ? Files.readString(file) : null;
            Action a = decide(v.outputTrim(), now, wrong(RUN));
            if (a == Action.NOTHING || a == Action.NOT_24) return;
            apply(file, fileContent());
        } catch (Throwable t) {
            LOGGER.warning("[DovecotSockets] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /**
     * Writes the file, validates, restarts and verifies; if the verification fails, puts it back as it was and
     * restarts.
     */
    static boolean apply(Path file, String content) throws Exception {
        if (!DovecotAuthWorker.running()) {
            LOGGER.info("[DovecotSockets] Dovecot is not running: sockets left as they are, retrying at the next start");
            return false;
        }
        int before = DovecotAuthWorker.lookup();
        if (!DovecotAuthWorker.LOOKUP_OK.contains(before)) {
            LOGGER.warning("[DovecotSockets] authentication already fails before any change (doveadm auth lookup exit "
                    + before + "): sockets left as they are");
            return false;
        }
        Path saved = Files.exists(file, LinkOption.NOFOLLOW_LINKS)
                ? Files.createTempFile(file.getParent().getParent(), ".sockets-", ".saved") : null;
        if (saved != null) Files.copy(file, saved, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        try {
            write(file, content);
            Shell.Result check = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n");
            if (!check.success()) {
                putBack(file, saved, false);
                LOGGER.warning("[DovecotSockets] ROLLED_BACK: doveconf refuses the file (" + firstLine(check.outputTrim()) + "): nothing changed");
                return false;
            }
            restart();
            String problem = verify();
            if (problem != null) {
                putBack(file, saved, true);
                String after = verifyRunning();
                LOGGER.warning("[DovecotSockets] ROLLED_BACK: " + problem + "; file removed and Dovecot restarted"
                        + (after == null ? " (running again)" : " (" + after + ")"));
                return false;
            }
            LOGGER.info("[DovecotSockets] DONE: indexer 0660 root:vmail, imap-urlauth and auth-token 0600 root (" + file
                    + "); Dovecot restarted, authentication, LMTP and IMAP checked");
            return true;
        } finally {
            if (saved != null) Files.deleteIfExists(saved);
        }
    }

    /**
     * After the restart, up to 20 s: Dovecot runs, authentication goes through, LMTP and IMAP are there, the
     * permissions are the right ones.
     */
    static String verify() throws InterruptedException {
        String last = "unreachable";
        for (int i = 0; i < 40; i++) {
            last = verifyRunning();
            if (last == null) {
                List<String> w = wrong(RUN);
                List<String> missing = new ArrayList<>();
                for (String s : WANTED.keySet()) if (!Files.exists(RUN.resolve(s), LinkOption.NOFOLLOW_LINKS)) missing.add(s);
                if (w.isEmpty() && missing.isEmpty()) return null;
                last = "sockets " + (w.isEmpty() ? "" : "with other permissions " + w) + (missing.isEmpty() ? "" : " missing " + missing);
            }
            Thread.sleep(500);
        }
        return last;
    }

    /** null if Dovecot runs and answers; otherwise what is missing. */
    static String verifyRunning() {
        if (!DovecotAuthWorker.running()) return "Dovecot does not run after the restart";
        int rc = DovecotAuthWorker.lookup();
        if (!DovecotAuthWorker.LOOKUP_OK.contains(rc)) return "doveadm auth lookup fails (exit " + rc + ")";
        if (!Files.exists(LMTP_SOCKET, LinkOption.NOFOLLOW_LINKS)) return "the LMTP socket " + LMTP_SOCKET + " is missing";
        Shell.Result imap = Shell.run(Duration.ofSeconds(10), "sockstat", "-46l", "-p", "993");
        if (!imap.outputTrim().contains(":993")) return "nothing listens on port 993";
        return null;
    }

    static void restart() throws InterruptedException {
        Shell.run(Duration.ofSeconds(60), "service", "dovecot", "restart");
        Thread.sleep(1000);
    }

    private static void write(Path file, String content) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.writeString(tmp, content);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Shell.run(Duration.ofSeconds(10), "chown", "root:wheel", tmp.toString());
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(Path file, Path saved, boolean restart) throws Exception {
        if (saved != null) Files.copy(saved, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        else Files.deleteIfExists(file);
        if (restart) {
            restart();
            // The earlier restart may have left Dovecot stopped: we try to start it again
            if (!DovecotAuthWorker.running()) Shell.run(Duration.ofSeconds(60), "service", "dovecot", "start");
        }
    }

    private static String firstLine(String s) {
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
