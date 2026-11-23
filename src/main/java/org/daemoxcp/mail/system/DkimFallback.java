package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.security.DkimManager;
import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Rspamd signs only the domains that have their own DKIM key: try_fallback = false in local.d/dkim_signing.conf.
 *
 * <p>Measured on the production server on 2026-11-21: every night at 03:01 and at 04:15 (periodic's reports for
 * root, from sendmail, which go through Rspamd with non_smtpd_milters) Rspamd wrote "cannot load dkim key
 * /var/db/rspamd/dkim/...: cannot stat key file". The domain of those messages, the machine's name, is not a mail
 * domain and has no key; with try_fallback set to true, the default, Rspamd looks for it in the default path, which
 * does not exist. On the VM installed from the README the file was not there at all: the same error for every local
 * or authenticated message of a domain without a key. What gets signed does not change: without a key nothing was
 * signed anyway.
 *
 * <p>The file is written by DkimManager, with the domains and their keys; here only the extra line:
 * <ul>
 *   <li>the file is not there: DkimManager writes it from the database (on a new server, no domain with DKIM);</li>
 *   <li>the file belongs to the panel (the DkimManager header or that of the RspamdScript installer) and does not
 *       say try_fallback: the line after allow_username_mismatch, the rest byte for byte as it was;</li>
 *   <li>try_fallback is already there, with any value, or the file was written by someone else: as it is.</li>
 * </ul>
 * Only on the panel's Rspamd, the one behind Postfix as a milter. Then rspamadm configtest, reload and the test:
 * rspamadm configdump dkim_signing says try_fallback = false and Rspamd scans. If something does not add up, the
 * file goes back to how it was (or is removed) and Rspamd is reloaded. At the second startup it does nothing.
 */
public final class DkimFallback {

    private static final Logger LOGGER = Logger.getLogger(DkimFallback.class.getName());

    static final Path FILE = Path.of(DkimManager.CONFIG_PATH);
    /** The header that the RspamdScript installer writes. */
    static final String SCRIPT_HEADER = "# DKIM Signing\n# Keys are generated per-domain by the panel\n";
    static final Pattern ANY_FALLBACK = Pattern.compile("(?m)^\\s*try_fallback\\s*=");
    static final Pattern ALLOW_LINE = Pattern.compile("(?m)^allow_username_mismatch = true;\\n");
    static final Pattern FALLBACK_FALSE = Pattern.compile("(?m)^\\s*try_fallback\\s*=\\s*false\\s*;");

    private DkimFallback() {}

    enum Action { NOTHING, WRITE, INSERT, LEFT_ALONE }

    /**
     * What to do. installed: rspamadm is there; proxy: the worker-proxy.inc of local.d (null if it is not
     * there); current: the current file (null if it is not there). A pure function.
     */
    static Action decide(boolean installed, String proxy, String current) {
        if (!installed || proxy == null || !HeaderFromCheck.MILTER.matcher(proxy).find()) return Action.NOTHING;
        if (current == null) return Action.WRITE;
        if (ANY_FALLBACK.matcher(current).find()) return Action.NOTHING;
        boolean ours = current.startsWith(DkimManager.CONFIG_HEADER) || current.startsWith(SCRIPT_HEADER);
        return ours && ALLOW_LINE.matcher(current).find() ? Action.INSERT : Action.LEFT_ALONE;
    }

    /** The file with the line after allow_username_mismatch, everything else as it was. A pure function. */
    static String inserted(String current) {
        var m = ALLOW_LINE.matcher(current);
        if (!m.find()) return null;
        return current.substring(0, m.end()) + DkimManager.NO_FALLBACK + "\n" + current.substring(m.end());
    }

    /** configdump says try_fallback = false. Pure function. */
    static boolean dumpSaysNoFallback(String dump) {
        return dump != null && FALLBACK_FALSE.matcher(dump).find();
    }

    public static void ensureAtBoot() {
        try {
            boolean installed = Files.isExecutable(Path.of(RspamdController.RSPAMADM));
            String proxy = Files.isRegularFile(HeaderFromCheck.PROXY, LinkOption.NOFOLLOW_LINKS)
                    ? Files.readString(HeaderFromCheck.PROXY, StandardCharsets.UTF_8) : null;
            String current = Files.isRegularFile(FILE, LinkOption.NOFOLLOW_LINKS) ? Files.readString(FILE, StandardCharsets.UTF_8)
                    : Files.exists(FILE, LinkOption.NOFOLLOW_LINKS) ? "" : null;
            switch (decide(installed, proxy, current)) {
                case NOTHING -> { }
                case LEFT_ALONE -> LOGGER.info("[DkimFallback] " + FILE + " was not written by the panel and does not say"
                        + " try_fallback: left as it is (Rspamd looks for a key under /var/db/rspamd/dkim for domains without one)");
                case WRITE -> {
                    if (Main.mailDatabase == null) {
                        LOGGER.info("[DkimFallback] no database yet: " + FILE + " is written at the next start");
                        return;
                    }
                    apply(new DkimManager(Main.mailDatabase).rspamdConfigText(), null, "no " + FILE + ": written with no domain"
                            + " signed without its own key");
                }
                case INSERT -> apply(inserted(current), current, NO_FALLBACK_REASON);
            }
        } catch (Throwable t) {
            LOGGER.warning("[DkimFallback] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static final String NO_FALLBACK_REASON = "Rspamd looked for a key under /var/db/rspamd/dkim for every domain without one"
            + " (the server's own name in root's reports) and logged «cannot load dkim key»";

    static boolean apply(String wanted, String previous, String reason) throws Exception {
        if (wanted == null) return false;
        if (!Shell.run(Duration.ofSeconds(30), "service", "rspamd", "status").success()) {
            LOGGER.info("[DkimFallback] Rspamd is not running: " + FILE + " left as it is, retrying at the next start");
            return false;
        }
        write(wanted);
        Shell.Result test = Shell.run(Duration.ofSeconds(60), RspamdController.RSPAMADM, "configtest");
        if (!test.success()) {
            putBack(previous, false);
            LOGGER.warning("[DkimFallback] ROLLED_BACK: rspamadm configtest refuses " + FILE + ": nothing changed");
            return false;
        }
        HeaderFromCheck.reload();
        String problem = "Rspamd does not answer a scan";
        for (int i = 0; i < 30 && problem != null; i++) {
            Thread.sleep(1000);
            String dump = Shell.run(Duration.ofSeconds(60), RspamdController.RSPAMADM, "configdump", "dkim_signing").output();
            if (!dumpSaysNoFallback(dump)) problem = "rspamadm configdump dkim_signing does not say " + DkimManager.NO_FALLBACK;
            else problem = HeaderFromCheck.scan("<" + HeaderFromCheck.PROBE_USER + ">") == null ? "Rspamd does not answer a scan" : null;
        }
        if (problem != null) {
            putBack(previous, true);
            LOGGER.warning("[DkimFallback] ROLLED_BACK: " + problem + "; " + FILE + " put back");
            return false;
        }
        LOGGER.info("[DkimFallback] DONE: Rspamd signs only the domains that have their own DKIM key (" + DkimManager.NO_FALLBACK
                + " in " + FILE + "; " + reason + ")");
        return true;
    }

    private static void write(String content) throws Exception {
        Files.createDirectories(FILE.getParent());
        Path tmp = FILE.resolveSibling("." + FILE.getFileName() + ".tmp");
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Files.move(tmp, FILE, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(String previous, boolean reload) throws Exception {
        if (previous != null) write(previous);
        else Files.deleteIfExists(FILE);
        if (reload) HeaderFromCheck.reload();
    }
}
