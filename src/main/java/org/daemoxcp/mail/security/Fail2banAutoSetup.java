package org.daemoxcp.mail.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Automatic Fail2ban setup for the mail panel at boot.
 *
 * Operations (ALL idempotent, fail-safe):
 *   1. Creates /var/log/daemoxcp-mail-auth.log with perms 640 root:wheel
 *   2. Writes the Fail2ban filter in /usr/local/etc/fail2ban/filter.d/daemoxcp-mail-auth.conf
 *   3. Adds the jail [daemoxcp-mail-auth] to /usr/local/etc/fail2ban/jail.local
 *      (only if it does not exist already -- it does not overwrite customizations)
 *   4. Adds log rotation in /usr/local/etc/newsyslog.conf.d/
 *   5. Reload Fail2ban
 *
 * All steps are best-effort: if one fails (permissions, fail2ban not
 * installed, etc.) a warning is logged but the panel keeps going.
 *
 * To be called ONCE at boot after the Fail2banManager has been initialized.
 */
public final class Fail2banAutoSetup {
    private static final Logger LOGGER = Logger.getLogger(Fail2banAutoSetup.class.getName());

    /** The jail for logins to the panel, with the product name (formerly mail-panel-auth: AuthJailRename). */
    public static final String AUTH_JAIL         = org.daemoxcp.mail.system.Product.SLUG + "-auth";
    public static final String LOG_FILE          = "/var/log/" + AUTH_JAIL + ".log";
    private static final String FILTER_DIR        = "/usr/local/etc/fail2ban/filter.d";
    private static final String JAIL_D            = "/usr/local/etc/fail2ban/jail.d";
    public static final String FILTER_FILE       = FILTER_DIR + "/" + AUTH_JAIL + ".conf";
    private static final String JAIL_LOCAL        = "/usr/local/etc/fail2ban/jail.local";
    private static final String NEWSYSLOG_DIR     = "/usr/local/etc/newsyslog.conf.d";
    public static final String NEWSYSLOG_CONF    = NEWSYSLOG_DIR + "/" + AUTH_JAIL + ".conf";
    private static final String FAIL2BAN_CLIENT   = "/usr/local/bin/fail2ban-client";

    private static final String JAIL_MARKER = "[" + AUTH_JAIL + "]";

    /** Starts the setup. Idempotent: can be called several times without harm. */
    public static void run() {
        try {
            // 1. Log file
            ensureLogFile();
            // 2. Filter
            boolean filterChanged = writeFilterIfMissing();
            // 3. Jail
            boolean jailChanged = appendJailIfMissing();
            // 4. Log rotation
            writeNewsyslogIfMissing();
            // 5. Permaban setup (file + pf anchor)
            ensurePermanentBanSetup();
            // 6. Reload Fail2ban if we changed something
            if (filterChanged || jailChanged) {
                reloadFail2ban();
            }
            // 7. The jails of the mail services, if missing
            ensureMailJailsIfMissing();
            // 8. If a block would stop nothing, say so: an unprotected panel must not
            //    look fine.
            warnIfBansWouldNotBite();
        } catch (Throwable t) {
            // Never propagate -- the setup must not crash the panel
            LOGGER.warning("[Fail2banAutoSetup] Setup failed: " + t.getMessage());
        }
    }

    /**
     * Setup of the permaban feature:
     *  1. Creates /var/db/daemoxcp-mail/permaban.list if missing
     *  2. Adds to /etc/pf.conf (if it exists): table <permaban> persist + block rule
     *  3. Reloads pf and fills the runtime table from the file
     */
    private static void ensurePermanentBanSetup() {
        try {
            // 1. File
            Path dir = Paths.get(Fail2banManager.PERMABAN_DIR);
            if (!Files.isDirectory(dir)) Files.createDirectories(dir);
            Path file = Paths.get(Fail2banManager.PERMABAN_FILE);
            if (!Files.exists(file)) {
                String header = "# Permaban list — managed by DaemoxCP Mail\n"
                    + "# Add or remove addresses from the panel's page, do not edit by hand.\n\n";
                Files.writeString(file, header);
                try {
                    Files.setPosixFilePermissions(file,
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-r-----"));
                } catch (Exception ignored) {}
                LOGGER.info("[Fail2banAutoSetup] Created " + Fail2banManager.PERMABAN_FILE);
            }

            // 2. Anchor / tabella in pf.conf
            Path pfConf = Paths.get("/etc/pf.conf");
            if (Files.exists(pfConf)) {
                String content = Files.readString(pfConf, java.nio.charset.StandardCharsets.UTF_8);
                boolean hasTable = content.contains("table <permaban>");
                boolean hasBlock = content.matches("(?s).*block\\s+in\\s+quick\\s+from\\s+<permaban>.*");
                boolean hasF2bAnchor = hasF2bAnchor(content);
                if (!hasTable || !hasBlock || !hasF2bAnchor) {
                    StringBuilder additions = new StringBuilder();
                    additions.append("\n# === Permaban (managed by DaemoxCP Mail) ===\n");
                    if (!hasTable) {
                        additions.append("table <permaban> persist file \"")
                            .append(Fail2banManager.PERMABAN_FILE).append("\"\n");
                    }
                    if (!hasBlock) {
                        additions.append("block in quick from <permaban>\n");
                    }
                    if (!hasF2bAnchor) {
                        // The fail2ban anchor. The jail [daemoxcp-mail-auth] has
                        // "action = pf[...]", and fail2ban's pf action puts its rules
                        // inside the anchor "f2b/<name>". An anchor that pf.conf does not
                        // name is NEVER looked at: fail2ban records the block, writes it
                        // in its log, says it has done it, and the packet gets through
                        // anyway. The panel knew how to add it, but only from the Firewall
                        // page, with a button pressed: not at boot. The anchor's rules
                        // have "quick", so they apply even when placed at the end.
                        additions.append("anchor \"f2b/*\"\n");
                    }
                    // Append (rules with 'quick' work even if placed at the end)
                    String newContent = content + (content.endsWith("\n") ? "" : "\n") + additions.toString();

                    // Pre-flight syntax check with a temporary file
                    Path tmp = Files.createTempFile("pf-permaban-", ".conf");
                    Files.writeString(tmp, newContent);
                    // TODO: migrate to Shell.run when touched
                    ProcessBuilder testPb = new ProcessBuilder("/sbin/pfctl", "-nf", tmp.toString());
                    org.daemoxcp.mail.util.Shell.applyPath(testPb);
                    testPb.redirectErrorStream(true);
                    Process tp = testPb.start();
                    String testOut = new String(tp.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                    tp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                    if (tp.exitValue() != 0) {
                        LOGGER.warning("[Fail2banAutoSetup] pf.conf permaban check failed, NOT applied: " + testOut);
                        Files.deleteIfExists(tmp);
                    } else {
                        // The backup copy is made NOW, not before: made before, a
                        // failed syntax check left one .bak.<timestamp> too many
                        // at every boot, i.e. one more file every time the
                        // repair did NOT happen.
                        org.daemoxcp.mail.system.ConfigBackups.copy(pfConf);
                        Files.move(tmp, pfConf, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                        // Live reload
                        try {
                            // TODO: migrate to Shell.run when touched
                            ProcessBuilder loadPb = new ProcessBuilder("/sbin/pfctl", "-f", "/etc/pf.conf");
                            org.daemoxcp.mail.util.Shell.applyPath(loadPb);
                            loadPb.redirectErrorStream(true);
                            Process lp = loadPb.start();
                            lp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                        } catch (Exception ignored) {}
                        LOGGER.info("[Fail2banAutoSetup] Permaban anchor added to /etc/pf.conf");
                    }
                }
            }

            // 3. Reload the runtime table from the file (if pf is active)
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-t", Fail2banManager.PERMABAN_TABLE,
                    "-T", "replace", "-f", Fail2banManager.PERMABAN_FILE);
                org.daemoxcp.mail.util.Shell.applyPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            } catch (Exception ignored) {}

        } catch (Exception e) {
            LOGGER.warning("[Fail2banAutoSetup] ensurePermabanSetup failed: " + e.getMessage());
        }
    }

    // ================== the jails of the mail services ==================

    private static final String MAIL_JAILS = JAIL_D + "/mail.local";

    /**
     * Is there really a mail server on this machine?
     *
     * <p>The configuration files are checked, not the record the panel keeps in SQLite:
     * those rows say what the panel <em>believes</em> it has installed, and fail2ban does not
     * load a jail for a service that is not there -- it only makes noise in the log and a
     * red mark on the Firewall page.
     */
    static boolean mailStackPresent() {
        return Files.exists(Paths.get("/usr/local/etc/postfix/main.cf"))
                && Files.isDirectory(Paths.get("/usr/local/etc/dovecot"));
    }

    /**
     * The jails of Postfix, Dovecot, Rspamd and Roundcube: they are written if missing.
     *
     * <p>Before, they existed only <strong>with a button pressed</strong>, from the Firewall page: on
     * a freshly installed machine the mail services sat on public ports with
     * nothing stopping whoever tried credentials in bursts, and nothing said that something
     * was missing. The panel's jail, instead, was already written at boot: there was no reason
     * why the mail ones should be different.
     *
     * <p>Only if missing. The real work is done by {@code Fail2banManager.installMailJails()} --
     * which writes the file, creates its own filters, turns on Roundcube's login log
     * (otherwise fail2ban rejects the roundcube-auth jail) and reloads -- but that method
     * overwrites {@code mail.local} without looking, and at boot that would mean erasing at
     * every restart the parameters an administrator has changed. If the file is already there
     * it is not touched, as for the panel's filter.
     */
    private static void ensureMailJailsIfMissing() {
        try {
            if (!Files.isDirectory(Paths.get(JAIL_D))
                    && !Files.isDirectory(Paths.get(FILTER_DIR))) {
                return;                                   // fail2ban not installed
            }
            if (Files.exists(Paths.get(MAIL_JAILS))) return;      // already there, even if tweaked
            if (!mailStackPresent()) {
                LOGGER.info("[Fail2banAutoSetup] no mail server here yet: mail jails skipped");
                return;
            }
            Fail2banManager.InstallResult r = new Fail2banManager().installMailJails();
            if (r != null && r.success) LOGGER.info("[Fail2banAutoSetup] mail jails written to " + MAIL_JAILS);
            else LOGGER.warning("[Fail2banAutoSetup] mail jails not written: "
                    + (r == null ? "no result" : String.valueOf(r.error)));
        } catch (Throwable t) {
            LOGGER.warning("[Fail2banAutoSetup] mail jails failed: " + t.getMessage());
        }
    }

    // ================== pf: do the blocks really stop a packet? ==================

    /**
     * Why a fail2ban block would stop nothing, or an empty string if it does stop it.
     *
     * <p>Four pieces must be there <strong>together</strong>, and the order matters because the
     * first one missing makes it pointless to look at the following ones: the pf module in the
     * kernel (without it, {@code pfctl} cannot even talk to the kernel and answers
     * {@code /dev/pf: No such file or directory}), the file {@code /etc/pf.conf}, the line
     * {@code anchor "f2b/*"} inside that file, and pf turned on.
     *
     * <p>Measured on a freshly installed FreeBSD 15.1, with the mail panel installed and
     * running: {@code fail2ban-client} declares the address blocked, and in pf there is nothing
     * because pf.conf does not exist and the module is not loaded. "Blocks and says it has
     * blocked" is the worst case: it leaves no trace from which to notice.
     *
     * <p>Pure function, because this is the thing to test: the four readings from the system
     * are in the methods below.
     */
    public static String whyBansWouldNotBite(boolean moduleLoaded, boolean confExists,
                                             boolean anchorPresent, boolean pfEnabled) {
        if (!moduleLoaded)
            return "the pf kernel module is not loaded, so pfctl cannot talk to the kernel at all";
        if (!confExists)
            return "/etc/pf.conf does not exist, so pf has no ruleset to put the bans in";
        if (!anchorPresent)
            return "/etc/pf.conf does not name anchor \"f2b/*\", and an anchor pf never looks at"
                    + " is where fail2ban writes its block rules";
        if (!pfEnabled)
            return "pf is not running (pfctl says Status: Disabled)";
        return "";
    }

    /** The pf module in the kernel. */
    public static boolean pfModuleLoaded() {
        return runSaying("/sbin/kldstat").contains("pf.ko");
    }

    /**
     * pf turned on.
     *
     * <p>"Status: Enabled" is read, not the exit code: {@code pfctl -s info} exits
     * <strong>0 even with pf off</strong>, printing "Status: Disabled". Asking only whether the
     * command succeeds means writing "pf on" next to a firewall that is off.
     */
    public static boolean pfEnabled() {
        return runSaying("/sbin/pfctl", "-s", "info").contains("Status: Enabled");
    }

    /** Inside a FreeBSD jail modules cannot be loaded: it is not a fault, it is an environment. */
    public static boolean insideFreebsdJail() {
        return runSaying("/sbin/sysctl", "-n", "security.jail.jailed").trim().equals("1");
    }

    /** What a command says, stderr included; empty string if it could not be launched. */
    private static String runSaying(String... command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            pb.redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null")));
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * At boot: if a block would stop nothing, it says so.
     *
     * <p>It does not turn pf on and does not write {@code /etc/pf.conf}: the boot recurs at every
     * restart, on a machine whose configuration may meanwhile have been changed by someone
     * else, and turning on a firewall there would mean changing a live machine behind the back
     * of whoever administers it. The <em>installation</em> does it, which is an explicit action,
     * and so does the Firewall page, which is a button pressed by a person.
     *
     * <p>What the boot must do is not make a panel that is not protected look fine:
     * before, it said nothing, and the login page sat on a public port
     * with fail2ban recording blocks that had no effect.
     */
    private static void warnIfBansWouldNotBite() {
        try {
            if (insideFreebsdJail()) return;          // in a jail pf is not a choice made here
            boolean anchor = false;
            boolean conf = Files.exists(Paths.get("/etc/pf.conf"));
            if (conf) {
                try {
                    anchor = hasF2bAnchor(Files.readString(Paths.get("/etc/pf.conf"), StandardCharsets.UTF_8));
                } catch (IOException ignored) { }
            }
            String why = whyBansWouldNotBite(pfModuleLoaded(), conf, anchor, pfEnabled());
            if (why.isEmpty()) return;
            // Yellow and two lines: one says what does not work, the other how to fix it. The
            // color is not the only carrier (r9): the text says everything on its own.
            System.out.println("\u001B[33mFail2ban can record bans but NOTHING WILL BE BLOCKED: "
                    + why + ".\u001B[0m");
            System.out.println("\u001B[33mFix it from the Firewall page ('fix all'), or run the"
                    + " mail server installation, which sets pf up.\u001B[0m");
            LOGGER.warning("[Fail2banAutoSetup] bans would not bite: " + why);
        } catch (Throwable t) {
            LOGGER.warning("[Fail2banAutoSetup] pf check failed: " + t.getMessage());
        }
    }

    /**
     * A filter already on disk: do we rewrite it?
     *
     * <p>Yes, only if it is still the panel's one and differs from what the panel
     * would write today. A file modified by hand is not touched, and it is recognized by the
     * fact that it no longer starts with the signature. The previous signature also counts
     * (legacy-names.json): on a server installed earlier the filter is rewritten once, and
     * takes the current one.
     */
    /** The filter was written by the panel: it starts with its signature, the current or a previous one. */
    public static boolean ownFilter(String existing) {
        if (existing == null) return false;
        for (String f : org.daemoxcp.mail.system.PanelMarker.forms(MARKER_SECTION, MARKER))
            if (existing.startsWith(f)) return true;
        return false;
    }

    static boolean shouldRewriteFilter(String existing) {
        if (existing == null) return true;
        if (existing.equals(filterContent())) return false;
        for (String f : org.daemoxcp.mail.system.PanelMarker.forms(MARKER_SECTION, MARKER))
            if (existing.startsWith(f)) return true;
        return false;
    }

    /**
     * Does this pf.conf already have the line that makes pf look at fail2ban's rules?
     *
     * <p>The forms pf accepts are accepted: with the name in quotes or without. Comments are
     * not looked into, because a commented-out line is not a rule -- and that file really does
     * contain comments, written by the panel itself.
     */
    public static boolean hasF2bAnchor(String pfConf) {
        for (String line : pfConf.split("\n")) {
            String t = line.trim();
            if (t.startsWith("#")) continue;
            if (t.startsWith("anchor \"f2b/*\"") || t.startsWith("anchor f2b/*")) return true;
        }
        return false;
    }

    /** Creates the log file with perms 640 root:wheel if it does not exist. */
    private static void ensureLogFile() {
        try {
            Path logPath = Paths.get(LOG_FILE);
            if (!Files.exists(logPath)) {
                Path parent = logPath.getParent();
                if (parent != null && !Files.exists(parent)) {
                    Files.createDirectories(parent);
                }
                Files.createFile(logPath);
                LOGGER.info("[Fail2banAutoSetup] Created " + LOG_FILE);
            }
            // Always set the perms (640 = rw-r-----)
            try {
                Set<PosixFilePermission> perms = new HashSet<>();
                perms.add(PosixFilePermission.OWNER_READ);
                perms.add(PosixFilePermission.OWNER_WRITE);
                perms.add(PosixFilePermission.GROUP_READ);
                Files.setPosixFilePermissions(logPath, perms);
            } catch (UnsupportedOperationException ignored) {
                // Non-POSIX FS -- ignore
            }
        } catch (IOException e) {
            LOGGER.warning("[Fail2banAutoSetup] Cannot create " + LOG_FILE + ": " + e.getMessage());
        }
    }

    /**
     * Writes the filter if missing, and rewrites it if it is still the panel's one and is
     * old. Returns true if it wrote.
     *
     * <p>"Write only if missing" left the broken filter forever for whoever had already started
     * the panel once: the file was there, so the fix would never have arrived.
     * A filter modified by whoever administers the machine, instead, is not touched, and is
     * recognized by the fact that its first line is no longer the panel's signature.
     */
    private static boolean writeFilterIfMissing() {
        try {
            Path filterDir = Paths.get(FILTER_DIR);
            if (!Files.isDirectory(filterDir)) {
                LOGGER.info("[Fail2banAutoSetup] " + FILTER_DIR + " does not exist — Fail2ban not installed? Skipping.");
                return false;
            }
            Path filterPath = Paths.get(FILTER_FILE);
            String wanted = filterContent();
            if (Files.exists(filterPath)) {
                String existing = Files.readString(filterPath, StandardCharsets.UTF_8);
                if (!shouldRewriteFilter(existing)) {
                    if (!existing.equals(wanted))
                        LOGGER.info("[Fail2banAutoSetup] " + FILTER_FILE + " was edited by hand — left alone");
                    return false;
                }
                LOGGER.info("[Fail2banAutoSetup] Rewriting our own older " + FILTER_FILE);
            }
            Files.writeString(filterPath, wanted, StandardCharsets.UTF_8);
            try { Files.setPosixFilePermissions(filterPath, PosixFilePermissions.fromString("rw-r--r--")); } catch (Exception ignored) {}
            LOGGER.info("[Fail2banAutoSetup] Wrote " + FILTER_FILE);
            return true;
        } catch (IOException e) {
            LOGGER.warning("[Fail2banAutoSetup] Cannot write filter: " + e.getMessage());
            return false;
        }
    }

    /** Adds the [daemoxcp-mail-auth] section to jail.local only if missing. */
    private static boolean appendJailIfMissing() {
        try {
            Path jailPath = Paths.get(JAIL_LOCAL);
            String existing = Files.exists(jailPath)
                ? Files.readString(jailPath, StandardCharsets.UTF_8)
                : "";

            if (existing.contains(JAIL_MARKER)) {
                return false; // jail already present, respect customizations
            }

            // Ensure a trailing newline before appending
            String prefix = existing.isEmpty() ? "" : (existing.endsWith("\n") ? "" : "\n");
            String toAppend = prefix + "\n" + JAIL_BLOCK;

            // Create jail.local if it does not exist
            if (!Files.exists(jailPath)) {
                Path parent = jailPath.getParent();
                if (parent != null && !Files.exists(parent)) {
                    LOGGER.info("[Fail2banAutoSetup] " + parent + " does not exist — Fail2ban not installed? Skipping jail.");
                    return false;
                }
                Files.writeString(jailPath, JAIL_BLOCK, StandardCharsets.UTF_8);
            } else {
                Files.writeString(jailPath, toAppend, StandardCharsets.UTF_8,
                    StandardOpenOption.APPEND);
            }
            try { Files.setPosixFilePermissions(jailPath, PosixFilePermissions.fromString("rw-r--r--")); } catch (Exception ignored) {}
            LOGGER.info("[Fail2banAutoSetup] Added jail [daemoxcp-mail-auth] to " + JAIL_LOCAL);
            return true;
        } catch (IOException e) {
            LOGGER.warning("[Fail2banAutoSetup] Cannot modify jail.local: " + e.getMessage());
            return false;
        }
    }

    /**
     * Writes the log rotation conf if missing.
     *
     * <p>The folder is <strong>created</strong>, not skipped: on a freshly installed FreeBSD
     * {@code /usr/local/etc/newsyslog.conf.d} does not exist yet, but {@code /etc/newsyslog.conf}
     * already includes it (line {@code <include> /usr/local/etc/newsyslog.conf.d/[!.]*.conf}).
     * Skipping meant precisely the normal case: no rotation, and an authentication
     * log that grows without end.
     */
    private static void writeNewsyslogIfMissing() {
        try {
            Path dir = Paths.get(NEWSYSLOG_DIR);
            if (!Files.isDirectory(dir)) Files.createDirectories(dir);
            Path conf = Paths.get(NEWSYSLOG_CONF);
            String content = newsyslogText(logOwner());
            if (Files.exists(conf)) {
                // Already present. Only the file written by the panel is rewritten, and only if the owner
                // of the log has changed: with the panel separated the web part writes it (daemoxcp_mail),
                // and the file that newsyslog recreates at every rotation must stay its own, otherwise the
                // web part can no longer write and fail2ban no longer sees the attempts.
                String now = Files.readString(conf, StandardCharsets.UTF_8);
                if (now.equals(content) || !ownNewsyslog(now)) return;
                Files.writeString(conf, content, StandardCharsets.UTF_8);
                LOGGER.info("[Fail2banAutoSetup] DONE: " + NEWSYSLOG_CONF + " recreates the log as " + logOwner());
                return;
            }
            Files.writeString(conf, content, StandardCharsets.UTF_8);
            LOGGER.info("[Fail2banAutoSetup] Wrote " + NEWSYSLOG_CONF);
        } catch (IOException e) {
            LOGGER.warning("[Fail2banAutoSetup] Cannot write newsyslog conf: " + e.getMessage());
        }
    }

    static final String NEWSYSLOG_HEADER = "# Rotation of the " + org.daemoxcp.mail.system.Product.NAME + " sign-in log ("
            + org.daemoxcp.mail.system.PanelMarker.WRITTEN + ")\n";

    /** The newsyslog file was written by the panel: the current header line or a previous one ("newsyslogHeaders"). */
    public static boolean ownNewsyslog(String text) {
        for (String h : org.daemoxcp.mail.system.PanelMarker.forms("newsyslogHeaders", NEWSYSLOG_HEADER.strip()))
            if (text.startsWith(h + "\n")) return true;
        return false;
    }

    /** The newsyslog.conf(5) line: file, owner:group, mode, copies, size in KB, when, flags. */
    static String newsyslogText(String owner) {
        return NEWSYSLOG_HEADER + LOG_FILE + "    " + owner + "    640    7    1024    *    JC\n";
    }

    /** The owner of the log: daemoxcp_mail:wheel with the panel separated (PanelSeparation), otherwise root:wheel. */
    static String logOwner() {
        try {
            String owner = Files.getOwner(Paths.get(LOG_FILE), java.nio.file.LinkOption.NOFOLLOW_LINKS).getName();
            return (org.daemoxcp.mail.system.PanelSeparation.USER.equals(owner) ? owner : "root") + ":wheel";
        } catch (IOException | UnsupportedOperationException e) {
            return "root:wheel";
        }
    }

    /** Reloads Fail2ban with fail2ban-client if available and running. */
    private static void reloadFail2ban() {
        try {
            if (!Files.isExecutable(Paths.get(FAIL2BAN_CLIENT))) {
                LOGGER.info("[Fail2banAutoSetup] " + FAIL2BAN_CLIENT + " not executable — skipping reload");
                return;
            }
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder(FAIL2BAN_CLIENT, "reload");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean done = p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) {
                p.destroyForcibly();
                LOGGER.warning("[Fail2banAutoSetup] Reload Fail2ban timeout");
                return;
            }
            int exit = p.exitValue();
            if (exit == 0) {
                LOGGER.info("[Fail2banAutoSetup] Fail2ban reloaded");
            } else {
                LOGGER.warning("[Fail2banAutoSetup] Reload Fail2ban exit=" + exit);
            }
        } catch (Exception e) {
            LOGGER.warning("[Fail2banAutoSetup] Fail2ban reload failed: " + e.getMessage());
        }
    }

    // ================== EMBEDDED CONFIG CONTENT ==================

    /** The line with which the panel signs the files it writes itself: only those does it rewrite. */
    public static final String MARKER = "# Fail2ban filter for " + org.daemoxcp.mail.system.Product.NAME + " sign-ins ("
            + org.daemoxcp.mail.system.PanelMarker.WRITTEN + ")";
    public static final String MARKER_SECTION = "fail2banFilterSignature";

    private static final String FAILURES = "LOGIN_FAILURE|LOGIN_2FA_FAILURE|LOGIN_INVALID_INPUT"
        + "|LOGIN_BLOCKED|CSRF_FAILURE|SSL_CERT_[A-Z_]+_FAILED|FAIL2BAN_[A-Z_]+_FAILED"
        + "|PASSKEY_REGISTER_FAILED|2FA_[A-Z_]+_FAILED|ADMIN_PASSWORD_CHANGE_FAILED";

    private static final String SUCCESSES = "LOGIN_SUCCESS|PASSKEY_LOGIN_SUCCESS|DOMAIN_CREATED"
        + "|DOMAIN_UPDATED|DOMAIN_DELETED|ALIAS_CREATED|ALIAS_DELETED|SSL_CERT_RENEWED"
        + "|SSL_CERT_ISSUED_HTTP01|SSL_CERT_ISSUED_DNS01|SSL_CERT_DEPLOYED"
        + "|SSL_CERT_INSTALLED_MANUAL|SSL_AUTO_RENEWAL_SETTINGS_CHANGED|SSL_MANUAL_CHECK_TRIGGERED"
        + "|FAIL2BAN_IP_BANNED|FAIL2BAN_IP_UNBANNED|2FA_ENABLED|2FA_DISABLED"
        + "|2FA_BACKUP_CODES_REGENERATED|PASSKEY_REGISTERED|PASSKEY_DELETED|ADMIN_PASSWORD_CHANGED"
        + "|HOSTNAME_CHANGED|ROUNDCUBE_DOMAIN_CHANGED|ROUNDCUBE_SSL_UPDATED";

    /**
     * The filter.
     *
     * <p>The {@code failregex} must handle <strong>two</strong> forms of the same line, because
     * fail2ban, when the {@code datepattern} matches, removes the date from the line before
     * searching in it, and when it does not match it leaves it. Before it was {@code ^\S+ \[},
     * i.e. written for the form with the date only: with the date removed a space remains in
     * front of the bracket, and {@code \S+} cannot consume it. Measured with
     * {@code fail2ban-regex}: it worked by chance, because the time had decimals and those
     * decimals acted as {@code \S+}; of the 42 test lines the two with a whole second were the
     * only ones fail2ban missed. A filter that finds nothing looks the same as a system without
     * attacks, so nobody would have noticed.
     *
     * <p>The {@code %%z} at the end of the {@code datepattern} takes the Z of the UTC time. The
     * two pieces go together with the line format ({@code SSLMailServer.auditLine}): changing
     * only one of them breaks nothing visibly, it simply stops blocking anyone.
     */
    public static String filterContent() {
        return MARKER + "\n"
        + "#\n"
        + "# The panel writes lines like these to " + LOG_FILE + ":\n"
        + "#   2026-10-17T21:20:28Z [LOGIN_FAILURE] ip=1.2.3.4 user=admin details=\"...\"\n"
        + "#\n"
        + "# Test:  fail2ban-regex " + LOG_FILE + " " + FILTER_FILE + "\n"
        + "\n"
        + "[Definition]\n"
        + "\n"
        + "failregex = ^\\s*(?:\\S+\\s+)?\\[(?:" + FAILURES + ")\\] ip=<HOST>\n"
        + "\n"
        + "ignoreregex = ^\\s*(?:\\S+\\s+)?\\[(?:" + SUCCESSES + ")\\]\n"
        + "\n"
        + "datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S%%z\n";
    }

    private static final String JAIL_BLOCK = ""
        + "# " + org.daemoxcp.mail.system.PanelMarker.WRITTEN + ": the values can be changed freely, the panel does not\n"
        + "# rewrite this section once it is there.\n"
        + "[" + AUTH_JAIL + "]\n"
        + "enabled  = true\n"
        + "filter   = " + AUTH_JAIL + "\n"
        + "logpath  = " + LOG_FILE + "\n"
        + "maxretry = 5\n"
        + "findtime = 600\n"
        + "bantime  = 3600\n"
        + "backend  = auto\n"
        + "action   = pf[name=" + AUTH_JAIL + ", port=\"0:65535\"]\n";
}
