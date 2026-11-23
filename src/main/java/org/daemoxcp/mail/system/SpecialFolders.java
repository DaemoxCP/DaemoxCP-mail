package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * The special folders of every mailbox (Drafts, Sent, Trash, Junk) and spam into Junk.
 *
 * Measured on the VM on 2026-11-20, after a clean install from the README:
 * <ul>
 *   <li>mail that Rspamd marks (action "add header", score between 6 and 15) arrived in the INBOX with only the line
 *       "X-Spam: Yes": no rule moved it into Junk;</li>
 *   <li>worse, the panel's rules ran on it too: with the auto-reply on, a message with "X-Spam: Yes" delivered via
 *       LMTP got its reply ("vacation action: sent vacation response"), that is a letter to a sender that in spam is
 *       almost always forged (backscatter: it ruins the server's reputation). The Pigeonhole documentation on the
 *       auto-reply lists the messages it does not reply to (lists, Auto-Submitted, Precedence bulk/junk/list, empty
 *       or system sender): no spam header. The same for forwarding: spam went out to the forwarding address, in the
 *       name of this server;</li>
 *   <li>Dovecot did not tell mail programs which folders are the special ones (IMAP SPECIAL-USE, RFC 6154): no
 *       namespace block, hence no \Drafts, \Sent, \Trash, \Junk. Every program creates them with its own name (Apple
 *       "Sent Messages" and "Deleted Messages", Outlook "Sent Items"), and sent mail ends up split. On the
 *       production server, counted on 2026-11-20: 8 mailboxes out of 12 with Drafts, Sent, Trash and Junk (the
 *       webmail creates them at the first login, create_default_folders = true), one "Sent Messages" and two
 *       "Deleted Messages".</li>
 * </ul>
 *
 * The remedy, from the Dovecot and Pigeonhole documentation (2.3 and 2.4):
 * <ul>
 *   <li>the INBOX namespace with the four folders and their special_use, with auto = subscribe: Dovecot creates and
 *       subscribes them for every mailbox, with the same names that the webmail already creates; so a program that
 *       looks for them finds them instead of inventing others. The separator stays the previous one (the Maildir
 *       dot, measured: LIST answers "." before and after) and no folder changes name;</li>
 *   <li>a fixed Sieve script, owned by root, that runs first, before the panel's rules and those of the mailbox:
 *       "X-Spam: Yes" (the header that the Rspamd proxy adds with the add header action, the default spam_header)
 *       goes into Junk and the sequence stops. In the Pigeonhole documentation the next script runs only if a keep
 *       is in effect: after fileinto and stop there is none, so no auto-reply, no forwarding and no mailbox rules on
 *       spam. In 2.4 the order is given by precedence (lower first; the others have the default one, infinite); in
 *       2.3 by sieve_before and sieve_before2, and the panel's rules move to the second.</li>
 * </ul>
 *
 * Whoever sends mail can write "X-Spam: Yes" themselves: all they get is that their message goes into Junk. Rspamd
 * does not write "X-Spam: No", so there is nothing to forge in the other direction.
 *
 * The installer writes the same two files (DovecotConfig); on servers installed earlier this boot repair writes
 * them. The script is compiled by sievec as the sievec user (SieveCompiler), never as root, on every start if
 * Pigeonhole has changed. Before touching the configuration it checks that authentication works and that nobody
 * else has written a namespace of their own; afterwards, that Dovecot runs, that authentication still passes and
 * that a mailbox sees Junk as \Junk. If something does not add up it removes the file and reloads: Dovecot goes back
 * to how it was. On the second start it does nothing.
 */
public final class SpecialFolders {

    private static final Logger LOGGER = Logger.getLogger(SpecialFolders.class.getName());

    public static final String FILE_NAME = "15-special-folders.conf";
    /** The script, relative to the Dovecot folder: the same for the installer and for the repair. */
    public static final String SCRIPT_IN_ETC = "sieve/spam-to-junk.sieve";
    public static final Path SCRIPT = Path.of("/usr/local/etc/dovecot").resolve(SCRIPT_IN_ETC);
    /** The panel's rules on 2.3: the same as DovecotConfig.SIEVE23, which here move to sieve_before2. */
    static final String PANEL_RULES_23 = "/var/mail/sieve/%d/%n/.dovecot.sieve";
    /** The spam header: the one that the Rspamd proxy writes with the add header action (spam_header). */
    public static final String SPAM_HEADER = "X-Spam";
    public static final String JUNK = "Junk";
    /** The name of the sieve_script block in 2.4. */
    static final String SCRIPT_BLOCK = "spam_to_junk";

    /** The folders and their special use (RFC 6154), with the names that the webmail already uses. */
    static final String[][] FOLDERS = {{"Drafts", "\\Drafts"}, {"Sent", "\\Sent"}, {"Trash", "\\Trash"}, {JUNK, "\\Junk"}};

    private SpecialFolders() {}

    /** The Sieve script: the same for the installer and for the repair. */
    public static String scriptContent() {
        return "# " + PanelMarker.WRITTEN + ".\n"
             + "# Spam that Rspamd marks (" + SPAM_HEADER + ": Yes) into " + JUNK + ", before any other rule: no\n"
             + "# automatic reply, forward or mailbox rules on spam.\n"
             + "require [\"fileinto\", \"mailbox\"];\n"
             + "\n"
             + "if header :is \"" + SPAM_HEADER + "\" \"Yes\" {\n"
             + "  fileinto :create \"" + JUNK + "\";\n"
             + "  stop;\n"
             + "}\n";
    }

    /** The conf.d file: the same for the installer (DovecotConfig) and for the repair. */
    public static String fileContent(boolean dovecot24) {
        StringBuilder s = new StringBuilder();
        s.append("# ").append(PanelMarker.WRITTEN).append(".\n")
         .append("# The special folders (IMAP SPECIAL-USE, RFC 6154): mail programs find them here instead of\n")
         .append("# creating their own. Dovecot creates and subscribes them for every mailbox, with the webmail's names.\n")
         .append("namespace inbox {\n")
         .append("  inbox = yes\n");
        for (String[] f : FOLDERS) {
            s.append("  mailbox ").append(f[0]).append(" {\n")
             .append("    special_use = ").append(f[1]).append("\n")
             .append("    auto = subscribe\n")
             .append("  }\n");
        }
        s.append("}\n\n")
         .append("# Spam (").append(SPAM_HEADER).append(": Yes, from Rspamd) into ").append(JUNK)
         .append(" before the panel's and the mailbox's rules.\n");
        if (dovecot24) {
            s.append("sieve_script ").append(SCRIPT_BLOCK).append(" {\n")
             .append("  type = before\n")
             .append("  driver = file\n")
             .append("  path = ").append(SCRIPT).append("\n")
             .append("  # Lowest first: the others have the default one (infinite).\n")
             .append("  precedence = 1\n")
             .append("}\n");
        } else {
            s.append("plugin {\n")
             .append("  sieve_before = ").append(SCRIPT).append("\n")
             .append("  # The panel's rules after: this line replaces their sieve_before of 10-master.conf.\n")
             .append("  sieve_before2 = ").append(PANEL_RULES_23).append("\n")
             .append("}\n");
        }
        return s.toString();
    }

    /** In `doveconf -n` there is already a namespace written by others (our file is not there). Pure. */
    static boolean otherNamespace(String doveconf, boolean ourFileThere) {
        return !ourFileThere && doveconf != null && doveconf.matches("(?s)(.*\\n)?namespace [^\\n]*\\{.*");
    }

    /** The panel's rules are already configured: Pigeonhole is there and the panel has set it up. Pure. */
    static boolean panelSieve(String doveconf, boolean dovecot24) {
        if (doveconf == null) return false;
        return dovecot24 ? doveconf.contains("sieve_script panel {") : doveconf.contains("sieve_before");
    }

    /** The LIST answer with RETURN (SPECIAL-USE) marks Junk as \Junk. Pure. */
    static boolean junkMarked(String imap) {
        return imap != null && imap.matches("(?s).*\\* LIST \\([^)]*\\\\Junk[^)]*\\) \"[^\"]*\" \"?" + JUNK + "\"?\\r?\\n.*");
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(DovecotAuthWorker.DOVECONF)) || !Files.isExecutable(Path.of(ManageSieveLocal.DOVECOT))) return;
            Shell.Result version = Shell.run(Duration.ofSeconds(15), ManageSieveLocal.DOVECOT, "--version");
            if (!version.success()) return;
            boolean v24 = ManageSieveLocal.is24(version.outputTrim());
            Shell.Result conf = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n");
            if (!conf.success() || !panelSieve(conf.output(), v24)) return;

            boolean scriptChanged = writeScript();
            if (scriptChanged || !Files.exists(SieveCompiler.binaryFor(SCRIPT))) {
                SieveCompiler.Outcome o = SieveCompiler.compile(SCRIPT);
                if (o.status() != SieveCompiler.Status.COMPILED)
                    LOGGER.warning("[SpecialFolders] " + SCRIPT + " not precompiled (" + o.status() + ": " + o.message()
                            + "): Dovecot compiles it at each delivery");
            } else {
                // Pigeonhole updated: the compiled script is redone if sievec now produces a different one.
                SieveCompiler.Outcome o = SieveCompiler.refresh(SCRIPT);
                if (o.status() == SieveCompiler.Status.COMPILED)
                    LOGGER.info("[SpecialFolders] DONE: " + SCRIPT + " compiled again for the Sieve now installed");
            }

            Path file = Path.of(DovecotAuthWorker.CONF_D, FILE_NAME);
            String wanted = fileContent(v24);
            boolean there = Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS);
            if (there && wanted.equals(Files.readString(file, StandardCharsets.UTF_8))) return;
            if (otherNamespace(conf.output(), there)) {
                LOGGER.warning("[SpecialFolders] Dovecot already has a namespace written by someone else: special folders and"
                        + " spam to " + JUNK + " not configured, nothing changed");
                return;
            }
            apply(file, wanted, v24);
        } catch (Throwable t) {
            LOGGER.warning("[SpecialFolders] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /** The script in its place, owned by root and readable (Dovecot reads it as vmail): true if it was written now. */
    static boolean writeScript() throws Exception {
        String wanted = scriptContent();
        if (Files.isRegularFile(SCRIPT, LinkOption.NOFOLLOW_LINKS)
                && wanted.equals(Files.readString(SCRIPT, StandardCharsets.UTF_8))) return false;
        Path dir = SCRIPT.getParent();
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectory(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-xr-x")));
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxr-xr-x"));
        }
        write(SCRIPT, wanted);
        return true;
    }

    static boolean apply(Path file, String content, boolean v24) throws Exception {
        if (!DovecotAuthWorker.running()) {
            LOGGER.info("[SpecialFolders] Dovecot is not running: folders left as they are, retrying at the next start");
            return false;
        }
        int before = DovecotAuthWorker.lookup();
        if (!DovecotAuthWorker.LOOKUP_OK.contains(before)) {
            LOGGER.warning("[SpecialFolders] authentication already fails before any change (doveadm auth lookup exit "
                    + before + "): folders left as they are");
            return false;
        }
        Path saved = Files.exists(file) ? Files.createTempFile(file.getParent().getParent(), ".special-folders-", ".saved") : null;
        if (saved != null) Files.copy(file, saved, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        try {
            write(file, content);
            Shell.Result check = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n");
            if (!check.success()) {
                putBack(file, saved, false);
                LOGGER.warning("[SpecialFolders] ROLLED_BACK: doveconf refuses the settings (" + firstLine(check.outputTrim())
                        + "): nothing changed");
                return false;
            }
            reload();
            String problem = verify(v24);
            if (problem != null) {
                putBack(file, saved, true);
                LOGGER.warning("[SpecialFolders] ROLLED_BACK: " + problem + "; everything put back");
                return false;
            }
            LOGGER.info("[SpecialFolders] DONE: every mailbox has Drafts, Sent, Trash and " + JUNK + " marked for the mail"
                    + " programs, and mail that Rspamd marks as spam goes to " + JUNK + " before any other rule (" + file + ")");
            return true;
        } finally {
            if (saved != null) Files.deleteIfExists(saved);
        }
    }

    /** After the reload: Dovecot runs, authentication passes, the configuration has the script, a mailbox sees \Junk. */
    static String verify(boolean v24) throws InterruptedException {
        String last = "Dovecot did not come back";
        for (int i = 0; i < 20; i++) {
            Thread.sleep(500);
            if (!DovecotAuthWorker.running()) { last = "Dovecot is not running after the reload"; continue; }
            int rc = DovecotAuthWorker.lookup();
            if (!DovecotAuthWorker.LOOKUP_OK.contains(rc)) { last = "doveadm auth lookup fails (exit " + rc + ")"; continue; }
            String conf = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n").output();
            if (!(v24 ? conf.contains("sieve_script " + SCRIPT_BLOCK + " {") : conf.contains("sieve_before = " + SCRIPT))) {
                last = "the spam script is not in the configuration Dovecot reads"; continue;
            }
            String user = firstUser();
            if (user != null) {
                String imap = list(user);
                if (!junkMarked(imap)) { last = "IMAP does not show " + JUNK + " as \\Junk"; continue; }
            }
            return null;
        }
        return last;
    }

    /** Any mailbox, for the LIST test; null if there is none yet. */
    static String firstUser() {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), "doveadm", "user", "*");
        if (!r.success()) return null;
        for (String line : r.output().split("\n")) {
            String u = line.trim();
            if (u.matches("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")) return u;
        }
        return null;
    }

    /** LIST of Junk with RETURN (SPECIAL-USE), from an IMAP launched for the mailbox (doveadm exec, as root). */
    static String list(String user) {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), "sh", "-c",
                "printf 'a LIST \"\" \"" + JUNK + "\" RETURN (SPECIAL-USE)\\r\\nb LOGOUT\\r\\n' | timeout -f 20 doveadm exec imap -u \"$1\" 2>/dev/null",
                "sh", user);
        return r.output();
    }

    static void reload() throws InterruptedException {
        Shell.run(Duration.ofSeconds(60), "service", "dovecot", "reload");
        Thread.sleep(1000);
    }

    private static void write(Path file, String content) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(Path file, Path saved, boolean reload) throws Exception {
        if (saved != null) Files.copy(saved, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        else Files.deleteIfExists(file);
        if (reload) reload();
    }

    private static String firstLine(String s) {
        if (s == null) return "";
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
