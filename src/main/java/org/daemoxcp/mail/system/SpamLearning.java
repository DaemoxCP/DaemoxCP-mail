package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.List;
import java.util.logging.Logger;

/**
 * Rspamd learns from the users: a message moved (or copied) into Junk is spam, one taken out of Junk is good mail,
 * except when it goes to the Trash.
 *
 * Before, Rspamd learned only from whoever ran rspamc by hand: the Bayesian filter (Redis, at least 200 messages per
 * side before it has its say) stayed empty. Now, with the IMAPSieve of Pigeonhole (Dovecot 2.4: the imap_sieve
 * plugin, the mailbox and imapsieve_from blocks of its documentation), when a mail program or the "Spam" button of
 * the webmail (markasjunk) moves a message, Dovecot passes it with vnd.dovecot.pipe to a program of the panel, which
 * deposits it in /var/spool/daemoxcp-learn/spam or /ham. The program runs as vmail, like IMAP; it knows no password.
 * Rspamd learns only from the controller with the "enable" password (learnspam and learnham are privileged
 * commands), which stays in root's secrets: the handover to Rspamd is done by the root part of the panel
 * (SpamLearner), every minute, and it deletes the message as soon as Rspamd answers. Giving that password to vmail
 * would also have given it all the rest of the controller (weights, maps, statistics).
 *
 * Measured on the VM on 2026-11-20 (Dovecot 2.4.5, Rspamd 4.1): MOVE and COPY into Junk start the script
 * (cause = copy also covers MOVE); Junk -> INBOX gives ham; Junk -> Trash nothing; the rule for spam at delivery
 * (SpecialFolders) does not act on moves, and a message marked X-Spam taken out of Junk stays where the user put it;
 * no Sieve error in the log. Rspamd answers 204 when it learns, 401 without a password, 400 to an empty body. sievec
 * does not know vnd.dovecot.pipe and imapsieve without -P sieve_imapsieve -P sieve_extprograms -x: with those
 * options the script compiled by the sievec user is identical to the one compiled by root.
 *
 * Only Dovecot 2.4 (on 2.3 the configuration is a different one: the panel says so and touches nothing), and only
 * where the panel's Junk exists (SpecialFolders). Before touching anything it checks that Dovecot runs and that
 * authentication works; after the reload, that Dovecot runs, that authentication works, that the plugin is active for
 * IMAP, that IMAP opens for a mailbox and that the program, as vmail, can write into the folder. If something does
 * not add up it removes the configuration file and reloads: Dovecot goes back to how it was (the scripts and the
 * program do nothing on their own). A configuration file with the same name written by hand stays as it is. On the
 * second start it does nothing.
 */
public final class SpamLearning {

    private static final Logger LOGGER = Logger.getLogger(SpamLearning.class.getName());

    static final Path ETC = Path.of("/usr/local/etc/dovecot");
    public static final String CONF_NAME = "16-learn-from-users.conf";
    public static final String SPAM_SCRIPT_IN_ETC = "sieve/learn-spam.sieve";
    public static final String HAM_SCRIPT_IN_ETC = "sieve/learn-ham.sieve";
    public static final String PIPE_DIR = "/usr/local/libexec/daemoxcp-mail/sieve-pipe";
    public static final String PROGRAM = "daemoxcp-learn";
    public static final String SPOOL = "/var/spool/daemoxcp-learn";
    public static final List<String> KINDS = List.of("spam", "ham");
    static final String VMAIL = "vmail";
    /** Past this size no message is deposited: Rspamd does not learn from huge attachments, nor does the folder swell. */
    public static final long MAX_BYTES = 10L << 20;
    /** Without these options sievec does not know the extensions used by the scripts (measured). */
    static final List<String> SIEVEC_OPTIONS = List.of("-P", "sieve_imapsieve", "-P", "sieve_extprograms", "-x", "+vnd.dovecot.pipe +imapsieve");

    private SpamLearning() {}

    /** The Dovecot 2.4 configuration. Pure. */
    public static String confContent() {
        return "# " + PanelMarker.WRITTEN + ".\n"
             + "# Rspamd learns from the users (SpamLearning): a message moved or copied into " + SpecialFolders.JUNK + " is spam,\n"
             + "# one moved out of it (not into " + TRASH + ") is ham. The scripts hand it to " + PROGRAM + ", which leaves it in\n"
             + "# " + SPOOL + "; the panel's root part gives it to Rspamd and deletes it.\n"
             + "protocol imap {\n"
             + "  mail_plugins {\n"
             + "    imap_sieve = yes\n"
             + "  }\n"
             + "}\n"
             + "sieve_plugins {\n"
             + "  sieve_imapsieve = yes\n"
             + "  sieve_extprograms = yes\n"
             + "}\n"
             + "sieve_global_extensions {\n"
             + "  vnd.dovecot.pipe = yes\n"
             + "}\n"
             + "sieve_pipe_bin_dir = " + PIPE_DIR + "\n"
             + "mailbox " + SpecialFolders.JUNK + " {\n"
             + "  sieve_script learn_spam {\n"
             + "    type = before\n"
             + "    cause = copy\n"
             + "    path = " + ETC + "/" + SPAM_SCRIPT_IN_ETC + "\n"
             + "  }\n"
             + "}\n"
             + "imapsieve_from " + SpecialFolders.JUNK + " {\n"
             + "  sieve_script learn_ham {\n"
             + "    type = before\n"
             + "    cause = copy\n"
             + "    path = " + ETC + "/" + HAM_SCRIPT_IN_ETC + "\n"
             + "  }\n"
             + "}\n";
    }

    static final String TRASH = "Trash";

    public static String spamScript() {
        return "# " + PanelMarker.WRITTEN + " (SpamLearning): moved or copied into " + SpecialFolders.JUNK + ", Rspamd learns it as spam.\n"
             + "require [\"vnd.dovecot.pipe\", \"copy\", \"imapsieve\"];\n"
             + "pipe :copy \"" + PROGRAM + "\" [\"spam\"];\n";
    }

    public static String hamScript() {
        return "# " + PanelMarker.WRITTEN + " (SpamLearning): moved out of " + SpecialFolders.JUNK + ", Rspamd learns it as ham;\n"
             + "# not when it goes to " + TRASH + ".\n"
             + "require [\"vnd.dovecot.pipe\", \"copy\", \"imapsieve\", \"environment\", \"variables\"];\n"
             + "if environment :matches \"imap.mailbox\" \"*\" { set \"mailbox\" \"${1}\"; }\n"
             + "if string \"${mailbox}\" \"" + TRASH + "\" { stop; }\n"
             + "pipe :copy \"" + PROGRAM + "\" [\"ham\"];\n";
    }

    /**
     * The program: it reads the whole message (Pigeonhole wants that), keeps at most MAX_BYTES of it, writes it with a
     * name that starts with a dot and then renames it, so the root part sees only complete messages. With "check" it
     * only tries to write (the check after the reload). It always exits 0: an error here must not stop the move. Pure.
     */
    public static String programContent() {
        return "#!/bin/sh\n"
             + "# " + PanelMarker.WRITTEN + " (SpamLearning): Dovecot pipes here a message moved into or out of "
             + SpecialFolders.JUNK + ".\n"
             + "# It runs as " + VMAIL + " and only leaves the message in " + SPOOL + "/<kind>; the panel gives it to Rspamd.\n"
             + "umask 077\n"
             + "PATH=/bin:/usr/bin; export PATH\n"
             + "case \"$1\" in\n"
             + "  spam|ham) ;;\n"
             + "  check) t=$(mktemp \"" + SPOOL + "/spam/.check.XXXXXXXX\") && rm -f \"$t\" && echo ok; exit 0 ;;\n"
             + "  *) cat > /dev/null; exit 0 ;;\n"
             + "esac\n"
             + "dir=" + SPOOL + "/$1\n"
             + "tmp=$(mktemp \"$dir/.in.XXXXXXXX\") || { cat > /dev/null; exit 0; }\n"
             + "head -c " + MAX_BYTES + " > \"$tmp\"\n"
             + "cat > /dev/null\n"
             + "mv \"$tmp\" \"$dir/$(date +%s).${tmp##*.in.}\"\n"
             + "exit 0\n";
    }

    enum Action { NOTHING, APPLY, LEFT_ALONE }

    /**
     * What to do. is24: Dovecot 2.4; junk: the panel's Junk exists (the SpecialFolders file); conf: the current file
     * (null if there is none); partsCurrent: script, program and folder are already the right ones. Pure.
     */
    static Action decide(boolean is24, boolean junk, String conf, boolean partsCurrent) {
        if (!is24 || !junk) return Action.NOTHING;
        if (conf == null) return Action.APPLY;
        if (!conf.contains(PanelMarker.WRITTEN)) return Action.LEFT_ALONE;
        return conf.equals(confContent()) && partsCurrent ? Action.NOTHING : Action.APPLY;
    }

    static Path conf() { return ETC.resolve("conf.d").resolve(CONF_NAME); }
    static Path spamScriptPath() { return ETC.resolve(SPAM_SCRIPT_IN_ETC); }
    static Path hamScriptPath() { return ETC.resolve(HAM_SCRIPT_IN_ETC); }
    static Path program() { return Path.of(PIPE_DIR, PROGRAM); }
    /** The folder of the program and the one above it, which the panel creates. */
    static List<Path> pipeDirs() { return List.of(Path.of(PIPE_DIR).getParent(), Path.of(PIPE_DIR)); }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(DovecotAuthWorker.DOVECONF)) || !Files.isExecutable(Path.of(ManageSieveLocal.DOVECOT))) return;
            Shell.Result version = Shell.run(Duration.ofSeconds(15), ManageSieveLocal.DOVECOT, "--version");
            if (!version.success()) return;
            boolean is24 = ManageSieveLocal.is24(version.outputTrim());
            boolean junk = Files.isRegularFile(ETC.resolve("conf.d").resolve(SpecialFolders.FILE_NAME), LinkOption.NOFOLLOW_LINKS);
            if (!is24) {
                LOGGER.info("[SpamLearning] Rspamd learning from the users' moves needs Dovecot 2.4: not set up");
                return;
            }
            Path conf = conf();
            String current = Files.isRegularFile(conf, LinkOption.NOFOLLOW_LINKS) ? Files.readString(conf, StandardCharsets.UTF_8)
                    : Files.exists(conf, LinkOption.NOFOLLOW_LINKS) ? "" : null;
            switch (decide(true, junk, current, partsCurrent())) {
                case NOTHING -> {
                    if (current != null) refreshBinaries();
                }
                case LEFT_ALONE -> LOGGER.info("[SpamLearning] " + conf + " was not written by the panel: left as it is");
                case APPLY -> apply(conf, current);
            }
        } catch (Throwable t) {
            LOGGER.warning("[SpamLearning] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /** Script, program and collection folder as the panel wants them. */
    static boolean partsCurrent() {
        try {
            if (!same(spamScriptPath(), spamScript()) || !same(hamScriptPath(), hamScript()) || !same(program(), programContent())) return false;
            if (!Files.isExecutable(program())) return false;
            for (Path d : pipeDirs()) {
                if (!Files.isDirectory(d, LinkOption.NOFOLLOW_LINKS)) return false;
                PosixFileAttributes a = Files.readAttributes(d, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!a.owner().getName().equals("root") || !PosixFilePermissions.toString(a.permissions()).equals("rwxr-xr-x")) return false;
            }
            for (String k : KINDS) if (!spoolDirRight(Path.of(SPOOL, k))) return false;
            return spoolDirRight(Path.of(SPOOL));
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean same(Path file, String content) throws Exception {
        return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) && content.equals(Files.readString(file, StandardCharsets.UTF_8));
    }

    /** A real folder, owned by vmail, 0700. */
    static boolean spoolDirRight(Path dir) throws Exception {
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) return false;
        PosixFileAttributes a = Files.readAttributes(dir, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return a.owner().getName().equals(VMAIL) && a.group().getName().equals(VMAIL)
                && PosixFilePermissions.toString(a.permissions()).equals("rwx------");
    }

    /** If Pigeonhole has changed, the compiled scripts are redone (like SpecialFolders); otherwise nothing. */
    static void refreshBinaries() {
        for (Path s : List.of(spamScriptPath(), hamScriptPath())) {
            SieveCompiler.Outcome o = SieveCompiler.refresh(s, SIEVEC_OPTIONS);
            if (o.status() == SieveCompiler.Status.COMPILED) LOGGER.info("[SpamLearning] DONE: " + s + " compiled again for the Sieve now installed");
        }
    }

    static boolean apply(Path conf, String previous) throws Exception {
        if (!DovecotAuthWorker.running()) {
            LOGGER.info("[SpamLearning] Dovecot is not running: learning from the users not set up, retrying at the next start");
            return false;
        }
        int before = DovecotAuthWorker.lookup();
        if (!DovecotAuthWorker.LOOKUP_OK.contains(before)) {
            LOGGER.warning("[SpamLearning] authentication already fails before any change (doveadm auth lookup exit " + before
                    + "): learning from the users not set up");
            return false;
        }
        // The parts that do nothing on their own: the collection folder, the program, the compiled scripts.
        String spool = makeSpool();
        if (spool != null) {
            LOGGER.warning("[SpamLearning] " + spool + ": learning from the users not set up");
            return false;
        }
        // The two folders of the program, owned by root and 0755: Dovecot launches it as vmail. They are created with
        // the umask of the root part (0700: measured on the VM, vmail could not launch it), so the permissions are set
        // afterwards, explicitly.
        for (Path d : pipeDirs()) {
            if (Files.isSymbolicLink(d)) {
                LOGGER.warning("[SpamLearning] " + d + " is a link: learning from the users not set up");
                return false;
            }
            Files.createDirectories(d);
            Files.setPosixFilePermissions(d, PosixFilePermissions.fromString("rwxr-xr-x"));
        }
        write(program(), programContent(), "rwxr-xr-x");
        write(spamScriptPath(), spamScript(), "rw-r--r--");
        write(hamScriptPath(), hamScript(), "rw-r--r--");
        for (Path s : List.of(spamScriptPath(), hamScriptPath())) {
            SieveCompiler.Outcome o = SieveCompiler.compile(s, SIEVEC_OPTIONS);
            if (o.status() != SieveCompiler.Status.COMPILED)
                LOGGER.warning("[SpamLearning] " + s + " not precompiled (" + o.status() + ": " + o.message() + "): Dovecot compiles it at each move");
        }
        write(conf, confContent(), "rw-r--r--");
        Shell.Result check = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n");
        if (!check.success()) {
            putBack(conf, previous, false);
            LOGGER.warning("[SpamLearning] ROLLED_BACK: doveconf refuses the configuration: nothing changed");
            return false;
        }
        reload();
        String problem = verify();
        if (problem != null) {
            putBack(conf, previous, true);
            LOGGER.warning("[SpamLearning] ROLLED_BACK: " + problem + "; Dovecot put back as it was");
            return false;
        }
        LOGGER.info("[SpamLearning] DONE: Rspamd learns from the users: moved into " + SpecialFolders.JUNK + " is spam, moved out"
                + " of it is ham (" + conf + ")");
        return true;
    }

    /** /var/spool/daemoxcp-learn and its two folders: owned by vmail, 0700. null if fine, otherwise the problem. */
    static String makeSpool() throws Exception {
        for (Path d : List.of(Path.of(SPOOL), Path.of(SPOOL, "spam"), Path.of(SPOOL, "ham"))) {
            if (Files.isSymbolicLink(d)) return d + " is a link";
            if (!Files.exists(d, LinkOption.NOFOLLOW_LINKS)) Files.createDirectory(d);
            if (!Files.isDirectory(d, LinkOption.NOFOLLOW_LINKS)) return d + " is not a folder";
            Shell.Result r = Shell.run(Duration.ofSeconds(15), "/usr/sbin/chown", "-h", VMAIL + ":" + VMAIL, d.toString());
            if (!r.success()) return "cannot give " + d + " to " + VMAIL;
            Files.setPosixFilePermissions(d, PosixFilePermissions.fromString("rwx------"));
        }
        return null;
    }

    /** After the reload: Dovecot runs, authentication passes, the plugin is active for IMAP, IMAP opens, vmail writes. */
    static String verify() throws InterruptedException {
        String last = "Dovecot did not come back";
        for (int i = 0; i < 20; i++) {
            Thread.sleep(500);
            if (!DovecotAuthWorker.running()) { last = "Dovecot is not running after the reload"; continue; }
            int rc = DovecotAuthWorker.lookup();
            if (!DovecotAuthWorker.LOOKUP_OK.contains(rc)) { last = "doveadm auth lookup fails (exit " + rc + ")"; continue; }
            String imap = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-h", "-f", "protocol=imap", "mail_plugins").output();
            if (!imap.contains("imap_sieve")) { last = "the imap_sieve plugin is not on for IMAP"; continue; }
            String opened = imapOpens();
            if (opened != null) { last = opened; continue; }
            Shell.Result w = Shell.run(Duration.ofSeconds(15), "su", "-m", VMAIL, "-c", program() + " check");
            if (!w.outputTrim().equals("ok")) { last = VMAIL + " cannot write in " + SPOOL; continue; }
            return null;
        }
        return last;
    }

    /** A real IMAP session for the first mailbox (CAPABILITY and LOGOUT, nothing else): null if it opens with no errors. */
    static String imapOpens() {
        String user = null;
        for (String u : Shell.run(Duration.ofSeconds(15), "doveadm", "user", "*").output().trim().split("\\s+"))
            if (u.contains("@")) { user = u; break; }
        if (user == null) return null;
        Shell.Result r = Shell.runWithInput(Duration.ofSeconds(30), "a CAPABILITY\r\nz LOGOUT\r\n", "doveadm", "exec", "imap", "-u", user);
        String out = r.output();
        if (!out.contains("a OK") || out.contains("Error") || out.contains("Fatal")) return "IMAP does not open with the new configuration";
        return null;
    }

    static void reload() throws InterruptedException {
        Shell.run(Duration.ofSeconds(60), "service", "dovecot", "reload");
        Thread.sleep(1000);
    }

    private static void write(Path file, String content, String perms) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString(perms));
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(Path conf, String previous, boolean reload) throws Exception {
        if (previous != null && !previous.isEmpty()) write(conf, previous, "rw-r--r--");
        else Files.deleteIfExists(conf);
        if (reload) reload();
    }
}
