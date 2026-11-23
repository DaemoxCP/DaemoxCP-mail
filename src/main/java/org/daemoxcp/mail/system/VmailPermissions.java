package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * Mail in /var/vmail readable only by vmail, inside too.
 *
 * Measured on 2026-11-07 on the production server: /var/vmail is 0770 vmail:vmail and the vmail group has
 * no members, so other users cannot get in. Inside, however, 17 folders were 0755 and 349 files
 * world-readable: the domain folders were created by root (umask 022), and Dovecot creates new things
 * with the permissions of the mailbox root folder. The Dovecot 2.3 manual
 * (admin_manual/filesystem_permission): "Dovecot copies the permissions from the mailbox root
 * directory", and "Dovecot never modifies permissions for existing mail files or directories". With a
 * single user (mail_uid = vmail) and delivery going through Dovecot (LMTP), 0700 for folders and
 * 0600 for files is right: it is a second defence, should /var/vmail ever be opened up.
 *
 * Group and other permissions are removed only from what belongs to vmail; what is not its own is not
 * touched (Dovecot might read it precisely thanks to those permissions) and is counted in the log. Afterwards,
 * vmail must still be able to enter every mailbox.
 */
public final class VmailPermissions {

    private static final Logger LOGGER = Logger.getLogger(VmailPermissions.class.getName());

    static Path root = Path.of("/var/vmail");

    /** The shell snippet that does the same, for the scripts that create the mailbox folders. */
    public static final String SHELL =
            "find /var/vmail -mindepth 1 -user vmail -perm +077 -exec chmod go-rwx {} + 2>/dev/null || true\n";

    private VmailPermissions() {}

    static int count(String findArgs) {
        Shell.Result r = Shell.runShell(Duration.ofSeconds(300), "find " + root + " -mindepth 1 " + findArgs + " 2>/dev/null | wc -l");
        try { return Integer.parseInt(r.outputTrim().trim()); } catch (NumberFormatException e) { return -1; }
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isDirectory(root) || Shell.run(Duration.ofSeconds(10), "id", "-u", "vmail").exitCode() != 0) return;
            int open = count("-user vmail -perm +077");
            if (open <= 0) return;
            int dirs = count("-user vmail -type d -perm +077");
            Shell.Result r = Shell.runShell(Duration.ofSeconds(600),
                    "find " + root + " -mindepth 1 -user vmail -perm +077 -exec chmod go-rwx {} +");
            int left = count("-user vmail -perm +077");
            int foreign = count("! -user vmail");
            String unreadable = unreadableByVmail();
            if (left != 0 || unreadable != null) {
                LOGGER.warning("[VmailPermissions] NOT_APPLIED: chmod exit " + r.exitCode() + ", still open: " + left
                        + (unreadable != null ? ", " + unreadable : ""));
                return;
            }
            LOGGER.info("[VmailPermissions] DONE: " + open + " entries under " + root + " (" + dirs + " folders) readable"
                    + " only by vmail now" + (foreign > 0 ? "; " + foreign + " entries not owned by vmail left as they are" : ""));
        } catch (Throwable t) {
            LOGGER.warning("[VmailPermissions] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /** Can vmail still enter every domain and every mailbox? null if so, otherwise the first one that fails. */
    static String unreadableByVmail() {
        Shell.Result r = Shell.runShell(Duration.ofSeconds(120),
                "find " + root + " -mindepth 1 -maxdepth 2 -type d -print0 | xargs -0 -n 50 su -m vmail -c 'for d; do [ -r \"$d\" ] && [ -x \"$d\" ] || echo \"$d\"; done' sh");
        String out = r.outputTrim();
        return out.isEmpty() ? null : "vmail cannot enter " + out.split("\n")[0];
    }
}
