package org.daemoxcp.mail.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

/**
 * Giving a user a folder and everything it contains, as root, without also giving them other people's files.
 *
 * A symbolic link was already known about (it is not followed). But a hard link too: on FreeBSD anyone
 * can make a hard link to another user's file on the same file system (security.bsd.hardlink_check_uid is 0
 * by default), and the link IS that file. /var/vmail is on the same file system as /etc (in the boot
 * environment, on the production server as on the VM): vmail made a hard link to a root file inside /var/vmail, and the
 * "chown -R vmail:vmail /var/vmail" that root runs at every regeneration of the mail folders gave it that
 * file. With /etc/master.passwd, root. Measured on the VM on 2026-11-17 with a test file (finding 252).
 *
 * So the owner is changed only on folders and on regular files with a single name; a file with several names does not
 * belong only to that folder and stays as it is, reported in the log. Folders cannot have hard links.
 */
public final class SafeOwnership {

    private SafeOwnership() {}

    /**
     * True if root can change the owner and permissions of p without touching anything else: a folder, or a file with a
     * single name.
     */
    public static boolean safeToChange(Path p) throws IOException {
        BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (a.isSymbolicLink()) return false;
        if (a.isDirectory()) return true;
        if (!a.isRegularFile()) return false;
        Object n = Files.getAttribute(p, "unix:nlink", LinkOption.NOFOLLOW_LINKS);
        return n instanceof Integer i && i == 1;
    }

    /**
     * The script fragment that gives dir and its content to owner:group: only folders and files with a single name, on the
     * same file system, never through a link (find does not follow them). Files with several names that are not its own are
     * counted and reported. dir, owner and group are panel names, never values that came from outside.
     */
    public static String shell(String dir, String owner, String group) {
        check(dir, owner, group);
        String target = owner + ":" + group;
        return "find '" + dir + "' -xdev \\( -type d -o \\( -type f -links 1 \\) \\) ! \\( -user " + owner + " -group "
                + group + " \\) -exec chown " + target + " {} + 2>/dev/null\n"
             + "SAFE_OWNERSHIP_LEFT=$(find '" + dir + "' -xdev ! -type d ! -type l -links +1 ! -user " + owner
                + " 2>/dev/null | wc -l | tr -d ' ')\n"
             + "[ \"$SAFE_OWNERSHIP_LEFT\" = 0 ] || echo \"WARNING: $SAFE_OWNERSHIP_LEFT file(s) in " + dir
                + " with more than one name were not given to " + owner + ": look at them (find " + dir
                + " -links +1 ! -user " + owner + ")\"\n";
    }

    private static void check(String dir, String owner, String group) {
        if (!dir.matches("/[A-Za-z0-9._/-]+") || dir.contains(".."))
            throw new IllegalArgumentException("not a panel folder: " + dir);
        if (!owner.matches("[a-z_][a-z0-9_-]*") || !group.matches("[a-z_][a-z0-9_-]*"))
            throw new IllegalArgumentException("not a user or group name: " + owner + ":" + group);
    }
}
