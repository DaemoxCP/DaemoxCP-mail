package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.RootOnlyPath;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Map;
import java.util.logging.Logger;

/**
 * The sticky bit on /var/mail (finding 221).
 *
 * <p>/var/mail is root:mail 0775 as FreeBSD makes it (mtree), and inside it is /var/mail/sieve, the folder of the
 * panel's Sieve rules, owned by root. Whoever has the mail group could rename it whole and put another one in its
 * place, with their own rules that Dovecot runs before the mailbox's ones (measured on the VM). The mail group is
 * held by postfix and clamav, dma (setgid mail, run by any user) and, until finding 221, Dovecot's mailbox
 * processes.
 *
 * <p>With the sticky bit, whoever writes in /var/mail can no longer rename or remove what is not theirs: root's
 * folder stays where it is. It is the way the Dovecot documentation indicates for /var/mail ("Set sticky bit to the
 * directory ... users can't delete each others mailboxes"). Measured on the VM: renaming with the mail group is
 * refused, one's own lock files are still created and removed; Postfix (local) and dma, as root and as nobody,
 * still deliver into /var/mail/root. freebsd-update keeps permissions changed in place (KeepModifiedMetadata,
 * default yes); only mtree -U or etcupdate would put back 0775, and then it is set again here at the first startup,
 * while in the meantime the panel does not write rules (RootOnlyPath wants the sticky bit above the rules folder).
 *
 * <p>It is touched only if the folder is real, owned by root, writable by others and without sticky; then it is
 * read again, and if it is not as it should be it is put back as it was. At the second startup it finds nothing to
 * do.
 */
public final class MailSpoolSticky {

    private static final Logger LOGGER = Logger.getLogger(MailSpoolSticky.class.getName());

    static final Path SPOOL = Path.of("/var/mail");
    static final Path PANEL_RULES = Path.of("/var/mail/sieve");
    static final int STICKY = 01000;

    private MailSpoolSticky() {}

    /**
     * The permissions with sticky, or -1 if there is nothing to do: nobody else writes, or it is already there. Only
     * the permission bits (07777). Pure.
     */
    static int next(int mode) {
        int perms = mode & 07777;
        if ((perms & 022) == 0 || (perms & STICKY) != 0) return -1;
        return perms | STICKY;
    }

    /** At the start of the root part. */
    public static void ensureAtBoot() {
        try {
            String r = ensure(SPOOL, PANEL_RULES);
            if (r == null) return;
            if (r.startsWith("DONE") && !r.contains("WARNING")) LOGGER.info("[MailSpoolSticky] " + r);
            else LOGGER.warning("[MailSpoolSticky] " + r);
        } catch (Throwable t) {
            LOGGER.warning("[MailSpoolSticky] failed: " + t);
        }
    }

    /** Null if there was nothing to do; otherwise what happened (DONE, ROLLED_BACK, or why it stays as it is). */
    static synchronized String ensure(Path spool, Path rules) throws IOException {
        if (!Files.exists(spool, LinkOption.NOFOLLOW_LINKS)) return null;
        Map<String, Object> a = Files.readAttributes(spool, "unix:mode,uid", LinkOption.NOFOLLOW_LINKS);
        int mode = (Integer) a.get("mode");
        if ((mode & 0170000) != 0040000) return "left as it is: " + spool + " is not a real folder";
        if ((Integer) a.get("uid") != 0) return "left as it is: " + spool + " does not belong to root";
        int want = next(mode);
        String rulesNote = rulesNote(rules);
        if (want < 0) return rulesNote;
        Files.setAttribute(spool, "unix:mode", want, LinkOption.NOFOLLOW_LINKS);
        int now = (Integer) Files.getAttribute(spool, "unix:mode", LinkOption.NOFOLLOW_LINKS) & 07777;
        if (now != want) {
            Files.setAttribute(spool, "unix:mode", mode & 07777, LinkOption.NOFOLLOW_LINKS);
            return "ROLLED_BACK: " + spool + " read back as " + String.format("%04o", now) + " instead of "
                    + String.format("%04o", want) + "; put back to " + String.format("%04o", mode & 07777);
        }
        String done = "DONE: " + spool + " " + String.format("%04o", mode & 07777) + " -> " + String.format("%04o", want)
                + " (sticky): who has group mail can no longer rename or remove what is not theirs, such as the panel's"
                + " Sieve rules";
        rulesNote = rulesNote(rules);
        return rulesNote == null ? done : done + "; " + rulesNote;
    }

    /**
     * If the rules folder exists but root would not write in it, the reason: it must be reported, not corrected at
     * random.
     */
    static String rulesNote(Path rules) {
        if (!Files.exists(rules, LinkOption.NOFOLLOW_LINKS)) return null;
        String why = RootOnlyPath.problem(rules);
        return why == null ? null : "WARNING: the panel will not write Sieve rules in " + rules + " (" + why + ")";
    }
}
