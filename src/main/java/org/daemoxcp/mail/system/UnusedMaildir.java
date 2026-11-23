package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * The empty Maildir/ folders that earlier versions created in every mailbox, removed.
 *
 * After "Add mailbox" the panel's script (ConfigRegeneratorScript) created
 * /var/vmail/domain/name/Maildir/{cur,new,tmp}, but Dovecot keeps the mail in the root of the mailbox (mail_location
 * maildir:/var/vmail/%d/%n): nobody used that folder. Found while installing from the README on the VM on
 * 2026-11-20; on the production server it was in 12 mailboxes out of 12, empty in all of them. Now the script
 * creates the mailbox the way Dovecot reads it; here, at boot, the old ones are removed.
 *
 * The script created them with /bin/sh, which on FreeBSD does not expand braces: inside Maildir/ there were no cur,
 * new and tmp, but one single folder literally named {cur,new,tmp}. That was the case on the production server (12
 * out of 12, seen during the upgrade of 2026-11-20, when this repair left them all in place): that name counts as
 * cur, new and tmp, under the same conditions.
 *
 * Only with rmdir, as vmail: rmdir removes a folder only if it is empty, so a Maildir/ with even a single file
 * inside (or a link) stays as it is, and the log says so. And only if Dovecot does not keep the mail precisely in a
 * folder called Maildir: then it would be its own, even if empty. On the second start it finds nothing to do (a
 * non-empty Maildir/ stays, and every start mentions it in one line of the log).
 */
public final class UnusedMaildir {

    private static final Logger LOGGER = Logger.getLogger(UnusedMaildir.class.getName());

    static Path vmail = Path.of("/var/vmail");

    /**
     * The job as vmail: for each mailbox, its Maildir/ only if inside it has at most empty cur, new and tmp (or an
     * empty {cur,new,tmp}), and with rmdir,
     * which in any case removes nothing that is not empty.
     */
    static final String SCRIPT = """
            PATH=/bin:/usr/bin; export PATH
            cd / || exit 1
            for m in "$1"/*/*; do
              [ -d "$m" ] && [ ! -L "$m" ] && [ ! -L "${m%/*}" ] || continue
              d="$m/Maildir"
              [ -d "$d" ] && [ ! -L "$d" ] || continue
              # Only if it holds at most cur, new and tmp (or the {cur,new,tmp} folder /bin/sh created without
              # expanding the braces), real and empty folders: otherwise nothing is touched.
              ok=1
              for e in $(ls -A "$d"); do case "$e" in cur|new|tmp|'{cur,new,tmp}') ;; *) ok=0 ;; esac; done
              for s in cur new tmp '{cur,new,tmp}'; do
                if [ -e "$d/$s" ] || [ -L "$d/$s" ]; then
                  { [ -d "$d/$s" ] && [ ! -L "$d/$s" ] && [ -z "$(ls -A "$d/$s")" ]; } || ok=0
                fi
              done
              if [ "$ok" = 1 ]; then
                rmdir "$d/cur" "$d/new" "$d/tmp" "$d/{cur,new,tmp}" 2>/dev/null
                if rmdir "$d" 2>/dev/null; then echo "REMOVED $d"; continue; fi
              fi
              echo "KEPT $d"
            done
            exit 0
            """;

    private UnusedMaildir() {}

    /** The Dovecot mail path ends in a Maildir folder: then that folder is its own. Pure function. */
    static boolean dovecotUsesMaildirFolder(String mailPath) {
        return mailPath != null && mailPath.contains("/Maildir");
    }

    /** The lines of the job, split by outcome. */
    record Outcome(List<String> removed, List<String> kept) {
        static Outcome of(String output) {
            List<String> removed = new ArrayList<>(), kept = new ArrayList<>();
            for (String l : output == null ? new String[0] : output.split("\n")) {
                if (l.startsWith("REMOVED ")) removed.add(l.substring(8));
                else if (l.startsWith("KEPT ")) kept.add(l.substring(5));
            }
            return new Outcome(removed, kept);
        }
    }

    /** The script on any folder, with the user that is running: for the tests. */
    static Outcome run(Path root) {
        return Outcome.of(Shell.run(Duration.ofSeconds(120), "sh", "-c", SCRIPT, "sh", root.toString()).output());
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isDirectory(vmail, LinkOption.NOFOLLOW_LINKS)) return;
            if (!Files.isExecutable(Path.of(DovecotAuthWorker.DOVECONF))) return;
            Shell.Result path = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-h", "mail_path");
            if (!path.success()) path = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-h", "mail_location");
            if (!path.success() || path.outputTrim().isEmpty() || dovecotUsesMaildirFolder(path.outputTrim())) return;
            Shell.Result r = Shell.run(Duration.ofSeconds(300), "su", "-m", "vmail", "-c", SCRIPT, "sh", vmail.toString());
            Outcome o = Outcome.of(r.output());
            if (!o.removed().isEmpty())
                LOGGER.info("[UnusedMaildir] DONE: " + o.removed().size() + " empty Maildir folder(s) Dovecot never used removed from"
                        + " the mailboxes (the mail is in the mailbox's own folder)");
            if (!o.kept().isEmpty())
                LOGGER.info("[UnusedMaildir] " + o.kept().size() + " Maildir folder(s) not empty: left as they are ("
                        + String.join(", ", o.kept().subList(0, Math.min(5, o.kept().size()))) + ")");
        } catch (Throwable t) {
            LOGGER.warning("[UnusedMaildir] ensureAtBoot exception: " + t.getMessage());
        }
    }
}
