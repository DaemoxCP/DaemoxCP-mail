package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.RootOnlyPath;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Il bit sticky su /var/mail (reperto 221).
 *
 * <p>/var/mail e' root:mail 0775 come la fa FreeBSD (mtree), e dentro c'e' /var/mail/sieve, la cartella delle regole
 * Sieve del pannello, di root. Chi ha il gruppo mail poteva rinominarla intera e metterne un'altra al suo posto, con
 * regole sue che Dovecot esegue prima di quelle della casella (misurato sulla VM). Il gruppo mail ce l'hanno postfix e
 * clamav, dma (setgid mail, lo lancia qualunque utente) e, fino al reperto 221, i processi delle caselle di Dovecot.
 *
 * <p>Col bit sticky chi scrive in /var/mail non puo' piu' rinominare ne' togliere quello che non e' suo: la cartella di
 * root resta dov'e'. E' il modo che la documentazione di Dovecot indica per /var/mail («Set sticky bit to the
 * directory ... users can't delete each others mailboxes»). Misurato sulla VM: la rinomina col gruppo mail e' rifiutata,
 * i file di blocco propri si fanno e si tolgono ancora; Postfix (local) e dma, da root e da nobody, consegnano ancora in
 * /var/mail/root. freebsd-update tiene i permessi cambiati sul posto (KeepModifiedMetadata, predefinito yes); solo
 * mtree -U o etcupdate rimetterebbero 0775, e allora qui si rimette al primo avvio, mentre il pannello intanto non
 * scrive regole (RootOnlyPath vuole lo sticky sopra la cartella delle regole).
 *
 * <p>Si tocca solo se la cartella e' vera, di root, scritta da altri e senza sticky; poi si rilegge, e se non e' come
 * deve essere si rimette com'era. Al secondo avvio non trova niente da fare.
 */
public final class MailSpoolSticky {

    private static final Logger LOGGER = Logger.getLogger(MailSpoolSticky.class.getName());

    static final Path SPOOL = Path.of("/var/mail");
    static final Path PANEL_RULES = Path.of("/var/mail/sieve");
    static final int STICKY = 01000;

    private MailSpoolSticky() {}

    /**
     * I permessi con lo sticky, o -1 se non c'e' niente da fare: nessun altro scrive, o c'e' gia'. Solo i bit dei
     * permessi (07777). Pura.
     */
    static int next(int mode) {
        int perms = mode & 07777;
        if ((perms & 022) == 0 || (perms & STICKY) != 0) return -1;
        return perms | STICKY;
    }

    /** All'avvio della parte root. */
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

    /** Null se non c'era niente da fare; altrimenti cosa e' successo (DONE, ROLLED_BACK, o perche' resta com'e'). */
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

    /** Se la cartella delle regole c'e' ma root non ci scriverebbe, il motivo: va detto, non corretto a caso. */
    static String rulesNote(Path rules) {
        if (!Files.exists(rules, LinkOption.NOFOLLOW_LINKS)) return null;
        String why = RootOnlyPath.problem(rules);
        return why == null ? null : "WARNING: the panel will not write Sieve rules in " + rules + " (" + why + ")";
    }
}
