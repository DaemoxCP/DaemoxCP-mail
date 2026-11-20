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
 * Le cartelle Maildir/ vuote che le versioni di prima creavano in ogni casella, tolte.
 *
 * Dopo «Add mailbox» lo script del pannello (ConfigRegeneratorScript) creava /var/vmail/dominio/nome/Maildir/{cur,new,
 * tmp}, ma Dovecot tiene la posta nella radice della casella (mail_location maildir:/var/vmail/%d/%n): quella cartella
 * non la usava nessuno. Trovata installando dal README sulla VM il 20/11/2026; sul server vero c'era in 12 caselle su 12,
 * vuota in tutte. Adesso lo script crea la casella come la legge Dovecot; qui, all'avvio, si tolgono quelle vecchie.
 *
 * Lo script le creava con /bin/sh, che su FreeBSD non espande le graffe: dentro Maildir/ non c'erano cur, new e tmp, ma
 * una cartella sola che si chiama proprio {cur,new,tmp}. Cosi' era sul server vero (12 su 12, visto al passaggio del
 * 20/11/2026, quando questa riparazione le ha lasciate tutte): quel nome vale come cur, new e tmp, alle stesse condizioni.
 *
 * Solo con rmdir, come vmail: rmdir toglie una cartella solo se e' vuota, quindi una Maildir/ con dentro anche un solo
 * file (o un collegamento) resta com'e', e il registro lo dice. E solo se Dovecot non tiene la posta proprio in una
 * cartella che si chiama Maildir: allora sarebbe la sua, anche vuota. Al secondo avvio non trova niente da fare (una
 * Maildir/ non vuota resta, e ogni avvio la ricorda in una riga del registro).
 */
public final class UnusedMaildir {

    private static final Logger LOGGER = Logger.getLogger(UnusedMaildir.class.getName());

    static Path vmail = Path.of("/var/vmail");

    /**
     * Il lavoro come vmail: per ogni casella, la sua Maildir/ solo se dentro ha al piu' cur, new e tmp vuote (o
     * {cur,new,tmp} vuota), e con rmdir,
     * che comunque non toglie niente che non sia vuoto.
     */
    static final String SCRIPT = """
            PATH=/bin:/usr/bin; export PATH
            cd / || exit 1
            for m in "$1"/*/*; do
              [ -d "$m" ] && [ ! -L "$m" ] && [ ! -L "${m%/*}" ] || continue
              d="$m/Maildir"
              [ -d "$d" ] && [ ! -L "$d" ] || continue
              # Solo se dentro ci sono al piu' cur, new e tmp (o la cartella {cur,new,tmp} che /bin/sh creava senza
              # espandere le graffe), cartelle vere e vuote: altrimenti non si tocca niente.
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

    /** Il percorso della posta di Dovecot finisce in una cartella Maildir: allora quella cartella e' sua. Funzione pura. */
    static boolean dovecotUsesMaildirFolder(String mailPath) {
        return mailPath != null && mailPath.contains("/Maildir");
    }

    /** Le righe del lavoro, divise per esito. */
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

    /** Lo script su una cartella qualsiasi, con l'utente che gira: per le prove. */
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
