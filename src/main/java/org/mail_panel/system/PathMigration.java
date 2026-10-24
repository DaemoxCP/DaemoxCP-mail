package org.mail_panel.system;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * All'avvio: i nomi di file e cartella che il pannello scriveva in italiano.
 *
 * <p>I nomi nel codice sono passati all'inglese (r26), ma un server gia' avviato ha sul disco
 * quelli vecchi. Senza questo passaggio il pannello non li troverebbe piu' e perderebbe lo
 * stato: il proprio log, il log dell'ultimo riavvio, lo stato del salto di versione, le copie
 * prese prima di ogni modifica a postfix, nginx e fail2ban.
 *
 * <p>Ogni passo controlla prima: ripeterlo non cambia niente. Se esistono ENTRAMBI i nomi il
 * vecchio viene lasciato dov'e' e si registra un avviso, perche' decidere quale dei due valga
 * non e' compito di una migrazione: non deve distruggere niente.
 *
 * <p>L'ordine conta dove una cartella contiene un file da rinominare: prima la cartella, poi
 * il file dentro, altrimenti il secondo passo cercherebbe un percorso che non esiste piu'.
 *
 * <p>Il file del ramo dei pacchetti conserva il prefisso "zz": pkg legge
 * /usr/local/etc/pkg/repos in ordine alfabetico e per ogni campo vale l'ultimo, quindi il nome
 * nuovo deve restare alfabeticamente ultimo. Il nome scelto e' lo stesso del pannello web,
 * cosi' i due smettono di chiamare in due modi la stessa cosa.
 *
 * <p>NON sono qui tre nomi che un servizio esterno legge, e che vogliono la rigenerazione
 * della sua configurazione invece di uno spostamento: i due filtri fail2ban
 * (filter.d e jail.d, mailpanel-pubblico.conf) e il log di accesso di nginx
 * (/var/log/nginx/mailpanel-pubblico-access.log), che e' anche in newsyslog.
 */
public final class PathMigration {

    private static final Logger LOGGER = Logger.getLogger(PathMigration.class.getName());

    private PathMigration() {}

    public static void run() {
        String db = "/var/db/mailpanel/";
        rename(db + "pannello.log", db + "panel.log");
        rename(db + "riavvio.log", db + "reboot.log");
        rename(db + "pubblico", db + "public");
        rename(db + "prova-copia.sql", db + "test-dump.sql");
        rename(db + "ssl-precedente", db + "ssl-previous");
        rename(db + "mailpanel-pubblico.conf-precedente", db + "mailpanel-public.conf-previous");
        rename(db + "mailpanel.rc.test", db + "mailpanel.rc.test");
        rename(db + "mailpanel.rc.removed", db + "mailpanel.rc.removed");
        rename(db + "master.cf-prima-della-465", db + "master.cf-before-465");
        rename(db + "nginx-prima-di-autoconfig.conf", db + "nginx-before-autoconfig.conf");
        rename(db + "nginx.conf-prima-di-include", db + "nginx.conf-before-include");

        // Prima la cartella, poi il file che contiene.
        rename(db + "sistema", db + "system");
        rename(db + "system/salto.json", db + "system/version-jump.json");

        rename("/var/db/mail-panel/copie-fail2ban", "/var/db/mail-panel/fail2ban-backups");
        rename("/usr/local/etc/pkg/repos/zz-pannello-ramo.conf",
               "/usr/local/etc/pkg/repos/zz-panel-branch.conf");
    }

    /** Sposta oldName su newName se c'e' il primo e non c'e' il secondo. Non segue i link. */
    private static void rename(String oldName, String newName) {
        // Se i due nomi coincidono non c'e' niente da spostare. La guardia esiste perche' una
        // passata di rinomina sul codice puo' cambiare ANCHE il nome vecchio qui dentro, e il
        // risultato sarebbe un avviso falso invece di un errore visibile.
        if (oldName.equals(newName)) return;
        Path from = Path.of(oldName);
        Path to = Path.of(newName);
        if (!Files.exists(from, LinkOption.NOFOLLOW_LINKS)) return;
        if (Files.exists(to, LinkOption.NOFOLLOW_LINKS)) {
            LOGGER.warning("Both " + oldName + " and " + newName + " exist: leaving the old one in place");
            return;
        }
        try {
            Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
            LOGGER.info("Renamed " + oldName + " to " + newName);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Could not rename " + oldName + " to " + newName, e);
        }
    }
}
