package org.daemoxcp.mail.system;

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
 * <p>I nomi vecchi e quelli nuovi stanno nel file di dati (LegacyNames, sezioni "files" e
 * "vmailFolders"), non qui. L'ordine e' quello del file, e conta dove una cartella contiene un
 * file da rinominare: prima la cartella, poi il file dentro, altrimenti il secondo passo
 * cercherebbe un percorso che non esiste piu'.
 *
 * <p>Il file del ramo dei pacchetti conserva il prefisso "zz": pkg legge
 * /usr/local/etc/pkg/repos in ordine alfabetico e per ogni campo vale l'ultimo, quindi il nome
 * nuovo deve restare alfabeticamente ultimo. Il nome scelto e' lo stesso del pannello web,
 * cosi' i due smettono di chiamare in due modi la stessa cosa.
 *
 * <p>NON sono qui i nomi che leggono anche nginx e fail2ban: il file della superficie pubblica
 * sulla 443, il suo log di accesso, il filtro e la jail di fail2ban (e con la jail l'ancora e la
 * tabella di pf), e la cartella dei suoi file (/var/db/daemoxcp-mail/pubblico, che nginx legge per
 * mta-sts.txt). Vanno spostati tutti insieme, con nginx e fail2ban ricaricati e un ritorno
 * indietro se uno dei due rifiuta: li sposta PublicSurfaceRename. La cartella stava qui fino al
 * 31/10/2026, ed era sbagliato: sul server vero nginx l'avrebbe cercata col nome vecchio.
 */
public final class PathMigration {

    private static final Logger LOGGER = Logger.getLogger(PathMigration.class.getName());

    private PathMigration() {}

    public static void run() {
        for (String[] p : LegacyNames.pairs("files")) rename(p[0], p[1]);
        migrateArchive(AddressTransform.vmail);
    }

    /**
     * L'archivio della posta delle caselle tolte o trasformate in alias, sotto /var/vmail.
     * A parte, perche' si possa provare su una cartella qualunque senza toccare le altre.
     */
    static void migrateArchive(Path vmail) {
        for (String[] p : LegacyNames.pairs("vmailFolders"))
            rename(vmail.resolve(p[0]).toString(), vmail.resolve(p[1]).toString());
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
