package org.mail_panel.system;

import java.nio.file.*;

/**
 * L'archivio delle caselle sotto /var/vmail aveva un nome di prima (file di dati, vmailFolders):
 * all'avvio passa al nome nuovo con tutto quello che contiene. Su una cartella temporanea, non su
 * /var/vmail.
 */
public class ArchiveMigrationTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        Path vmail = Files.createTempDirectory("vmail");
        String oldName = LegacyNames.oldNamesOf("vmailFolders", ".panel-archive").stream().findFirst().orElse("");
        check("il file di dati ha il nome di prima dell'archivio", !oldName.isEmpty());
        Path old = vmail.resolve(oldName + "/domain-d.test/dmarc-20260921T120000");
        Files.createDirectories(old.resolve("cur"));
        Files.writeString(old.resolve("cur/1.M1"), "mail");

        PathMigration.migrateArchive(vmail);
        Path moved = vmail.resolve(".panel-archive/domain-d.test/dmarc-20260921T120000/cur/1.M1");
        check("l'archivio vecchio passa al nome nuovo, con la posta dentro",
                Files.exists(moved) && !Files.exists(vmail.resolve(oldName)));

        PathMigration.migrateArchive(vmail);
        check("ripeterlo non cambia niente", Files.exists(moved));

        // se ci sono tutti e due, il vecchio resta dov'e': decidere quale valga non e' della migrazione
        Files.createDirectories(vmail.resolve(oldName + "/other"));
        PathMigration.migrateArchive(vmail);
        check("con tutti e due, nessuno dei due si tocca",
                Files.exists(vmail.resolve(oldName + "/other")) && Files.exists(moved));

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failures++;
    }
}
