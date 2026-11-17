package org.daemoxcp.mail.system;

import java.nio.file.*;

/**
 * The mailbox archive under /var/vmail had an old name (data file, vmailFolders): at start it
 * moves to the new name with everything inside. On a temporary folder, not on /var/vmail.
 */
public class ArchiveMigrationTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        Path vmail = Files.createTempDirectory("vmail");
        String oldName = LegacyNames.oldNamesOf("vmailFolders", ".panel-archive").stream().findFirst().orElse("");
        check("the data file has the archive's old name", !oldName.isEmpty());
        Path old = vmail.resolve(oldName + "/domain-d.test/dmarc-20260921T120000");
        Files.createDirectories(old.resolve("cur"));
        Files.writeString(old.resolve("cur/1.M1"), "mail");

        PathMigration.migrateArchive(vmail);
        Path moved = vmail.resolve(".panel-archive/domain-d.test/dmarc-20260921T120000/cur/1.M1");
        check("the old archive moves to the new name, with the mail inside",
                Files.exists(moved) && !Files.exists(vmail.resolve(oldName)));

        PathMigration.migrateArchive(vmail);
        check("doing it again changes nothing", Files.exists(moved));

        // if both are there, the old one stays where it is: deciding which one counts is not the migration's job
        Files.createDirectories(vmail.resolve(oldName + "/other"));
        PathMigration.migrateArchive(vmail);
        check("with both, neither is touched",
                Files.exists(vmail.resolve(oldName + "/other")) && Files.exists(moved));

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failures++;
    }
}
