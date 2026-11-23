package org.daemoxcp.mail;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The test bench with the current jar, after InstallFromScratch: what a real server has in addition,
 * made with the functions of the installed version. Certificate of the panel, first
 * administrator, a domain with two mailboxes and the start script. Like RehearsalOldSetup, but with
 * the English names: that one compiles only against the jar of 11 October. The surface on 443 is not
 * there: the tests that use it start from the test bench of 11 October.
 *
 * It is compiled against the installed jar and launched from its folder (jarPath() and the current
 * folder end up in the start script):
 *   javac --release 25 -cp daemoxcp-mail.jar -d classes RehearsalCurrentSetup.java
 *   java -cp classes:daemoxcp-mail.jar org.daemoxcp.mail.RehearsalCurrentSetup rehearsal.test
 */
public class RehearsalCurrentSetup {
    public static void main(String[] a) throws Exception {
        String domain = a[0];
        Main.dbManager = new org.daemoxcp.mail.sqli.dataBaseManager();
        String cert = Files.readString(Path.of("/usr/local/etc/ssl/mail/fullchain.pem"));
        String key = Files.readString(Path.of("/usr/local/etc/ssl/mail/privkey.pem"));
        System.out.println("panel: " + Main.dbManager.update_panel_config("127.0.0.1", "2096", cert, key, "", "mailpanel-"));
        String err = Main.connectFromConfig();
        System.out.println("MySQL: " + (err == null ? "connesso" : err));
        System.out.println("administrator: " + Main.createFirstAdmin("rehearsal-admin", "admin@" + domain, System.out, System.err));
        org.daemoxcp.mail.database.MailDatabase db = Main.mailDatabase;
        // The columns that the web panel adds at startup (SSLMailServer.ensureSchemaUpgrades):
        // without them, a mailbox cannot be created.
        db.ensureMailboxReceiveEnabledColumn();
        db.ensureMailboxPasswordVaultColumns();
        db.ensureThemeColumn();
        db.ensureLanguageColumn();
        db.ensureDkimRotationColumns();
        db.ensureCloudflareAccountsSchema();
        db.ensureDkimRotationHistoryTable();
        int id;
        try (java.sql.PreparedStatement q = db.getConnection().prepareStatement(org.daemoxcp.mail.database.SqlCatalog.MAIL_GET_DOMAIN_BY_NAME)) {
            q.setString(1, domain);
            try (java.sql.ResultSet rs = q.executeQuery()) { id = rs.next() ? rs.getInt("id") : db.addDomain(domain, "rehearsal"); }
        }
        // The test credentials are only here and in /root/rehearsal/mailboxes, readable by root.
        String[][] boxes = {{"alice@" + domain, "Rehearsal-Alice-2026x", "Alice"}, {"bob@" + domain, "Rehearsal-Bob-2026x", "Bob"}};
        StringBuilder list = new StringBuilder();
        for (String[] b : boxes) {
            try (java.sql.PreparedStatement q = db.getConnection().prepareStatement(org.daemoxcp.mail.database.SqlCatalog.UM_ACTIVE_MAILBOX_COUNT)) {
                q.setString(1, b[0]);
                try (java.sql.ResultSet rs = q.executeQuery()) {
                    System.out.println("mailbox " + b[0] + ": " + (rs.next() && rs.getInt(1) > 0 ? "already there" : db.addMailbox(id, b[0], b[1], b[2], 1024)));
                }
            }
            list.append(b[0]).append(' ').append(b[1]).append('\n');
        }
        Path f = Path.of("/root/rehearsal/mailboxes");
        Files.createDirectories(f.getParent());
        Files.writeString(f, list.toString());
        Files.setPosixFilePermissions(f, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        System.out.println("start script: " + org.daemoxcp.mail.system.UpdateManager.panelRcScript(true));
        System.exit(0);
    }
}
