package org.mail_panel;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * After the installation: what the production server has in addition, made with the functions of the
 * server's version. Certificate of the panel, first administrator, a domain with two mailboxes, the
 * surface on 443 with MTA-STS in enforce, its jail, the start script.
 */
public class RehearsalOldSetup {
    public static void main(String[] a) throws Exception {
        String host = a[0], domain = a[1];
        Main.dbManager = new org.mail_panel.sqli.dataBaseManager();
        String cert = Files.readString(Path.of("/usr/local/etc/ssl/mail/fullchain.pem"));
        String key = Files.readString(Path.of("/usr/local/etc/ssl/mail/privkey.pem"));
        System.out.println("panel: " + Main.dbManager.update_panel_config("127.0.0.1", "2096", cert, key, "", "mailpanel-"));
        String err = Main.connectFromConfig();
        System.out.println("MySQL: " + (err == null ? "connesso" : err));
        System.out.println("administrator: " + Main.createFirstAdmin("rehearsal-admin", "admin@" + domain, System.out, System.err));
        org.mail_panel.database.MailDatabase db = Main.mailDatabase != null ? Main.mailDatabase : new org.mail_panel.database.MailDatabase();
        if (!db.isConnected()) db.connect();
        // The columns that the server's version adds at the start of the web panel (SSLMailServer,
        // lines 481-490 of 419b0a2), in the same order: without them, a mailbox cannot be created.
        db.ensureMailboxReceiveEnabledColumn();
        db.ensureMailboxPasswordVaultColumns();
        db.ensureThemeColumn();
        db.ensureLanguageColumn();
        db.ensureDkimRotationColumns();
        db.ensureCloudflareAccountsSchema();
        db.ensureDkimRotationHistoryTable();
        int id;
        try (java.sql.PreparedStatement q = db.getConnection().prepareStatement("SELECT id FROM domains WHERE domain = ?")) {
            q.setString(1, domain);
            try (java.sql.ResultSet rs = q.executeQuery()) { id = rs.next() ? rs.getInt(1) : db.addDomain(domain, "rehearsal"); }
        }
        // The test credentials are only here and in /root/rehearsal/mailboxes, readable by root.
        String[][] boxes = {{"alice@" + domain, "Rehearsal-Alice-2026x", "Alice"}, {"bob@" + domain, "Rehearsal-Bob-2026x", "Bob"}};
        StringBuilder list = new StringBuilder();
        for (String[] b : boxes) {
            try (java.sql.PreparedStatement q = db.getConnection().prepareStatement("SELECT id FROM mailboxes WHERE email = ?")) {
                q.setString(1, b[0]);
                try (java.sql.ResultSet rs = q.executeQuery()) {
                    System.out.println("mailbox " + b[0] + ": " + (rs.next() ? "already there" : db.addMailbox(id, b[0], b[1], b[2], 1024)));
                }
            }
            list.append(b[0]).append(' ').append(b[1]).append('\n');
        }
        Path f = Path.of("/root/rehearsal/mailboxes");
        Files.createDirectories(f.getParent());
        Files.writeString(f, list.toString());
        Files.setPosixFilePermissions(f, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        System.out.println("include: " + org.mail_panel.system.ProtezioneWeb.aggiungiInclude());
        System.out.println("443: " + org.mail_panel.system.ProtezioneWeb.installa("/usr/local/etc/ssl/mail/fullchain.pem", "/usr/local/etc/ssl/mail/privkey.pem"));
        System.out.println("MTA-STS mode: " + org.mail_panel.system.MtaSts.impostaModo("enforce"));
        System.out.println("policy: " + org.mail_panel.system.ProtezioneWeb.scriviPolitica());
        System.out.println("jail: " + org.mail_panel.system.ProtezioneWeb.installaJail());
        System.out.println("start script: " + org.mail_panel.system.UpdateManager.scriptRcPannello(true));
        System.exit(0);
    }
}
