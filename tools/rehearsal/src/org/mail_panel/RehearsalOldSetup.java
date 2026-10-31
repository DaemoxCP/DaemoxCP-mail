package org.mail_panel;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Dopo l'installazione: quello che il server vero ha in piu', fatto con le funzioni della versione
 * del server. Certificato del pannello, primo amministratore, un dominio con due caselle, la
 * superficie sulla 443 con MTA-STS in enforce, la sua jail, lo script di avvio.
 */
public class RehearsalOldSetup {
    public static void main(String[] a) throws Exception {
        String host = a[0], domain = a[1];
        Main.dbManager = new org.mail_panel.sqli.dataBaseManager();
        String cert = Files.readString(Path.of("/usr/local/etc/ssl/mail/fullchain.pem"));
        String key = Files.readString(Path.of("/usr/local/etc/ssl/mail/privkey.pem"));
        System.out.println("pannello: " + Main.dbManager.update_panel_config("127.0.0.1", "2096", cert, key, "", "mailpanel-"));
        String err = Main.connectFromConfig();
        System.out.println("MySQL: " + (err == null ? "connesso" : err));
        System.out.println("amministratore: " + Main.createFirstAdmin("rehearsal-admin", "admin@" + domain, System.out, System.err));
        org.mail_panel.database.MailDatabase db = Main.mailDatabase != null ? Main.mailDatabase : new org.mail_panel.database.MailDatabase();
        if (!db.isConnected()) db.connect();
        // Le colonne che la versione del server aggiunge all'avvio del pannello web (SSLMailServer,
        // righe 481-490 di 419b0a2), nello stesso ordine: senza, una casella non si crea.
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
        // Le credenziali di prova stanno solo qui e in /root/rehearsal/mailboxes, leggibile da root.
        String[][] boxes = {{"alice@" + domain, "Rehearsal-Alice-2026x", "Alice"}, {"bob@" + domain, "Rehearsal-Bob-2026x", "Bob"}};
        StringBuilder list = new StringBuilder();
        for (String[] b : boxes) {
            try (java.sql.PreparedStatement q = db.getConnection().prepareStatement("SELECT id FROM mailboxes WHERE email = ?")) {
                q.setString(1, b[0]);
                try (java.sql.ResultSet rs = q.executeQuery()) {
                    System.out.println("casella " + b[0] + ": " + (rs.next() ? "c'era gia'" : db.addMailbox(id, b[0], b[1], b[2], 1024)));
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
        System.out.println("modo MTA-STS: " + org.mail_panel.system.MtaSts.impostaModo("enforce"));
        System.out.println("politica: " + org.mail_panel.system.ProtezioneWeb.scriviPolitica());
        System.out.println("jail: " + org.mail_panel.system.ProtezioneWeb.installaJail());
        System.out.println("script di avvio: " + org.mail_panel.system.UpdateManager.scriptRcPannello(true));
        System.exit(0);
    }
}
